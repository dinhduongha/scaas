# P1d — `UnderlyingLib` + `UnderlyingToken`: one wrapper kind for 1–8 legs, the native-coin leg, rate admin and guardian as `AdminLib` roles — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `SingleUnderlyingToken`, `MultiUnderlyingToken` and the two Hedera wrapper children by one
implementation `UnderlyingToken` (kind `UNDERLYING`, CTR-TOK-21) whose legs, reserves and rates live in an external
library `UnderlyingLib` (ERC-7201 `scaas.underlying`, CTR-TOK-24), add the native-coin leg (CTR-TOK-26), and move the
rate admin and the guardian onto the `AdminLib` roles of `RATE_ADJUSTABLE` and `WRAP_DISABLEABLE` (CTR-TOK-22).

**Architecture:** `UnderlyingLib` (public mutations linked at deploy, small internal helpers inlined) owns
`UnderlyingStorage {legs, legIndex, pending, legCount, rateDelay, maxRateStepBps}` and does the core of wrap and unwrap
without a destination: pull (or take `msg.value` on the native leg), price, reserve, pay out; rate proposals with
timelock; `disableWrap`; init (decode, check against the factory's `underlyings`, `AdminLib.init`, legs; Hedera HTS
association under `IS_HEDERA`). `UnderlyingToken` keeps the ERC-20 side inline (mint after the pull, burn before the
payout), emits `Wrapped`/`Unwrapped`/`ReserveAdded`, and declares every library event and error through
`IUnderlyingToken` so they are in its ABI. Factory v2 keeps `initialize(creator, underlyings, version, initData)`;
`META_SINGLE` now takes 1–8 legs; P1e replaces the factory with `createToken`/`TokenConfig`.

**Tech Stack:** Solidity 0.8.28, Foundry (forge 1.3.5; external libraries are auto-linked in tests and scripts),
OpenZeppelin Contracts 5.2.0, forge-std 1.16.2; `scaas-node` e2e (Rust, `cargo test --ignored`) as the deploy check.

**Spec:** `docs/history/specs/2026-10-08-token-tree-design.md` (§2, §4, §5, §7); normative:
`docs/contracts/token-wrappers.md` CTR-TOK-04…08, -10, -11, -13, -19, -20, -21, -22, -23, -24, -25, -26, §8, §12;
`docs/networks/hedera.md` NET-HED-14; TODO.md §00 P1 ("P1d: wrappers over EIP-170", P1c note (c)).

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge runs in `smartcontracts/evm` of the worktree
  `.claude/worktrees/p1d` (branch `p1d-underlying`), created by the controller with `lib/` copied.
- **Heavy commands only through `scripts/capped`, one at a time machine-wide**:
  `timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge test …'`. `rtk` rewrites git/grep output: use
  `/usr/bin/grep`, `rtk proxy git diff`.
- Build pins unchanged (solc 0.8.28, optimizer 200, no via-IR, EVM prague). New/touched src files `pragma solidity ^0.8.24;`.
- **Size: not optimised in this plan (owner, 2026-10-11: "tạm thời chưa quan tâm kích thước, tối ưu sau").** Measured in
  the spike: `UnderlyingToken` 25,408 B (over EIP-170 24,576 — see D2), `UnderlyingLib` 11,018 B, `NoUnderlyingToken`
  20,038 B (unchanged), `AdminLib` 3,406 B. Size tests pin ceilings, they do not shrink anything.
- Flag bits (CTR-TOK-22): 0 `PAYABLE`, 1 `MINTABLE`, 2 `BURNABLE`, 3 `RATE_ADJUSTABLE` (role rateAdmin, contract only),
  4 `WRAP_DISABLEABLE` (role guardian, any address), 5–8 regulated (refused `FeatureNotBuilt`). Valid on `UNDERLYING`:
  {0, 3, 4} (+ 5–8 refused). Kind `UNDERLYING` = 1.
- Namespaces: `scaas.underlying` `0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000`
  (`cast index-erc7201 scaas.underlying`); `scaas.token` `0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00`;
  `scaas.metatx` `0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00`. `UnderlyingStorage` slots:
  `legs` NS+0 (leg i at `keccak256(abi.encode(i, NS))`, +1 `num ‖ den`, +2 `reserve`), `legIndex` NS+1, `pending` NS+2,
  `legCount ‖ rateDelay ‖ maxRateStepBps` NS+3.
- Linear layout of every token after this plan: ERC-20 slots 0–4 only (`_legCount` is removed from `MetaTokenBase`).
- Token ABI added/kept on `UnderlyingToken`: `wrap(uint256)` payable, `wrap(address,uint256)` payable,
  `unwrap(uint256,address)`, `unwrap(uint256,address,uint256)`, `unwrap(address,uint256,address,uint256) returns (out,
  burned)`, `addReserve(address,uint256)` payable, `disableWrap(address,bytes32)`, `proposeRate`, `cancelRate`,
  `executeRate`, views `underlying`, `underlyings`, `legOf`, `collateralValue`, `previewWrap`, `previewUnwrap`,
  `rateAdjustable`, `rateDelay`, `maxRateStepBps`, `pendingRate`, constant `RATE_WINDOW` (7 days). Removed:
  `renounceRateAdmin`, `renounceGuardian`, `rateAdmin()`, `guardian()`, events `RateAdminRenounced`,
  `GuardianRenounced`, error `RateAdminNotContract`. New error `NativeValueMismatch(uint256 value, uint256 expected)`.
- Allowlist of `UnderlyingToken` (CTR-MTX-19), rule = (class, amountArg, staticLen): `cancelNonce` (1,0,36),
  `wrap(uint256)` (1,0,36), `unwrap(uint256,address,uint256)` (2,0,100), `wrap(address,uint256)` (1,0,68),
  `unwrap(address,uint256,address,uint256)` (2,1,132), `addReserve(address,uint256)` (1,0,68). `_mtxRule` falls back to
  `super._mtxRule` (closes P1c note (c)).
- Test chain: id 7622, `chain_uid` `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464`; key `0xA11CE`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push. Never `git add claude-code-api.txt`.

## Review Focus

- Coin that is not reserve priced as reserve: coin forced in (`selfdestruct`, block reward), a native balance below the
  reserve, a donation — pinned by `test_native_forcedCoinIsNotReserve`, `test_native_shortfallStopsWrapNotUnwrap`,
  `test_native_executeRateChecksTheCoinBalance` (Task 2).
- Value sent where it is not used (stuck coin): `msg.value` on an ERC-20 leg, `msg.value ≠ amount` on the native leg,
  a gasless native wrap — pinned by `test_native_erc20LegRefusesValue`, `test_native_valueMustMatch`,
  `test_native_noGaslessWrap_gaslessUnwrapWorks` (Task 2).
- The native payout: a recipient that refuses coin, re-enters, or needs more than a 2,300 stipend — pinned by
  `test_native_refusingRecipientRevertsTheUnwrap`, `test_native_reentrantRecipientIsBlocked`,
  `test_native_contractRecipientGetsAllGas` (Task 2).
- A revoked, renounced or disabled role still acting (rate admin after revoke, guardian after `disableFeature`), and a
  pending change surviving `disableFeature(RATE_ADJUSTABLE)` — pinned by `test_rateRole_grantRevokeRenounce_leaveTheRate`,
  `test_disableRateAdjustable_cancelsThePendingChange_andFixesTheRate`, `test_guardianRole_disableWrap_oneWay_andFlagGates`
  (Task 2) and the ported `Rates.t.sol`/`Multi.t.sol` (Task 1).
- Init data whose legs differ from the factory's `underlyings` (the factory index would lie) — pinned by
  `test_init_legsMustMatchTheFactoryUnderlyings` (Task 2).

## Rulings (docs vs code) and defaults taken

- **D1 — `mtxWrap` (CTR-TOK-20) moves to P2.** It calls `underlying.mtxTrade(TradeOrder, …)`, which does not exist
  before `TradeLib` (P2, MT-5). `NativeNotGasless()` goes with it. A native wrap through `mtxExecute(wrap(…))` fails with
  `NativeValueMismatch(0, amount)` (a self-call carries no value). Cost if wrong: none now; P2 adds one entry point.
- **D2 — Size is out of scope (owner).** `UnderlyingToken` is ~25.4 KB, over EIP-170, so it cannot be deployed on a real
  chain yet; forge tests do not enforce EIP-170. The deploy scripts keep deploying only `META_NONE` (the P1b R3
  arrangement continues) and the size tests pin a ceiling (26,624). The size work (the owner's "optimise later", at
  the latest the P1e CI size gate) must bring it under 24,576 (and the 20,480 budget). Flag to the owner.
- **D3 — `UnderlyingToken.sol` is `git mv` of `SingleUnderlyingToken.sol`, rewritten**; most of its logic moves to the
  new `UnderlyingLib.sol`. `MultiUnderlyingToken.sol` and `src/hedera/HederaTokensV2.sol` are deleted.
- **D4 — Rate admin and guardian are `AdminLib` roles.** The spec's errors stay: `RateFixed()` when `RATE_ADJUSTABLE` is
  clear, `NotRateAdmin()` without the role, `NotGuardian()` when `WRAP_DISABLEABLE` is clear or without the role. A
  non-contract rate admin is `ITokenAdmin.RoleNotContract(3, a)` (from `AdminLib`, at init or grant), replacing
  `RateAdminNotContract`. `renounceRole(bit)` replaces `renounceRateAdmin`/`renounceGuardian` and, per CTR-TOK-06,
  **leaves the rate and a pending change as they are**; `rateAdmin()`/`guardian()` are gone (a role may have several
  holders: `hasRole` + `RoleGranted`/`RoleRevoked`). The rate admin is optional at init (the owner may grant it later).
- **D5 — `disableFeature(RATE_ADJUSTABLE)` cancels a pending change** (CTR-TOK-06): `MetaTokenBase.disableFeature`
  becomes `virtual`; `UnderlyingToken` overrides it, emits `FeatureDisabled(3, owner)` then, if a change was pending,
  `RateChangeCancelled(u)`.
- **D6 — Native leg decimals: 18, but 8 on Hedera.** The spec says 18; Hedera's EVM counts HBAR in tinybars (8
  decimals), and decimals are display only (CTR-TOK-08). Cost if wrong: a display value on Hedera.
- **D7 — `NativeValueMismatch(value, expected)`** is the one error for `msg.value ≠ amount` on the native leg and
  `msg.value ≠ 0` on an ERC-20 leg (the spec names none).
- **D8 — Init encoding (transitional until P1e):** `initData = abi.encode(IUnderlyingToken.UnderlyingInit)` = the
  UNDERLYING subset of `TokenConfig`: `name, symbol, decimals, features, lockedFeatures, owner, roles, legs[] (underlying,
  num, den as uint256), rate (rateDelay, maxRateStepBps)`. `legs[i].underlying` must equal the factory's
  `underlyings[i]` (`UnknownUnderlying(u)`; length `UnderlyingCountInvalid(n)`), so the factory index cannot lie.
  `rate` must be zero without `RATE_ADJUSTABLE` and within bounds with it (`RateConfigInvalid`).
- **D9 — Factory v2 (transitional until P1e):** `META_SINGLE` is kind `UNDERLYING` and takes 1–8 legs; nothing
  implements `META_MULTI` any more (registering `UnderlyingToken` under it fails `VersionKindMismatch(MULTI, SINGLE)`).
  `tokenKind()` of `UnderlyingToken` is `META_SINGLE` for every leg count.
- **D10 — `HtsQueryFailed`/`AssociateFailed`** are raised by `HederaLib` (inlined in `UnderlyingLib`) and re-declared in
  `IUnderlyingToken` with the same selectors so they are in the token ABI.
- **D11 — Where the code sits (size, D2):** init decoding, `collateralValue`, `previewWrap`, `previewUnwrap` are public
  in `UnderlyingLib`; `underlying`, `underlyings`, `legOf`, `pendingRate` read the namespace inline (moving them out made
  the token larger in the spike).
- **D12 — Test fixture owner:** every wrapper the fixture builds has `owner = wrapperOwner = address(0x0A11)`, nothing
  locked, `PAYABLE` set (as built), `RATE_ADJUSTABLE` with an adjustable `Rate`, `WRAP_DISABLEABLE` with a non-zero
  guardian.

## File Structure

| File | Task | Responsibility |
|---|---|---|
| `src/metatx/IUnderlyingToken.sol` (new) | 1 | structs `LegInit`, `RateConfig`, `UnderlyingInit`; events, errors, functions of kind UNDERLYING |
| `src/metatx/UnderlyingLib.sol` (new) | 1 | `scaas.underlying` storage; init, wrap/addReserve pull, unwrap quote + payout, rates, `disableWrap`, views |
| `src/metatx/UnderlyingToken.sol` (`git mv` of `SingleUnderlyingToken.sol`) | 1 | thin token: ABI, mint/burn, events, allowlist |
| `src/metatx/MultiUnderlyingToken.sol`, `src/hedera/HederaTokensV2.sol` | 1 | deleted |
| `src/metatx/MetaTokenBase.sol` | 1 | drop `_legCount`; `disableFeature` `virtual` |
| `src/factory/OpenFactoryV2.sol`, `src/common/IOpenFactoryV2.sol` | 1 | `META_SINGLE` takes 1–8 legs |
| `test/v2/helpers/V2Fixture.sol` | 1 | `Rate`, `underlyingInit`, `_single`/`_multi` build `UnderlyingToken` |
| `test/v2/*.t.sol`, `test/hedera/HederaV2.t.sol`, `test/metatx/MsgSenderLint.t.sol`, `test/v2/layout/*.json` | 1 | port |
| `test/v2/Underlying.t.sol`, `test/v2/NativeLeg.t.sol` (new) | 2 | conformance of the new rules |
| `script/Deploy.s.sol`, `script/hedera/DeployHedera.s.sol` | 3 | comments only (NONE-only stays, D2) |
| `docs/contracts/token-wrappers.md`, `docs/contracts/metatx.md`, `docs/networks/hedera.md`, `docs/history/dropped-artifacts.tsv`, `TODO.md`, `HANDOFF.md` | 3 | docs |

---

### Task 1: `UnderlyingLib` + `UnderlyingToken`; delete the wrapper tiers; port every test

**Model:** Opus, effort high (money path: src transcription + a judgment-heavy port across many test files).

**Files (src):**
- Create: `smartcontracts/evm/src/metatx/IUnderlyingToken.sol`, `smartcontracts/evm/src/metatx/UnderlyingLib.sol` (full texts below)
- Rename + rewrite: `git mv smartcontracts/evm/src/metatx/SingleUnderlyingToken.sol smartcontracts/evm/src/metatx/UnderlyingToken.sol` (full text below)
- Delete: `git rm smartcontracts/evm/src/metatx/MultiUnderlyingToken.sol smartcontracts/evm/src/hedera/HederaTokensV2.sol`
- Modify: `smartcontracts/evm/src/metatx/MetaTokenBase.sol`, `smartcontracts/evm/src/factory/OpenFactoryV2.sol`,
  `smartcontracts/evm/src/common/IOpenFactoryV2.sol`

**Files (tests):** `test/v2/helpers/V2Fixture.sol`; every file that names `SingleUnderlyingToken`,
`MultiUnderlyingToken`, `HederaTokensV2`, `Hedera{Single,Multi}UnderlyingToken`, `renounceRateAdmin`, `renounceGuardian`,
`rateAdmin()`, `guardian()`, `_legCount`, `META_MULTI`: at least `test/v2/{Tier2,Multi,Rates,UnwrapOp,WrapperInvariant,
RateVectors,Allowlist,Features,MetaTxGasV2,FactoryV2,Layout}.t.sol`, `test/metatx/MsgSenderLint.t.sol`,
`test/hedera/HederaV2.t.sol`, `test/v2/layout/*.json`. Find them with
`/usr/bin/grep -rlE "SingleUnderlyingToken|MultiUnderlyingToken|HederaTokensV2|Hedera(Single|Multi)Underlying|renounceRateAdmin|renounceGuardian|rateAdmin\(\)|guardian\(\)|_legCount|META_MULTI" smartcontracts/evm/test smartcontracts/evm/script`.

**Interfaces:**
- Consumes: `AdminLib` (`init`, `disableFeature`, `hasFeature`, `hasRole`, `$()`, `Roles`, flag constants, `KIND_UNDERLYING`),
  `HederaLib.checkAndAssociate(address) internal returns (bool)`, `MetaTokenBase` (`IS_HEDERA`, `_msgSender`,
  `UnderlyingCountInvalid(uint256)`, `nonReentrant`, `FEE_CLASS_*`, `MtxRule`).
- Produces (Task 2 relies on these exact names): `IUnderlyingToken.{LegInit, RateConfig, UnderlyingInit}`, every
  event/error listed in the file below; fixture `struct Rate {bool adjustable; address rateAdmin; uint32 rateDelay;
  uint16 maxRateStepBps;}`, free function `underlyingInit(address[] us, uint256[] nums, uint256[] dens, uint8 dec, Rate
  cfg, address guardian, address owner) returns (IUnderlyingToken.UnderlyingInit)`, members `wrapperOwner`
  (`address(0x0A11)`), `_underlyingImpl()`, `_one(address)`, `_oneU(uint256)`, `_singleInit(address u, uint8 dec,
  uint256 num, uint256 den, Rate cfg) returns (bytes)`, `_single(address u, uint8 dec, uint256 num, uint256 den, Rate
  cfg) returns (UnderlyingToken)`, `_multiInit(address[] us, uint256[] nums, uint256[] dens, Rate cfg, address guardian)
  returns (bytes)`, `_multi(… same …) returns (UnderlyingToken)`, `_fixedRate()`, `_adjustable(address admin)` (both
  return `Rate`).

- [ ] **Step 1: Write `IUnderlyingToken.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AdminLib} from "./AdminLib.sol";

/// @title Kind `UNDERLYING` (CTR-TOK-21): 1–8 legs, each an ERC-20 or the native coin (`address(0)`, CTR-TOK-26).
/// @notice Events and errors raised by `UnderlyingLib` (an external library) are declared here so that they are in the
///         token ABI.
interface IUnderlyingToken {
    /// @notice One leg at creation: `underlying` (`address(0)` = the native coin), rate `num/den` (CTR-TOK-04).
    ///         `uint256` so a value `≥ 2^96` reverts `RateInvalid` instead of failing to decode.
    struct LegInit {
        address underlying;
        uint256 num;
        uint256 den;
    }

    /// @notice With `RATE_ADJUSTABLE`: `2 days ≤ rateDelay ≤ 30 days`, `1 ≤ maxRateStepBps ≤ 1000`; without: both 0.
    struct RateConfig {
        uint32 rateDelay;
        uint16 maxRateStepBps;
    }

    /// @notice The UNDERLYING subset of `TokenConfig` (CTR-TOK-25); `legs[i].underlying == underlyings[i]` of the
    ///         factory call.
    struct UnderlyingInit {
        string name;
        string symbol;
        uint8 decimals;
        uint256 features;
        uint256 lockedFeatures;
        address owner;
        AdminLib.Roles roles;
        LegInit[] legs;
        RateConfig rate;
    }

    event Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted);
    event Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned,
        uint256 underlyingOut);
    event ReserveAdded(address indexed from, address indexed underlying, uint256 amount);
    event RateChangeProposed(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen,
        uint64 eta);
    event RateChangeCancelled(address indexed underlying);
    event RateChanged(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen);
    event WrapDisabled(address indexed underlying, address indexed guardian, bytes32 reason);

    error UnderlyingInvalid(address u);
    error DecimalsUnreadable(address u);
    error DuplicateUnderlying(address u);
    error RateInvalid(uint256 num, uint256 den);
    error RateConfigInvalid();
    error WrapTooSmall();
    error UnwrapTooSmall();
    error UnwrapBelowMin(uint256 out, uint256 minOut);
    error UnwrapRecipientInvalid(address recipient);
    error InsufficientReserve(address u, uint256 out, uint256 reserve);
    error ReserveShortfall(address u, uint256 balance, uint256 reserve);
    error UnderlyingTransferMismatch(address u, uint256 expected, uint256 actual);
    error UnknownUnderlying(address u);
    error WrapDisabledFor(address u);
    error UnderlyingRequired();
    error RateFixed();
    error NotRateAdmin();
    error NotGuardian();
    error RateChangePending();
    error NoRateChangePending();
    error RateChangeNotReady(uint64 eta);
    error RateChangeExpired(uint64 eta);
    error RateStepTooLarge();
    error RateChangeUndercollateralized(uint256 collateral, uint256 supply);
    error RateDecreaseWithDisabledLeg();
    error WrapPausedForRateChange(address u);
    /// @notice `msg.value` must equal `amount` on the native leg and be 0 on any other leg (CTR-TOK-26).
    error NativeValueMismatch(uint256 value, uint256 expected);
    /// @notice Raised by `HederaLib` at init on Hedera (same selectors), listed here for the ABI.
    error HtsQueryFailed(address u, int64 responseCode);
    error AssociateFailed(int64 responseCode);

    function wrap(uint256 amount) external payable returns (uint256 minted);
    function wrap(address underlying, uint256 amount) external payable returns (uint256 minted);
    function unwrap(uint256 wrapped, address recipient) external returns (uint256 out);
    function unwrap(uint256 wrapped, address recipient, uint256 minOut) external returns (uint256 out);
    function unwrap(address underlying, uint256 wrapped, address recipient, uint256 minOut)
        external returns (uint256 out, uint256 burned);
    function addReserve(address underlying, uint256 amount) external payable;
    function disableWrap(address underlying, bytes32 reason) external;
    function proposeRate(address underlying, uint96 num, uint96 den) external;
    function cancelRate() external;
    function executeRate() external;

    function underlying() external view returns (address);
    function underlyings() external view returns (address[] memory);
    function legOf(address u)
        external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals, bool wrapEnabled);
    function collateralValue() external view returns (uint256);
    function previewWrap(address u, uint256 amount) external view returns (uint256 minted, uint256 used);
    function previewUnwrap(address u, uint256 wrapped) external view returns (uint256 out, uint256 burned);
    function rateAdjustable() external view returns (bool);
    function rateDelay() external view returns (uint32);
    function maxRateStepBps() external view returns (uint16);
    function pendingRate() external view returns (address u, uint96 num, uint96 den, uint64 eta);
}
```

- [ ] **Step 2: Write `UnderlyingLib.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IUnderlyingToken} from "./IUnderlyingToken.sol";
import {AdminLib} from "./AdminLib.sol";
import {MetaTokenBase} from "./MetaTokenBase.sol";
import {HederaLib} from "../hedera/HederaLib.sol";

/// @title Legs, reserve and rates of kind `UNDERLYING` (CTR-TOK-24), in the ERC-7201 namespace `scaas.underlying`.
/// @notice External library: the core of wrap and unwrap **without a destination** (pull, rate, reserve; pay out),
///         rate changes with timelock, `disableWrap`. The token mints and burns (ERC-20 stays inline) and emits
///         `Wrapped`/`Unwrapped`/`ReserveAdded`.
///
///         Rate `q = num/den` = wrapped raw units per underlying raw unit (CTR-TOK-04); every output rounds DOWN:
///         `minted = ⌊in·q⌋`, `out = ⌊w/q⌋`, unwrap burns only `⌈out·q⌉ ≤ w`. Invariant (CTR-TOK-05):
///         `Σ⌊reserve_i·q_i⌋ ≥ totalSupply()`; `reserve` changes only through wrap, unwrap, `addReserve`; the raw
///         balance never prices anything. The native leg (`address(0)`, CTR-TOK-26) reads `address(this).balance`
///         where an ERC-20 leg reads `balanceOf(this)`.
library UnderlyingLib {
    using SafeERC20 for IERC20;

    /// @dev slot a: token ‖ decimals ‖ wrapEnabled ‖ adjustable (copy, so a fixed-rate wrap reads no config);
    ///      slot b: num ‖ den; slot c: reserve.
    struct Leg {
        address token;
        uint8 decimals;
        bool wrapEnabled;
        bool adjustable;
        uint96 num;
        uint96 den;
        uint256 reserve;
    }

    /// @dev One slot; `eta == 0` ⇒ none.
    struct PendingRate {
        uint8 leg;
        uint96 num;
        uint96 den;
        uint56 eta;
    }

    /// @custom:storage-location erc7201:scaas.underlying
    struct UnderlyingStorage {
        mapping(uint256 => Leg) legs;
        mapping(address => uint256) legIndex; // index + 1
        PendingRate pending;
        uint8 legCount;
        uint32 rateDelay;
        uint16 maxRateStepBps;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.underlying")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000;

    address internal constant NATIVE = address(0);
    uint256 internal constant MAX_LEGS = 8;
    uint256 internal constant MAX_RATE = type(uint96).max;
    /// @notice Execution window after `eta`; past it the change counts as none everywhere.
    uint256 internal constant RATE_WINDOW = 7 days;

    function $() internal pure returns (UnderlyingStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init

    /// @notice The token's `_init`: decode `UnderlyingInit`, check it against the factory's `underlyings` (1–8, same
    ///         order), write the metadata, the flags/owner/roles (`AdminLib.init`), the rate config and the legs in the
    ///         factory's order (which never changes).
    function initToken(address[] calldata underlyings, bytes calldata initData, bool isHedera) public {
        IUnderlyingToken.UnderlyingInit memory c = abi.decode(initData, (IUnderlyingToken.UnderlyingInit));
        uint256 n = underlyings.length;
        if (n == 0 || n > MAX_LEGS) revert MetaTokenBase.UnderlyingCountInvalid(n);
        if (c.legs.length != n) revert MetaTokenBase.UnderlyingCountInvalid(c.legs.length);
        for (uint256 i; i < n; ++i) {
            if (c.legs[i].underlying != underlyings[i]) revert IUnderlyingToken.UnknownUnderlying(underlyings[i]);
        }
        AdminLib.TokenStorage storage t = AdminLib.$();
        t.name = c.name;
        t.symbol = c.symbol;
        t.decimals = c.decimals;
        AdminLib.init(AdminLib.KIND_UNDERLYING, c.features, c.lockedFeatures, c.owner, c.roles);
        bool adjustable = AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE);
        UnderlyingStorage storage s = $();
        IUnderlyingToken.RateConfig memory rate = c.rate;
        if (!adjustable) {
            if (rate.rateDelay != 0 || rate.maxRateStepBps != 0) revert IUnderlyingToken.RateConfigInvalid();
        } else {
            if (rate.rateDelay < 2 days || rate.rateDelay > 30 days || rate.maxRateStepBps == 0
                || rate.maxRateStepBps > 1000) revert IUnderlyingToken.RateConfigInvalid();
            s.rateDelay = rate.rateDelay;
            s.maxRateStepBps = rate.maxRateStepBps;
        }
        for (uint256 i; i < n; ++i) _addLeg(s, c.legs[i], adjustable, isHedera);
    }

    function _addLeg(UnderlyingStorage storage s, IUnderlyingToken.LegInit memory l, bool adjustable, bool isHedera)
        private
    {
        address u = l.underlying;
        uint8 d;
        if (u == NATIVE) {
            d = isHedera ? 8 : 18; // Hedera's EVM counts the native coin in tinybars
        } else {
            if (u == address(this) || u.code.length == 0) revert IUnderlyingToken.UnderlyingInvalid(u);
            if (isHedera && !HederaLib.checkAndAssociate(u)) revert IUnderlyingToken.UnderlyingInvalid(u);
            (bool ok, bytes memory ret) = u.staticcall(abi.encodeCall(IERC20Metadata.decimals, ()));
            if (!ok || ret.length != 32 || uint256(bytes32(ret)) > type(uint8).max) {
                revert IUnderlyingToken.DecimalsUnreadable(u);
            }
            d = uint8(uint256(bytes32(ret)));
        }
        (uint256 num, uint256 den) = (l.num, l.den);
        if (num == 0 || den == 0 || num > MAX_RATE || den > MAX_RATE) revert IUnderlyingToken.RateInvalid(num, den);
        if (s.legIndex[u] != 0) revert IUnderlyingToken.DuplicateUnderlying(u);
        uint256 i = s.legCount;
        s.legs[i] = Leg({
            token: u, decimals: d, wrapEnabled: true, adjustable: adjustable,
            num: uint96(num), den: uint96(den), reserve: 0
        });
        s.legIndex[u] = i + 1;
        s.legCount = uint8(i + 1);
    }

    // ------------------------------------------------------------------ wrap / reserve / unwrap

    /// @notice Pull `amount` from `from` (or take `value` on the native leg), price the measured delta.
    function wrap(uint256 i, uint256 amount, address from, uint256 value)
        public returns (address u, uint256 received, uint256 minted)
    {
        UnderlyingStorage storage s = $();
        Leg storage L = s.legs[i];
        u = L.token;
        if (!L.wrapEnabled) revert IUnderlyingToken.WrapDisabledFor(u);
        if (L.adjustable && _isPending(s)) revert IUnderlyingToken.WrapPausedForRateChange(u);
        received = _pull(L, amount, from, value);
        minted = Math.mulDiv(received, L.num, L.den);
        if (minted == 0) revert IUnderlyingToken.WrapTooSmall();
    }

    /// @notice Anyone; no mint. Refused on a leg whose wrap is disabled.
    function addReserve(uint256 i, uint256 amount, address from, uint256 value) public returns (uint256 received) {
        Leg storage L = $().legs[i];
        if (!L.wrapEnabled) revert IUnderlyingToken.WrapDisabledFor(L.token);
        received = _pull(L, amount, from, value);
    }

    /// @dev One balance read before serves both the shortfall check (no wrap or top-up while `balance < reserve`)
    ///      and the measurement. Native: the balance already holds `value`, which is the measured delta.
    function _pull(Leg storage L, uint256 amount, address from, uint256 value) private returns (uint256 received) {
        address u = L.token;
        uint256 reserve = L.reserve;
        if (u == NATIVE) {
            if (value != amount) revert IUnderlyingToken.NativeValueMismatch(value, amount);
            uint256 before = address(this).balance - value;
            if (before < reserve) revert IUnderlyingToken.ReserveShortfall(u, before, reserve);
            received = value;
        } else {
            if (value != 0) revert IUnderlyingToken.NativeValueMismatch(value, 0);
            uint256 before = IERC20(u).balanceOf(address(this));
            if (before < reserve) revert IUnderlyingToken.ReserveShortfall(u, before, reserve);
            IERC20(u).safeTransferFrom(from, address(this), amount);
            received = IERC20(u).balanceOf(address(this)) - before;
        }
        L.reserve = reserve + received;
    }

    /// @notice Every check before any effect: recipient, `0 < out`, `out ≥ minOut`, `out ≤ reserve`.
    function quoteUnwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut)
        public view returns (uint256 out, uint256 burned)
    {
        if (recipient == address(0) || recipient == address(this)) {
            revert IUnderlyingToken.UnwrapRecipientInvalid(recipient);
        }
        Leg storage L = $().legs[i];
        (uint256 num, uint256 den) = (L.num, L.den);
        out = Math.mulDiv(wrapped, den, num);
        if (out == 0) revert IUnderlyingToken.UnwrapTooSmall();
        if (out < minOut) revert IUnderlyingToken.UnwrapBelowMin(out, minOut);
        uint256 reserve = L.reserve;
        if (out > reserve) revert IUnderlyingToken.InsufficientReserve(L.token, out, reserve);
        burned = Math.mulDiv(out, num, den, Math.Rounding.Ceil);
    }

    /// @notice After the token burned: `reserve -= out`, then the one outside call, under the token's guard (CEI).
    ///         The balance must drop by EXACTLY `out` (a sender-pays fee reverts, CTR-TOK-11). The native coin goes
    ///         with all gas; a recipient that refuses it reverts the unwrap.
    function payOut(uint256 i, address recipient, uint256 out) public returns (address u) {
        Leg storage L = $().legs[i];
        L.reserve -= out;
        u = L.token;
        uint256 before = _balance(u);
        if (u == NATIVE) Address.sendValue(payable(recipient), out);
        else IERC20(u).safeTransfer(recipient, out);
        uint256 after_ = _balance(u);
        uint256 sent = before > after_ ? before - after_ : 0;
        if (sent != out) revert IUnderlyingToken.UnderlyingTransferMismatch(u, out, sent);
    }

    // ------------------------------------------------------------------ guardian (WRAP_DISABLEABLE)

    /// @notice One-way: no re-enable (a compromised guardian reopening a depegged inflow would drain the good legs).
    function disableWrap(address u, bytes32 reason, address caller) public {
        if (!AdminLib.hasFeature(AdminLib.WRAP_DISABLEABLE) || !AdminLib.hasRole(AdminLib.WRAP_DISABLEABLE, caller)) {
            revert IUnderlyingToken.NotGuardian();
        }
        Leg storage L = $().legs[indexOf(u)];
        if (!L.wrapEnabled) revert IUnderlyingToken.WrapDisabledFor(u);
        L.wrapEnabled = false;
        emit IUnderlyingToken.WrapDisabled(u, caller, reason);
    }

    // ------------------------------------------------------------------ rates (CTR-TOK-06, CTR-TOK-13)

    function _onlyRateAdmin(address caller) private view {
        if (!AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE)) revert IUnderlyingToken.RateFixed();
        if (!AdminLib.hasRole(AdminLib.RATE_ADJUSTABLE, caller)) revert IUnderlyingToken.NotRateAdmin();
    }

    /// @notice The step is checked ONCE, here, against the current rate (which cannot change while pending).
    function proposeRate(address u, uint96 num, uint96 den, address caller) public {
        _onlyRateAdmin(caller);
        UnderlyingStorage storage s = $();
        if (_isPending(s)) revert IUnderlyingToken.RateChangePending();
        uint256 i = indexOf(u);
        if (num == 0 || den == 0) revert IUnderlyingToken.RateInvalid(num, den);
        Leg storage L = s.legs[i];
        (uint96 n0, uint96 d0) = (L.num, L.den);
        // |num'·den − num·den'|·10⁴ ≤ num·den'·bps — exact in integers, every product < 2^207.
        uint256 a = uint256(num) * d0;
        uint256 b = uint256(n0) * den;
        if ((a > b ? a - b : b - a) * 10_000 > b * s.maxRateStepBps) revert IUnderlyingToken.RateStepTooLarge();
        uint64 eta = uint64(block.timestamp + s.rateDelay);
        s.pending = PendingRate({leg: uint8(i), num: num, den: den, eta: uint56(eta)});
        emit IUnderlyingToken.RateChangeProposed(u, n0, d0, num, den, eta);
    }

    function cancelRate(address caller) public {
        _onlyRateAdmin(caller);
        UnderlyingStorage storage s = $();
        if (!_isPending(s)) revert IUnderlyingToken.NoRateChangePending();
        _drop(s);
    }

    /// @notice `disableFeature(RATE_ADJUSTABLE)` fixes the rate and cancels a pending change (CTR-TOK-06).
    function dropPending() public {
        UnderlyingStorage storage s = $();
        if (_isPending(s)) _drop(s);
        else delete s.pending;
    }

    function _drop(UnderlyingStorage storage s) private {
        address u = s.legs[s.pending.leg].token;
        delete s.pending;
        emit IUnderlyingToken.RateChangeCancelled(u);
    }

    /// @notice Only the rate admin executes: a third party cannot bundle the execution with its own wraps.
    function executeRate(address caller, uint256 supply) public {
        _onlyRateAdmin(caller);
        UnderlyingStorage storage s = $();
        PendingRate memory p = s.pending;
        if (p.eta == 0) revert IUnderlyingToken.NoRateChangePending();
        if (block.timestamp < p.eta) revert IUnderlyingToken.RateChangeNotReady(p.eta);
        if (block.timestamp > uint256(p.eta) + RATE_WINDOW) revert IUnderlyingToken.RateChangeExpired(p.eta);
        bool anyDisabled = _requireCollateral(s, p, supply);
        Leg storage T = s.legs[p.leg];
        (uint96 n0, uint96 d0) = (T.num, T.den);
        if (anyDisabled && uint256(p.num) * d0 < uint256(n0) * p.den) {
            revert IUnderlyingToken.RateDecreaseWithDisabledLeg();
        }
        T.num = p.num;
        T.den = p.den;
        delete s.pending;
        emit IUnderlyingToken.RateChanged(T.token, n0, d0, p.num, p.den);
    }

    /// @dev Every leg: `balance ≥ reserve` (no phantom reserve); then `C' ≥ supply` with the new rate, summing with an
    ///      early exit once covered but still checking every leg's balance. Returns "some leg has wrap disabled".
    function _requireCollateral(UnderlyingStorage storage s, PendingRate memory p, uint256 supply)
        private view returns (bool anyDisabled)
    {
        uint256 c;
        uint256 n = s.legCount;
        for (uint256 i; i < n; ++i) {
            Leg storage L = s.legs[i];
            uint256 r = L.reserve;
            uint256 bal = _balance(L.token);
            if (bal < r) revert IUnderlyingToken.ReserveShortfall(L.token, bal, r);
            if (!L.wrapEnabled) anyDisabled = true;
            if (c < supply) {
                c = Math.saturatingAdd(c, i == p.leg ? _value(r, p.num, p.den) : _value(r, L.num, L.den));
            }
        }
        if (c < supply) revert IUnderlyingToken.RateChangeUndercollateralized(c, supply);
    }

    // ------------------------------------------------------------------ views

    function collateralValue() public view returns (uint256 c) {
        UnderlyingStorage storage s = $();
        uint256 n = s.legCount;
        for (uint256 i; i < n; ++i) {
            Leg storage L = s.legs[i];
            c = Math.saturatingAdd(c, _value(L.reserve, L.num, L.den));
        }
    }

    function previewWrap(address u, uint256 amount) public view returns (uint256 minted, uint256 used) {
        Leg storage L = $().legs[indexOf(u)];
        minted = Math.mulDiv(amount, L.num, L.den);
        used = Math.mulDiv(minted, L.den, L.num, Math.Rounding.Ceil);
    }

    function previewUnwrap(address u, uint256 wrapped) public view returns (uint256 out, uint256 burned) {
        Leg storage L = $().legs[indexOf(u)];
        out = Math.mulDiv(wrapped, L.den, L.num);
        burned = Math.mulDiv(out, L.num, L.den, Math.Rounding.Ceil);
    }

    // ------------------------------------------------------------------ internal helpers (inlined in the token)

    function indexOf(address u) internal view returns (uint256) {
        uint256 x = $().legIndex[u];
        if (x == 0) revert IUnderlyingToken.UnknownUnderlying(u);
        return x - 1;
    }

    /// @dev The single-asset ABI works only with exactly one leg.
    function sole() internal view returns (uint256) {
        if ($().legCount != 1) revert IUnderlyingToken.UnderlyingRequired();
        return 0;
    }

    function isPending() internal view returns (bool) {
        return _isPending($());
    }

    function _isPending(UnderlyingStorage storage s) private view returns (bool) {
        uint256 eta = s.pending.eta;
        return eta != 0 && block.timestamp <= eta + RATE_WINDOW;
    }

    function _balance(address u) private view returns (uint256) {
        return u == NATIVE ? address(this).balance : IERC20(u).balanceOf(address(this));
    }

    /// @dev `⌊r·num/den⌋`, saturating where the result exceeds 256 bits (`mulDiv` would revert).
    function _value(uint256 r, uint256 num, uint256 den) private pure returns (uint256) {
        (uint256 hi,) = Math.mul512(r, num);
        return hi >= den ? type(uint256).max : Math.mulDiv(r, num, den);
    }
}
```

- [ ] **Step 3: `git mv` and rewrite `UnderlyingToken.sol`; delete the tiers**

```bash
cd smartcontracts/evm
git mv src/metatx/SingleUnderlyingToken.sol src/metatx/UnderlyingToken.sol
git rm -q src/metatx/MultiUnderlyingToken.sol src/hedera/HederaTokensV2.sol
```

Full text of `src/metatx/UnderlyingToken.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {AdminLib} from "./AdminLib.sol";
import {UnderlyingLib} from "./UnderlyingLib.sol";
import {IUnderlyingToken} from "./IUnderlyingToken.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Kind `UNDERLYING` (CTR-TOK-21): a wrapper of 1–8 legs, each an ERC-20 or the native coin (CTR-TOK-26), at
///        per-leg rates `num/den`, with internal per-leg reserves; the logic is in `UnderlyingLib`.
/// @notice Any-of (CTR-TOK-07): wrap one chosen leg, unwrap into one chosen leg, bounded by that leg's reserve. The
///         single-asset ABI (`wrap(amount)`, `unwrap(amount, recipient[, minOut])`) works only with exactly one leg
///         (`UnderlyingRequired`). Flags (CTR-TOK-22): `PAYABLE`, `RATE_ADJUSTABLE` (role rateAdmin, a contract:
///         timelocked rate changes), `WRAP_DISABLEABLE` (role guardian: one-way `disableWrap`). Built by the factory
///         through `initialize(creator, underlyings, version, abi.encode(UnderlyingInit))`; P1e switches to
///         `TokenConfig`.
contract UnderlyingToken is MetaTokenBase, IUnderlyingToken {
    uint256 public constant RATE_WINDOW = UnderlyingLib.RATE_WINDOW;

    bytes4 internal constant SEL_WRAP = bytes4(keccak256("wrap(uint256)"));
    bytes4 internal constant SEL_UNWRAP_MIN = bytes4(keccak256("unwrap(uint256,address,uint256)"));
    bytes4 internal constant SEL_WRAP_LEG = bytes4(keccak256("wrap(address,uint256)"));
    bytes4 internal constant SEL_UNWRAP_LEG = bytes4(keccak256("unwrap(address,uint256,address,uint256)"));
    bytes4 internal constant SEL_ADD_RESERVE = bytes4(keccak256("addReserve(address,uint256)"));

    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
        MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
    {}

    /// @dev Transitional: factory v2's `META_SINGLE` takes 1–8 legs (P1e replaces the enum).
    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_SINGLE;
    }

    /// @param initData `abi.encode(UnderlyingInit)`; decoded and checked in `UnderlyingLib.initToken`.
    function _init(address, address[] calldata us, bytes calldata initData) internal override {
        UnderlyingLib.initToken(us, initData, IS_HEDERA);
    }

    // ------------------------------------------------------------------ wrap / unwrap / reserve

    /// @notice Single-asset ABI. Mints the MEASURED amount received at the leg's rate, rounded down.
    function wrap(uint256 amount) external payable nonReentrant returns (uint256) {
        return _wrap(UnderlyingLib.sole(), amount);
    }

    function wrap(address u, uint256 amount) external payable nonReentrant returns (uint256) {
        return _wrap(UnderlyingLib.indexOf(u), amount);
    }

    /// @notice Single-asset ABI, `minOut = 0`; not allowlisted.
    function unwrap(uint256 wrapped, address recipient) external nonReentrant returns (uint256 out) {
        (out,) = _unwrap(UnderlyingLib.sole(), wrapped, recipient, 0);
    }

    function unwrap(uint256 wrapped, address recipient, uint256 minOut) external nonReentrant returns (uint256 out) {
        (out,) = _unwrap(UnderlyingLib.sole(), wrapped, recipient, minOut);
    }

    function unwrap(address u, uint256 wrapped, address recipient, uint256 minOut)
        external nonReentrant returns (uint256 out, uint256 burned)
    {
        return _unwrap(UnderlyingLib.indexOf(u), wrapped, recipient, minOut);
    }

    /// @notice Anyone; no mint. Over-collateralises before a rate decrease; otherwise a donation to every holder.
    function addReserve(address u, uint256 amount) external payable nonReentrant {
        address from = _msgSender();
        emit ReserveAdded(from, u, UnderlyingLib.addReserve(UnderlyingLib.indexOf(u), amount, from, msg.value));
    }

    function _wrap(uint256 i, uint256 amount) private returns (uint256 minted) {
        address account = _msgSender();
        (address u, uint256 received, uint256 m) = UnderlyingLib.wrap(i, amount, account, msg.value);
        minted = m;
        _mint(account, minted);
        emit Wrapped(account, u, received, minted);
    }

    /// @dev Burn before the one outside call (CEI), under the contract-wide guard.
    function _unwrap(uint256 i, uint256 wrapped, address recipient, uint256 minOut)
        private returns (uint256 out, uint256 burned)
    {
        (out, burned) = UnderlyingLib.quoteUnwrap(i, wrapped, recipient, minOut);
        address from = _msgSender();
        _burn(from, burned);
        address u = UnderlyingLib.payOut(i, recipient, out);
        emit Unwrapped(from, u, recipient, burned, out);
    }

    // ------------------------------------------------------------------ roles: guardian, rate admin

    function disableWrap(address u, bytes32 reason) external {
        UnderlyingLib.disableWrap(u, reason, _msgSender());
    }

    function proposeRate(address u, uint96 num, uint96 den) external {
        UnderlyingLib.proposeRate(u, num, den, _msgSender());
    }

    function cancelRate() external {
        UnderlyingLib.cancelRate(_msgSender());
    }

    function executeRate() external {
        UnderlyingLib.executeRate(_msgSender(), totalSupply());
    }

    /// @notice `disableFeature(RATE_ADJUSTABLE)` also cancels a pending rate change (CTR-TOK-06).
    function disableFeature(uint8 bit) external override {
        AdminLib.disableFeature(bit, _msgSender());
        if (bit == AdminLib.RATE_ADJUSTABLE) UnderlyingLib.dropPending();
    }

    // ------------------------------------------------------------------ allowlist (CTR-MTX-19)

    /// @notice `cancelNonce` (base); `wrap(uint256)`, `wrap(address,uint256)`, `addReserve` `ABSOLUTE` (fee from the
    ///         minted units or the caller's balance); `unwrap(uint256,address,uint256)` `AMOUNT(0)`,
    ///         `unwrap(address,uint256,address,uint256)` `AMOUNT(1)` (gasless unwrap, CTR-MTX-12). The two-argument
    ///         `unwrap` is not listed (same intent, second digest, no `minOut`).
    function mtxSelectors()
        public pure override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](6);
        c = new uint8[](6);
        a = new uint8[](6);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (SEL_WRAP, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (SEL_UNWRAP_MIN, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (SEL_WRAP_LEG, FEE_CLASS_ABSOLUTE);
        (s[4], c[4], a[4]) = (SEL_UNWRAP_LEG, FEE_CLASS_AMOUNT, 1);
        (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == SEL_WRAP) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == SEL_UNWRAP_MIN) return MtxRule(FEE_CLASS_AMOUNT, 0, 100);
        if (sel == SEL_WRAP_LEG) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        if (sel == SEL_UNWRAP_LEG) return MtxRule(FEE_CLASS_AMOUNT, 1, 132);
        if (sel == SEL_ADD_RESERVE) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 68);
        return super._mtxRule(sel);
    }

    // ------------------------------------------------------------------ views

    /// @notice The one underlying of a one-leg token (`address(0)` for the native coin); `address(0)` with more legs.
    function underlying() external view returns (address) {
        UnderlyingLib.UnderlyingStorage storage s = UnderlyingLib.$();
        return s.legCount == 1 ? s.legs[0].token : address(0);
    }

    function underlyings() external view returns (address[] memory us) {
        UnderlyingLib.UnderlyingStorage storage s = UnderlyingLib.$();
        uint256 n = s.legCount;
        us = new address[](n);
        for (uint256 i; i < n; ++i) us[i] = s.legs[i].token;
    }

    function legOf(address u)
        external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals_, bool wrapEnabled)
    {
        UnderlyingLib.Leg storage L = UnderlyingLib.$().legs[UnderlyingLib.indexOf(u)];
        return (L.num, L.den, L.reserve, L.decimals, L.wrapEnabled);
    }

    /// @notice `Σ⌊reserve_i·num_i/den_i⌋`, saturating at `type(uint256).max` instead of overflowing.
    function collateralValue() external view returns (uint256) {
        return UnderlyingLib.collateralValue();
    }

    /// @notice `(⌊amount·q⌋, ⌈minted/q⌉)`: clients round `amount` down to `used` so no dust stays in the reserve.
    ///         Ignores fee-on-transfer (assumes `received == amount`).
    function previewWrap(address u, uint256 amount) external view returns (uint256 minted, uint256 used) {
        return UnderlyingLib.previewWrap(u, amount);
    }

    function previewUnwrap(address u, uint256 wrapped) external view returns (uint256 out, uint256 burned) {
        return UnderlyingLib.previewUnwrap(u, wrapped);
    }

    function rateAdjustable() external view returns (bool) {
        return AdminLib.hasFeature(AdminLib.RATE_ADJUSTABLE);
    }

    function rateDelay() external view returns (uint32) {
        return UnderlyingLib.$().rateDelay;
    }

    function maxRateStepBps() external view returns (uint16) {
        return UnderlyingLib.$().maxRateStepBps;
    }

    /// @notice All zero when nothing is pending or the pending change has expired.
    function pendingRate() external view returns (address u, uint96 num, uint96 den, uint64 eta) {
        if (!UnderlyingLib.isPending()) return (address(0), 0, 0, 0);
        UnderlyingLib.UnderlyingStorage storage s = UnderlyingLib.$();
        UnderlyingLib.PendingRate memory p = s.pending;
        return (s.legs[p.leg].token, p.num, p.den, p.eta);
    }
}
```

- [ ] **Step 4: `MetaTokenBase` and the factory**

In `src/metatx/MetaTokenBase.sol` delete the `_legCount` declaration and its comment, and make `disableFeature` virtual:

```diff
-    /// @dev Transitional (P1d moves it to `scaas.underlying`): number of underlying legs, 0 on tier 1.
-    uint8 internal _legCount;
-
...
-    function disableFeature(uint8 bit) external { AdminLib.disableFeature(bit, _msgSender()); }
+    function disableFeature(uint8 bit) external virtual { AdminLib.disableFeature(bit, _msgSender()); }
```

In `src/factory/OpenFactoryV2.sol` `_createTiered`, replace the count line:

```solidity
        uint256 n = underlyings.length;
        // Transitional (P1d): `META_SINGLE` is kind UNDERLYING (`UnderlyingToken`, 1–8 legs); nothing implements
        // `META_MULTI` any more. P1e replaces the enum (CTR-TOK-25).
        bool countBad = kind == TokenKind.META_NONE ? n != 0
            : kind == TokenKind.META_SINGLE ? n == 0 || n > MAX_LEGS : n < 2 || n > MAX_LEGS;
        if (countBad) revert UnderlyingCountInvalid(n);
```

In `src/common/IOpenFactoryV2.sol`: enum comments `META_SINGLE // v2 kind UNDERLYING: 1–8 legs (P1d)`,
`META_MULTI // retired in P1d: no implementation`; the `createTiered` notice `META_NONE 0, META_SINGLE 1–8`.

Run `timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge build src'` — expected: compiles (the size
table reports `UnderlyingToken` over EIP-170 and `forge build --sizes` exits non-zero: that is D2, not an error here).

- [ ] **Step 5: Fixture** — apply to `test/v2/helpers/V2Fixture.sol` (the spike's diff against `main`):

```diff
diff --git a/smartcontracts/evm/test/v2/helpers/V2Fixture.sol b/smartcontracts/evm/test/v2/helpers/V2Fixture.sol
index 2442e96..f82a06f 100644
--- a/smartcontracts/evm/test/v2/helpers/V2Fixture.sol
+++ b/smartcontracts/evm/test/v2/helpers/V2Fixture.sol
@@ -8,8 +8,8 @@ import {AdminLib} from "../../../src/metatx/AdminLib.sol";
 import {IOpenFactoryV2} from "../../../src/common/IOpenFactoryV2.sol";
 import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
 import {NoUnderlyingToken} from "../../../src/metatx/NoUnderlyingToken.sol";
-import {SingleUnderlyingToken} from "../../../src/metatx/SingleUnderlyingToken.sol";
-import {MultiUnderlyingToken} from "../../../src/metatx/MultiUnderlyingToken.sol";
+import {UnderlyingToken} from "../../../src/metatx/UnderlyingToken.sol";
+import {IUnderlyingToken} from "../../../src/metatx/IUnderlyingToken.sol";
 
 bytes32 constant UID_ = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
 
@@ -48,6 +48,34 @@ function noneInit(string memory n, string memory s, uint8 d, uint256 supply, add
     c.initialHolder = holder;
 }
 
+/// Test-side rate setup (the shape of the removed `Rate`): `adjustable` sets
+/// `RATE_ADJUSTABLE` and grants `rateAdmin` the role.
+struct Rate {
+    bool adjustable;
+    address rateAdmin;
+    uint32 rateDelay;
+    uint16 maxRateStepBps;
+}
+
+/// `UnderlyingInit` for legs `us` at `nums/dens`: `PAYABLE` (as built), `RATE_ADJUSTABLE` with `cfg.adjustable`,
+/// `WRAP_DISABLEABLE` with a non-zero `guardian`; nothing locked; `owner` (0 = none).
+function underlyingInit(address[] memory us, uint256[] memory nums, uint256[] memory dens, uint8 dec, Rate memory cfg,
+    address guardian, address owner) pure returns (IUnderlyingToken.UnderlyingInit memory c)
+{
+    c.name = "Wrapped";
+    c.symbol = "WRP";
+    c.decimals = dec;
+    c.features = 1 << AdminLib.PAYABLE;
+    if (cfg.adjustable) c.features |= 1 << AdminLib.RATE_ADJUSTABLE;
+    if (guardian != address(0)) c.features |= 1 << AdminLib.WRAP_DISABLEABLE;
+    c.owner = owner;
+    c.roles.rateAdmin = cfg.rateAdmin;
+    c.roles.guardian = guardian;
+    c.legs = new IUnderlyingToken.LegInit[](us.length);
+    for (uint256 i; i < us.length; ++i) c.legs[i] = IUnderlyingToken.LegInit(us[i], nums[i], dens[i]);
+    c.rate = IUnderlyingToken.RateConfig(cfg.rateDelay, cfg.maxRateStepBps);
+}
+
 /// ERC-1271 đốt ~100k gas rồi trả magic: qua được với 400k, không qua với 50k.
 contract GasBurner1271 {
     function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
@@ -79,7 +107,9 @@ abstract contract V2Fixture is Test {
     }
 
     address internal noneImpl;
-    address internal singleImpl;
+    address internal underlyingImpl;
+    /// Owner the fixture gives every wrapper it builds (`disableFeature`, `grantRole` in tests).
+    address internal wrapperOwner = address(0x0A11);
 
     function _none(address creator_, uint256 supply, address minter) internal returns (NoUnderlyingToken) {
         if (noneImpl == address(0)) {
@@ -89,44 +119,52 @@ abstract contract V2Fixture is Test {
             abi.encode(noneInit("Points", "PTS", 0, supply, creator_, minter))));
     }
 
-    function _fixedRate() internal pure returns (SingleUnderlyingToken.RateConfig memory c) {}
+    function _fixedRate() internal pure returns (Rate memory c) {}
 
-    function _adjustable(address admin) internal pure returns (SingleUnderlyingToken.RateConfig memory c) {
-        c = SingleUnderlyingToken.RateConfig({adjustable: true, rateAdmin: admin, rateDelay: 7 days, maxRateStepBps: 100});
+    function _adjustable(address admin) internal pure returns (Rate memory c) {
+        c = Rate({adjustable: true, rateAdmin: admin, rateDelay: 7 days, maxRateStepBps: 100});
     }
 
-    function _singleInit(uint8 dec, uint256 num, uint256 den, SingleUnderlyingToken.RateConfig memory cfg)
-        internal pure returns (bytes memory)
-    {
-        return abi.encode("Wrapped", "WRP", dec, num, den, cfg);
+    function _one(address a) internal pure returns (address[] memory us) {
+        us = new address[](1);
+        us[0] = a;
+    }
+
+    function _oneU(uint256 x) internal pure returns (uint256[] memory xs) {
+        xs = new uint256[](1);
+        xs[0] = x;
     }
 
-    function _single(address u, uint8 dec, uint256 num, uint256 den, SingleUnderlyingToken.RateConfig memory cfg)
-        internal returns (SingleUnderlyingToken)
+    /// `abi.encode(UnderlyingInit)` for one leg `u`.
+    function _singleInit(address u, uint8 dec, uint256 num, uint256 den, Rate memory cfg)
+        internal view returns (bytes memory)
     {
-        if (singleImpl == address(0)) {
-            singleImpl = address(new SingleUnderlyingToken(address(this), address(0), UID_, false));
+        return abi.encode(underlyingInit(_one(u), _oneU(num), _oneU(den), dec, cfg, address(0), wrapperOwner));
+    }
+
+    function _underlyingImpl() internal returns (address) {
+        if (underlyingImpl == address(0)) {
+            underlyingImpl = address(new UnderlyingToken(address(this), address(0), UID_, false));
         }
-        address[] memory us = new address[](1);
-        us[0] = u;
-        return SingleUnderlyingToken(_clone(singleImpl, address(this), us, _singleInit(dec, num, den, cfg)));
+        return underlyingImpl;
     }
 
-    address internal multiImpl;
+    function _single(address u, uint8 dec, uint256 num, uint256 den, Rate memory cfg)
+        internal returns (UnderlyingToken)
+    {
+        return UnderlyingToken(_clone(_underlyingImpl(), address(this), _one(u), _singleInit(u, dec, num, den, cfg)));
+    }
 
-    function _multiInit(uint256[] memory nums, uint256[] memory dens, SingleUnderlyingToken.RateConfig memory cfg,
-        address guardian) internal pure returns (bytes memory)
+    function _multiInit(address[] memory us, uint256[] memory nums, uint256[] memory dens, Rate memory cfg,
+        address guardian) internal view returns (bytes memory)
     {
-        return abi.encode("Any USD", "aUSD", uint8(18), nums, dens, cfg, guardian);
+        return abi.encode(underlyingInit(us, nums, dens, 18, cfg, guardian, wrapperOwner));
     }
 
-    function _multi(address[] memory us, uint256[] memory nums, uint256[] memory dens,
-        SingleUnderlyingToken.RateConfig memory cfg, address guardian) internal returns (MultiUnderlyingToken)
+    function _multi(address[] memory us, uint256[] memory nums, uint256[] memory dens, Rate memory cfg,
+        address guardian) internal returns (UnderlyingToken)
     {
-        if (multiImpl == address(0)) {
-            multiImpl = address(new MultiUnderlyingToken(address(this), address(0), UID_, false));
-        }
-        return MultiUnderlyingToken(_clone(multiImpl, address(this), us, _multiInit(nums, dens, cfg, guardian)));
+        return UnderlyingToken(_clone(_underlyingImpl(), address(this), us, _multiInit(us, nums, dens, cfg, guardian)));
     }
 
     /// A `MetaTransfer` from `from` on lane `batch`, nonce 0, valid 300 s, relayer `relayer`, no fee.
```

- [ ] **Step 6: Port the tests.** Rules, in this order (mechanical first, then the behaviour changes):

1. Types: `\bSingleUnderlyingToken\.RateConfig\b` and `\bMultiUnderlyingToken\.RateConfig\b` → `Rate` (import
   `Rate` from the fixture). **Use the word boundary**: a plain `s/SingleUnderlyingToken.RateConfig/Rate/` also turns
   `SingleUnderlyingToken.RateConfigInvalid` into `RateInvalid` (a different error). Then `\bSingleUnderlyingToken\b`,
   `\bMultiUnderlyingToken\b` → `UnderlyingToken`; imports of the two files → `UnderlyingToken.sol`.
2. Events and errors of the kind are members of the interface: `UnderlyingToken.<Event|Error>` →
   `IUnderlyingToken.<…>` (`UnderlyingToken.WrapTooSmall.selector` does not compile: inherited interface members are not
   reachable through the contract name). Import `IUnderlyingToken`.
3. Init data: `_singleInit(dec, num, den, cfg)` → `_singleInit(u, dec, num, den, cfg)`; `_multiInit(nums, dens, cfg,
   guardian)` → `_multiInit(us, nums, dens, cfg, guardian)`; hand-rolled `abi.encode("Wrapped", …)` /
   `abi.encode("Any USD", …)` → `abi.encode(underlyingInit(us, nums, dens, dec, cfg, guardian, owner))`.
4. Roles instead of the legacy admin (D4):
   - `t.rateAdmin()` → `t.hasRole(3, a)`; `t.guardian()` → `t.hasRole(4, g)`.
   - `RateAdminNotContract(a)` → `ITokenAdmin.RoleNotContract(3, a)`.
   - `renounceRateAdmin()` → `renounceRole(3)`, `renounceGuardian()` → `renounceRole(4)`; events
     `RateAdminRenounced()` / `GuardianRenounced()` → `ITokenAdmin.RoleRevoked(bit, holder, holder)`.
   - Behaviour change: renouncing the rate role **keeps** `rateAdjustable()` and the pending change. Rewrite
     `Rates.t.sol test_renounceDropsPendingAndFixesTheRate` as `test_renounceRoleKeepsThePendingChange_disableFeatureCancelsIt`:
     propose; `_admin(renounceRole(3))`; `rateAdjustable()` still true, `pendingRate()` still set, `proposeRate` by the
     ex-admin → `NotRateAdmin`; `vm.prank(wrapperOwner); t.disableFeature(3)` → `pendingRate()` all zero,
     `rateAdjustable()` false, a wrap succeeds. Remove the `renounceRateAdmin` lines from `test_fixedRateHasNoSetters`
     and `test_onlyTheAdminProposesCancelsExecutes` (`renounceRole` is `AdminLib`'s and tested in `AdminLib.t`/`Features.t`).
   - `Multi.t.sol test_renounceGuardian` → `renounceRole(4)`: `hasRole(4, g)` false, a later `disableWrap` by `g` →
     `NotGuardian`, a second `renounceRole(4)` → `ITokenAdmin.MissingRole(4, g)`.
   - `Allowlist.t.sol`: the "admin functions are never allowlisted" cases use `renounceRole(uint8)` instead of the two
     removed functions (keep `disableWrap`, `proposeRate`, `executeRate`, `cancelRate` as they are).
5. Leg counts (D9): one implementation takes 1–8 legs. A test that expected `UnderlyingCountInvalid(1)` from the Multi
   tier or `UnderlyingCountInvalid(2)` from the Single tier now builds a valid token: assert that instead (one leg:
   `underlying()` is the leg; two legs: the single-asset ABI reverts `UnderlyingRequired()`). `UnderlyingCountInvalid(0)`
   and `(9)` stay. `tokenKind()` is `META_SINGLE` for every count.
6. `address(0)` is the native leg now: drop the `_refuse(address(0), …, UnderlyingInvalid(0))` case of
   `Tier2.t.sol test_initRefusals` (Task 2 tests the native leg); `address(0xDEAD)` (no code) stays `UnderlyingInvalid`.
7. `Features.t.sol`: delete `test_wrappersReportLegacyFeatures`, `_checkWrapper` and the "legacy wrappers (ruling C5)"
   heading (Task 2's `test_validFlags_underlyingKind` replaces them), and the now-unused imports.
8. `FactoryV2.t.sol`: register one `UnderlyingToken` under `SINGLE`; `SINGLE` creates 1–8 legs (3 legs is a valid
   SINGLE creation now; 0 and 9 → `UnderlyingCountInvalid`); `registerImplementation(MULTI, 1, underlyingImpl)` →
   `VersionKindMismatch(MULTI, SINGLE)`; `createTiered(MULTI, …)` → `VersionUnknown(MULTI, 1)`; size pins:
   `noneImpl ≤ 20_480`, `underlyingImpl ≤ 26_624` with the comment `// Transitional (P1d, D2): over EIP-170 until the
   size work; measured 25,408`.
9. `Layout.t.sol`: `_pin("NoUnderlyingToken", "NoUnderlyingToken")` and `_pin("UnderlyingToken", "UnderlyingToken")`
   only; delete `test/v2/layout/{Single,Multi,HederaSingle,HederaMulti}UnderlyingToken.json`; write
   `test/v2/layout/UnderlyingToken.json` and rewrite `NoUnderlyingToken.json` to exactly
   `{"labels": ["_balances", "_allowances", "_totalSupply", "_name", "_symbol"], "slots": ["0", "1", "2", "3", "4"],
   "offsets": [0, 0, 0, 0, 0]}` (pretty-printed like the old files). `test_reserveSlotIsWhereIndexersReadIt` reads the
   namespace: `bytes32 NS = 0x38d6…1000; bytes32 leg0 = keccak256(abi.encode(uint256(0), NS));` token at `leg0`,
   `num ‖ den` at `leg0 + 1`, `reserve` at `leg0 + 2`, `legCount` = low byte of `NS + 3` (== 1); slot 5 is zero.
10. `MsgSenderLint.t.sol`: `FILES` = MetaTxBase, ERC20MetaTx, MetaTokenBase, NoUnderlyingToken, UnderlyingToken,
    UnderlyingLib, AdminLib, HederaLib (8 entries; `string[8]`); expected `msg.sender` count 0 for `UnderlyingToken.sol`
    and `UnderlyingLib.sol`; drop the `HederaTokensV2` line.
11. `HederaV2.t.sol` — apply the spike's diff:

```diff
diff --git a/smartcontracts/evm/test/hedera/HederaV2.t.sol b/smartcontracts/evm/test/hedera/HederaV2.t.sol
index 83fa0a6..0ff60cc 100644
--- a/smartcontracts/evm/test/hedera/HederaV2.t.sol
+++ b/smartcontracts/evm/test/hedera/HederaV2.t.sol
@@ -8,12 +8,12 @@ import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
 import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
 import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
 import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
-import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";
+import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
+import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
 import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
 import {HederaLib} from "../../src/hedera/HederaLib.sol";
-import {HederaSingleUnderlyingToken, HederaMultiUnderlyingToken} from "../../src/hedera/HederaTokensV2.sol";
 import {MockERC20} from "../helpers/Mocks.sol";
-import {noneInit} from "../v2/helpers/V2Fixture.sol";
+import {noneInit, underlyingInit, Rate} from "../v2/helpers/V2Fixture.sol";
 import {MockHederaAccountService, MockHts} from "./HederaMocks.sol";
 
 /// T5: con Hedera của ba tầng (TW2 §11, R144) — HIP-632 trên mỗi tầng, associate lúc init, kiểm phí HTS fail-closed.
@@ -43,9 +43,7 @@ contract HederaV2Test is Test {
         f.registerImplementation(IOpenFactoryV2.TokenKind.META_NONE, 1,
             address(new NoUnderlyingToken(address(f), address(0), UID, true)));
         f.registerImplementation(IOpenFactoryV2.TokenKind.META_SINGLE, 1,
-            address(new HederaSingleUnderlyingToken(address(f), UID)));
-        f.registerImplementation(IOpenFactoryV2.TokenKind.META_MULTI, 1,
-            address(new HederaMultiUnderlyingToken(address(f), UID)));
+            address(new UnderlyingToken(address(f), address(0), UID, true)));
         vm.stopPrank();
         usdc = new MockERC20("USD Coin", "USDC", 6);
         plain = new MockERC20("Plain", "PLN", 6);
@@ -53,12 +51,9 @@ contract HederaV2Test is Test {
     }
 
     function test_implementationSizes() public view {
-        IOpenFactoryV2.TokenKind[3] memory k = [IOpenFactoryV2.TokenKind.META_NONE, IOpenFactoryV2.TokenKind.META_SINGLE,
-            IOpenFactoryV2.TokenKind.META_MULTI];
-        assertLe(f.implementationOf(k[0], 1).code.length, 20_480); // CTR-TOK-24 (measured 20,038)
-        // Transitional (R3): Hedera wrappers over EIP-170 until P1d (`UnderlyingLib`); measured 29,201 / 30,052
-        assertLe(f.implementationOf(k[1], 1).code.length, 29_696);
-        assertLe(f.implementationOf(k[2], 1).code.length, 30_720);
+        assertLe(f.implementationOf(IOpenFactoryV2.TokenKind.META_NONE, 1).code.length, 20_480); // CTR-TOK-24
+        // Transitional (P1d, D2): over EIP-170 until the size work; measured 25,408
+        assertLe(f.implementationOf(IOpenFactoryV2.TokenKind.META_SINGLE, 1).code.length, 26_624);
     }
 
     function _edSign(bytes32 digest) internal pure returns (bytes memory) {
@@ -76,16 +71,22 @@ contract HederaV2Test is Test {
     function _single(address u) internal returns (address) {
         address[] memory us = new address[](1);
         us[0] = u;
-        SingleUnderlyingToken.RateConfig memory c;
-        return f.createTiered(IOpenFactoryV2.TokenKind.META_SINGLE, 1, us,
-            abi.encode("Wrapped", "W", uint8(6), uint256(1), uint256(1), c), keccak256(abi.encode(u)));
+        return f.createTiered(IOpenFactoryV2.TokenKind.META_SINGLE, 1, us, _init(us), keccak256(abi.encode(u)));
+    }
+
+    /// One leg at 1:1, rates fixed, no owner.
+    function _init(address[] memory us) internal pure returns (bytes memory) {
+        uint256[] memory one = new uint256[](1);
+        one[0] = 1;
+        Rate memory c;
+        return abi.encode(underlyingInit(us, one, one, 6, c, address(0), address(0)));
     }
 
     function _wrapFor(address t, MockERC20 u, address who, uint256 v) internal {
         u.mint(who, v);
         vm.startPrank(who);
         u.approve(t, v);
-        SingleUnderlyingToken(t).wrap(v);
+        UnderlyingToken(t).wrap(v);
         vm.stopPrank();
     }
 
@@ -148,22 +149,22 @@ contract HederaV2Test is Test {
         (us[0], us[1], us[2]) = (address(usdc), address(usdt), address(plain));
         uint256[] memory n = new uint256[](3);
         (n[0], n[1], n[2]) = (1, 1, 1);
-        SingleUnderlyingToken.RateConfig memory c;
-        address t = f.createTiered(IOpenFactoryV2.TokenKind.META_MULTI, 1, us,
-            abi.encode("Any", "ANY", uint8(6), n, n, c, address(0)), "m");
+        Rate memory c;
+        address t = f.createTiered(IOpenFactoryV2.TokenKind.META_SINGLE, 1, us,
+            abi.encode(underlyingInit(us, n, n, 6, c, address(0), address(0))), "m");
         assertTrue(MockHts(HTS).associated(t, address(usdc)));
         assertTrue(MockHts(HTS).associated(t, address(usdt)));
         assertFalse(MockHts(HTS).associated(t, address(plain))); // not an HTS token: nothing to associate
         usdt.mint(alice, 10e6);
         vm.startPrank(alice);
         usdt.approve(t, 10e6);
-        HederaMultiUnderlyingToken(t).wrap(address(usdt), 10e6);
+        UnderlyingToken(t).wrap(address(usdt), 10e6);
         vm.stopPrank();
         bytes32 payId = keccak256("inv");
-        MetaTxLib.MetaTransfer memory x = _tr(shop, 3e6, payId, HederaMultiUnderlyingToken(t).payLane(payId));
+        MetaTxLib.MetaTransfer memory x = _tr(shop, 3e6, payId, UnderlyingToken(t).payLane(payId));
         bytes memory sig = _edSign(IERC20MetaTx(t).mtxTransferDigest(x));
         vm.prank(relayer);
-        HederaMultiUnderlyingToken(t).mtxPay(alice, shop, 3e6, payId, x.validUntil, RR, relayer, 0, address(0), sig);
+        UnderlyingToken(t).mtxPay(alice, shop, 3e6, payId, x.validUntil, RR, relayer, 0, address(0), sig);
         assertEq(IERC20MetaTx(t).balanceOf(shop), 3e6);
     }
 
@@ -182,8 +183,7 @@ contract HederaV2Test is Test {
     function _refuse(bytes memory err) internal {
         address[] memory us = new address[](1);
         us[0] = address(usdc);
-        SingleUnderlyingToken.RateConfig memory c;
-        bytes memory init = abi.encode("Wrapped", "W", uint8(6), uint256(1), uint256(1), c);
+        bytes memory init = _init(us);
         vm.expectRevert(err);
         f.createTiered(IOpenFactoryV2.TokenKind.META_SINGLE, 1, us, init, "x");
     }
@@ -204,7 +204,7 @@ contract HederaV2Test is Test {
     }
 
     function test_anyCustomFeeRefuses() public {
-        bytes memory e = abi.encodeWithSelector(SingleUnderlyingToken.UnderlyingInvalid.selector, address(usdc));
+        bytes memory e = abi.encodeWithSelector(IUnderlyingToken.UnderlyingInvalid.selector, address(usdc));
         MockHts(HTS).setFees(address(usdc), MockHts.Fees.Fixed);
         _refuse(e);
         MockHts(HTS).setFees(address(usdc), MockHts.Fees.Fractional);
```

12. `MetaTxGasV2.t.sol`: the wrapper rows run on `UnderlyingToken` (`createTiered(META_SINGLE, …)` with
    `abi.encode(underlyingInit(…))`); update logged numbers only, keep the assertions that are about the NONE token.
13. `WrapperInvariant.t.sol`, `UnwrapOp.t.sol`, `RateVectors.t.sol`, `Tier2.t.sol`, `Multi.t.sol`, `Rates.t.sol`: rules
    1–6; guardian and rate admin are set through `_multi(…, guardian)` / `_adjustable(admin)` as before.

Do not change what a test asserts beyond these rules. If a ported test fails for a reason the rules do not explain,
stop and report it (it is a behaviour change of the rewrite).

- [ ] **Step 7: Run the full suite**

Run: `timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge test'`
Expected: all pass; count = 792 − 1 (`test_wrappersReportLegacyFeatures`) ± tests split/merged by rules 4–5 (report
the exact number and every split/merge). `forge build --sizes` is expected to fail on EIP-170 (D2).

- [ ] **Step 8: Commit** — `git add` the src, tests and layout files (never `claude-code-api.txt`); message
`P1d: UnderlyingLib + UnderlyingToken (1–8 legs, native leg, roles); delete Single/Multi/Hedera tiers; port tests` + trailer.

---

### Task 2: Conformance tests for the new rules

**Model:** Sonnet, effort medium (transcription: both files are complete and passed in the spike).

**Files:**
- Create: `smartcontracts/evm/test/v2/Underlying.t.sol`, `smartcontracts/evm/test/v2/NativeLeg.t.sol`

**Interfaces:**
- Consumes: Task 1's fixture (`Rate`, `underlyingInit`, `wrapperOwner`, `_underlyingImpl`, `_one`, `_singleInit`,
  `_single`, `_multi`, `_fixedRate`, `_adjustable`, `_clone`, `_call`, `_signCall`, `_execCall`, `relayer`, `RR`),
  `RateAdminForwarder` (`test/v2/helpers/V2Mocks.sol`), `IUnderlyingToken`, `ITokenAdmin`, `AdminLib`.
- Produces: nothing later tasks consume.

- [ ] **Step 1: Write `test/v2/Underlying.t.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {V2Fixture, Rate, underlyingInit} from "./helpers/V2Fixture.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";

/// Kind `UNDERLYING` on `AdminLib` (CTR-TOK-22): flags valid for the kind, the rate role and the guardian as roles,
/// `disableFeature(RATE_ADJUSTABLE)` cancels a pending change, the single-asset ABI rule, init vs the factory's
/// `underlyings`, and `UnderlyingLib` writing only its own namespace.
contract UnderlyingTest is V2Fixture {
    uint8 constant RATE = 3;
    uint8 constant GUARD = 4;
    bytes32 constant NS_UNDERLYING = 0x38d6f7edefffa65376a58a6aced8a2c86698d3a0b5d15a785f69ed89d0cd1000;
    bytes32 constant NS_TOKEN = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00;

    MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
    MockERC20 usdt = new MockERC20("Tether", "USDT", 6);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function initExt(address[] memory us, bytes memory d) external returns (address) {
        return _clone(_underlyingImpl(), address(this), us, d);
    }

    function _two() internal view returns (address[] memory us, uint256[] memory one) {
        us = new address[](2);
        (us[0], us[1]) = (address(usdc), address(usdt));
        one = new uint256[](2);
        (one[0], one[1]) = (1, 1);
    }

    function _wrap(UnderlyingToken t, MockERC20 u, address who, uint256 v) internal {
        u.mint(who, v);
        vm.startPrank(who);
        u.approve(address(t), v);
        t.wrap(address(u), v);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ flags and init

    function test_validFlags_underlyingKind() public {
        (address[] memory us, uint256[] memory one) = _two();
        Rate memory fixedRate;
        IUnderlyingToken.UnderlyingInit memory c = underlyingInit(us, one, one, 6, fixedRate, address(0), address(0));
        c.features |= 1 << AdminLib.MINTABLE;
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.FeatureInvalidForKind.selector, AdminLib.MINTABLE));
        this.initExt(us, abi.encode(c));
        c = underlyingInit(us, one, one, 6, fixedRate, address(0), address(0));
        c.roles.rateAdmin = address(new RateAdminForwarder());
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleWithoutFeature.selector, RATE));
        this.initExt(us, abi.encode(c));
        c = underlyingInit(us, one, one, 6, _adjustable(bob), address(0), address(0));
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.RoleNotContract.selector, RATE, bob));
        this.initExt(us, abi.encode(c));
        // adjustable without an initial rate admin is valid: the owner grants the role later
        c = underlyingInit(us, one, one, 6, _adjustable(address(0)), address(0), wrapperOwner);
        UnderlyingToken t = UnderlyingToken(this.initExt(us, abi.encode(c)));
        assertTrue(t.rateAdjustable());
        assertEq(t.kind(), AdminLib.KIND_UNDERLYING);
        assertEq(t.features(), (1 << AdminLib.PAYABLE) | (1 << RATE));
    }

    function test_init_legsMustMatchTheFactoryUnderlyings() public {
        (address[] memory us, uint256[] memory one) = _two();
        Rate memory fixedRate;
        bytes memory d = abi.encode(underlyingInit(us, one, one, 6, fixedRate, address(0), address(0)));
        address[] memory swapped = new address[](2);
        (swapped[0], swapped[1]) = (us[1], us[0]);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, address(usdt)));
        this.initExt(swapped, d);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 2));
        this.initExt(_one(address(usdc)), d);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 0));
        this.initExt(new address[](0), d);
        address[] memory nine = new address[](9);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 9));
        this.initExt(nine, d);
    }

    // ------------------------------------------------------------------ rate role (RATE_ADJUSTABLE)

    function test_rateRole_grantRevokeRenounce_leaveTheRate() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _adjustable(address(0)));
        vm.expectRevert(IUnderlyingToken.NotRateAdmin.selector);
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 101, 100)));
        vm.prank(wrapperOwner);
        t.grantRole(RATE, address(adm));
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 101, 100)));
        vm.prank(wrapperOwner);
        t.revokeRole(RATE, address(adm));
        vm.expectRevert(IUnderlyingToken.NotRateAdmin.selector);
        adm.exec(address(t), abi.encodeCall(t.cancelRate, ()));
        // revoking leaves the pending change and the rate as they are
        (address u,,, uint64 eta) = t.pendingRate();
        assertEq(u, address(usdc));
        assertGt(eta, 0);
        assertTrue(t.rateAdjustable());
        vm.prank(wrapperOwner);
        t.grantRole(RATE, address(adm));
        adm.exec(address(t), abi.encodeCall(t.renounceRole, (RATE)));
        assertFalse(t.hasRole(RATE, address(adm)));
        assertTrue(t.rateAdjustable());
    }

    function test_disableRateAdjustable_cancelsThePendingChange_andFixesTheRate() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _adjustable(address(adm)));
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 101, 100)));
        usdc.mint(alice, 10);
        vm.prank(alice);
        usdc.approve(address(t), 10);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapPausedForRateChange.selector, address(usdc)));
        t.wrap(10);
        vm.expectEmit(address(t));
        emit ITokenAdmin.FeatureDisabled(RATE, wrapperOwner);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.RateChangeCancelled(address(usdc));
        vm.prank(wrapperOwner);
        t.disableFeature(RATE);
        (address u, uint96 n, uint96 d, uint64 eta) = t.pendingRate();
        assertEq(abi.encode(u, n, d, eta), abi.encode(address(0), uint96(0), uint96(0), uint64(0)));
        assertFalse(t.rateAdjustable());
        vm.prank(alice);
        t.wrap(10);
        vm.expectRevert(IUnderlyingToken.RateFixed.selector);
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 101, 100)));
        vm.expectRevert(IUnderlyingToken.RateFixed.selector);
        adm.exec(address(t), abi.encodeCall(t.executeRate, ()));
    }

    function test_disableRateAdjustable_withNothingPending_emitsNoCancel() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _adjustable(address(adm)));
        vm.recordLogs();
        vm.prank(wrapperOwner);
        t.disableFeature(RATE);
        assertEq(vm.getRecordedLogs().length, 1); // FeatureDisabled only
    }

    // ------------------------------------------------------------------ guardian (WRAP_DISABLEABLE)

    function test_guardianRole_disableWrap_oneWay_andFlagGates() public {
        (address[] memory us, uint256[] memory one) = _two();
        UnderlyingToken t = _multi(us, one, one, _fixedRate(), bob); // an EOA guardian is allowed
        vm.prank(alice);
        vm.expectRevert(IUnderlyingToken.NotGuardian.selector);
        t.disableWrap(address(usdt), "x");
        vm.expectEmit(address(t));
        emit IUnderlyingToken.WrapDisabled(address(usdt), bob, "depeg");
        vm.prank(bob);
        t.disableWrap(address(usdt), "depeg");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapDisabledFor.selector, address(usdt)));
        t.disableWrap(address(usdt), "again");
        // a disabled flag stops the role: the guardian keeps the role but has no power
        vm.prank(wrapperOwner);
        t.disableFeature(GUARD);
        assertTrue(t.hasRole(GUARD, bob));
        vm.prank(bob);
        vm.expectRevert(IUnderlyingToken.NotGuardian.selector);
        t.disableWrap(address(usdc), "late");
    }

    function test_guardianRenounces() public {
        (address[] memory us, uint256[] memory one) = _two();
        UnderlyingToken t = _multi(us, one, one, _fixedRate(), bob);
        vm.prank(bob);
        t.renounceRole(GUARD);
        vm.prank(bob);
        vm.expectRevert(IUnderlyingToken.NotGuardian.selector);
        t.disableWrap(address(usdt), "x");
    }

    // ------------------------------------------------------------------ single-asset ABI (CTR-TOK-07)

    function test_singleAssetAbi_onlyWithExactlyOneLeg() public {
        (address[] memory us, uint256[] memory one) = _two();
        UnderlyingToken m = _multi(us, one, one, _fixedRate(), address(0));
        _wrap(m, usdc, alice, 100);
        vm.startPrank(alice);
        vm.expectRevert(IUnderlyingToken.UnderlyingRequired.selector);
        m.wrap(1);
        vm.expectRevert(IUnderlyingToken.UnderlyingRequired.selector);
        m.unwrap(1, alice);
        vm.expectRevert(IUnderlyingToken.UnderlyingRequired.selector);
        m.unwrap(1, alice, 0);
        vm.stopPrank();
        assertEq(m.underlying(), address(0));
        assertEq(m.underlyings().length, 2);

        UnderlyingToken s = _single(address(usdc), 6, 1, 1, _fixedRate());
        assertEq(s.underlying(), address(usdc));
        // the per-leg ABI works on one leg too
        _wrap(s, usdc, alice, 50);
        vm.prank(alice);
        (uint256 out, uint256 burned) = s.unwrap(address(usdc), 20, bob, 20);
        assertEq(out, 20);
        assertEq(burned, 20);
        assertEq(usdc.balanceOf(bob), 20);
    }

    // ------------------------------------------------------------------ storage (CTR-TOK-24)

    /// `UnderlyingLib` keeps the legs in `scaas.underlying`: leg i at `keccak256(i ‖ NS)` (+1 rate, +2 reserve);
    /// a wrap and a rate proposal write nothing in `scaas.token`.
    function test_underlyingStateLivesInItsNamespace() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(usdc), 6, 3, 7, _adjustable(address(adm)));
        bytes32[12] memory tokBefore;
        for (uint256 i; i < 12; ++i) tokBefore[i] = vm.load(address(t), bytes32(uint256(NS_TOKEN) + i));
        usdc.mint(address(this), 1_000);
        usdc.approve(address(t), 1_000);
        t.wrap(1_000);
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(usdc), 3, 7)));
        for (uint256 i; i < 12; ++i) assertEq(vm.load(address(t), bytes32(uint256(NS_TOKEN) + i)), tokBefore[i]);
        bytes32 leg0 = keccak256(abi.encode(uint256(0), NS_UNDERLYING));
        assertEq(address(uint160(uint256(vm.load(address(t), leg0)))), address(usdc));
        uint256 rate = uint256(vm.load(address(t), bytes32(uint256(leg0) + 1)));
        assertEq(rate & type(uint96).max, 3);
        assertEq(rate >> 96, 7);
        assertEq(uint256(vm.load(address(t), bytes32(uint256(leg0) + 2))), 1_000);
        // nothing below slot 6 except the ERC-20 state: no `_legCount` in the linear layout
        for (uint256 s = 3; s < 8; ++s) assertEq(vm.load(address(t), bytes32(s)), bytes32(0));
    }
}
```

- [ ] **Step 2: Write `test/v2/NativeLeg.t.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Errors} from "@openzeppelin/contracts/utils/Errors.sol";
import {V2Fixture, UID_, Rate, underlyingInit} from "./helpers/V2Fixture.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Has no `receive`: refuses the native coin.
contract CoinRefuser {}

/// Re-enters the token from `receive` (unwrap to itself again).
contract CoinReenterer {
    UnderlyingToken public t;
    function arm(UnderlyingToken t_) external { t = t_; }
    receive() external payable {
        t.unwrap(1, address(this), 0);
    }
}

/// The native-coin leg (CTR-TOK-26): `address(0)`, payable wrap with `msg.value == amount`, CEI payout with all gas,
/// balance mechanics on `address(this).balance`, forced coin is not reserve, no gasless native wrap.
contract NativeLegTest is V2Fixture {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice = vm.addr(ALICE_PK);
    address bob = address(0xB0B);
    MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);

    function initExt(address[] memory us, bytes memory d) external returns (address) {
        return _clone(_underlyingImpl(), address(this), us, d);
    }

    /// One native leg at 1:1, 18 decimals, rates fixed.
    function _native() internal returns (UnderlyingToken) {
        return _single(address(0), 18, 1, 1, _fixedRate());
    }

    function _wrapNative(UnderlyingToken t, address who, uint256 v) internal {
        vm.deal(who, v);
        vm.prank(who);
        t.wrap{value: v}(v);
    }

    function test_native_wrapAndUnwrap() public {
        UnderlyingToken t = _native();
        assertEq(t.underlying(), address(0));
        (,,, uint8 dec,) = t.legOf(address(0));
        assertEq(dec, 18);
        vm.deal(alice, 3 ether);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.Wrapped(alice, address(0), 3 ether, 3 ether);
        vm.prank(alice);
        assertEq(t.wrap{value: 3 ether}(3 ether), 3 ether);
        assertEq(t.balanceOf(alice), 3 ether);
        assertEq(address(t).balance, 3 ether);
        assertEq(t.collateralValue(), 3 ether);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.Unwrapped(alice, address(0), bob, 1 ether, 1 ether);
        vm.prank(alice);
        assertEq(t.unwrap(1 ether, bob, 1 ether), 1 ether);
        assertEq(bob.balance, 1 ether);
        (,, uint256 reserve,,) = t.legOf(address(0));
        assertEq(reserve, 2 ether);
        assertEq(t.totalSupply(), 2 ether);
    }

    function test_native_valueMustMatch() public {
        UnderlyingToken t = _native();
        vm.deal(alice, 2 ether);
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 1 ether, 2 ether));
        t.wrap{value: 1 ether}(2 ether);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 0, 1 ether));
        t.addReserve(address(0), 1 ether);
        vm.stopPrank();
    }

    function test_native_erc20LegRefusesValue() public {
        address[] memory us = new address[](2);
        (us[0], us[1]) = (address(usdc), address(0));
        uint256[] memory one = new uint256[](2);
        (one[0], one[1]) = (1, 1);
        UnderlyingToken t = _multi(us, one, one, _fixedRate(), address(0));
        usdc.mint(alice, 5);
        vm.deal(alice, 1);
        vm.startPrank(alice);
        usdc.approve(address(t), 5);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 1, 0));
        t.wrap{value: 1}(address(usdc), 5);
        t.wrap(address(usdc), 5);
        t.wrap{value: 1}(address(0), 1);
        vm.stopPrank();
        assertEq(t.collateralValue(), 6);
    }

    function test_native_atMostOneLeg() public {
        address[] memory us = new address[](2);
        uint256[] memory one = new uint256[](2);
        (one[0], one[1]) = (1, 1);
        Rate memory fixedRate;
        bytes memory d = abi.encode(underlyingInit(us, one, one, 18, fixedRate, address(0), address(0)));
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.DuplicateUnderlying.selector, address(0)));
        this.initExt(us, d);
    }

    function test_native_forcedCoinIsNotReserve() public {
        UnderlyingToken t = _native();
        _wrapNative(t, alice, 1 ether);
        vm.deal(address(t), 5 ether); // selfdestruct / block reward
        (,, uint256 reserve,,) = t.legOf(address(0));
        assertEq(reserve, 1 ether);
        assertEq(t.collateralValue(), 1 ether);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.InsufficientReserve.selector, address(0), 2 ether,
            1 ether));
        t.unwrap(2 ether, alice, 0);
        _wrapNative(t, bob, 1 ether); // the surplus does not stop a wrap
        assertEq(t.balanceOf(bob), 1 ether);
    }

    function test_native_shortfallStopsWrapNotUnwrap() public {
        UnderlyingToken t = _native();
        _wrapNative(t, alice, 2 ether);
        vm.deal(address(t), 1 ether); // the balance fell below the reserve
        vm.deal(bob, 1 ether);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.ReserveShortfall.selector, address(0), 1 ether,
            2 ether));
        t.wrap{value: 1 ether}(1 ether);
        vm.prank(alice);
        t.unwrap(1 ether, alice, 0);
        assertEq(alice.balance, 1 ether);
    }

    function test_native_addReserveIsPayable() public {
        UnderlyingToken t = _native();
        vm.deal(bob, 1 ether);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.ReserveAdded(bob, address(0), 1 ether);
        vm.prank(bob);
        t.addReserve{value: 1 ether}(address(0), 1 ether);
        assertEq(t.collateralValue(), 1 ether);
        assertEq(t.totalSupply(), 0);
    }

    function test_native_refusingRecipientRevertsTheUnwrap() public {
        UnderlyingToken t = _native();
        _wrapNative(t, alice, 1 ether);
        address r = address(new CoinRefuser());
        vm.prank(alice);
        vm.expectRevert(Errors.FailedCall.selector);
        t.unwrap(1 ether, r, 0);
        assertEq(t.balanceOf(alice), 1 ether); // nothing burned
    }

    function test_native_reentrantRecipientIsBlocked() public {
        UnderlyingToken t = _native();
        CoinReenterer r = new CoinReenterer();
        r.arm(t);
        _wrapNative(t, address(r), 2 ether);
        vm.prank(address(r));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        t.unwrap(1 ether, address(r), 0);
    }

    function test_native_contractRecipientGetsAllGas() public {
        UnderlyingToken t = _native();
        _wrapNative(t, alice, 1 ether);
        GasHungry g = new GasHungry();
        vm.prank(alice);
        t.unwrap(1 ether, address(g), 0);
        assertEq(address(g).balance, 1 ether);
    }

    function test_native_noGaslessWrap_gaslessUnwrapWorks() public {
        UnderlyingToken t = _native();
        MetaTxLib.MetaTransaction memory m = _call(alice, abi.encodeWithSignature("wrap(uint256)", 1 ether), 1, RR);
        bytes memory sig = _signCall(ALICE_PK, address(t), m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 0, 1 ether));
        t.mtxExecute(m, sig);
        _wrapNative(t, alice, 1 ether);
        m = _call(alice, abi.encodeWithSignature("unwrap(uint256,address,uint256)", 1 ether, bob, 1 ether), 1, RR);
        _execCall(ALICE_PK, address(t), m);
        assertEq(bob.balance, 1 ether);
    }

    function test_native_executeRateChecksTheCoinBalance() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(0), 18, 1, 1, _adjustable(address(adm)));
        _wrapNative(t, alice, 1 ether);
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(0), 101, 100)));
        vm.warp(block.timestamp + 7 days);
        vm.deal(address(t), 0.5 ether);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.ReserveShortfall.selector, address(0), 0.5 ether,
            1 ether));
        adm.exec(address(t), abi.encodeCall(t.executeRate, ()));
        vm.deal(address(t), 1 ether);
        adm.exec(address(t), abi.encodeCall(t.executeRate, ()));
        (uint96 n, uint96 d,,,) = t.legOf(address(0));
        assertEq(abi.encode(n, d), abi.encode(uint96(101), uint96(100)));
    }

    function test_native_decimalsOnHederaAre8() public {
        UnderlyingToken h = UnderlyingToken(_clone(address(new UnderlyingToken(address(this), address(0), UID_, true)),
            address(this), _one(address(0)), _singleInit(address(0), 8, 1, 1, _fixedRate())));
        (,,, uint8 dec,) = h.legOf(address(0));
        assertEq(dec, 8);
    }
}

/// Burns 100k gas on receipt: more than a 2,300 stipend.
contract GasHungry {
    receive() external payable {
        uint256 g = gasleft();
        while (g - gasleft() < 100_000) {}
    }
}
```

- [ ] **Step 3: Run**

Run: `timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge test --match-path "test/v2/{Underlying,NativeLeg}.t.sol"'`
Expected: 9 + 13 = 22 passed. If one fails, the code of Task 1 differs from the plan: report, do not edit src.
Full suite: Task 1's count + 22.

- [ ] **Step 4: Commit** — message `P1d: conformance — roles, single-asset ABI, init vs factory, namespace, native leg` + trailer.

---

### Task 3: Deploy scripts, size record, e2e, docs, TODO and HANDOFF

**Model:** Sonnet, effort medium.

**Files:**
- Modify: `smartcontracts/evm/script/Deploy.s.sol`, `smartcontracts/evm/script/hedera/DeployHedera.s.sol` — comments
  only: "Single/Multi chờ P1d" / "Transitional (R3): Single/Multi are over EIP-170 until P1d" → "Transitional (P1d,
  D2): `UnderlyingToken` is over EIP-170 until the size work; only META_NONE is deployed and registered".
- Modify: `docs/contracts/token-wrappers.md` — every "Transitional (BUILT)" note that names the Single/Multi tiers,
  their init encodings, `renounceRateAdmin`/`renounceGuardian`, the Hedera wrapper children, `_legCount` or "until P1d":
  §2.2 (built encoding = `UnderlyingInit`, D8; `RoleNotContract(3, a)`), CTR-TOK-26 (built in P1d: `NativeValueMismatch`
  (D7), native decimals 8 on Hedera (D6); `mtxWrap`/`NativeNotGasless` with P2 (D1)), §2.2.1 (built multi-leg encoding
  replaced; `renounceRole(4)`), §3 CTR-TOK-06 "built: dropped by `renounceRateAdmin`" (now: `renounceRole` leaves it;
  `disableFeature(RATE_ADJUSTABLE)` cancels, D5), CTR-TOK-20 (transitional: P2, D1), CTR-TOK-22 transitional (kind
  `UNDERLYING` on `AdminLib` roles), §7 Interfaces (block and table: one `UnderlyingToken` row with `IUnderlyingToken`
  events/errors, no Single/Multi/Hedera-children rows), §8 CTR-TOK-24 (`UnderlyingLib` row as built with its size;
  transitional sizes; D2 "controller ruling, pending the owner") and the storage table (`scaas.underlying` with the slot
  formula of the Global Constraints; linear layout = ERC-20 slots 0–4), §10 CTR-TOK-23 transitional (children deleted;
  association in `UnderlyingLib` under `IS_HEDERA`). Net ≤ 0 lines (budget warning).
- Modify: `docs/contracts/metatx.md` — the P1b/P1c "(BUILT)" bullet of §16 gains P1d (the `UNDERLYING` allowlist of six
  selectors, Global Constraints).
- Modify: `docs/networks/hedera.md` — `HederaTokensV2.sol` children gone; `HederaLib.checkAndAssociate` runs in
  `UnderlyingLib` init under `IS_HEDERA`; a native (HBAR) leg has 8 decimals (D6).
- Modify: `docs/history/dropped-artifacts.tsv` — a row for every load-bearing token the checker (C7) reports as gone
  (e.g. `renounceRateAdmin()`, `renounceGuardian()`, `RateAdminRenounced`, `GuardianRenounced`, `RateAdminNotContract`,
  `HederaSingleUnderlyingToken`, `HederaMultiUnderlyingToken`, `MultiUnderlyingToken`, `SingleUnderlyingToken`),
  reason `renamed` or `obsolete`, pointing at the CTR id where the meaning lives now.
- Modify: `TODO.md` §00 (P1 line: P1d done with its merge and test count; MT-3 "`mtxWrap` … (P1d)" → "(P2, D1)"; the
  "P1d: wrappers over EIP-170" bullet → "`UnderlyingToken` 25,408 B over EIP-170 until the size work (owner: optimise
  later; D2)"; P1c note (c) done; P2 notes gain D1 `mtxWrap`), `HANDOFF.md` (top section "Session 2026-10-11 (P1d)":
  state, what was built, rulings D1–D12 with D2/D4/D6 flagged for the owner, sizes, next = P1e plan).

- [ ] **Step 1: Size record**

```bash
timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge build --sizes --json 2>/dev/null' > /tmp/p1d-sizes.json || true
jq -r 'to_entries[] | select(.value.runtime_size > 24576) | "\(.key) \(.value.runtime_size)"' /tmp/p1d-sizes.json
jq -r 'to_entries[] | select(.key | test("^(NoUnderlyingToken|UnderlyingToken|UnderlyingLib|AdminLib|HederaLib)$")) | "\(.key) \(.value.runtime_size)"' /tmp/p1d-sizes.json
```

Expected over 24,576: exactly `UnderlyingToken` and `ZetherToken`. Anything else over: stop, report. Use the measured
numbers in the docs.

- [ ] **Step 2: e2e** (the scripts still deploy only `META_NONE`; this proves the deploy path still links and runs):
  `timeout 1800 scripts/capped bash -c 'cd scaas-node && CARGO_BUILD_JOBS=4 cargo test --test e2e -- --ignored 2>&1 | tail -15'`
  and the same for `e2e_hedera`. Expected: 4/4 and 1/1; if a prerequisite is missing, say so in the report and HANDOFF.

- [ ] **Step 3: Docs edits**, then `python3 scripts/docs_check.py check`, `python3 scripts/docs_check.py facts check`,
  `python3 scripts/test_docs_check.py` — 0 errors (budget warnings may stay; `token-wrappers.md` must not grow). Old-style
  ids (`D1`, `R3`) are refused in component docs by the checker: write "controller ruling, pending the owner".

- [ ] **Step 4: Full suite** — record the count in TODO/HANDOFF.

- [ ] **Step 5: Commit** — message `P1d: docs, deploy-script notes, TODO and HANDOFF` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh); one fix wave if needed; scoped re-review.
- Merge `p1d-underlying` into `main` with `--no-ff` (local, as P1a–P1c); do not push; remove the worktree.
