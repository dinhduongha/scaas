# P1c — `MetaTokenBase`: features, owner and roles (`AdminLib`), `PAYABLE` gate, init/provenance in `scaas.token`, `IS_HEDERA` + `HederaLib`, kind `NORMAL` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every token the creation-time feature flags and the one-owner administration model of CTR-TOK-22
through an external library `AdminLib` (ERC-7201 `scaas.token`), gate pay behind `PAYABLE`, move init/provenance into
that namespace, replace the Hedera children by the implementation immutable `IS_HEDERA` with `HederaLib`, and move kind
`NORMAL` (`NormalToken`) fully onto it (`MINTABLE` role instead of `minter`, `BURNABLE`, `PAYABLE`); the wrapper
tiers only report their legacy powers as flags until P1d replaces them.

**Architecture:** `AdminLib` (new, `public` mutations linked at deploy, `internal` checks inlined) owns
`TokenStorage` at `keccak256(abi.encode(uint256(keccak256("scaas.token")) - 1)) & ~0xff` = features, locked
features, owner, pending owner, creator, version, kind, decimals, initialized, name, symbol, roles. `MetaTokenBase`
keeps one-line wrappers (`grantRole` …), the views, ERC-165, the `PAYABLE` gate and the `IS_HEDERA` signature branch.
`NormalToken` decodes a `NoneInit` (the NORMAL subset of `TokenConfig`) from the unchanged factory-v2
`initialize(creator, underlyings, version, initData)`; P1e switches to `TokenConfig`.

**Tech Stack:** Solidity 0.8.28, Foundry (forge 1.3.5; external libraries are auto-linked in tests and scripts),
OpenZeppelin Contracts 5.2.0, forge-std 1.16.2; `scaas-node` e2e (Rust, `cargo test --ignored`) as the deploy check.

**Spec:** `docs/history/specs/2026-10-08-token-tree-design.md` (§2 T2/T3/T8/T11, §4, §5 Features, §7 TokenConfig);
normative: `docs/contracts/token-wrappers.md` CTR-TOK-10, -21, -22, -23, -24, -25; `docs/contracts/asset-suite.md`
CTR-AS-17; `docs/contracts/metatx.md` CTR-MTX-07; TODO.md §00 "P1c notes" (a)–(e).

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; forge runs in `smartcontracts/evm` of the worktree
  `.claude/worktrees/p1c` (branch `p1c-metatokenbase`), created by the controller with `lib/` copied.
- **Heavy commands only through `scripts/capped`, one at a time machine-wide**:
  `timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge test …'`. `rtk` rewrites git/grep output: use
  `/usr/bin/grep`, `rtk proxy git diff`.
- Build pins unchanged (solc 0.8.28, optimizer 200, no via-IR, EVM prague). Touched/new files `pragma solidity ^0.8.24;`.
- Flag bits (CTR-TOK-22, verbatim): 0 `PAYABLE`, 1 `MINTABLE` (role minter), 2 `BURNABLE`, 3 `RATE_ADJUSTABLE` (role
  rateAdmin, contract), 4 `WRAP_DISABLEABLE` (role guardian), 5 `FREEZE`, 6 `FORCE`, 7 `PAUSE`, 8 `ALLOWLIST`.
  Valid: `NORMAL` {0,1,2,5–8}, `WRAPPED` {0,3,4,5–8}, `NORMAL_ZETHER` {0,1,2}, `WRAPPED_ZETHER` {0,3,4}.
  `PAYABLE`/`BURNABLE` are always locked. Kinds (fresh): 0 `NORMAL`, 1 `WRAPPED`, 2 `NORMAL_ZETHER`,
  3 `WRAPPED_ZETHER`; ≥ 4 reserved (no valid flag).
- `scaas.token` slot `0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00` (`cast index-erc7201 scaas.token`);
  `scaas.metatx` `0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00` (P1a).
- `AdminLib` errors: `FeatureInvalidForKind(uint8)`, `FeatureNotBuilt(uint8)`, `LockedNotSubset()`,
  `RoleWithoutFeature(uint8)`, `RoleNotContract(uint8,address)`, `NoSuchRole(uint8)`, `FeatureLocked(uint8)`,
  `FeatureNotSet(uint8)`, `NotOwner(address)`, `NotPendingOwner(address)`, `MissingRole(uint8,address)`; events
  `RoleGranted(uint8 indexed bit, address indexed account, address indexed sender)`, `RoleRevoked(…same…)`,
  `FeatureDisabled(uint8 indexed bit, address indexed by)`, `OwnershipTransferStarted(address indexed, address indexed)`,
  `OwnershipTransferred(address indexed, address indexed)`.
- Token functions added: `features()`, `lockedFeatures()`, `owner()`, `pendingOwner()`, `hasRole(uint8,address)`,
  `kind() returns (uint8)`, `creator()`, `version()`, `grantRole(uint8,address)`, `revokeRole(uint8,address)`,
  `renounceRole(uint8)`, `disableFeature(uint8)`, `transferOwnership(address)`, `acceptOwnership()`,
  `renounceOwnership()`, `supportsInterface(bytes4)`, immutable `IS_HEDERA`. None is allowlisted. Removed on
  `NormalToken`: `minter()`, `renounceMinter()`, `NotMinter`, `MinterRenounced`.
- Constructors: tiers `(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)`; Hedera wrapper children
  `(factory_, chainUid_)`; `HederaNoUnderlyingToken` is deleted (kind NORMAL on Hedera = `NormalToken` with
  `isHedera_ = true`).
- Size budget (CTR-TOK-24): token implementation ≤ 20,480 B. Measured in a scratch copy of this plan's code:
  `NormalToken` 20,038 (NORMAL has 442 B left — see C9), `SingleUnderlyingToken` 28,296, `MultiUnderlyingToken`
  29,337, `HederaSingleUnderlyingToken` 29,201, `HederaMultiUnderlyingToken` 30,242 (wrappers over EIP-170 until P1d,
  P1b ruling R3), `AdminLib` 3,359, `HederaLib` 753.
- Test chain: id 7622, `chain_uid` `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464`; key `0xA11CE`.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push.

## Review Focus

- A gated function reachable with its flag cleared (mint after `disableFeature(MINTABLE)`, pay with `PAYABLE` off,
  burn with `BURNABLE` off, also through `mtxExecute(burn)`) — pinned by `test_mint_needsTheFlagAndTheRole`,
  `test_payable_off_gatesThePayEntries_notMetaTransfer`, `test_burn_onlyWithBurnable_directAndGasless` (Task 3).
- An admin function reachable gaslessly or by someone other than the owner, or ownership taken in one step —
  pinned by `test_adminFunctionsAreNeverSelfCalls`, `test_grantRevokeRenounce`, `test_twoStepTransferAndRenounce_rolesSurvive`.
- A flag accepted on the wrong kind, a regulated flag accepted although its controls are not built, or a disabled flag
  set again — pinned by `test_validFlagsPerKind`, `test_regulatedFlags_notBuiltOnPublicKinds_invalidOnConfidential`,
  `test_disableFeature_oneWay_lockedRefused` (Task 1).
- `AdminLib` writing outside `scaas.token` (lanes, balances) — pinned by `test_adminWritesDoNotTouchOtherNamespaces`.
- A 64-byte signature taking the HIP-632 path on a non-Hedera implementation (or not on a Hedera one) — pinned by
  `test_isHedera_takesTheHip632Path_onlyWhenSet` and the ported `HederaV2.t.sol`.

## Rulings (docs vs code) and defaults taken

- **C1 — Own `AdminLib`, not OpenZeppelin `AccessControlDefaultAdminRules`** (the spec's "candidate, decided in
  P1"). ADAR is inline contract code with linear storage, a `bytes32` role-admin hierarchy and a transfer delay —
  more than CTR-TOK-22 asks and bytes the 20,480 B budget does not have. `AdminLib` keeps exactly CTR-TOK-22: roles
  keyed by flag bit, one owner, two-step `transferOwnership`/`acceptOwnership` **without delay** (the owner cannot
  touch balances, CTR-TOK-10), `renounceOwnership`, holders keep roles. Event names follow OZ `Ownable2Step`.
- **C2 — Regulated flags 5–8 are refused at init with `FeatureNotBuilt(bit)`** on the non-confidential kinds (and
  `FeatureInvalidForKind` on confidential ones). Their controls (CTR-AS-04…07) are specified only; accepting the flag
  without the control would advertise a power that does nothing. The asset-suite stream lifts the refusal.
  `Roles.issuer`/`compliance` ≠ 0 ⇒ `RoleWithoutFeature(5|8)`. Flag to the owner.
- **C3 — No external `PayLib`.** The pay entries are thin builders over the inline `MetaTransfer` core (CTR-TOK-24
  keeps that core inline), which an external library cannot call. Pay stays in `MetaTokenBase` behind
  `AdminLib.requireFeature(PAYABLE)` on `mtxPay`, `payWithFee`, `mtxPayReceiverFee`; `payLane` (pure helper) and every
  `MetaTransfer` (with or without `entryRef`) stay ungated (T2: "`MetaTransfer` is never gated"). Flag to the owner.
- **C4 — `HederaLib`** = `git mv src/hedera/HederaV2Lib.sol` with `HederaSig`/`HederaHts` merged: `requireValid` is
  `public view` (linked; −225 B per token), `checkAndAssociate` stays `internal` (only the transitional Hedera wrapper
  children use it; P1d moves it into `WrappedLib`). The `asView` comment in `HederaAccountAuth` is updated (P1c
  note d).
- **C5 — Wrapper tiers transitional.** `SingleUnderlyingToken`/`MultiUnderlyingToken` keep their init data, their
  `rateAdmin`/`guardian` storage and `renounceRateAdmin`/`renounceGuardian`; they call `AdminLib.init(WRAPPED, f, f,
  0, noRoles)` with `f = PAYABLE | (rateAdjustable ? RATE_ADJUSTABLE) | (guardian ≠ 0 ? WRAP_DISABLEABLE)` so the views
  report their powers (locked, no owner; `PAYABLE` on as built). P1d replaces them.
- **C6 — NORMAL init data** is `abi.encode(NormalToken.NoneInit)` (name, symbol, decimals, features,
  lockedFeatures, owner, roles, initialSupply, initialHolder — field names of `TokenConfig`); the factory-v2
  `initialize` signature is unchanged until P1e. `initialHolder = 0` with a supply reverts in OZ `_mint`
  (`ERC20InvalidReceiver`).
- **C7 — Error reuse:** `FeatureNotSet(bit)` both for `disableFeature` on a clear flag and for calling a gated function
  whose flag is clear; `MissingRole(bit, account)` for a missing role. `kind()` returns `uint8` (P1e defines the enum).
- **C8 — Storage:** the `MetaTokenBase` state moves into `scaas.token`; `_legCount` stays linear (P1d moves it with
  the legs). Layout: NORMAL = ERC-20 slots 0–4 + `_legCount` 5; Single `_legs` 6, `_legIndex` 7, `_pending` 8, rate
  config 9; Multi `guardian` 10.
- **C9 — Size is the next constraint.** NORMAL is 20,038 / 20,480 B after P1c; P2 (`TradeLib`'s token side and three
  `mtx…` entries) will not fit without finding room (a slimmer `MetaTxBase`, more behind libraries, or a budget change).
  Flag to the owner now; P2's plan starts with it. Wrapper ceilings in the size tests rise to Single 28,672, Multi
  29,696, HederaSingle 29,696, HederaMulti 30,720 (transitional, R3).
- **C10 — KATs:** if the linked libraries move the test contract's deploy nonce, the `TokenKat` clone address and so
  both vectors change; regenerate with `WRITE_KAT=true` and record the new digests (only TokenKat reads them until P5).

---

### Task 1: `AdminLib` + harness tests

**Model:** Sonnet, effort high (complete code below, run green in a scratch copy).

**Files:**
- Create: `smartcontracts/evm/src/metatx/AdminLib.sol`
- Create: `smartcontracts/evm/test/metatx/helpers/AdminHarness.sol`, `smartcontracts/evm/test/metatx/AdminLib.t.sol`

**Interfaces:**
- Produces: `library AdminLib` — constants `PAYABLE…ALLOWLIST`, `KIND_NORMAL…KIND_WRAPPED_ZETHER`, `REGULATED`,
  `ROLE_BITS`, `ALWAYS_LOCKED`; `struct Roles {minter, rateAdmin, guardian, issuer, compliance}`;
  `struct TokenStorage {features, lockedFeatures, owner, pendingOwner, creator, version, kind, decimals, initialized,
  name, symbol, roles}`; `$() internal pure returns (TokenStorage storage)`; public `init(uint8 kind, uint256 features,
  uint256 locked, address owner, Roles memory roles)`, `grantRole(uint8,address,address caller)`,
  `revokeRole(uint8,address,address caller)`, `renounceRole(uint8,address caller)`, `disableFeature(uint8,address caller)`,
  `transferOwnership(address,address caller)`, `acceptOwnership(address caller)`, `renounceOwnership(address caller)`;
  internal `hasFeature(uint8)`, `hasRole(uint8,address)`, `requireRole(uint8,address)`, `requireFeature(uint8)`.

- [ ] **Step 1: Write the harness and the failing tests**

`test/metatx/helpers/AdminHarness.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AdminLib} from "../../../src/metatx/AdminLib.sol";

/// Exposes `AdminLib` on its own storage, for every kind (the built tokens use NORMAL and, transitionally, WRAPPED).
contract AdminHarness {
    function init(uint8 kind, uint256 features, uint256 locked, address owner_, AdminLib.Roles memory roles) external {
        AdminLib.init(kind, features, locked, owner_, roles);
    }

    function grantRole(uint8 bit, address account) external { AdminLib.grantRole(bit, account, msg.sender); }
    function revokeRole(uint8 bit, address account) external { AdminLib.revokeRole(bit, account, msg.sender); }
    function renounceRole(uint8 bit) external { AdminLib.renounceRole(bit, msg.sender); }
    function disableFeature(uint8 bit) external { AdminLib.disableFeature(bit, msg.sender); }
    function transferOwnership(address o) external { AdminLib.transferOwnership(o, msg.sender); }
    function acceptOwnership() external { AdminLib.acceptOwnership(msg.sender); }
    function renounceOwnership() external { AdminLib.renounceOwnership(msg.sender); }

    function features() external view returns (uint256) { return AdminLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return AdminLib.$().lockedFeatures; }
    function owner() external view returns (address) { return AdminLib.$().owner; }
    function pendingOwner() external view returns (address) { return AdminLib.$().pendingOwner; }
    function hasRole(uint8 bit, address a) external view returns (bool) { return AdminLib.hasRole(bit, a); }
    function requireRole(uint8 bit, address a) external view { AdminLib.requireRole(bit, a); }
}
```

`test/metatx/AdminLib.t.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {AdminHarness} from "./helpers/AdminHarness.sol";
import {Puller} from "../helpers/WalletMocks.sol";

/// CTR-TOK-22: creation-time flag validation, owner, roles, `disableFeature`.
contract AdminLibTest is Test {
    AdminHarness internal h;
    address internal ownerA = address(0x0A);
    address internal ownerB = address(0x0B);
    address internal minter = address(0x111);
    AdminLib.Roles internal none;

    uint256 internal constant PAYABLE = 1 << 0;
    uint256 internal constant MINTABLE = 1 << 1;
    uint256 internal constant BURNABLE = 1 << 2;
    uint256 internal constant RATE = 1 << 3;
    uint256 internal constant WRAPDIS = 1 << 4;

    function setUp() public {
        h = new AdminHarness();
    }

    function _roles(address m) internal pure returns (AdminLib.Roles memory r) {
        r.minter = m;
    }

    // ------------------------------------------------------------------ validation

    function test_storageSlotIsTheErc7201Namespace() public pure {
        bytes32 slot = keccak256(abi.encode(uint256(keccak256("scaas.token")) - 1)) & ~bytes32(uint256(0xff));
        assertEq(slot, 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00);
    }

    function test_validFlagsPerKind() public {
        uint256[4] memory valid = [
            PAYABLE | MINTABLE | BURNABLE, PAYABLE | RATE | WRAPDIS, PAYABLE | MINTABLE | BURNABLE, PAYABLE | RATE | WRAPDIS
        ];
        for (uint8 k; k < 4; ++k) {
            for (uint8 b; b < 9; ++b) {
                if (b >= 5) continue; // regulated: separate test
                AdminHarness x = new AdminHarness();
                if (valid[k] & (1 << b) != 0) {
                    x.init(k, 1 << b, 0, address(0), none);
                    assertEq(x.features(), 1 << b);
                } else {
                    vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureInvalidForKind.selector, b));
                    x.init(k, 1 << b, 0, address(0), none);
                }
            }
        }
    }

    function test_regulatedFlags_notBuiltOnPublicKinds_invalidOnConfidential() public {
        for (uint8 b = 5; b < 9; ++b) {
            vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotBuilt.selector, b));
            h.init(AdminLib.KIND_NORMAL, 1 << b, 0, address(0), none);
            vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotBuilt.selector, b));
            h.init(AdminLib.KIND_WRAPPED, 1 << b, 0, address(0), none);
            vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureInvalidForKind.selector, b));
            h.init(AdminLib.KIND_NORMAL_ZETHER, 1 << b, 0, address(0), none);
            vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureInvalidForKind.selector, b));
            h.init(AdminLib.KIND_WRAPPED_ZETHER, 1 << b, 0, address(0), none);
        }
    }

    function test_unknownBitsAndKinds_refused() public {
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureInvalidForKind.selector, uint8(9)));
        h.init(AdminLib.KIND_NORMAL, 1 << 9, 0, address(0), none);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureInvalidForKind.selector, uint8(0)));
        h.init(4, PAYABLE, 0, address(0), none); // reserved PQZ kinds: nothing valid
    }

    function test_lockedMustBeSubset_payableBurnableAlwaysLocked() public {
        vm.expectRevert(AdminLib.LockedNotSubset.selector);
        h.init(AdminLib.KIND_NORMAL, MINTABLE, BURNABLE, address(0), none);
        h.init(AdminLib.KIND_NORMAL, PAYABLE | MINTABLE | BURNABLE, 0, address(0), none);
        assertEq(h.lockedFeatures(), PAYABLE | BURNABLE);
    }

    function test_initialRoles_onlyForSetFlags() public {
        vm.expectRevert(abi.encodeWithSelector(AdminLib.RoleWithoutFeature.selector, uint8(1)));
        h.init(AdminLib.KIND_NORMAL, BURNABLE, 0, address(0), _roles(minter));
        AdminLib.Roles memory r;
        r.issuer = address(1);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.RoleWithoutFeature.selector, uint8(5)));
        h.init(AdminLib.KIND_NORMAL, 0, 0, address(0), r);
        r.issuer = address(0);
        r.compliance = address(1);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.RoleWithoutFeature.selector, uint8(8)));
        h.init(AdminLib.KIND_NORMAL, 0, 0, address(0), r);
    }

    function test_rateAdminMustBeAContract() public {
        AdminLib.Roles memory r;
        r.rateAdmin = address(0xEE);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.RoleNotContract.selector, uint8(3), address(0xEE)));
        h.init(AdminLib.KIND_WRAPPED, RATE, 0, address(0), r);
        r.rateAdmin = address(new Puller());
        h.init(AdminLib.KIND_WRAPPED, RATE, 0, address(0), r);
        assertTrue(h.hasRole(3, r.rateAdmin));
    }

    function test_initEmitsRolesAndOwner() public {
        vm.expectEmit(address(h));
        emit AdminLib.RoleGranted(1, minter, address(0));
        vm.expectEmit(address(h));
        emit AdminLib.OwnershipTransferred(address(0), ownerA);
        h.init(AdminLib.KIND_NORMAL, MINTABLE, 0, ownerA, _roles(minter));
        assertEq(h.owner(), ownerA);
        assertTrue(h.hasRole(1, minter));
    }

    // ------------------------------------------------------------------ owner powers

    function test_grantRevokeRenounce() public {
        h.init(AdminLib.KIND_NORMAL, MINTABLE, 0, ownerA, none);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.NotOwner.selector, minter));
        h.grantRole(1, minter);
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit AdminLib.RoleGranted(1, minter, ownerA);
        h.grantRole(1, minter);
        vm.prank(ownerA);
        h.grantRole(1, address(0x222)); // several holders
        assertTrue(h.hasRole(1, address(0x222)));
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit AdminLib.RoleRevoked(1, address(0x222), ownerA);
        h.revokeRole(1, address(0x222));
        assertFalse(h.hasRole(1, address(0x222)));
        vm.prank(minter);
        h.renounceRole(1);
        assertFalse(h.hasRole(1, minter));
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.MissingRole.selector, uint8(1), minter));
        h.renounceRole(1);
    }

    function test_grant_onlyARoleOfASetFlag() public {
        h.init(AdminLib.KIND_NORMAL, PAYABLE | BURNABLE, 0, ownerA, none);
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.NoSuchRole.selector, uint8(0)));
        h.grantRole(0, minter);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.NoSuchRole.selector, uint8(2)));
        h.grantRole(2, minter);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.RoleWithoutFeature.selector, uint8(1)));
        h.grantRole(1, minter);
        vm.stopPrank();
    }

    function test_disableFeature_oneWay_lockedRefused() public {
        h.init(AdminLib.KIND_NORMAL, PAYABLE | MINTABLE | BURNABLE, 0, ownerA, _roles(minter));
        vm.startPrank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureLocked.selector, uint8(0)));
        h.disableFeature(0);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureLocked.selector, uint8(2)));
        h.disableFeature(2);
        vm.expectEmit(address(h));
        emit AdminLib.FeatureDisabled(1, ownerA);
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotSet.selector, uint8(1)));
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.RoleWithoutFeature.selector, uint8(1)));
        h.grantRole(1, address(0x333)); // never set again, no new holder
        vm.stopPrank();
        assertTrue(h.hasRole(1, minter)); // the role stays, but the flag gate refuses it
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotSet.selector, uint8(1)));
        h.requireRole(1, minter);
    }

    function test_lockedFlagCannotBeDisabled() public {
        h.init(AdminLib.KIND_NORMAL, MINTABLE, MINTABLE, ownerA, none);
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureLocked.selector, uint8(1)));
        h.disableFeature(1);
    }

    function test_twoStepTransferAndRenounce_rolesSurvive() public {
        h.init(AdminLib.KIND_NORMAL, MINTABLE, 0, ownerA, _roles(minter));
        vm.prank(ownerA);
        vm.expectEmit(address(h));
        emit AdminLib.OwnershipTransferStarted(ownerA, ownerB);
        h.transferOwnership(ownerB);
        assertEq(h.owner(), ownerA);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.NotPendingOwner.selector, minter));
        h.acceptOwnership();
        vm.prank(ownerB);
        vm.expectEmit(address(h));
        emit AdminLib.OwnershipTransferred(ownerA, ownerB);
        h.acceptOwnership();
        assertEq(h.owner(), ownerB);
        assertEq(h.pendingOwner(), address(0));
        vm.prank(ownerB);
        h.renounceOwnership();
        assertEq(h.owner(), address(0));
        assertTrue(h.hasRole(1, minter));
        vm.prank(ownerB);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.NotOwner.selector, ownerB));
        h.grantRole(1, ownerB);
    }

    function test_noOwnerMeansNoAdministration() public {
        h.init(AdminLib.KIND_NORMAL, MINTABLE, 0, address(0), _roles(minter));
        vm.prank(address(0));
        vm.expectRevert(abi.encodeWithSelector(AdminLib.NotOwner.selector, address(0)));
        h.disableFeature(1);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.NotPendingOwner.selector, address(0)));
        vm.prank(address(0));
        h.acceptOwnership();
    }
}
```

Run `forge test --match-path test/metatx/AdminLib.t.sol` (capped). Expected: compile error, `AdminLib.sol` not found.

- [ ] **Step 2: Implement `src/metatx/AdminLib.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {SigCheck} from "../common/SigCheck.sol";

/// @title Features, owner and roles of every SCaaS token (CTR-TOK-22), in the ERC-7201 namespace `scaas.token`.
/// @notice External library: the token keeps one-line wrappers, the logic is linked at deploy (CTR-TOK-24).
///         `features`/`lockedFeatures` are written once by `init`; a flag can later only be cleared, once, by the
///         owner and only when not locked. One `owner` (0 = no administration ever) grants and revokes the role of a
///         set flag, disables disableable flags, transfers (two-step) or renounces ownership. Role holders keep their
///         roles after the owner renounces; a holder may renounce its own role.
library AdminLib {
    // ------------------------------------------------------------------ flags (bit numbers, CTR-TOK-22)
    uint8 internal constant PAYABLE = 0;
    uint8 internal constant MINTABLE = 1;
    uint8 internal constant BURNABLE = 2;
    uint8 internal constant RATE_ADJUSTABLE = 3;
    uint8 internal constant WRAP_DISABLEABLE = 4;
    uint8 internal constant FREEZE = 5;
    uint8 internal constant FORCE = 6;
    uint8 internal constant PAUSE = 7;
    uint8 internal constant ALLOWLIST = 8;

    // ------------------------------------------------------------------ kinds (CTR-TOK-21, fresh enum)
    uint8 internal constant KIND_NORMAL = 0;
    uint8 internal constant KIND_WRAPPED = 1;
    uint8 internal constant KIND_NORMAL_ZETHER = 2;
    uint8 internal constant KIND_WRAPPED_ZETHER = 3;

    /// @dev Flags 5–8 (regulated controls, CTR-AS-17): valid on non-confidential kinds, not built yet (asset suite).
    uint256 internal constant REGULATED = (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << ALLOWLIST);
    /// @dev Flags with a role. PAYABLE and BURNABLE have none and are always locked.
    uint256 internal constant ROLE_BITS = (1 << MINTABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE);
    uint256 internal constant ALWAYS_LOCKED = (1 << PAYABLE) | (1 << BURNABLE);

    /// @notice Initial role holders (CTR-TOK-25 `Roles`); each only for a set flag, 0 = none.
    struct Roles {
        address minter;      // MINTABLE
        address rateAdmin;   // RATE_ADJUSTABLE, contract only
        address guardian;    // WRAP_DISABLEABLE
        address issuer;      // FREEZE / FORCE / PAUSE (not built)
        address compliance;  // FORCE / ALLOWLIST (not built)
    }

    /// @custom:storage-location erc7201:scaas.token
    struct TokenStorage {
        uint256 features;
        uint256 lockedFeatures;
        address owner;
        address pendingOwner;
        address creator;
        uint64 version;
        uint8 kind;
        uint8 decimals;
        bool initialized;
        string name;
        string symbol;
        mapping(uint256 bit => mapping(address account => bool)) roles;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.token")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00;

    event RoleGranted(uint8 indexed bit, address indexed account, address indexed sender);
    event RoleRevoked(uint8 indexed bit, address indexed account, address indexed sender);
    event FeatureDisabled(uint8 indexed bit, address indexed by);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error FeatureInvalidForKind(uint8 bit);
    error FeatureNotBuilt(uint8 bit);
    error LockedNotSubset();
    error RoleWithoutFeature(uint8 bit);
    error RoleNotContract(uint8 bit, address account);
    error NoSuchRole(uint8 bit);
    error FeatureLocked(uint8 bit);
    error FeatureNotSet(uint8 bit);
    error NotOwner(address caller);
    error NotPendingOwner(address caller);
    error MissingRole(uint8 bit, address account);

    function $() internal pure returns (TokenStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init (CTR-TOK-22 "Validation in the token")

    /// @notice Validates the flags for `kind` and writes features, owner and initial roles. Called once by the
    ///         token's `initialize` (the factory only forwards; anyone may bring an implementation).
    function init(uint8 kind, uint256 features, uint256 locked, address owner, Roles memory roles) public {
        uint256 bad = features & ~_validFor(kind);
        if (bad != 0) revert FeatureInvalidForKind(_lowest(bad));
        if (features & REGULATED != 0) revert FeatureNotBuilt(_lowest(features & REGULATED));
        if (locked & ~features != 0) revert LockedNotSubset();
        TokenStorage storage s = $();
        s.kind = kind;
        s.features = features;
        s.lockedFeatures = locked | (features & ALWAYS_LOCKED);
        if (roles.issuer != address(0)) revert RoleWithoutFeature(FREEZE);
        if (roles.compliance != address(0)) revert RoleWithoutFeature(ALLOWLIST);
        if (roles.minter != address(0)) _grant(s, MINTABLE, roles.minter, address(0));
        if (roles.rateAdmin != address(0)) _grant(s, RATE_ADJUSTABLE, roles.rateAdmin, address(0));
        if (roles.guardian != address(0)) _grant(s, WRAP_DISABLEABLE, roles.guardian, address(0));
        if (owner != address(0)) {
            s.owner = owner;
            emit OwnershipTransferred(address(0), owner);
        }
    }

    // ------------------------------------------------------------------ owner

    function grantRole(uint8 bit, address account, address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        _grant(s, bit, account, caller);
    }

    function revokeRole(uint8 bit, address account, address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        if (s.roles[bit][account]) {
            s.roles[bit][account] = false;
            emit RoleRevoked(bit, account, caller);
        }
    }

    /// @notice A holder gives up its own role (replaces `renounceMinter`/`renounceRateAdmin`/`renounceGuardian`).
    function renounceRole(uint8 bit, address caller) public {
        TokenStorage storage s = $();
        if (!s.roles[bit][caller]) revert MissingRole(bit, caller);
        s.roles[bit][caller] = false;
        emit RoleRevoked(bit, caller, caller);
    }

    /// @notice One-way: clears a set, unlocked flag (replaces `disableControls`).
    function disableFeature(uint8 bit, address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        uint256 m = _bit(bit);
        if (s.lockedFeatures & m != 0) revert FeatureLocked(bit);
        if (s.features & m == 0) revert FeatureNotSet(bit);
        s.features &= ~m;
        emit FeatureDisabled(bit, caller);
    }

    function transferOwnership(address newOwner, address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        s.pendingOwner = newOwner;
        emit OwnershipTransferStarted(caller, newOwner);
    }

    function acceptOwnership(address caller) public {
        TokenStorage storage s = $();
        if (caller != s.pendingOwner || caller == address(0)) revert NotPendingOwner(caller);
        address previous = s.owner;
        s.owner = caller;
        s.pendingOwner = address(0);
        emit OwnershipTransferred(previous, caller);
    }

    /// @notice The owner becomes 0 forever; role holders keep their roles (to freeze everything, revoke first).
    function renounceOwnership(address caller) public {
        TokenStorage storage s = _onlyOwner(caller);
        s.owner = address(0);
        s.pendingOwner = address(0);
        emit OwnershipTransferred(caller, address(0));
    }

    // ------------------------------------------------------------------ checks used inline by the token

    function hasFeature(uint8 bit) internal view returns (bool) {
        return $().features & _bit(bit) != 0;
    }

    function hasRole(uint8 bit, address account) internal view returns (bool) {
        return $().roles[bit][account];
    }

    /// @dev The flag is set and `account` holds its role.
    function requireRole(uint8 bit, address account) internal view {
        TokenStorage storage s = $();
        if (s.features & _bit(bit) == 0) revert FeatureNotSet(bit);
        if (!s.roles[bit][account]) revert MissingRole(bit, account);
    }

    function requireFeature(uint8 bit) internal view {
        if ($().features & _bit(bit) == 0) revert FeatureNotSet(bit);
    }

    // ------------------------------------------------------------------ internals

    function _grant(TokenStorage storage s, uint8 bit, address account, address caller) private {
        if (ROLE_BITS & _bit(bit) == 0) revert NoSuchRole(bit);
        if (s.features & _bit(bit) == 0) revert RoleWithoutFeature(bit);
        if (bit == RATE_ADJUSTABLE && !SigCheck.isContract(account)) revert RoleNotContract(bit, account);
        if (s.roles[bit][account]) return;
        s.roles[bit][account] = true;
        emit RoleGranted(bit, account, caller);
    }

    function _onlyOwner(address caller) private view returns (TokenStorage storage s) {
        s = $();
        if (caller != s.owner || caller == address(0)) revert NotOwner(caller);
    }

    /// @dev Valid flags per kind (CTR-TOK-22 table): NORMAL* mint/burn, WRAPPED* rate/wrap, regulated only on
    ///      non-confidential kinds (CTR-AS-17), PAYABLE everywhere. An unknown kind has no valid flag.
    function _validFor(uint8 kind) private pure returns (uint256) {
        uint256 none = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE);
        uint256 und = (1 << PAYABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE);
        if (kind == KIND_NORMAL) return none | REGULATED;
        if (kind == KIND_WRAPPED) return und | REGULATED;
        if (kind == KIND_NORMAL_ZETHER) return none;
        if (kind == KIND_WRAPPED_ZETHER) return und;
        return 0;
    }

    function _bit(uint8 bit) private pure returns (uint256) {
        return uint256(1) << bit;
    }

    function _lowest(uint256 x) private pure returns (uint8 i) {
        while (x & 1 == 0) { x >>= 1; ++i; }
    }
}
```

- [ ] **Step 3: Run** — Expected: 14 passed. Full suite: 758 + 14 = 772 passed.

- [ ] **Step 4: Commit** — message `P1c: AdminLib — feature flags, owner, roles in scaas.token (CTR-TOK-22)` + trailer.

---

### Task 2: `MetaTokenBase` on `AdminLib`, `IS_HEDERA` + `HederaLib`, kind NORMAL, wrappers transitional; port the tests

**Model:** Opus, effort high (src rewrite + test port across many files).

**Files (src):**
- Rename + rewrite: `src/hedera/HederaV2Lib.sol` → `src/hedera/HederaLib.sol` (`git mv`; full text below)
- Rewrite: `src/metatx/MetaTokenBase.sol`, `src/metatx/NormalToken.sol`, `src/hedera/HederaTokensV2.sol` (full texts below)
- Modify: `src/metatx/SingleUnderlyingToken.sol`, `src/metatx/MultiUnderlyingToken.sol`, `src/hedera/HederaAccountAuth.sol`
- Modify: `script/Deploy.s.sol`, `script/hedera/DeployHedera.s.sol`

**Files (tests):** every test that constructs a v2 tier, decodes the old NORMAL init data, uses `minter()`,
`renounceMinter`, `NotMinter`, `MinterRenounced`, `HederaNoUnderlyingToken`, `HederaHts`/`HederaSig`/`HederaV2Lib`, or
pins sizes/layout: at least `test/v2/helpers/V2Fixture.sol`, `test/v2/{Base,Tier1,Tier2,Multi,Rates,FactoryV2,
MetaTxGasV2,UnwrapOp,WrapperInvariant,Layout,Allowlist,ReceiverPays}.t.sol`, `test/v2/layout/*.json`,
`test/metatx/{TokenKat,MsgSenderLint}.t.sol`, `test/hedera/HederaV2.t.sol`. Find them with
`/usr/bin/grep -rlE "WrappedToken\(|HederaNoUnderlying|HederaHts|HederaSig|HederaV2Lib|renounceMinter|NotMinter|MinterRenounced|\.minter\(\)|META_NONE" smartcontracts/evm/test smartcontracts/evm/script`.

**Interfaces:**
- Consumes: Task 1 `AdminLib`.
- Produces: `MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)`, `IS_HEDERA`, the token functions
  listed in Global Constraints; `NormalToken.NoneInit`; `HederaLib.requireValid` (public view),
  `HederaLib.checkAndAssociate` (internal), errors `HederaLib.HtsQueryFailed`, `HederaLib.AssociateFailed`;
  `SingleUnderlyingToken._initLegacyFeatures(bool)`.

- [ ] **Step 1: `HederaLib`** — `git mv src/hedera/HederaV2Lib.sol src/hedera/HederaLib.sol`, then replace the whole file:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IMetaTx} from "../metatx/IMetaTx.sol";
import {HederaAccountAuth} from "./HederaAccountAuth.sol";

/// @title Hedera branches of every token (CTR-TOK-23, NET-HED-14), behind the implementation's immutable `IS_HEDERA`.
/// @notice `requireValid`: a 64-byte signature from an address without code (a native ED25519 account `0.0.N`) goes
///         through `isAuthorizedRaw` (HIP-632): the precompile reads the account's key from Hedera state, a key sent by
///         the client is never the basis. Every other signature (ECDSA 65 bytes, ERC-1271) takes the EVM path.
///         `checkAndAssociate`: HTS underlying check at init, FAIL-CLOSED (TW2 §11, review M5):
///         1. `isToken(u)` ≠ SUCCESS ⇒ `HtsQueryFailed`. 2. Nếu là HTS: `getTokenCustomFees(u)` ≠ SUCCESS hoặc không
///         giải mã được ⇒ `HtsQueryFailed`; có bất kỳ phí fixed/fractional/royalty nào ⇒ người gọi từ chối
///         (`UnderlyingInvalid`). 3. Nếu là HTS: `associateToken(this, u)` ≠ SUCCESS/ALREADY ⇒ `AssociateFailed`.
///         Precompile vắng mặt (lời gọi "thành công" với returndata rỗng) cũng là `HtsQueryFailed(u, -1)`.
///         Một fee-schedule key vẫn thêm được phí về sau: không chặn on-chain, ví và wizard cảnh báo (§6.6).
library HederaLib {
    /// @dev Public (linked, DELEGATECALL): keeps the HIP-632 call out of every token's bytecode. Declared `view` for the
    ///      `view` caller; `HederaAccountAuth.asView` issues a plain CALL, and every call site is a non-view entry point
    ///      (CTR-TOK-23), so the frame is never static.
    function requireValid(address from, bytes32 digest, bytes calldata sig) public view {
        if (!HederaAccountAuth.asView()(from, digest, sig)) revert IMetaTx.MetaTxBadSignature();
    }

    address internal constant HTS = address(0x167);
    int64 internal constant SUCCESS = 22;
    int64 internal constant ALREADY_ASSOCIATED = 194; // TOKEN_ALREADY_ASSOCIATED_TO_ACCOUNT

    error HtsQueryFailed(address u, int64 responseCode);
    error AssociateFailed(int64 responseCode);

    /// @return feeFree `false` nếu `u` là token HTS có custom fee.
    function checkAndAssociate(address u) internal returns (bool feeFree) {
        bytes memory ret = _query(u, abi.encodeWithSignature("isToken(address)", u), 64);
        if (_word(ret, 32) == 0) return true; // ERC-20 thường trên EVM của Hedera: không phí HTS, không associate
        ret = _query(u, abi.encodeWithSignature("getTokenCustomFees(address)", u), 128);
        // (int64, FixedFee[], FractionalFee[], RoyaltyFee[]): mỗi độ dài mảng phải nằm trong returndata.
        for (uint256 i = 1; i <= 3; ++i) {
            uint256 off = _word(ret, 32 * i);
            if (off > ret.length || ret.length - off < 32) revert HtsQueryFailed(u, SUCCESS);
            if (_word(ret, off) != 0) return false;
        }
        (bool ok, bytes memory r) =
            HTS.call(abi.encodeWithSignature("associateToken(address,address)", address(this), u));
        int64 rc = ok && r.length == 32 ? _rc(r) : int64(-1);
        if (rc != SUCCESS && rc != ALREADY_ASSOCIATED) revert AssociateFailed(rc);
        return true;
    }

    /// @dev Gọi HTS; `rc ≠ SUCCESS` (kể cả không trả lời: `-1`) hoặc returndata ngắn hơn `minLen` ⇒ `HtsQueryFailed`.
    function _query(address u, bytes memory call, uint256 minLen) private returns (bytes memory ret) {
        bool ok;
        (ok, ret) = HTS.call(call);
        int64 rc = ok && ret.length >= 32 ? _rc(ret) : int64(-1);
        if (rc != SUCCESS || ret.length < minLen) revert HtsQueryFailed(u, rc);
    }

    function _rc(bytes memory ret) private pure returns (int64) {
        return int64(int256(_word(ret, 0)));
    }

    function _word(bytes memory b, uint256 off) private pure returns (uint256 w) {
        assembly ("memory-safe") { w := mload(add(add(b, 32), off)) }
    }
}
```

In `src/hedera/HederaAccountAuth.sol`, in the `asView` notice, replace
"chỗ gọi duy nhất là `executeMetaTransaction` (không phải view, frame không tĩnh)" by
"mọi chỗ gọi là entry point không-view (`mtxExecute`, `mtxExecuteTransfer`, các hàm có tên; frame không tĩnh)"
(wrap the comment at 120 columns).

- [ ] **Step 2: `MetaTokenBase.sol`** — replace the whole file:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20MetaTx} from "./ERC20MetaTx.sol";
import {AdminLib} from "./AdminLib.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {HederaLib} from "../hedera/HederaLib.sol";
import {IMetaTokenV2} from "./IMetaTokenV2.sol";
import {IFactoryTokenV2} from "../factory/IFactoryTokenV2.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title Common root of the v2 tiers on `ERC20MetaTx` (TW2 §3.3, §7; CTR-MTX-07). EIP-1167 clones.
/// @notice The named functions (CTR-MTX-09) only build the struct of their kind and run its pipeline; receiver-pays
///         (CTR-MTX-05/06). Features, owner and roles (CTR-TOK-22) live in `AdminLib`, init and provenance in the
///         ERC-7201 namespace `scaas.token`. Pay (`mtxPay`, `payWithFee`, `mtxPayReceiverFee`) works only with
///         `PAYABLE`; a `MetaTransfer` (with or without `entryRef`) is never gated. Hedera is the immutable
///         `IS_HEDERA` (CTR-TOK-23): HIP-632 signatures through `HederaLib`.
abstract contract MetaTokenBase is ERC20MetaTx, IMetaTokenV2, IFactoryTokenV2, IERC165 {
    using MetaTxLib for MetaTxLib.MetaTransfer;

    bytes32 internal constant RECEIVER_FEE_TYPEHASH =
        keccak256("ReceiverFee(bytes32 paymentDigest,uint256 fee,address feeRecipient,uint256 validUntil)");

    address public immutable FACTORY;
    address private immutable _SELF;
    /// @notice SmartKeyAccount implementation of this chain (built: `SubjectAccount`, renamed in P4; 0 = none). Only its EIP-1167 clones get 400k gas for
    ///         ERC-1271; every other contract wallet 50k.
    address public immutable SMART_KEY_ACCOUNT_IMPL;
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    /// @notice Set on implementations deployed for Hedera (CTR-TOK-23): 64-byte signatures from accounts without code
    ///         take the HIP-632 path.
    bool public immutable IS_HEDERA;

    /// @dev Transitional (P1d moves it to `scaas.underlying`): number of underlying legs, 0 on tier 1.
    uint8 internal _legCount;

    error NotFactory();
    error AlreadyInitialized();
    error MtxModeShape(uint32 mode);
    /// @notice Wrong underlying count for the tier (0 / 1 / 2–8).
    error UnderlyingCountInvalid(uint256 n);

    /// @dev Runs ONCE on the implementation and locks it, so nobody can `initialize` it.
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
        ERC20MetaTx(chainUid_)
    {
        FACTORY = factory_;
        _SELF = address(this);
        SMART_KEY_ACCOUNT_IMPL = smartKeyAccountImpl_;
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        IS_HEDERA = isHedera_;
        AdminLib.$().initialized = true;
    }

    /// @notice The factory calls it in the SAME call as CREATE2. `initData` per tier (TW2 §4, §5.1, §8.1).
    function initialize(address creator_, address[] calldata underlyings, uint64 version_, bytes calldata initData)
        external
    {
        if (msg.sender != FACTORY) revert NotFactory();
        AdminLib.TokenStorage storage t = AdminLib.$();
        if (t.initialized) revert AlreadyInitialized();
        t.initialized = true;
        t.creator = creator_;
        t.version = version_;
        _init(creator_, underlyings, initData);
    }

    /// @dev The tier decodes `initData`, calls `_setMetadata` and `AdminLib.init`, checks `underlyings`.
    function _init(address creator_, address[] calldata underlyings, bytes calldata initData) internal virtual;

    function _setMetadata(string memory n, string memory sym, uint8 d) internal {
        AdminLib.TokenStorage storage t = AdminLib.$();
        t.name = n;
        t.symbol = sym;
        t.decimals = d;
    }

    function tokenKind() external pure virtual returns (IOpenFactoryV2.TokenKind);

    function name() public view override returns (string memory) { return AdminLib.$().name; }
    function symbol() public view override returns (string memory) { return AdminLib.$().symbol; }
    function decimals() public view override returns (uint8) { return AdminLib.$().decimals; }

    function factory() external view returns (address) { return FACTORY; }
    function implementation() external view returns (address) { return _SELF; }
    function creator() external view returns (address) { return AdminLib.$().creator; }
    function version() external view returns (uint64) { return AdminLib.$().version; }
    /// @notice CTR-TOK-21 kind: 0 `NORMAL`, 1 `WRAPPED`, 2 `NORMAL_ZETHER`, 3 `WRAPPED_ZETHER`.
    function kind() external view returns (uint8) { return AdminLib.$().kind; }

    // ------------------------------------------------------------------ features, owner, roles (CTR-TOK-22)

    function features() external view returns (uint256) { return AdminLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return AdminLib.$().lockedFeatures; }
    function owner() external view returns (address) { return AdminLib.$().owner; }
    function pendingOwner() external view returns (address) { return AdminLib.$().pendingOwner; }
    function hasRole(uint8 bit, address account) external view returns (bool) { return AdminLib.hasRole(bit, account); }

    function grantRole(uint8 bit, address account) external { AdminLib.grantRole(bit, account, _msgSender()); }
    function revokeRole(uint8 bit, address account) external { AdminLib.revokeRole(bit, account, _msgSender()); }
    function renounceRole(uint8 bit) external { AdminLib.renounceRole(bit, _msgSender()); }
    function disableFeature(uint8 bit) external { AdminLib.disableFeature(bit, _msgSender()); }
    function transferOwnership(address newOwner) external { AdminLib.transferOwnership(newOwner, _msgSender()); }
    function acceptOwnership() external { AdminLib.acceptOwnership(_msgSender()); }
    function renounceOwnership() external { AdminLib.renounceOwnership(_msgSender()); }

    /// @notice ERC-165; `IERC20Payment` only while `PAYABLE` is set.
    function supportsInterface(bytes4 id) external view returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IERC20).interfaceId || id == type(IMetaTx).interfaceId
            || id == type(IERC20MetaTx).interfaceId
            || (id == type(IERC20Payment).interfaceId && AdminLib.hasFeature(AdminLib.PAYABLE));
    }

    function payLane(bytes32 payId) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked("scaas.pay.lane", payId)));
    }

    // ------------------------------------------------------------------ named functions (CTR-MTX-09)

    function mtxTransfer(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, bytes calldata signature
    ) external nonReentrant returns (bool) {
        if (mode & ~MetaTxLib.MODE_RESTRICT_RELAYER != 0) revert MtxModeShape(mode);
        MetaTxLib.MetaTransfer memory t;
        t.from = from;
        t.to = to;
        t.value = amount;
        t.batch = batch;
        t.nonce = nonce;
        t.validUntil = validUntil;
        t.mode = mode;
        t.relayer = relayer;
        _executeTransfer(t, signature);
        return true;
    }

    function mtxTransferWithFee(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external nonReentrant returns (bool) {
        _requireFeeShape(mode, feeRecipient);
        MetaTxLib.MetaTransfer memory t;
        t.from = from;
        t.to = to;
        t.value = amount;
        t.batch = batch;
        t.nonce = nonce;
        t.validUntil = validUntil;
        t.mode = mode;
        t.relayer = relayer;
        t.fee = fee;
        t.feeRecipient = feeRecipient;
        _executeTransfer(t, signature);
        return true;
    }

    /// @notice `mtxExecute` that says "this intent pays a fee": fee nibble ≠ `NONE`.
    function mtxExecuteWithFee(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bytes memory)
    {
        if (m.mode & MetaTxLib.MODE_FEE_MASK == 0) revert MtxModeShape(m.mode);
        return _execute(m, signature);
    }

    /// @notice Payment `payId` on its own lane `payLane(payId)`, nonce 0 (CTR-MTX-10).
    function mtxPay(
        address from, address to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external nonReentrant returns (bool) {
        AdminLib.requireFeature(AdminLib.PAYABLE);
        MetaTxLib.MetaTransfer memory t;
        t.from = from;
        t.to = to;
        t.value = amount;
        t.entryRef = payId;
        t.batch = payLane(payId);
        t.validUntil = validUntil;
        t.mode = mode;
        t.relayer = relayer;
        t.fee = fee;
        t.feeRecipient = feeRecipient;
        _executeTransfer(t, signature);
        return true;
    }

    // ------------------------------------------------------------------ receiver-pays (CTR-MTX-05, CTR-MTX-06)

    function receiverFeeDigest(bytes32 paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)
        public view returns (bytes32)
    {
        return _hashTypedDataV4(keccak256(abi.encode(RECEIVER_FEE_TYPEHASH, paymentDigest, fee, feeRecipient, validUntil)));
    }

    /// @notice The payer's payment runs untouched; then the payee, who co-signed `ReceiverFee` over the payer's
    ///         digest, pays `fee` to `feeRecipient` in the same transaction.
    function mtxPayReceiverFee(
        MetaTxLib.MetaTransfer calldata t, bytes calldata payerSig,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeSig
    ) external nonReentrant returns (bool) {
        AdminLib.requireFeature(AdminLib.PAYABLE);
        if (t.entryRef == 0 || t.mode & MetaTxLib.MODE_FEE_MASK != 0 || t.fee != 0
            || t.mode & MetaTxLib.MODE_RESTRICT_RELAYER == 0 || t.batch != payLane(t.entryRef) || t.nonce != 0
            || feeRecipient == address(0)) revert ReceiverFeeShape();
        if (block.timestamp > rfValidUntil) revert ReceiverFeeExpired(rfValidUntil, block.timestamp);
        if (fee == 0 || fee > t.value) revert ReceiverFeeAmount(fee, t.value);
        if (feeRecipient == t.to) revert FeeRecipientIsPayee();
        if (feeRecipient == address(this)) revert TransferToSelf();
        bytes32 d = _executeTransfer(t, payerSig);
        _requireValidSignature(t.to, receiverFeeDigest(d, fee, feeRecipient, rfValidUntil), payeeSig);
        _transfer(t.to, feeRecipient, fee);
        emit ReceiverFeePaid(d, t.to, feeRecipient, fee);
        return true;
    }

    /// @dev Fee `PERCENT`/`FIXED`, recipient bound by the signer and non-zero.
    function _requireFeeShape(uint32 mode, address feeRecipient) private pure {
        uint32 f = mode & MetaTxLib.MODE_FEE_MASK;
        if ((f != MetaTxLib.MODE_FEE_PERCENT && f != MetaTxLib.MODE_FEE_FIXED)
            || mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT == 0 || feeRecipient == address(0)) {
            revert MtxModeShape(mode);
        }
    }

    // ------------------------------------------------------------------ direct path

    /// @notice The caller pays gas itself; the fee is on top, `amount` arrives whole; never to the payee (CTR-MTX-08).
    function payWithFee(
        address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient, bytes32 entryRef
    ) external returns (bool) {
        AdminLib.requireFeature(AdminLib.PAYABLE);
        address payer = _msgSender();
        uint256 feeAmount = FeePolicy.compute(feeMode, amount, fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        if (feeAmount != 0) {
            if (feeRecipient == to) revert FeeRecipientIsPayee();
            _transfer(payer, feeRecipient, feeAmount);
        }
        _transfer(payer, to, amount);
        emit PaymentSettled(payer, to, amount, feeAmount, feeRecipient, entryRef);
        return true;
    }

    /// @dev Hedera (CTR-TOK-23): a 64-byte signature from an account without code is HIP-632; all else is EVM.
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (IS_HEDERA && sig.length == 64 && !_isContract(from)) return HederaLib.requireValid(from, digest, sig);
        super._requireValidSignature(from, digest, sig);
    }

    function _erc1271Gas(address from) internal view override returns (uint256) {
        bytes32 h = _SMART_KEY_CLONE_CODEHASH;
        return h != bytes32(0) && from.codehash == h ? 400_000 : 50_000;
    }
}
```

- [ ] **Step 3: `NormalToken.sol`** — replace the whole file:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "./MetaTokenBase.sol";
import {AdminLib} from "./AdminLib.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Kind `NORMAL` (CTR-TOK-21): a standalone token, no underlying.
/// @notice Flags valid here: `PAYABLE`, `MINTABLE` (role `minter`), `BURNABLE` (holder burn). A supply cap or a mint
///         rate limit, if an issuer needs one, lives in its minter contract. Built by the factory through
///         `initialize(creator, [], version, abi.encode(NoneInit))`; P1e switches to `TokenConfig`.
contract NormalToken is MetaTokenBase {
    /// @notice The NORMAL subset of `TokenConfig` (CTR-TOK-25).
    struct NoneInit {
        string name;
        string symbol;
        uint8 decimals;
        uint256 features;
        uint256 lockedFeatures;
        address owner;
        AdminLib.Roles roles;
        uint256 initialSupply;
        address initialHolder;
    }

    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
        MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
    {}

    function tokenKind() external pure override returns (IOpenFactoryV2.TokenKind) {
        return IOpenFactoryV2.TokenKind.META_NONE;
    }

    /// @param initData `abi.encode(NoneInit)`.
    function _init(address, address[] calldata underlyings, bytes calldata initData) internal override {
        if (underlyings.length != 0) revert UnderlyingCountInvalid(underlyings.length);
        NoneInit memory c = abi.decode(initData, (NoneInit));
        _setMetadata(c.name, c.symbol, c.decimals);
        AdminLib.init(AdminLib.KIND_NORMAL, c.features, c.lockedFeatures, c.owner, c.roles);
        if (c.initialSupply != 0) _mint(c.initialHolder, c.initialSupply);
    }

    /// @notice `MINTABLE` and the `minter` role; never allowlisted (a minter contract's caps run on its own call).
    function mint(address to, uint256 amount) external {
        AdminLib.requireRole(AdminLib.MINTABLE, _msgSender());
        _mint(to, amount);
    }

    /// @notice Allowlisted `AMOUNT(0)` (CTR-MTX-19): gasless through `mtxExecute`.
    function burn(uint256 amount) external nonReentrant {
        AdminLib.requireFeature(AdminLib.BURNABLE);
        _burn(_msgSender(), amount);
    }

    /// @notice The allowlist (CTR-MTX-19): `cancelNonce` (base), `burn(uint256)` `AMOUNT(0)`.
    function mtxSelectors()
        public pure override(IMetaTx, MetaTxBase) returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](2);
        c = new uint8[](2);
        a = new uint8[](2);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (this.burn.selector, FEE_CLASS_AMOUNT);
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.burn.selector) return MtxRule(FEE_CLASS_AMOUNT, 0, 36);
        return super._mtxRule(sel);
    }
}
```

- [ ] **Step 4: Wrapper tiers (transitional, C5)**

`SingleUnderlyingToken.sol`: add `import {AdminLib} from "./AdminLib.sol";` after the `MetaTokenBase` import; the
constructor becomes

```solidity
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
        MetaTokenBase(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
    {}
```

and `_init` calls `_initLegacyFeatures(false);` right after `_setRateConfig(cfg);`, with this function added after `_init`:

```solidity
    /// @dev Transitional (P1d replaces the wrapper tiers with `WrappedToken`): the rate admin and the guardian stay
    ///      in this contract's storage and are not `AdminLib` roles; the flags only report them, locked, with
    ///      `PAYABLE` on as built and no owner.
    function _initLegacyFeatures(bool wrapDisableable) internal {
        uint256 f = 1 << AdminLib.PAYABLE;
        if (rateAdjustable) f |= 1 << AdminLib.RATE_ADJUSTABLE;
        if (wrapDisableable) f |= 1 << AdminLib.WRAP_DISABLEABLE;
        AdminLib.Roles memory none;
        AdminLib.init(AdminLib.KIND_WRAPPED, f, f, address(0), none);
    }
```

`MultiUnderlyingToken.sol`: the constructor becomes

```solidity
    constructor(address factory_, address smartKeyAccountImpl_, bytes32 chainUid_, bool isHedera_)
        SingleUnderlyingToken(factory_, smartKeyAccountImpl_, chainUid_, isHedera_)
    {}
```

and in `_init` insert `_initLegacyFeatures(guardian_ != address(0));` directly before the `_addLeg` loop.

`src/hedera/HederaTokensV2.sol` — replace the whole file (the NORMAL child is gone; the signature override now lives
in `MetaTokenBase`):

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {SingleUnderlyingToken} from "../metatx/SingleUnderlyingToken.sol";
import {MultiUnderlyingToken} from "../metatx/MultiUnderlyingToken.sol";
import {HederaLib} from "./HederaLib.sol";

/// @title Transitional Hedera wrapper tiers (CTR-TOK-23): `IS_HEDERA = true` gives them HIP-632 signatures from
///        `MetaTokenBase`; what is left here is the fail-closed HTS check and association of every leg at init
///        (`HederaLib.checkAndAssociate`), which moves into `WrappedLib` with `WrappedToken` in P1d. Kind `NORMAL`
///        on Hedera is a `NormalToken` deployed with `isHedera_ = true`. No SmartKeyAccount on Hedera:
///        `SMART_KEY_ACCOUNT_IMPL = 0`, every contract wallet keeps the 50k ERC-1271 cap.
contract HederaSingleUnderlyingToken is SingleUnderlyingToken {
    constructor(address factory_, bytes32 chainUid_) SingleUnderlyingToken(factory_, address(0), chainUid_, true) {}

    function _checkUnderlying(address u) internal override {
        super._checkUnderlying(u);
        if (!HederaLib.checkAndAssociate(u)) revert UnderlyingInvalid(u);
    }
}

contract HederaMultiUnderlyingToken is MultiUnderlyingToken {
    constructor(address factory_, bytes32 chainUid_) MultiUnderlyingToken(factory_, address(0), chainUid_, true) {}

    function _checkUnderlying(address u) internal override {
        super._checkUnderlying(u);
        if (!HederaLib.checkAndAssociate(u)) revert UnderlyingInvalid(u);
    }
}
```

- [ ] **Step 5: Scripts** — `script/Deploy.s.sol`: `new NormalToken(address(f), subjectImpl, uid)` →
`new NormalToken(address(f), subjectImpl, uid, false)`. `script/hedera/DeployHedera.s.sol`: import
`{NormalToken} from "../../src/metatx/NormalToken.sol"` instead of `HederaNoUnderlyingToken`, and
`new HederaNoUnderlyingToken(address(f), uid)` → `new NormalToken(address(f), address(0), uid, true)`.
`forge build src` (capped) — Expected: success.

- [ ] **Step 6: Port the tests.** Rules:
  - every `new NormalToken/SingleUnderlyingToken/MultiUnderlyingToken(f, s, uid)` gains `, false`;
    `new HederaNoUnderlyingToken(f, uid)` → `new NormalToken(f, address(0), uid, true)`;
    `HederaHts.X` / `HederaSig` → `HederaLib.X`; imports from `HederaV2Lib.sol` → `HederaLib.sol`.
  - NORMAL init data `abi.encode(name, symbol, decimals, supply, minter)` → `abi.encode(NormalToken.NoneInit({…}))`
    with `features: PAYABLE | MINTABLE | BURNABLE` (= `7`, the built behaviour), `lockedFeatures: 0`,
    `owner: address(0)`, `roles.minter: <old minter>`, `initialSupply: <old supply>`, `initialHolder: <old creator>`.
    Put one helper `_noneInit(...)` in `V2Fixture` (and reuse it; tests outside V2Fixture may inline the struct).
  - `t.minter()` → `t.hasRole(1, x)`; `renounceMinter()` → `renounceRole(1)`; `NormalToken.NotMinter` →
    `AdminLib.MissingRole(1, caller)` (or `AdminLib.FeatureNotSet(1)` when the flag is off — "zero minter means fixed
    supply" becomes "no MINTABLE flag"); `MinterRenounced` → `AdminLib.RoleRevoked(1, minter, minter)`.
  - `Allowlist.t.sol` `test_refusedEverywhere`: `renounceMinter` → `renounceRole(uint8)`; keep `mint`.
  - Size tests: `FactoryV2.t.sol` `test_implementationSizes` ceilings Single **28,672**, Multi **29,696** (NORMAL stays
    ≤ 20,480); `HederaV2.t.sol` NORMAL ≤ 20,480, HederaSingle ≤ **29,696**, HederaMulti ≤ **30,720**; update the
    "measured" comments with the numbers `forge build --sizes` prints.
  - `Layout.t.sol`: regenerate the six pins → five (`HederaNoUnderlyingToken` is gone: drop its `_pin` line and file)
    with the `jq` loop from P1b (`{labels, slots, offsets}` of `.storageLayout.storage[]`);
    `test_reserveSlotIsWhereIndexersReadIt`: base `keccak256(abi.encode(uint256(0), uint256(6)))`, `_legCount` at
    slot 5 offset 0 (`uint256(vm.load(t, bytes32(uint256(5)))) & 0xff`). Expected Single slots
    `["0","1","2","3","4","5","6","7","8","9","9","9","9"]`.
  - `MsgSenderLint.t.sol`: add `src/metatx/AdminLib.sol` (expected 0) and `src/hedera/HederaLib.sol` (expected 0) to
    both pins; `MetaTokenBase` keeps 1 (`initialize`).
  - `TokenKat.t.sol` (C10): build the clone with the new init data; if the vectors no longer match, regenerate with
    `WRITE_KAT=true forge test --match-contract TokenKatTest` and record both new digests in the report.
  - Everything else keeps its assertions.

- [ ] **Step 7: Full suite** — Expected: 0 failed. Then the e2e deploy check (it deploys `NormalToken` with the
  linked libraries): `timeout 1800 scripts/capped bash -c 'cd scaas-node && CARGO_BUILD_JOBS=4 cargo test --test e2e -- --ignored 2>&1 | tail -15'`
  and the same for `e2e_hedera`. Expected: 4/4 and 1/1; if a prerequisite is missing, say so.

- [ ] **Step 8: Commit** — `git status --short` first; message `P1c: MetaTokenBase on AdminLib — PAYABLE gate, init/provenance in scaas.token, IS_HEDERA + HederaLib, NORMAL on MINTABLE/BURNABLE roles` + trailer.

---

### Task 3: Feature tests on kind NORMAL

**Model:** Sonnet, effort high (complete code below, run green in a scratch copy).

**Files:**
- Create: `smartcontracts/evm/test/v2/Features.t.sol`

**Interfaces:**
- Consumes: Task 2 (`NormalToken(f, s, uid, isHedera)`, `NoneInit`, the token admin functions), Task 1
  (`AdminLib` errors/events), `test/hedera/HederaMocks.sol` (`MockHederaAccountService`).

- [ ] **Step 1: Write `test/v2/Features.t.sol`**

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";

/// Kind NORMAL on the flags and the owner model (CTR-TOK-21, CTR-TOK-22) and the Hedera branch (CTR-TOK-23).
contract FeaturesTest is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant PK = 0xA11CE;
    address internal alice = vm.addr(PK);
    address internal ownerA = address(0x0A);
    address internal minter = address(0x111);
    address internal relayer = address(0xBEEF);
    address internal shop = address(0x5409);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;

    uint256 internal constant PAYABLE = 1 << 0;
    uint256 internal constant MINTABLE = 1 << 1;
    uint256 internal constant BURNABLE = 1 << 2;

    address internal impl;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        impl = address(new NormalToken(address(this), address(0), UID, false));
    }

    function _cfg(uint256 features, uint256 locked, address owner_, address minter_, uint256 supply)
        internal view returns (bytes memory)
    {
        AdminLib.Roles memory r;
        r.minter = minter_;
        return abi.encode(NormalToken.NoneInit({
            name: "Points", symbol: "PTS", decimals: 6, features: features, lockedFeatures: locked, owner: owner_,
            roles: r, initialSupply: supply, initialHolder: alice
        }));
    }

    function _token(address implementation, bytes memory cfg) internal returns (NormalToken t) {
        t = NormalToken(Clones.clone(implementation));
        t.initialize(address(this), new address[](0), 1, cfg);
    }

    function _sig(bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, d);
        return abi.encodePacked(r, s, v);
    }

    // ------------------------------------------------------------------ init, provenance

    function test_initWritesMetadataProvenanceAndFlags() public {
        NormalToken t = _token(impl, _cfg(PAYABLE | MINTABLE | BURNABLE, MINTABLE, ownerA, minter, 1_000));
        assertEq(t.name(), "Points");
        assertEq(t.symbol(), "PTS");
        assertEq(t.decimals(), 6);
        assertEq(t.kind(), 0);
        assertEq(t.creator(), address(this));
        assertEq(t.version(), 1);
        assertEq(t.features(), PAYABLE | MINTABLE | BURNABLE);
        assertEq(t.lockedFeatures(), PAYABLE | MINTABLE | BURNABLE);
        assertEq(t.owner(), ownerA);
        assertTrue(t.hasRole(1, minter));
        assertEq(t.balanceOf(alice), 1_000);
        assertFalse(t.IS_HEDERA());
    }

    function test_initRefusesFlagsOfAnotherKind() public {
        NormalToken t = NormalToken(Clones.clone(impl));
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureInvalidForKind.selector, uint8(3)));
        t.initialize(address(this), new address[](0), 1, _cfg(1 << 3, 0, address(0), address(0), 0));
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotBuilt.selector, uint8(7)));
        t.initialize(address(this), new address[](0), 1, _cfg(1 << 7, 0, address(0), address(0), 0));
    }

    // ------------------------------------------------------------------ MINTABLE, BURNABLE

    function test_mint_needsTheFlagAndTheRole() public {
        NormalToken t = _token(impl, _cfg(MINTABLE, 0, ownerA, minter, 0));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.MissingRole.selector, uint8(1), alice));
        t.mint(alice, 1);
        vm.prank(minter);
        t.mint(alice, 5);
        assertEq(t.balanceOf(alice), 5);
        vm.prank(ownerA);
        t.disableFeature(1);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotSet.selector, uint8(1)));
        t.mint(alice, 1);
    }

    function test_mint_withoutTheFlag_fixedSupply() public {
        NormalToken t = _token(impl, _cfg(0, 0, address(0), address(0), 7));
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotSet.selector, uint8(1)));
        t.mint(alice, 1);
        assertEq(t.totalSupply(), 7);
    }

    function test_burn_onlyWithBurnable_directAndGasless() public {
        NormalToken off = _token(impl, _cfg(0, 0, address(0), address(0), 100));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotSet.selector, uint8(2)));
        off.burn(1);
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: alice,
            data: abi.encodeCall(NormalToken.burn, (1)), batch: 1, nonce: 0, validUntil: block.timestamp + 300,
            mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
        bytes memory s = _sig(off.mtxDigest(m));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.FeatureNotSet.selector, uint8(2)));
        off.mtxExecute(m, s);
        NormalToken on = _token(impl, _cfg(BURNABLE, 0, address(0), address(0), 100));
        s = _sig(on.mtxDigest(m));
        vm.prank(relayer);
        on.mtxExecute(m, s);
        assertEq(on.balanceOf(alice), 99);
    }

    // ------------------------------------------------------------------ PAYABLE

    function test_payable_off_gatesThePayEntries_notMetaTransfer() public {
        NormalToken t = _token(impl, _cfg(0, 0, address(0), address(0), 100));
        bytes memory off = abi.encodeWithSelector(AdminLib.FeatureNotSet.selector, uint8(0));
        vm.prank(alice);
        vm.expectRevert(off);
        t.payWithFee(shop, 1, FeeMode.NONE, 0, address(0), bytes32("r"));
        bytes32 ref = keccak256("r");
        MetaTxLib.MetaTransfer memory x = MetaTxLib.MetaTransfer({from: alice, to: shop, value: 10, entryRef: ref,
            batch: t.payLane(ref), nonce: 0, validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0,
            feeRecipient: address(0)});
        bytes memory s = _sig(t.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(off);
        t.mtxPay(alice, shop, 10, ref, x.validUntil, RR, relayer, 0, address(0), s);
        vm.prank(relayer);
        vm.expectRevert(off);
        t.mtxPayReceiverFee(x, s, 1, address(0xFEE), block.timestamp, s);
        vm.prank(relayer);
        vm.expectEmit(address(t));
        emit IERC20Payment.PaymentSettled(alice, shop, 10, 0, relayer, ref); // a MetaTransfer payment is never gated
        t.mtxExecuteTransfer(x, s);
        assertEq(t.balanceOf(shop), 10);
    }

    function test_payable_on_payWithFeeWorks() public {
        NormalToken t = _token(impl, _cfg(PAYABLE, 0, address(0), address(0), 100));
        vm.prank(alice);
        t.payWithFee(shop, 10, FeeMode.NONE, 0, address(0), bytes32("r"));
        assertEq(t.balanceOf(shop), 10);
    }

    function test_supportsInterface_paymentOnlyWhenPayable() public {
        NormalToken off = _token(impl, _cfg(0, 0, address(0), address(0), 0));
        NormalToken on = _token(impl, _cfg(PAYABLE, 0, address(0), address(0), 0));
        bytes4[4] memory always = [type(IERC165).interfaceId, type(IERC20).interfaceId, type(IMetaTx).interfaceId,
            type(IERC20MetaTx).interfaceId];
        for (uint256 i; i < 4; ++i) {
            assertTrue(off.supportsInterface(always[i]));
            assertTrue(on.supportsInterface(always[i]));
        }
        assertFalse(off.supportsInterface(type(IERC20Payment).interfaceId));
        assertTrue(on.supportsInterface(type(IERC20Payment).interfaceId));
        assertFalse(on.supportsInterface(0xffffffff));
    }

    // ------------------------------------------------------------------ owner through the token

    function test_ownerAdministersThroughTheToken() public {
        NormalToken t = _token(impl, _cfg(MINTABLE, 0, ownerA, address(0), 0));
        vm.prank(ownerA);
        vm.expectEmit(address(t));
        emit AdminLib.RoleGranted(1, minter, ownerA);
        t.grantRole(1, minter);
        vm.prank(minter);
        t.mint(alice, 3);
        vm.prank(ownerA);
        t.transferOwnership(address(0x0B));
        vm.prank(address(0x0B));
        t.acceptOwnership();
        assertEq(t.owner(), address(0x0B));
        vm.prank(address(0x0B));
        t.renounceOwnership();
        assertEq(t.owner(), address(0));
        vm.prank(minter);
        t.mint(alice, 1);                                     // holders keep their role after the owner renounces
        vm.prank(minter);
        t.renounceRole(1);
        vm.prank(minter);
        vm.expectRevert(abi.encodeWithSelector(AdminLib.MissingRole.selector, uint8(1), minter));
        t.mint(alice, 1);
    }

    function test_adminFunctionsAreNeverSelfCalls() public {
        NormalToken t = _token(impl, _cfg(MINTABLE, 0, alice, address(0), 0));
        bytes4[7] memory sels = [t.grantRole.selector, t.revokeRole.selector, t.renounceRole.selector,
            t.disableFeature.selector, t.transferOwnership.selector, t.acceptOwnership.selector,
            t.renounceOwnership.selector];
        for (uint256 i; i < 7; ++i) {
            MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: alice,
                data: abi.encodeWithSelector(sels[i]), batch: i, nonce: 0, validUntil: block.timestamp + 300,
                mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
            bytes memory s = _sig(t.mtxDigest(m));
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, sels[i]));
            t.mtxExecute(m, s);
        }
    }

    /// AdminLib writes `scaas.token` only: the meta-tx lanes (`scaas.metatx`) and the ERC-20 slots stay put.
    function test_adminWritesDoNotTouchOtherNamespaces() public {
        NormalToken t = _token(impl, _cfg(MINTABLE, 0, ownerA, address(0), 100));
        bytes32 lane = keccak256(abi.encode(uint256(1), keccak256(abi.encode(alice,
            bytes32(0x06b01547c739946503c06c80685cc72ae2fec5074fd602f84cd2fa888722ac00)))));
        bytes32 bal = keccak256(abi.encode(alice, uint256(0)));
        vm.prank(alice);
        t.cancelNonce(1);
        bytes32 laneBefore = vm.load(address(t), lane);
        bytes32 balBefore = vm.load(address(t), bal);
        assertEq(uint256(laneBefore), 1);
        assertEq(uint256(balBefore), 100);
        vm.startPrank(ownerA);
        t.grantRole(1, minter);
        t.disableFeature(1);
        t.transferOwnership(minter);
        vm.stopPrank();
        assertEq(vm.load(address(t), lane), laneBefore);
        assertEq(vm.load(address(t), bal), balBefore);
        assertEq(t.balanceOf(alice), 100);
    }

    // ------------------------------------------------------------------ IS_HEDERA (CTR-TOK-23)

    function test_isHedera_takesTheHip632Path_onlyWhenSet() public {
        address has = address(0x16a);
        vm.etch(has, type(MockHederaAccountService).runtimeCode);
        uint256 edKey = 0xA11CE5;
        address native = address(uint160(1_234_567));
        MockHederaAccountService(has).setEdKey(native, vm.addr(edKey));
        address hImpl = address(new NormalToken(address(this), address(0), UID, true));
        AdminLib.Roles memory r;
        bytes memory cfg = abi.encode(NormalToken.NoneInit({name: "P", symbol: "P", decimals: 0, features: 0,
            lockedFeatures: 0, owner: address(0), roles: r, initialSupply: 100, initialHolder: native}));
        NormalToken h = _token(hImpl, cfg);
        NormalToken e = _token(impl, cfg);
        assertTrue(h.IS_HEDERA());
        MetaTxLib.MetaTransfer memory x = MetaTxLib.MetaTransfer({from: native, to: shop, value: 10, entryRef: 0,
            batch: 1, nonce: 0, validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0,
            feeRecipient: address(0)});
        (bytes32 rr, bytes32 vs) = vm.signCompact(edKey, h.mtxTransferDigest(x));
        vm.prank(relayer);
        h.mtxExecuteTransfer(x, abi.encodePacked(rr, vs));
        assertEq(h.balanceOf(shop), 10);
        (rr, vs) = vm.signCompact(edKey, e.mtxTransferDigest(x));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        e.mtxExecuteTransfer(x, abi.encodePacked(rr, vs));
    }
}
```

- [ ] **Step 2: Run** — Expected: 12 passed. Full suite: 0 failed.

- [ ] **Step 3: Commit** — message `P1c: kind NORMAL feature tests — flags, owner, PAYABLE gate, ERC-165, IS_HEDERA, namespace isolation` + trailer.

---

### Task 4: Docs, size gate, TODO and HANDOFF

**Model:** Sonnet, effort medium.

**Files:**
- Modify: `docs/contracts/token-wrappers.md` — CTR-TOK-22 "Transitional (BUILT)" paragraph (owner model and flags
  built on kind NORMAL through `AdminLib`; regulated flags refused `FeatureNotBuilt` until the asset suite (C2); wrapper
  tiers report legacy powers (C5)); CTR-TOK-23 Transitional (NORMAL child gone; `IS_HEDERA` built; Hedera wrapper children
  remain until P1d); CTR-TOK-24 (the `AdminLib`/`HederaLib` rows as built, no external `PayLib` (C3), the measured
  sizes and C9); §8 storage table (C8 and the `scaas.token` namespace); §7 Interfaces rows for `NormalToken`
  (no `MinterRenounced`/`NotMinter`; `AdminLib` events/errors) and Hedera children. Net ≤ 0 lines (budget warning).
- Modify: `docs/contracts/metatx.md` §16 "P1b (BUILT)" bullet → add P1c (features/roles/`PAYABLE` gate built on NORMAL).
- Modify: `docs/contracts/asset-suite.md` CTR-AS-17 neighbourhood: one sentence "Transitional (BUILT): the flags exist,
  `initialize` refuses 5–8 with `FeatureNotBuilt` until this stream builds the controls" (only if no such note exists).
- Modify: `TODO.md` (§00 P1 line: P1c done with its merge; P1c notes (a)–(e) dispositions: (a) no `_update`
  refusal added in P1c — carry to the asset-suite stream; (b) unchanged; (c) unchanged, moot after P1d; (d) done;
  (e) open test gaps listed; new "P2 notes" bullet with C9), `HANDOFF.md` (top section "Session 2026-10-10 (P1c)":
  state, what was built, rulings C1/C2/C3/C9 for the owner, sizes, next = P1d plan).

- [ ] **Step 1: Size gate**

```bash
timeout 900 scripts/capped bash -c 'cd smartcontracts/evm && forge build --sizes --json 2>/dev/null' > /tmp/p1c-sizes.json || true
jq -r 'to_entries[] | select(.value.runtime_size > 24576) | "\(.key) \(.value.runtime_size)"' /tmp/p1c-sizes.json
jq -r 'to_entries[] | select(.key | test("NormalToken|AdminLib|HederaLib")) | "\(.key) \(.value.runtime_size)"' /tmp/p1c-sizes.json
```

Expected over 24,576: exactly `ZetherToken`, `SingleUnderlyingToken`, `MultiUnderlyingToken`,
`HederaSingleUnderlyingToken`, `HederaMultiUnderlyingToken`; `NormalToken` ≤ 20,480. Anything else: stop, report.

- [ ] **Step 2: Docs edits**, then `python3 scripts/docs_check.py check`, `… facts check`,
  `python3 scripts/test_docs_check.py` — 0 errors (budget warnings may stay; `token-wrappers.md` must not grow).
  Old-style ids (`C1`, `R3`) are refused in component docs by the checker: write "controller ruling, pending the owner".

- [ ] **Step 3: Full suite** — record the count.

- [ ] **Step 4: Commit** — message `P1c: docs, TODO and HANDOFF after the owner model landed` + trailer.

---

### Final

- Whole-branch review (Opus, effort xhigh); one fix wave if needed; scoped re-review.
- Merge `p1c-metatokenbase` into `main` with `--no-ff`; do not push; remove the worktree.
