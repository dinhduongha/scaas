# Token kinds, wrappers and the open factory

SCaaS tokens are created by anyone through an open factory as immutable EIP-1167 clones of versioned
implementations. There are two axes: the **kind** is code (a standalone token, or a wrapper of 1–8 ERC-20s or the native coin ([CTR-TOK-26](#CTR-TOK-26)) at
conversion rates, each with or without the Zether layer) and the **features** are flags chosen at creation. Every
token carries the meta-transaction layer of [metatx.md](metatx.md). Status: the tree, kinds, features, libraries and
the `createToken` factory **SPECIFIED** (accepted 2026-10-08, implemented in phase P1; what is built today is under
[Transitional (BUILT)](#transitional-built-tokens)); node and client support **SPECIFIED**; the regulated controls
as flags ([asset-suite.md](asset-suite.md)) **SPECIFIED**.

**Contents**

1. [Overview](#1-overview)
2. [Kinds](#2-kinds)
   - 2.1 [NORMAL — `NormalToken`](#21-normal--normaltoken)
   - 2.2 [WRAPPED — `WrappedToken` (1–8 legs)](#22-wrapped--wrappedtoken-18-legs)
3. [Rates](#rates)
4. [Features](#4-features)
5. [Allowance lockdown](#5-allowance-lockdown)
6. [Factory](#factory)
   - 6.1 [`OpenFactory`](#61-openfactory)
   - 6.2 [Transitional (BUILT)](#62-transitional-built)
7. [Interfaces](#interfaces)
8. [Storage layout (clones)](#8-storage-layout-clones)
9. [Gas](#9-gas)
10. [Hedera](#10-hedera)
11. [No migration](#11-no-migration)
12. [Conformance](#conformance)
13. [Limitations](#13-limitations)

## 1. Overview

```mermaid
classDiagram
    MetaTxBase <|-- ERC20MetaTx
    ERC20MetaTx <|-- MetaTokenBase
    MetaTokenBase <|-- NormalToken
    MetaTokenBase <|-- WrappedToken
    MetaTokenBase <|-- NormalZetherToken
    MetaTokenBase <|-- WrappedZetherToken
    class MetaTxBase {
        <<abstract>>
        MetaTransaction, nonce lanes, SigCheck
        transient sender + ticket, selector allowlist
        mtxExecute, mtxBatch, cancelNonce
    }
    class ERC20MetaTx {
        <<abstract>>
        ERC-20, MetaTransfer (entryRef), fee
        receiver-pays, approve only by contracts, UA ledger
    }
    class MetaTokenBase {
        <<abstract>>
        trade (TradeLib), pay behind PAYABLE (inline, no external PayLib built)
        features + roles (AdminLib)
        init, provenance (factory, implementation, kind, version, IS_HEDERA)
    }
    class NormalToken { kind NORMAL }
    class WrappedToken { kind WRAPPED, 1-8 legs (WrappedLib) }
    class NormalZetherToken { kind NORMAL_ZETHER, ZetherLayer + ZetherLib }
    class WrappedZetherToken { kind WRAPPED_ZETHER, ZetherLayer, wrap-shield and unshield-unwrap }
```

<a id="CTR-TOK-21"></a>**CTR-TOK-21** — **One implementation per kind; features are flags
([CTR-TOK-22](#CTR-TOK-22)).** The tree is `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → the kinds below. Two axes:
the **kind** is code (one implementation per large combination, so each implementation's audit surface is only what it
holds); the **features** are flags chosen at creation. Heavy logic lives in external libraries linked at deploy
([CTR-TOK-24](#CTR-TOK-24)). Every EVM token can trade (`TradeOrder`, in the base); pay is the flag `PAYABLE`. Hedera
is a per-chain variant, not a creator's choice ([CTR-TOK-23](#CTR-TOK-23)).

| Kind | Contract | Meaning |
|---|---|---|
| `NORMAL` | `NormalToken` | standalone: loyalty, internal units, access tokens |
| `WRAPPED` | `WrappedToken` | wrapper of 1–8 ERC-20s or the native coin ([CTR-TOK-26](#CTR-TOK-26)) at per-leg rates |
| `NORMAL_ZETHER` | `NormalZetherToken` | standalone + Zether layer ([zether.md](zether.md)) |
| `WRAPPED_ZETHER` | `WrappedZetherToken` | wrapper + Zether layer, wrap-shield and unshield-unwrap |
| `NORMAL_PQZ` | `NormalPqzToken` | standalone + post-quantum layer ([pq-zero-knowledge.md](pq-zero-knowledge.md)) |
| `WRAPPED_PQZ` | `WrappedPqzToken` | wrapper + post-quantum layer |

There are four confidential-layer kinds and no combined kind: `NORMAL_ZETHER_PQZ` and `WRAPPED_ZETHER_PQZ` (ids 6 and 7)
were dropped (owner 2026-10-20, plan 5h D21; the ids are not reused, and the factory's ABI decoder rejects them). Both
layers expose one `mtx*` interface (`IConfidentialToken`, [CTR-ZTH-45](zether.md#CTR-ZTH-45)), so a combined token needs
no layer argument. Both layers keep shielded value in the `SHIELD_POOL` sentinel instead of burning it
([CTR-PQZ-15](pq-zero-knowledge.md#CTR-PQZ-15), [CTR-ZTH-51](zether.md#CTR-ZTH-51)); `SHIELD_POOL` is a token-level
address like `UA_POOL`, not payable and unable to spend.

| Node | Role |
|---|---|
| `MetaTxBase` | any SCaaS contract (`MandateWallet`, `SmartKeyAccount`, third parties): [CTR-MTX-22](metatx.md#CTR-MTX-22) |
| `ERC20MetaTx` | every token is gasless ([CTR-MTX-07](metatx.md#CTR-MTX-07)); UA ledger, `UAMetaTransaction` ([CTR-UA-18](accounts.md#CTR-UA-18)) |
| `MetaTokenBase` | `TradeLib`, pay behind `PAYABLE` (no external `PayLib` built: pay is inline, controller ruling pending the owner), `AdminLib`, init, provenance |
| Zether verifiers (one per curve), the UA registry `UARegistry`, `ZetherDisclosure`, `ZetherStatements`, `OpenFactory` | outside the tokens; roles unchanged |

Confidential tokens are kinds of the same tree, not a parallel branch: every one is relayable through the same
envelope ([CTR-PQZ-15](pq-zero-knowledge.md#CTR-PQZ-15)). Non-EVM families implement the same roles natively.

The `MetaTransaction` struct, its typehash and the digest rule are one for every kind; only the domain's
`verifyingContract` differs per clone. Not covered: baskets (proportional, weighted multi-asset redemption), oracle
rates, rebasing/share wrappers (ERC-4626 style).

## 2. Kinds

The kinds are in [CTR-TOK-21](#CTR-TOK-21). The two public kinds without a Zether layer:

| Kind | Contract | `underlyings` | Supply rule | Invariant |
|---|---|---|---|---|
| `NORMAL` | `NormalToken` | none | `initialSupply` minted to `initialHolder` at init; `mint` by `minter` only with `MINTABLE`; holder `burn` with `BURNABLE` ([CTR-TOK-22](#CTR-TOK-22)) | `Σ balances == totalSupply` |
| `WRAPPED` | `WrappedToken` | 1–8 ERC-20s or the native coin ([CTR-TOK-26](#CTR-TOK-26)), fixed at creation | Only via `wrap` (mints `⌊received·num/den⌋` of the **measured** delta) / `unwrap` (pays `⌊w·den/num⌋`, burns `⌈out·num/den⌉`) on a chosen leg at that leg's rate; `num = den = 1` is the 1:1 case | `Σ_i⌊reserve_i·num_i/den_i⌋ ≥ totalSupply` with internal per-leg `reserve` (pooled; no per-leg invariant) |

Example (owner requirement): a wrapper over USDT and DAI at 1 → 25,000, i.e. one stablecoin mints 25,000 units of a
low-value currency token — an `WrappedToken` with two legs and one rate per leg (`num/den` adjusted for each leg's decimals); one leg at a rate is the one-leg case.

`initData` per kind below. Fee-on-transfer underlyings are measured on the way in and must
transfer exactly on the way out; rebasing underlyings are unsupported (a negative rebase stops wrap, exits stay
first-come); the confidential kinds use the same `WrappedLib` (built, P3; the old `ZetherToken` refused fee-on-transfer
with `UnsupportedUnderlying`, [CTR-ZTH-14](zether.md#CTR-ZTH-14), [CTR-TOK-11](#CTR-TOK-11)). Weighted baskets are not planned.

### 2.1 NORMAL — `NormalToken`

<a id="CTR-TOK-09"></a>**CTR-TOK-09** — `NormalToken` (kind `NORMAL`) mints `initialSupply` to `initialHolder` at
init (`NORMAL*` kinds only; with `initialSupply == 0` nothing is minted and `initialHolder` is ignored). Further supply and burning are features, not class: `mint` by the `minter` with `MINTABLE`
(`minter == 0` and no flag ⇒ fixed supply), holder `burn` with `BURNABLE`, and the role and its lifecycle are in
[CTR-TOK-22](#CTR-TOK-22). (Built: the holder's `renounceRole(MINTABLE)`.)

`underlyings.length == 0`. The creation parameters are the `TokenConfig` fields of [CTR-TOK-25](#CTR-TOK-25)
(`name`, `symbol`, `decimals`, `features`, `lockedFeatures`, `owner`, `roles`, `initialSupply`, `initialHolder`).

| Function | Rule |
|---|---|
| `initialize` | mints `initialSupply` to `initialHolder`; validates the flags ([CTR-TOK-22](#CTR-TOK-22)) |
| `mint(to, amount)` | `FeatureNotSet(MINTABLE)` when the flag is clear, `MissingRole(MINTABLE, caller)` when the caller (read through `_msgSender()`) lacks the role (not allowlisted: the minter acts through its own contract); to a public balance only |
| `burn(amount)` | `BURNABLE`; any holder, own public balance (`_msgSender()`; gasless through `mtxExecute`); `Transfer(from, 0, amount)` |

Invariant: `Σ balances == totalSupply`. A supply cap or mint-rate limit, if an issuer wants one, belongs in the
minter contract it controls, not in this kind.

### 2.2 WRAPPED — `WrappedToken` (1–8 legs)

`WrappedToken` (kind `WRAPPED`) takes 1–8 legs at creation; a one-leg token is what the earlier design called a
single-underlying wrapper and a multi-leg token a multi-underlying wrapper, so there are no separate single/multi
kind labels: the leg count says it. The single-asset convenience ABI (`wrap(amount)`, `unwrap(amount, recipient[,
minOut])`) works **only** with exactly one leg (`UnderlyingRequired()` otherwise); the per-leg ABI works for every
count. Everything below until the multi-leg subsection holds per leg, and for a one-leg token as it stands.

A one-leg token: `underlyings.length == 1`. Creation parameters are the `TokenConfig` fields `legs` and `rate` of
[CTR-TOK-25](#CTR-TOK-25); the rate role and the flags are in [CTR-TOK-22](#CTR-TOK-22).

Checks (all revert at init, so a bad token is never born):

| Check | Error |
|---|---|
| underlying `≠ address(this)`, and is a contract (code, not an EIP-7702 designator: `SigCheck.isContract`, owner ruling D5, 2026-10-30), or is `address(0)` = the native coin ([CTR-TOK-26](#CTR-TOK-26)) | `UnderlyingInvalid(u)` |
| `decimals()` returns a `uint8` (staticcall); not checked for the native leg (18) | `DecimalsUnreadable(u)` |
| `1 ≤ num, den < 2^96` | `RateInvalid(num, den)` |
| rates fixed ⇒ no rate role | `RoleWithoutFeature(3)` (from `AdminLib.init`) |
| rates fixed ⇒ `rateDelay == 0 && maxRateStepBps == 0`; adjustable ⇒ `2 days ≤ rateDelay ≤ 30 days`, `1 ≤ maxRateStepBps ≤ 1000` | `RateConfigInvalid()` |
| rates adjustable ⇒ the rate role is a contract (the `_isContract` of the allowance lockdown) | `RoleNotContract(3, a)` |

Client defaults (UI and ERP wizard): `decimals = d_u`, `num = den = 1` (a plain 1:1 wrapper), rates fixed; when the
issuer makes them adjustable: `rateDelay = 7 days`, `maxRateStepBps = 100`. Role and its lifecycle:
[CTR-TOK-22](#CTR-TOK-22).

**Transitional (BUILT, P1e; 5g-Z2).** Built: `initialize(creator, version, abi.encode(TokenConfig))` ([CTR-TOK-25](#CTR-TOK-25)); the token checks its legs (`UnderlyingCountInvalid(n)`) and the factory indexes the token's `underlyings()`; `rate` is zero without `RATE_ADJUSTABLE`, in bounds with it.

```
wrap(uint256 amount) returns (uint256 minted)                  // sender = _msgSender() (the signer under mtxExecute)
    require leg.wrapEnabled                                    // always true for one leg
    require leg.adjustable ⇒ no pending rate change            // WrapPausedForRateChange (leg slot a)
    before = U.balanceOf(this)
    require before ≥ reserve                                   // ReserveShortfall (one balanceOf serves both)
    U.safeTransferFrom(sender, this, amount); received = U.balanceOf(this) − before
    minted = mulDiv(received, num, den)                        // floor
    require minted > 0                                         // WrapTooSmall
    reserve += received; _mint(sender, minted); emit Wrapped(sender, U, received, minted)

unwrap(uint256 wrapped, address recipient) returns (uint256 out)                    // minOut = 0; direct calls only
unwrap(uint256 wrapped, address recipient, uint256 minOut) returns (uint256 out)
    require recipient ∉ {0, address(this), UA_POOL, SHIELD_POOL}  // UnwrapRecipientInvalid (SHIELD_POOL: review C5-4)
    require U ≠ NATIVE or recipient is not an EIP-7702 designator  // UnwrapRecipientInvalid (owner ruling D4, 2026-10-30:
                                                               //   no native coin into a delegate's code; also the
                                                               //   Zether / PQZ unshield-unwrap; an ERC-20 leg may pay
                                                               //   a designator: a plain ERC-20 runs no recipient code,
                                                               //   an outside token with ERC-777 / ERC-1363 hooks may,
                                                               //   but the unwrapper chose the recipient)
    out    = mulDiv(wrapped, den, num)                         // floor
    require out > 0                                            // UnwrapTooSmall
    require out ≥ minOut                                       // UnwrapBelowMin(out, minOut)
    require out ≤ reserve                                      // InsufficientReserve(U, out, reserve) (Multi only;
                                                               //   a one-leg token cannot hit it: w ≤ S ≤ ⌊R·q⌋)
    burned = mulDiv(out, num, den, Ceil)                       // ≤ wrapped
    _burn(sender, burned); reserve −= out
    before = U.balanceOf(this); U.safeTransfer(recipient, out)
    require before − U.balanceOf(this) == out                  // UnderlyingTransferMismatch
    emit Unwrapped(sender, U, recipient, burned, out)

addReserve(address u, uint256 amount)                          // anyone; no mint
    same measured pull as wrap, require leg.wrapEnabled and no shortfall; reserve += received; emit ReserveAdded
```

`mulDiv` is OpenZeppelin `Math.mulDiv` (512-bit intermediate). `addReserve` exists so an issuer can
over-collateralise before a rate change that needs it; otherwise it is a donation that raises every holder's backing.
The gasless forms are `mtxExecute` with this calldata ([CTR-MTX-12](metatx.md#CTR-MTX-12),
[CTR-MTX-19](metatx.md#CTR-MTX-19)); a holder of a SCaaS underlying wraps by signature ([CTR-TOK-20](#CTR-TOK-20)).

Why the invariant holds, per operation, with `C = Σ⌊reserve·num/den⌋`:

- wrap: `⌊(R+r)·q⌋ ≥ ⌊R·q⌋ + ⌊r·q⌋ = ⌊R·q⌋ + minted` (floor is superadditive), supply rises by `minted`.
- unwrap: `out·q ≤ burned` (ceil), so `(R−out)·q ≥ R·q − burned` and `⌊(R−out)·q⌋ ≥ ⌊R·q⌋ − burned` (`burned` is an
  integer); supply falls by `burned`.
- `addReserve`: `C` rises, supply unchanged. Transfers, meta-tx and fees: supply unchanged.
- rate change: see [rates](#rates).

The plain `underlying.balanceOf(this)` is **not** used for pricing anything; donations sent with a plain transfer are
outside `reserve` and stay locked (no sweep: no owner).

Views: `underlying()` (a one-leg token: the single underlying), `underlyings() returns (address[])`, `legOf(address u) returns
(uint96 num, uint96 den, uint256 reserve, uint8 decimals, bool wrapEnabled)`, `collateralValue()` (saturates at
`type(uint256).max` instead of overflowing), `previewWrap(u, amount) returns (minted, used)`,
`previewUnwrap(u, wrapped) returns (out, burned)`, `rateAdjustable()`, `rateDelay()`,
`maxRateStepBps()`, `pendingRate() returns (address u, uint96 num, uint96 den, uint64 eta)` (all zero when nothing is
pending or the pending change has expired). Previews ignore fee-on-transfer (they assume `received == amount`).

<a id="CTR-TOK-26"></a>**CTR-TOK-26** — **A leg of every `WRAPPED*` kind may be the chain's native coin** (owner), wrapped like WETH or WXDAI, because some chains have
no standard wrapped native token. `underlying = address(0)` in a `Leg` is the native coin; the per-leg rules above and
[CTR-TOK-05](#CTR-TOK-05) hold, with these differences:

- **Wrap** for the native leg is `payable` and takes `msg.value`, which must equal `amount`; a non-native leg refuses
  `msg.value != 0`. A native wrap cannot be gasless (the caller sends the value); gasless unwrap and every other path
  are unchanged.
- **Unwrap** pays the native coin with checks-effects-interactions (burn and `reserve -= out` before the send) under
  the token's reentrancy guard, to a recipient that may be a contract (no gas-stipend limit); a recipient that fails to
  receive reverts the unwrap.
- **Balance mechanics of [CTR-TOK-05](#CTR-TOK-05)** read `address(this).balance` for the native leg: `ReserveShortfall`
  (`balance ≥ reserve`), `UnderlyingTransferMismatch`, the `balance_i ≥ reserve_i` check in `executeRate` and the
  invariant. This is safe because forced coin only raises the balance, and minting stays bounded by the internal
  `reserve`. The measured delta of a native wrap is `msg.value`; `addReserve` for the native leg is `payable` with
  `msg.value == amount`.
- **`mtxWrap(address underlying, …)` with `address(0)` reverts** (`NativeNotGasless()`): a signature cannot carry value.
- **At most one native leg** per token; its rate math uses 18 decimals (Hedera: 8, the tinybar).
- **Reserve** is internal ([CTR-TOK-05](#CTR-TOK-05)): `collateralValue()` counts the internal `reserve_i` for the native leg, never
  the raw balance; coins forced in by `selfdestruct` or as a block reward are not reserve.
- **Provenance:** the factory's index ([CTR-TOK-25](#CTR-TOK-25), [CTR-TOK-17](#CTR-TOK-17)) records `address(0)` as the
  native underlying; `underlying()` of a one-leg native token therefore returns `address(0)` too, and clients read
  `underlyings()`. Libraries and size budget: [CTR-TOK-24](#CTR-TOK-24).

**Transitional (BUILT, P1d).** The native leg is built, with `NativeValueMismatch(value, expected)` for `msg.value ≠ amount` (and `≠ 0` on an ERC-20 leg), 8 decimals on Hedera; `mtxWrap` and `NativeNotGasless` followed in P2a (CTR-TOK-20); `mtxExecute(wrap(…))` on a native leg still reverts `NativeValueMismatch(0, amount)` (tested in `NativeLeg.t`).

#### 2.2.1 More than one leg

<a id="multi"></a>

<a id="CTR-TOK-07"></a>**CTR-TOK-07** — A token with more than one leg is **any-of**: the underlying set (≤ 8, no duplicates) and
each leg's initial rate are set at creation and never added to or removed (rates themselves may be adjustable,
[CTR-TOK-13](#CTR-TOK-13)); a user wraps one chosen underlying and unwraps into one chosen underlying, bounded by that
leg's reserve (`InsufficientReserve`). The `guardian` (role of the `WRAP_DISABLEABLE` flag, [CTR-TOK-22](#CTR-TOK-22); granted by the owner, may be an EOA) has exactly one power:
`disableWrap(underlying, reason)` — one-way; unwrap from a disabled leg stays open. A disabled leg refuses
`addReserve`, and no rate change that lowers `collateralValue()` executes while any leg is disabled. A re-enable power
would let a compromised guardian reopen a depegged inflow and drain the good legs.

Init: `1 ≤ underlyings.length ≤ 8` (`UnderlyingCountInvalid(n)`), each checked as for one leg, no duplicates
(`DuplicateUnderlying(u)`). The guardian may be any address — its only power stops inflow, so an on-call key is acceptable and speed
matters in a depeg; role and lifecycle: [CTR-TOK-22](#CTR-TOK-22). The leg order is the factory's `underlyings` order and never changes.

| Function | Rule |
|---|---|
| `wrap(address u, uint256 amount) returns (uint256 minted)` | one-leg wrap on leg `u`; `UnknownUnderlying(u)`, `WrapDisabledFor(u)`, `WrapPausedForRateChange(u)` while any change is pending |
| `unwrap(address u, uint256 wrapped, address recipient, uint256 minOut) returns (uint256 out, uint256 burned)` | one-leg unwrap on leg `u`, bounded by `reserve_u` and `minOut`; works on disabled legs and during a pending change |
| `addReserve(address u, uint256 amount)` | as for one leg; refused on disabled legs |
| `disableWrap(address u, bytes32 reason)` | guardian; one-way; `WrapDisabled(u, guardian, reason)`; second call reverts `WrapDisabledFor(u)` |
| `wrap(uint256)`, `unwrap(uint256,address)`, `unwrap(uint256,address,uint256)` (single-asset ABI) | revert `UnderlyingRequired()` unless exactly one leg |
| `underlying()` | returns `address(0)` with more than one leg; clients use `underlyings()` |
| rate functions | as for one leg with the leg named in `proposeRate` (default fixed; adjustable per [CTR-TOK-13](#CTR-TOK-13)); one pending change per token; admin-only execution; `RateDecreaseWithDisabledLeg()` if a change lowers `C` while any leg is disabled |
| gasless unwrap (`mtxExecute`) | with the leg chosen by the signer; works on disabled legs |

**Transitional (BUILT, P1d).** One `WrappedToken` takes 1–8 legs with the encoding of §2.2; the guardian is optional at init.
`renounceRole(bit)` replaces `renounceGuardian()`/`renounceRateAdmin()` (`RoleNotContract(3, a)` for a non-contract rate role); `rateAdmin()` and `guardian()` are gone (several holders: `hasRole`, `RoleGranted`/`RoleRevoked`).

Invariant and solvency: `C = Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()` is the aggregate invariant; the one-leg
per-operation argument holds leg by leg. There is **no** per-leg invariant: the backing is pooled and redemption is
any-of.

**Depeg risk (disclosure text for issuers and holders).** At fixed nominal rates the token treats its underlyings as
equal. When one depegs (say USDT trades at 0.95 while the rate says 1:1), anyone can wrap the cheap asset and unwrap
a good one: the good reserves drain first and the remaining holders end up backed by the weakest asset. This is the
expected behaviour of an any-of wrapper, not a bug.

- The guardian's `disableWrap` stops new inflow of the depegged asset; it does **not** stop the exit into good legs
  (that would trap holders) and cannot restore drained legs.
- Holders carry the risk of the worst underlying in the set. More than that: **each leg's admin key can take the
  whole basket.** An upgradeable or compromised underlying that fakes a `transferFrom`/`balanceOf` delta mints
  without limit and drains every good leg in one transaction, before any guardian can react. Plus each underlying
  issuer's freeze power. The reserve composition is public (`legOf`) and the node/ERP should alert on composition
  drift.
- Issuers should list only assets they would accept at par, keep a guardian on call, and expect the composition to
  move toward the cheapest leg during stress. `disableWrap` can be front-run like any transaction, so the guardian
  should submit it privately (a private relay or a builder bundle).
- No re-enable: a mistaken disable is permanent for that leg. Holders lose nothing by it; the issuer creates a new
  token if the leg must come back.
- <a id="CTR-TOK-19"></a>**CTR-TOK-19** — **A shortfall on one leg does not stop wrapping into the others** (owner
  decision 2026-10-06; the reserve rule of [CTR-TOK-05](#CTR-TOK-05) is per leg).
  `wrap(A)` checks only leg A's `balanceOf ≥ reserve`. If leg B loses backing (a blacklist burn, a negative rebase, a
  confiscation), new deposits into A still mint at par into a pool that is now under-backed, and early exiters
  through A take the good assets those deposits brought. `disableWrap(B)` does not prevent this. The node/ERP should
  alert when any leg's `balanceOf < reserve` and the issuer should pause intake by communication; a wallet that shows
  a multi-underlying token should show the per-leg backing before a wrap. (Checking every leg on a multi `wrap` and
  `addReserve` — at most 8 `balanceOf`, as `executeRate` already does — was considered and not adopted.)

## <a id="rates"></a>3. Rates

<a id="CTR-TOK-04"></a>**CTR-TOK-04** — A conversion rate is `(num, den)`, `uint96` each, `1 ≤ num, den < 2^96`,
meaning **wrapped raw units per underlying raw unit**. Every output rounds **down** (in the contract's favour):
`minted = ⌊in·num/den⌋`, `out = ⌊w·den/num⌋`, and unwrap burns only `⌈out·num/den⌉ ≤ w` (the holder keeps the dust).
Zero output reverts (`WrapTooSmall`, `UnwrapTooSmall`). Wrap dust (the part of `in` that mints less than one wrapped
unit, i.e. less than `⌈den/num⌉` raw underlying) stays in the reserve; `previewWrap` returns `(minted, used =
⌈minted·den/num⌉)` and clients round `in` down to `used`. Dust is lost to the reserve instead of to the holder, never
to a third party.

`q = num/den` = wrapped raw units per underlying raw unit. Raising `q` means each wrapped unit redeems for **less**
underlying; lowering `q` means each wrapped unit redeems for **more**.

<a id="CTR-TOK-05"></a>**CTR-TOK-05** — Reserve accounting is internal: `reserve_i` changes only through `wrap`,
`unwrap`, `addReserve` (on `WRAPPED_ZETHER` also `mtxWrapShield` / `mtxUnshieldUnwrap`, no `Wrapped` /
`Unwrapped`). The solvency invariant is **`collateralValue() := Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()`** (`+
totalShielded·shieldScale`, [CTR-ZTH-44](zether.md#CTR-ZTH-44)), plus `underlying_i.balanceOf(this) ≥ reserve_i` while
the underlying behaves. Wrap mints the **measured** balance delta; unwrap requires the balance to drop by exactly `out`
(`UnderlyingTransferMismatch`); wrap and `addReserve` refuse while `balanceOf < reserve_i` (`ReserveShortfall`); unwrap
never checks that, so exits stay open. Internal accounting keeps donations and rebases from moving the price.

<a id="CTR-TOK-06"></a>**CTR-TOK-06** — **Rate mode is the issuer's choice at creation:** `fixed` (default; no setter
exists) or `adjustable`. Adjustable: a `rateAdmin` that **has code** (the same `_isContract` as the allowance
lockdown; meant to be a multisig or timelock, which the contract cannot prove); propose → wait `rateDelay` (default
7 days, bounds [2 days, 30 days]) → **only the `rateAdmin` executes**, within a 7-day window (no third party can bundle
the execution with its own wraps); **one pending change per token**, and while it is pending **wrap is paused on
every leg** (unwrap stays open); each step ≤ `maxRateStepBps` (default 100 = 1 %, bounds [1, 1 000]); every execution
requires `balanceOf_i ≥ reserve_i` on every leg and `collateralValue() ≥ totalSupply()` afterwards; balances never
change (no rebase). The rate role is granted and revoked by the owner and may be renounced by its holder; revoking or renouncing it leaves
the rate as it is, and only `disableFeature(RATE_ADJUSTABLE)` fixes the rate and cancels a pending change
([CTR-TOK-22](#CTR-TOK-22)). Delay and step are set once; the rate role is granted by the owner ([CTR-TOK-22](#CTR-TOK-22)). A holder who disagrees has at least `rateDelay` to unwrap at the old
rate, bound by `minOut`, and loses at most one step per delay.

One pending change per token (`PendingRate` in one slot). A change is **pending** from `proposeRate` until it is
executed, cancelled (also by `disableFeature(RATE_ADJUSTABLE)`; `renounceRole` leaves it), or its window (`eta + 7 days`) has passed; an expired change
counts as no change everywhere (`proposeRate`, `pendingRate()`, the wrap pause).

```
proposeRate(address u, uint96 num, uint96 den)   // rateAdmin; nothing pending (RateChangePending); RateInvalid;
                                                  //   step bound against the current rate (RateStepTooLarge)
    eta = now + rateDelay; emit RateChangeProposed(u, oldNum, oldDen, num, den, eta)
cancelRate()                                      // rateAdmin; emit RateChangeCancelled(u)
executeRate()                                     // rateAdmin only; eta ≤ now ≤ eta + 7 days
                                                  //   (RateChangeNotReady / RateChangeExpired)
    every leg: U_i.balanceOf(this) ≥ reserve_i    // ReserveShortfall(u_i, balance, reserve) — no phantom reserve
    C' with the new rate, summed with early exit once ≥ totalSupply
    require C' ≥ totalSupply                       // RateChangeUndercollateralized(C', supply)
    Multi: a change that lowers C' while any leg is disabled ⇒ RateDecreaseWithDisabledLeg
    apply; delete pending; emit RateChanged(u, oldNum, oldDen, num, den)
renounceRole(3)                                   // a holder gives up the role; the rate and a pending change stay
```

While a change is pending, `wrap` reverts `WrapPausedForRateChange(u)` **on every leg** of the token; unwrap (direct
and gasless, both with `minOut`) and `addReserve` stay open. The step bound is checked once, at proposal: the
current rate cannot change while a change is pending. Step bound, exact in integers (`uint96` inputs keep every
product below 2^207):

```
|num'·den − num·den'| · 10_000 ≤ num·den' · maxRateStepBps          // RateStepTooLarge
```

Fixed-rate tokens have no pending storage in use and every function above reverts `RateFixed()`.

| Direction | Effect on holders | Solvency | Control |
|---|---|---|---|
| Raise `q` | Redemption value of every outstanding unit falls by ≤ one step (dilution). New wrappers get more units per underlying. | `C` rises: always solvent. The extra backing stays in the reserve; nobody can withdraw it. | Timelock: every holder sees `RateChangeProposed` and can unwrap at the old rate for `rateDelay`, bound by `minOut`. |
| Lower `q` | Redemption value rises. | `C` falls: could go below `totalSupply` (insolvency = a run where the last holders get nothing). | `executeRate` refuses phantom reserve and reverts `RateChangeUndercollateralized(C', supply)` unless `C' ≥ totalSupply`. The issuer funds it first with `addReserve`. |

Consequences, stated for issuers and holders:

1. A fixed-rate token has no admin and its redemption price never moves. This is the default and the only form the
   catalogue templates offer without an explicit opt-in.
2. An adjustable token's worst case for a holder who never reacts: one step of dilution per `rateDelay`, so after a
   year the redemption value can be `(1 + maxRateStepBps/10⁴)^−(365 days / rateDelay)` of the start: ≈ 59 % at the
   defaults (1 % per 7 days), ≈ 0 at the bounds (10 % per 2 days). Wallets compute it from the token's actual
   parameters and show `rateAdjustable()` as a warning; issuers who promise a stable value should not choose
   `adjustable`.
3. Insolvency through a rate change is impossible (real balances and `C' ≥ totalSupply` checked at execution);
   insolvency through a failing underlying is not preventable by any rate rule.
4. `rateAdmin` must have code; that proves only that it is not an EOA. A forwarder owned by one key passes, so
   wallets must not call it a multisig or a timelock unless they verified it.
5. Only the admin executes. A third party cannot bundle `executeRate` with its own wraps and unwraps in one
   transaction; the admin itself could (it controls the execution), which is one more reason to use a multisig.
6. Rounding never favours the caller ([CTR-TOK-04](#CTR-TOK-04)), so repeated wrap/unwrap cycles cannot extract
   value at any rate.
7. Nobody can wrap at a rate that is about to change: wrap is paused on every leg for the whole window, while holders
   keep the unwrap exit at the current rate (`minOut` protects intents that land late).

<a id="CTR-TOK-13"></a>**CTR-TOK-13** — **Multi-underlying rates may be adjustable per leg**: issuer option at
creation, default **off**, the same timelock as [CTR-TOK-06](#CTR-TOK-06) (admin-only execution, one pending change per
token, wrap paused on **all** legs while it is pending, `minOut` on every unwrap). Changing one leg's `q_i` changes
the price of that leg against every other leg, in either direction: a raise makes wrapping `i` and redeeming another
leg profitable; a decrease makes wrapping another leg and redeeming `i` profitable. The guards remove the front-run
at the old rate (no leg can be wrapped while a change is pending) and the third-party flash bundle around the
execution (only the admin executes). They do **not** remove the value shift itself: once a change has landed, a leg
priced off its market value is an arbitrage from the next transaction on, and holders who exit through different legs
end up with different value. A per-leg share cap (`maxLegShareBps`) was rejected: anyone could switch it off or trip
it atomically with a flash loan. Recommendation: fixed rates, or a multisig/timelocked `rateAdmin` that only moves
legs toward their market value.

Residual risk, stated plainly (this text goes into the wizard and wallet disclosure):

1. **A per-leg rate change moves value between holders.** After a change to `q_i`, a unit redeemed through leg `i` is
   worth a different amount of market value than a unit redeemed through another leg. If the new rate is off the
   market price, arbitrageurs wrap the leg that is now cheap and redeem the leg that is now dear, starting in the
   transaction after the execution, until that leg's reserve is gone or the guardian disables wrap. Holders who exit
   through the dear leg first gain; holders left with the cheap leg lose. A decrease that the issuer funded with
   `addReserve` can be captured the same way (wrap another leg, redeem `i`).
2. **What the guards remove:** nobody can wrap at the old rate while a change is pending (all legs paused), nobody but
   the admin can execute (no third-party flash bundle of wrap → execute → unwrap), and every unwrap carries `minOut`.
   So there is no front-run of a pending change and no same-transaction drain around the execution by a third party.
3. **What they do not remove:** the shift in item 1, and the admin's own ability to order its execution with its own
   trades. A change moved **toward** a leg's market value removes an existing arbitrage instead of creating one; only
   such changes are safe.
4. A rate admin can keep wrap paused on the whole token for long periods by proposing changes back to back. That
   denies new wraps (never exits) and is visible on chain.
5. **Recommendation:** keep multi rates fixed (the default). If an issuer needs adjustable legs, the `rateAdmin`
   should be a multisig behind a timelock that only re-pegs legs toward their market value; wallets show the rate
   admin and every pending change. The depeg disclosure above still applies.

<a id="CTR-TOK-08"></a>**CTR-TOK-08** — **Decimals are display only.** `decimals()` of every token is the issuer's
choice at creation; rates are in raw units, so `1 human unit of U_i = num_i/den_i × 10^(D − d_i)` wrapped human
units (human rate = `num/den × 10^(D − d_i)`) (`D` = wrapper decimals, `d_i` = underlying decimals, snapshot at init). Underlyings without a readable
`decimals()` are refused (`DecimalsUnreadable`), because a UI could not show the human rate.

Examples (wrapper `D = 18`):

| Underlying | `d_i` | Intended human rate | `num` / `den` |
|---|---|---|---|
| xDAI / WXDAI | 18 | 1 : 1 | 1 / 1 |
| USDC, USDT | 6 | 1 : 1 | 10^12 / 1 |
| loyalty: 1 USDC → 100 points (`D = 0`) | 6 | 1 : 100 | 1 / 10^4 |

With integer rates (`den = 1`) wrap has no rounding; unwrap pays `⌊w/10^12⌋` and burns a multiple of `10^12`, the
holder keeps the rest. The wizard computes `num/den` from the human rate and the two decimals and shows the result
back; it refuses a rate whose `num` or `den` reaches 2^96. For wraps it rounds the amount down to `used` from
`previewWrap` (a multiple of `den/gcd(num, den)`), so no wrap leaves dust in the reserve: in the loyalty row,
wrapping 15 000 raw would mint 1 point and leave 5 000 raw behind. Minimum amounts: only the zero-output rule;
anything else (minimum ticket sizes) is the issuer's front-end policy — on chain it would only block small exits.

<a id="CTR-TOK-11"></a>**CTR-TOK-11** — **Unsupported underlyings.** Fee-on-transfer underlyings: inbound is handled
(measured delta), outbound must be exact; sender-pays fee designs revert on unwrap and are therefore **unsupported**
(the UI refuses them). Rebasing underlyings are **unsupported**: a positive rebase is a locked donation; a negative
rebase stops wrap ([CTR-TOK-05](#CTR-TOK-05)) and leaves a first-come exit. The contract cannot detect an unsupported
underlying at creation; an unsupported underlying can lock or socialise a loss.

| Underlying behaviour | Effect | Handling |
|---|---|---|
| Fee on transfer, charged from the amount | wrap credits what arrived; unwrap recipient gets `out − fee` | supported; UI discloses |
| Fee charged to the sender on top (incl. HTS fractional fee with `netOfTransfers`) | unwrap reverts `UnderlyingTransferMismatch` ⇒ that reserve is stuck | **unsupported**; UI refuses; Hedera init refuses ([NET-HED-14](../networks/hedera.md#NET-HED-14)) |
| Positive rebase / donation | `balance > reserve` | excess locked; harmless |
| Negative rebase, confiscation, blacklist burn | `balance < reserve` | wrap and `addReserve` refuse (`ReserveShortfall`); unwrap stays first-come until the balance runs out |
| Underlying blacklists the wrapper | unwrap of that leg reverts in the underlying | multi: holders exit through other legs; single: stuck until lifted — disclosure |
| Upgradeable underlying (USDC, USDT) | behaviour can change after creation | disclosure; node alert on an implementation `EXTCODEHASH` change |
| Hooks (ERC-777) | reentrancy | contract-wide transient guard |

**Gasless wrap.** A holder of an **outside** underlying (USDT, DAI) approves the wrapper once on that underlying (an
EOA may approve a contract on a token SCaaS does not control) and wraps gaslessly with `mtxExecute(wrap(…))`; the
`ABSOLUTE` fee is paid from the minted units ([CTR-MTX-20](metatx.md#CTR-MTX-20)). A holder of a **SCaaS** underlying
cannot approve anything ([CTR-TOK-01](#CTR-TOK-01)) and wraps by signature:

<a id="CTR-TOK-20"></a>**CTR-TOK-20** — **Signature wrap of a SCaaS underlying** (owner). The holder signs a
`TradeOrder` ([CTR-DEX-13](dex.md#CTR-DEX-13)) in the **underlying's** domain with `dex` = the wrapper, `receiveToken`
= the wrapper, `receiveAmount` = the minimum it accepts to receive (its `minOut`), `minFill = amount`, `fee` = the
relayer's rate. **BUILT on `WrappedToken` (P2a)**, inherited by `WrappedZetherToken` (P3). Both expose

```solidity
function mtxWrap(address underlying, TradeOrder calldata o, bytes calldata sig) external nonReentrant returns (uint256 minted);
```

1. `address(0)` ⇒ `NativeNotGasless()` (checked first); resolve the leg: `_legOf(underlying)` (both `WRAPPED*` kinds), which refuses an
   unknown "underlying" whose `mtxTrade` could be a no-op (built: `UnknownUnderlying(u)`, controller ruling, pending the owner); require `wrapEnabled`, no pending
   rate change and no reserve shortfall;
2. require `o.receiveToken == address(this)` (`WrapOrderInvalid`); the relayer binding is the underlying's (`submitter` = `msg.sender`, `WrongRelayer`; controller ruling, pending the owner: the wrapper does not repeat it); `o.receiveAmount` is gross, the holder receives `minted − wrapFee`;
3. quote `minted = ⌊o.amount · num / den⌋` and `wrapFee = ⌈minted · o.fee / 10⁶⌉`
   ([CTR-DEX-11](dex.md#CTR-DEX-11) rounding; `fee = 0` ⇒ 0);
4. call `underlying.mtxTrade(o, sig, TradeFill(o.amount, minted, wrapFee, msg.sender))` — the underlying checks the
   signature, that the wrapper is `o.dex`, the price `amount·receiveAmount ≤ minted·amount` and the fee bound, and moves
   the funds **only into the wrapper** ([CTR-DEX-15](dex.md#CTR-DEX-15));
5. require `received == o.amount` (balance delta, as the direct wrap; else `WrapReceivedMismatch(expected, received)`), record the reserve, mint `minted − wrapFee` to `destination` (or `from`) and `wrapFee` to `msg.sender`,
   the submitting relayer — the order's `fee` is how a gasless wrap pays its relayer; emit
   `Wrapped(destination or from, u, received, minted − wrapFee)`: the credited party and what it got (review W-Q,
   2026-10-19; before, `from` and the gross `minted`).

No allowance; only the named wrapper can pull, and only at the signed minimum. The call to the underlying is a wrap
talking to its underlying, as the direct wrap's pull is, not the meta-tx pipeline calling out. `mtxWrap` is not
allowlisted, so never a self-call; the submitter may be any address, an EOA relayer included; the node runs it as a metatx-job entry point.
Clients refuse by default to build or sign such an order when `dex` is not a registered wrapper of that underlying
([CTR-DEX-19](dex.md#CTR-DEX-19)).

**`uaWrap`** (owner 2026-10-13; BUILT, UA-5b): `uaWrap(address u, UATradeOrder o, bytes auth)` is `mtxWrap` with
the holder's `UATradeOrder` ([CTR-DEX-25](dex.md#CTR-DEX-25)) pulled by the underlying's `uaTrade`; the underlying must
be a SCaaS ledger token (`UALegNotLedger(u)`); `minted − wrapFee` goes to `o.destination` (0 ⇒ `o.from`), a derived id
by `_uaMint`, a native one by `_mint`; event `UAWrapped(bytes32 indexed to, address indexed u, uint256 received,
uint256 minted)` only (no `Wrapped`), with the credited id (`destination` or `from`) and `minted − wrapFee` (review
W-Q, 2026-10-19); the leg check is ERC-165 on `IUALedger`, before the pull; the fee goes to
`msg.sender`; not allowlisted (`test/ua/UAWrap.t.sol`). A native holder uses it to wrap straight into its UA. A holder of an outside underlying wraps into a
UA with `wrapToUA`, and unwraps a SCaaS ledger leg straight into a UA with `unwrapToUA` (both BUILT, UA-5a;
[CTR-UA-28](accounts.md#CTR-UA-28)).

## 4. Features

<a id="CTR-TOK-10"></a>**CTR-TOK-10** — "No one alters a deployed token" holds with only visible exceptions: the feature flags are
fixed at creation ([CTR-TOK-22](#CTR-TOK-22)) and the roles are held by the accounts the owner granted them to; an owner
can give everything up. The factory and its registrar have no power over any token, and no role can mint into a shielded
balance, move balances (except under the forced-transfer flag), touch reserves, pause unwrap or add or remove an
underlying.

<a id="CTR-TOK-22"></a>**CTR-TOK-22** — **Features are flags chosen at creation.** `features` and `lockedFeatures` are
two immutable words written by `initialize`, with `lockedFeatures ⊆ features`. Per flag the creator chooses **locked**
(exists forever) or **disableable** (the owner may clear it once, never set it again). Roles and the owner are not
immutable: see the administration bullet below.

| Bit | Flag | Role | Valid kinds | Meaning |
|---|---|---|---|---|
| 0 | `PAYABLE` | — | all | `IERC20Payment` works (`mtxPay`, `payWithFee`, `payLane`, `PaymentSettled`); **default off**; immutable (no role). `MetaTransfer` is never gated (`PaymentSettled` is also emitted by any `MetaTransfer` with `entryRef ≠ 0`, whatever the flag; the flag gates `mtxPay`, `payWithFee`, `mtxPayReceiverFee` and `supportsInterface(IERC20Payment)`) |
| 1 | `MINTABLE` | `minter` | `NORMAL*` | `mint` to a public balance (a minter never mints into a shielded balance) |
| 2 | `BURNABLE` | — (holder) | `NORMAL*` | holder `burn` of its public balance |
| 3 | `RATE_ADJUSTABLE` | `rateAdmin` (contract) | `WRAPPED*` | rate change with timelock; off ⇒ rates fixed at creation |
| 4 | `WRAP_DISABLEABLE` | `guardian` | `WRAPPED*` | disable wrap per leg, one-way |
| 5 | `FREEZE` | `issuer` (contract) | non-confidential ([CTR-AS-17](asset-suite.md#CTR-AS-17)) | as [CTR-AS-05](asset-suite.md#CTR-AS-05) |
| 6 | `FORCE` | `issuer` + `compliance` | non-confidential | forced transfer on a recorded order ([CTR-AS-04](asset-suite.md#CTR-AS-04)) |
| 7 | `PAUSE` | `issuer` | non-confidential | as [CTR-AS-06](asset-suite.md#CTR-AS-06) |
| 8 | `ALLOWLIST` | `compliance` | non-confidential | receivers checked against a `ComplianceRegistry` ([CTR-AS-07](asset-suite.md#CTR-AS-07)) |

- **Administration: one `owner`.** Each token has one `owner` (0 at creation = no administration ever). Candidate
  implementation, decided in P1: OpenZeppelin `AccessControlDefaultAdminRules` (owner = default admin, delayed two-step
  transfer, renounce). The owner can: `grantRole(bit, account)` / `revokeRole(bit, account)` for the role of a flag set
  in `features` (a role may have several holders; the contract-only roles stay contract-only); `disableFeature(bit)`,
  one-way, only for a flag not in `lockedFeatures` (reverts `FeatureLocked(bit)`; `FeatureNotSet(bit)` when already
  clear); two-step `transferOwnership`; `renounceOwnership()`, after which the owner is 0 forever. After
  `renounceOwnership()` the existing role holders **keep** their roles; to make a token unchangeable the owner revokes
  every role, then renounces. A role holder performs the flag's actions (mint, rate change, freeze, …) and may
  `renounceRole(bit)` itself. The owner only administers: it acts on a flag only if it grants itself the role.
  `PAYABLE` and `BURNABLE` have no role and are always treated as locked: `disableFeature(PAYABLE|BURNABLE)` reverts `FeatureLocked(bit)`. Events: `RoleGranted`/`RoleRevoked`,
  `FeatureDisabled(bit, by)`, the ownership events.
- **Validation in the token**, in `initialize` through `AdminLib` (the factory only forwards; `createTokenUnregistered`
  lets anyone bring an implementation, so the token is the one authority): each flag valid for the kind
  (`FeatureInvalidForKind(bit)`); `lockedFeatures ⊆ features` (`LockedNotSubset()`); a role holder in `roles` only for a
  set flag (`RoleWithoutFeature(bit)`); contract-only roles are contracts. Roles may also be granted later by the owner.
- **Views:** `features()`, `lockedFeatures()`, `owner()`, `hasRole(bit, account)`, `kind()`, `version()`.
  `supportsInterface(IERC20Payment)` is true iff `PAYABLE` is set. `rateAdjustable()` and the role holders stay public so
  wallets and indexers flag them. (The wrap pause during a pending rate change is a consequence of that change, not a
  separate power.)
- **The four regulated controls are flags 5–8** on the ordinary kinds ([CTR-AS-17](asset-suite.md#CTR-AS-17)), not separate kinds; their rules (caps, cooldowns, orders, receiver-only allowlist, the shape-step plus `_update` check) are
  unchanged and live in `AdminLib`. A token with none of the flags is fully permissionless. Confidential kinds refuse
  flags 5–8 (`FeatureInvalidForKind`).
- Flags valid on confidential kinds: `PAYABLE`; `MINTABLE`/`BURNABLE` (`NORMAL_ZETHER`); `RATE_ADJUSTABLE`/
  `WRAP_DISABLEABLE` (`WRAPPED_ZETHER`).

<a id="permissionless-vs-controlled"></a>

| | No regulated flag | Any of flags 5–8 |
|---|---|---|
| Admin powers | None beyond the creation-time flags 1, 3, 4: no pause, blacklist, freeze, confiscation | The flags chosen at creation; a flag can only be disabled later (where not locked), never set; no regulated flag mints, changes a rate or touches the reserve |
| Use | Loyalty, internal units, B2B settlement tokens, wrapped stablecoins | Central-bank digital currency, licensed stablecoins, digital securities and bonds, real-world-asset claims |
| Guarantee | "Your key, your funds": neither the issuer nor the factory can touch balances | Due-process intervention against a recorded order, permanently evidenced on chain; mandatory disclosure (`termsHash`) |

**Transitional (BUILT, P1c).** Kind `NORMAL` has the flags, the owner and the roles (`AdminLib`, namespace `scaas.token`;
admin functions, events and errors in `ITokenAdmin`, including `RoleAccountZero(uint8)`); flags 5–8 are refused
`FeatureNotBuilt` until the asset suite builds the controls. Kind `WRAPPED` (P1d) uses the same `AdminLib` roles for
`RATE_ADJUSTABLE` (rate role, contract only) and `WRAP_DISABLEABLE` (guardian); `disableFeature(RATE_ADJUSTABLE)` also cancels a pending change.

## 5. Allowance lockdown

<a id="CTR-TOK-01"></a>**CTR-TOK-01** — **Only a contract may call `approve`, an `approve`/allowance spender must be a
contract, and only a contract may call `transferFrom`. An EOA never holds or grants an allowance on a SCaaS token** —
directly, through `mtxExecute` (`approve` is in no allowlist, [CTR-MTX-19](metatx.md#CTR-MTX-19)), or by any permit.
Nor does a Universal Account, on any `ua*` path ([CTR-UA-27](accounts.md#CTR-UA-27): no `uaApprove`; its pulls are
signed `UATradeOrder`s).
Enforced in the token code of every family (owner). The caller is `_msgSender()`, equal to `msg.sender` because
`approve` is never a self-call. Allowance-like grants obey the same rule: a `TradeOrder` names its executor `dex`,
which must be a contract (`mtxTrade` checks `msg.sender == o.dex` and `_isContract(o.dex)`), so signing `dex` = an EOA
grants nothing; that `dex` is a contract and nothing more is an owner-accepted residual risk
([CTR-DEX-19](dex.md#CTR-DEX-19)). `extcodesize` alone decides wrongly in three cases (which is why a simple `isEOA`
check was dropped); the rule handles each one explicitly:

| Case | `code.length` | Treated as | Why |
|---|---|---|---|
| Plain EOA | 0 | EOA | — |
| EOA with an EIP-7702 delegation (`0xef0100 ‖ addr`, 23 bytes, starting `0xef0100`; Prague; off on the SCaaS testnet 7622 from its next reset, live on most customer chains) | 23 | **EOA** (refused) | the code is only a designator; the EOA's private key still signs anything. As a caller it is refused even before this check: `_msgSender()` reverts `CallerDelegated(caller)` ([CTR-UA-24](accounts.md#CTR-UA-24), owner ruling D2, 2026-10-30); as a spender it gets `SpenderNotContract` |
| Contract during its constructor | 0 | **EOA** (refused) | indistinguishable from an EOA at that moment; consequence: a contract **cannot** be approved or spend an allowance from its own constructor |
| Deployed contract | > 0, not a designator | contract | — |

- EVM `ERC20MetaTx` (the root of every token): `approve` reverts `CallerNotContract(caller)` for an EOA caller and
  `SpenderNotContract(spender)` for an EOA spender; `transferFrom` reverts `CallerNotContract(caller)` **before** the
  allowance check. No `permit`, no `increaseAllowance`, no meta-tx `approve`. Errors: `SpenderNotContract(address)`,
  `CallerNotContract(address)`. Built on every kind (P1b); the v1 line with its EOA `approve` is in `legacy/p5/` (P5).
- Contract accounts approve through **their own call path**: `SmartKeyAccount.mtxExecuteAsOwner → execute(token,
  approve)`, a Safe `execTransaction`, or a Safe MultiSend that approves and uses the allowance in one transaction. The
  token sees `msg.sender` = the account. A signature check (`isValidSignature`) is not the account's execution policy
  (Safe guards, modules and thresholds run only on execution), which is why a gasless `approve` by ERC-1271 is refused.
- Payments never need allowances (`pay`, `payWithFee`), the DEX needs none for SCaaS tokens
  ([CTR-DEX-15](dex.md#CTR-DEX-15)), and a mandate is not an allowance: a `MandateWallet` delegate (possibly an EOA)
  pays from the wallet under caps, and the wallet, a contract, is the token's `msg.sender` ([CTR-ACC-06](mandates.md#CTR-ACC-06)).
- Outside tokens are not ours to enforce: wrapping USDT still needs the holder to approve the wrapper on USDT. Hedera
  HIP-632 signers are non-contracts, so they cannot `approve`.
- Soroban `approve` → `require_contract(spender)`; Cosmos `IncreaseAllowance` only for contract spenders and
  `TransferFrom` only from contracts; Move/TON/Solana have no allowance on the hot path (balances live in the
  subject's account object/wallet/PDA, moved only by subject-signed ops).
- Hedera HTS allowances at protocol level cannot be restricted; HTS tokens are used only through a wrapper (`WrappedToken`)
  ([NET-HED-04](../networks/hedera.md#NET-HED-04)).
- **Agents never sign allowances.** Spending authority is expressed as exact-amount, expiring meta-tx signatures or
  as an on-chain mandate ([CTR-ACC-06](mandates.md#CTR-ACC-06)).

An earlier "EOA caller" form (`msg.sender == tx.origin && extcodesize == 0`) was dropped because `tx.origin` misjudges
contracts in their constructor and 7702-delegated EOAs; the caller check uses the classifier above (a 7702-delegated
caller is refused earlier, by `_msgSender()`, [CTR-UA-24](accounts.md#CTR-UA-24)).

## <a id="factory"></a>6. Factory

<a id="CTR-TOK-15"></a>**CTR-TOK-15** — **The factory is open to everyone.** Anyone creates tokens; anyone wraps any
ERC-20 into a meta token (or a confidential token where enabled); the market decides which one is used. SCaaS deploys
the factory (the protocol), not tokens: ten people wrapping xDAI get ten different contracts, and that is normal. The
factory stays open for token creation; what a creator cannot choose is the code behind a confidential token: its
verifiers are fixed by the implementation release (owner 2026-10-19, [CTR-ZTH-20](zether.md#CTR-ZTH-20)), and the creator
picks them only by picking the version (plan 5g-Z2: they are the dependencies of the env version the registrar names
when it deploys the release, [CTR-TOK-03](#CTR-TOK-03)).

<a id="CTR-TOK-18"></a>**CTR-TOK-18** — **The factory is the most critical immutable artifact.** A wrong line in the
factory is wrong forever for every token anyone ever created through it, so the audit budget concentrates there.
Nobody controls who uses it for what (that is what permissionless means); what SCaaS can do is clear documentation,
high-quality reference verifiers, and never claiming a role it does not hold. Verifier support per chain is checked at
creation, by the implementation's `initialize` (plan 5g-Z2; `isSupportedOnThisChain()` is mandatory): a BLS12-381 verifier deploys **successfully** on a chain without
EIP-2537 and then reverts on every proof forever — an absent precompile does not revert, it returns success with
empty output — with no symptom until someone has deposited funds.

- **No proxy upgrades anywhere** ([CTR-GEN-02](README.md#CTR-GEN-02)). Each implementation version is deployed once;
  every token is a 45-byte EIP-1167 clone (`363d3d373d3d3d363d73<impl>5af43d82803e903d91602b57fd5bf3`) that
  `DELEGATECALL`s it with its own storage. A clone costs ~45 000 gas instead of ~2.5 M.
- **Versions live in the factory, which deploys them** (owner 2026-10-20, plan 5g-Z2): the registrar publishes
  versioned environments (`publishEnv(kind, envVersion, Env)`, never changed) and releases code with
  `deployImplementation(kind, version, envVersion, initcode, implArgs)` (registrar only, append-only, version 0
  forbidden; the factory's own `CREATE2` with the named env appended, [CTR-TOK-03](#CTR-TOK-03)); a release is usable
  `noticePeriod` seconds after its deployment; `deprecate` is immediate and refuses new tokens of that version (owner 2026-10-20; tokens already
  made are untouched), `createTokenUnregistered` deploys an off-catalogue implementation with `version() == 0` (visibly),
  plain kinds only (owner 2026-10-19). A bug in a version is permanent for that version's tokens; the remedy is
  voluntary migration (unwrap the old token, wrap the new one).
- **Atomic init**: CREATE2 salt = `keccak256(abi.encode(msg.sender, salt))` (nobody can take another creator's
  address); `initialize` runs in the same call and requires `msg.sender == FACTORY`; implementations lock themselves
  in the constructor.
- **Kind gate**: `setKindEnabled(kind, on)` (registrar); the plain kinds start on, the confidential kinds off (owner
  2026-10-20, plan 5g-Z2; it replaces `setZetherEnabled` / `setPqzEnabled`). The chain gates are the implementations':
  a Zether `initialize` reverts when the release's transfer verifier does not run on the chain (no chain-id
  allowlist, [CTR-ZTH-52](zether.md#CTR-ZTH-52)); a PQZ `initialize` runs `PqzSafety` (allowlist and
  precompile self-test). `OpenFactoryV1` (with its own gate) is in `legacy/p5/` (P5).
- **Registrar** is an EOA by default (deployer); it must become a multisig before mainnet. Its only powers are
  `publishEnv`, `publishDexEnv`, `deployImplementation`, `deployDexImplementation`, `deprecate`, `deprecateDex` and
  `setKindEnabled`.
- **Same rule on every family**: a fix to an Aptos package, Sui package, Solana program, Cosmos contract, GRAM or
  Soroban contract is a new deployment at a new address plus voluntary migration by the owners of the balances;
  accounts on the old deployment keep working with the old code ([CTR-GEN-02](README.md#CTR-GEN-02)).

<a id="CTR-TOK-16"></a>**CTR-TOK-16** — **One wrapper per creator, looked up by `(creator, underlying)`.** There is no
"official" wrapper of an asset: `getWrapper(creator, underlying)` answers "which xDAI wrapper is A's" (exactly one:
the first), while a function answering "which is *the* xDAI wrapper" would lie. A creator may still have several
(one per curve, or per fee schedule): `getWrapperCount(creator, underlying)` / `getWrapperAt(creator, underlying, i)`;
"which wrappers of xDAI exist, by whom" is `deployCountFor(underlying)` / `deployedFor(underlying, i)`. There is no
uniqueness on the underlying alone, no name or symbol vetting. The ranking signal needs no new function:
`IERC20(xDAI).balanceOf(wrapper)` is the real asset locked behind each wrapper, readable on chain for free.

<a id="CTR-TOK-17"></a>**CTR-TOK-17** — **Provenance instead of gatekeeping.** Every token answers, immutably,
`factory()`, `creator()`, `underlying()`, `verifier()`, `implementation()`, `version()`, and the factory keeps
`isToken(token)` for the reverse check — a contract that claims a `factory()` the factory does not confirm is
only a self-declared string. This answers "is this contract really a wrap of xDAI with verifier X created by Y"; it
does **not** answer "is this the token I should use" — that has no on-chain answer (reputation and liquidity decide).
`isRegisteredToken(token)` says the token was made from a registered version (`version ≠ 0`); a version-0 token
(`createTokenUnregistered`, plain kinds only) is unvetted code and clients and the gateway treat it so. For confidential
tokens the factory is the published source of the verifiers: the release's env (`releaseOf(kind, version)` gives
`envVersion` and `envHash`, `envOf(kind, envVersion).deps` the addresses, [CTR-ZTH-20](zether.md#CTR-ZTH-20)). Provenance metadata published for
every asset: `creator`, `underlying`, `version`, `implementation`, creation block (issuance timestamp), and for
wrappers the live reserve `underlying.balanceOf(token)` — readable by anyone for free.

### 6.1 `OpenFactory`

<a id="factory-v1"></a>
<a id="factory-v2"></a>

<a id="CTR-TOK-03"></a>**CTR-TOK-03** — **One factory, `OpenFactory`** (owner), the only factory of a chain. The
constructor takes the registrar, `chain_uid` (immutable, exposed as `chainUid()`) and the notice period (`noticePeriod()`,
seconds); an env must name this factory and `chain_uid`, and `deployImplementation` refuses a release whose `chainUid()`
differs, so a clone's domain `salt` has exactly one source ([CTR-GEN-05](README.md#CTR-GEN-05)). The kinds are in [CTR-TOK-21](#CTR-TOK-21), the creation API in
[CTR-TOK-25](#CTR-TOK-25). The factory is deployed through the deterministic CREATE2 deployer
([CTR-GEN-06](README.md#CTR-GEN-06)).

<a id="release-env"></a>**Releases and their environment** (owner 2026-10-20, plan 5g-Z2). The factory deploys every
implementation itself, so what a release depends on is fixed in its code by construction:

- **Split.** The implementation carries what never changes for it: the release's `Env` as constructor immutables —
  `factory`, `chainUid`, the UA `registry`, the `SmartKeyAccount` implementation, `hedera`, the kind's dependencies
  `deps` by position (`*_ZETHER`: transfer, burn and inner-product verifier and `ZetherDisclosure` of one curve;
  `*_PQZ`: the `UAPqzVerifier`; plain kinds and the DEX: none) and the linked libraries `libs` with their
  `libCodeHashes`. Each instance carries its own configuration in `initArgs` (rates, features, roles, the confidential
  settings…), decoded by the implementation's generic `initialize(creator, version, initArgs)`; the factory never reads it
  (owner 2026-10-20).
- **Envs** are published per kind (and one domain for the DEX) by `publishEnv(kind, envVersion, Env)` /
  `publishDexEnv(envVersion, Env)`: versions from 1, append-only, never changed (`EnvAlreadyPublished`), `Env.factory` and
  `Env.chainUid` the factory's own and no library code hash `0` or `keccak256("")`, a pin that checks nothing
  (`EnvInvalid`); `EnvPublished(domain, envVersion, envHash)` with
  `envHash = keccak256(abi.encode(env))`; views `envOf`, `dexEnvOf`, `latestEnvVersion`, `latestDexEnvVersion`.
- **Deployment.** `deployImplementation(kind, version, envVersion, initcode, implArgs)` /
  `deployDexImplementation(version, envVersion, initcode, implArgs)` name the env explicitly: it must be published for
  that kind or the DEX (`EnvUnknown(domain, envVersion)`). Interim rule, controller proposal 2026-10-20 (owner may
  override; the owner declined "bind the kind's latest env"): the final binding rule belongs to a later
  governance-matrix spec. The factory checks each `libs[i].codehash` against `libCodeHashes[i]`
  (`LibraryCodeHashMismatch`; the list is the registrar's, checked by code hash, not compared with the init code's link
  references — owner 2026-10-20), `CREATE2`s `initcode ‖ abi.encode(envVersion, env, implArgs)` (salt
  `keccak256(abi.encode(kind, version))`, DEX `keccak256(abi.encode("dex", version))`), bubbles a constructor's revert
  (`DeployFailed` without revert data, e.g. a runtime over the chain's code-size limit; init code over the chain's
  EIP-3860 limit halts the factory's frame instead, so the registrar's call consumes all its gas without `DeployFailed`), checks `kind()`, `factory()`, `chainUid()`, and records
  `Release {implementation, envVersion, envHash, usableFrom, deprecated}`. The event carries the env version and hash,
  `keccak256(initcode)` (without the appended arguments: a reproducible-build check) and the deployed code hash.
- **Notice period.** `usableFrom = block.timestamp + noticePeriod`; `createToken` / `createDex` refuse a release before
  it (`VersionNotYetUsable`, `DexVersionNotYetUsable`). The deploy script reads `NOTICE_PERIOD`: every mainnet (any
  chain outside `DeployBase._isTestChain`'s fixed test / dev list — 22776, Hedera 295, Ethereum, BSC, an unknown chain)
  defaults to and may not go below 3 days; the SCaaS testnet defaults to 10 minutes, the other test / dev chains to 0 (owner
  ruling 2026-10-20). The constructor caps it at 30 days (`MAX_NOTICE_PERIOD`, `NoticePeriodTooLong`: near `2^64` every deployment would overflow).
- **Limit.** The registrar's key is the trust root for code: it chooses the init code and the env. The factory proves
  which env was appended to the init code and that each library listed in the env had its pinned code hash at
  deployment; the init code may link libraries the env does not list (owner 2026-10-20), and nothing proves the code
  honest.

<a id="CTR-TOK-25"></a>**CTR-TOK-25** — **Creation API: `createToken`, `createTokenUnregistered`, `TokenConfig`,
`TokenCreated`.**

```solidity
function createToken(TokenKind kind, uint64 version, bytes calldata initArgs, bytes32 salt) external returns (address);
function createTokenUnregistered(TokenKind kind, address implementation, bytes calldata initArgs, bytes32 salt) external returns (address);
function createDex(uint64 version, bytes calldata initArgs, bytes32 salt) external returns (address);
// every implementation: initialize(address creator, uint64 version, bytes initArgs) — the kinds of this repository
// decode initArgs = abi.encode(TokenConfig), SCaaSDex abi.encode(DexConfig) (owner 2026-10-20, plan 5g-Z2)

struct TokenConfig {
    string name; string symbol; uint8 decimals;
    uint256 features; uint256 lockedFeatures;
    address owner;                             // 0 = no administration ever
    Roles roles;                               // initial holders (optional, each only for a set flag): minter, rateAdmin, guardian, issuer, compliance
    uint256 initialSupply; address initialHolder;   // NORMAL* only; initialHolder is ignored when initialSupply == 0
    Leg[] legs;                                // underlying (address(0) = native coin, CTR-TOK-26), num, den — WRAPPED* only, 1..8
    RateConfig rate;                           // with RATE_ADJUSTABLE
    ConfidentialConfig conf;                   // auditorKey (empty = none), shieldScale, maxShielded, confidentialFee, disclosureMode {BUNDLE, COMPACT}, auditorMode {NONE, FULL, OPTIONAL}, minDecoyFee (both confidential layers; the least per-leg `decoyFee`, renamed from `multiLegFee`, owner 2026-10-20) — confidential kinds only (modes: CTR-ZTH-48/49, built in P3b; the token refuses a key that does not match auditorMode); no verifier field since plan 5g-Z2: the verifiers are the release's env deps, CTR-ZTH-20
}
struct DexConfig { address admin; uint32 relayerSharePpm; address treasury; bool listedOnly; }
```

- **Creation (unchanged pattern).** `CREATE2` of an EIP-1167 clone, then `initialize(creator, version, initArgs)` **in the same call** (no
  front-run of `initialize`, no deployed-but-uninitialized state); the implementation locks its own `initialize` in
  its constructor. The address is predictable from `(factory, salt, implementation)`.
- **Kinds** (fresh enum, nothing deployed): `NORMAL`, `WRAPPED`, `NORMAL_ZETHER`, `WRAPPED_ZETHER`, `NORMAL_PQZ`,
  `WRAPPED_PQZ` (6 and 7 were `NORMAL_ZETHER_PQZ` / `WRAPPED_ZETHER_PQZ`, dropped 2026-10-20, ids not reused). The catalogue keeps versions per kind
  (deploy, deprecate; [CTR-TOK-03](#CTR-TOK-03)); it is append-only.
- **One event per creation:** `TokenCreated(token, creator, kind, version, implementation, features, lockedFeatures,
  owner, underlyings)`, where `lockedFeatures` is the value the token stored (`locked | (features & ALWAYS_LOCKED)`, read
  back from `lockedFeatures()` after `initialize`), not the requested one; `DexCreated(dex, creator, version, implementation, admin)` for a DEX clone
  ([CTR-DEX-24](dex.md#CTR-DEX-24)).
- **Registry views:** `isToken`, `versionOf`; for a DEX `isDex`, `dexVersionOf` (advisory, tokens never consult them,
  [CTR-DEX-24](dex.md#CTR-DEX-24)); catalogue `deployDexImplementation`, `dexReleaseOf`, `dexImplementationOf`,
  `latestDexVersion`.
- One `IOpenFactory` and one `IFactoryToken` (the v1 and v2 interfaces are in `legacy/`).

Flag validation is the token's ([CTR-TOK-22](#CTR-TOK-22)): the factory only forwards `initArgs`.

### 6.2 Transitional (BUILT)

<a id="transitional-built-tokens"></a>

**Transitional (BUILT, P1e).** `OpenFactory` (`src/factory/OpenFactory.sol`, `IOpenFactory.sol`, `IFactoryToken.sol`) is
built as [CTR-TOK-03](#CTR-TOK-03) and [CTR-TOK-25](#CTR-TOK-25) specify, the Zether gate and kinds 2–3 included (P3);
`createDex` and the DEX catalogue are built (P2b-1, [CTR-DEX-24](dex.md#CTR-DEX-24)); the releases, envs and the
generic creation API are built in plan 5g-Z2. Every kind has the constructor `(uint16 envVersion, Env env, bytes
implArgs)` (the factory's append), `initialize(creator, version, bytes initArgs)` with
`initArgs = abi.encode(TokenConfig)`, `underlyings()` and a constant `kind()`. The v1 line (`ERC20MetaTxV1`, `MetaToken`,
`HederaMetaToken`, `MetaTxDex`, `OpenFactoryV1` with `createMetaToken`) went to `smartcontracts/evm/legacy/p5/` once the
node and clientkeys moved (P5), not deleted.
Factory v2 is backed up in `smartcontracts/evm/legacy/p1e/` (not built).

- `constructor(address registrar, bytes32 chainUid, uint64 noticePeriod)`, `chainUid` non-zero (`ChainUidZero`).
  `publishEnv`, `publishDexEnv`, `deployImplementation`, `deployDexImplementation`, `deprecate`, `deprecateDex` and
  `setKindEnabled` are registrar-only (`NotRegistrar`; a registrar that is an EIP-7702 designator gets
  `CallerDelegated`, owner ruling D2, 2026-10-30); envs and the catalogue are append-only (`EnvAlreadyPublished`,
  `VersionAlreadyRegistered`, `DexVersionAlreadyRegistered`); env version 0 and release version 0 are refused.
- **Deployment** ([CTR-TOK-03](#CTR-TOK-03)): `EnvUnknown`, `LibraryCodeHashMismatch`, the constructor's own error or
  `DeployFailed`, then `kind()`, `factory()` and `chainUid()` read by staticcall: `ImplementationNotAContract` (also for an
EIP-7702 designator: `SigCheck.isContract`, owner ruling D5, 2026-10-30; a designator implementation would be a mutable
backdoor, since clones `DELEGATECALL` through it),
  `VersionKindMismatch(expected, got)` (`got = type(uint256).max` when there is no answer),
  `ImplementationFactoryMismatch`, `ChainUidMismatch`. The constructor refuses a notice period over 30 days
  (`NoticePeriodTooLong`). Kinds 6–7 do not exist (`NORMAL_ZETHER_PQZ` / `WRAPPED_ZETHER_PQZ` dropped, plan 5h D21: `KindReserved` removed, the ABI decoder rejects them); kinds 2–5 are built (Zether P3, PQZ P6g; review W-Q, 2026-10-19: this text had kinds 4–7 reserved).
  The constructors check their env: a confidential kind needs its `deps` (`*_ZETHER`: four with code, a registry, the
  two verifiers of one `proofSystemId`, both fixed to `deps[2]`, two addresses, the transfer verifier answering
  `ringSize()` and the burn verifier not; `*_PQZ`: the verifier) and refuses a Hedera env
  (`BadInit`); "with code" means a contract, never an EIP-7702 designator (`SigCheck.isContract`, owner ruling D5,
  2026-10-30; also the Zether inner-product verifier).
- **Creation:** `createToken` (a deployed release: `VersionUnknown`; not deprecated: `VersionDeprecated`; past
  `usableFrom`: `VersionNotYetUsable`) and `createTokenUnregistered` (plain kinds only, `UnregisteredConfidentialKind`
  for 2–7; the implementation checks of a deployment, recorded with `version == 0`) refuse a disabled kind
  (`KindDisabled`), clone with salt `keccak256(abi.encode(msg.sender, salt))` (`SaltAlreadyUsed` when the predicted address is already in the
  index or has code: an unregistered implementation may self-destruct its clone in `initialize`), call `initialize` in the same call,
  then read the token's `underlyings()` (at most 8, else `UnderlyingCountInvalid`; the token checks the count per kind:
  `NORMAL*` 0, `WRAPPED*` 1–8), `features()`, `lockedFeatures()` and `owner()` for the index and the one
  `TokenCreated`. A field of another kind reverts
  `ConfigFieldForOtherKind(field)`: 1 `initialSupply`/`initialHolder` (not `NORMAL*`), 2 `legs`, 3 `rate` (not
  `WRAPPED*`), 4 `conf` (not a confidential kind).
- `latestVersion` / `latestDexVersion` may name a deprecated version: clients pick the newest non-deprecated one
  (`isDeprecated`, `isDexDeprecated`).
- **Views:** `registrar`, `chainUid`, `implementationOf`, `isDeprecated`, `latestVersion`, `predictAddress`, `isToken`,
  `creatorOf`, `versionOf`, `getWrapper(creator, underlying)` (the first; it may be a multi-leg token: read
  `underlyings()`), `getWrapperCount/At`, `deployCountFor/deployedFor`. Every leg is indexed, `address(0)` for the
  native coin.
- **Confidential creation (BUILT, P3; 5g-Z2).** The chain and verifier gates are the implementation's `initialize`
  (moved from the factory, owner 2026-10-20): a Zether token (`ZetherLib.init`) reverts outside a dev chain, and with
  `IZetherToken.VerifierUnsupportedOnThisChain(verifier, curveName)` when the release's transfer verifier's
  `isSupportedOnThisChain()` is false or unanswered, so a BLS12-381 verifier cannot serve a chain without EIP-2537; a
  PQZ token (`PqzStateLib.init`) requires the allowlisted chain, the precompile and its self-test (`PqzSafety`).
  `ConfidentialConfig` has no verifier field.
- **Trust the index only for registered versions** (`isRegisteredToken(token)`, `versionOf(token).version != 0`): the
  factory indexes what the config says, and an unregistered implementation (version 0) may do anything else with it.
  The registrar's key is the trust root for registered code (a multisig / UA msig before mainnet).

<a id="factory-interface"></a>

The built interface is `IOpenFactory.sol` and the `TokenConfig` block of [CTR-TOK-25](#CTR-TOK-25); the event is
`TokenCreated(token, creator, kind, version, implementation, features, lockedFeatures, owner, underlyings)`, the
enum `TokenKind { NORMAL, WRAPPED, NORMAL_ZETHER, WRAPPED_ZETHER, NORMAL_PQZ, WRAPPED_PQZ }`. The deploy scripts publish env 1 of `NORMAL` and of the DEX and deploy `NormalToken` as
version 1 of `NORMAL` and `SCaaSDex` as DEX version 1 through the factory (with `DEPLOY_ZETHER=1` also both `*_ZETHER` kinds on
the BLS12-381 env, the kinds enabled); `WrappedToken` is not deployed ([CTR-GEN-06](README.md#CTR-GEN-06), [CTR-TOK-24](#CTR-TOK-24)). Separate `AssetFactory` for action
contracts: [asset-suite.md](asset-suite.md#templates).

## <a id="interfaces"></a>7. Interfaces

The block is the **built** function set, grouped by the built contracts; the role holder's `renounceRole(bit)` replaces
`renounceRateAdmin`/`renounceGuardian` (P1d) and the factory is [CTR-TOK-25](#CTR-TOK-25) (built in P1e).

```solidity
// built v2 line also has executeMetaTransactionWithFee, mtxUnwrap(…, validUntil, …), mtxUnwrapWithFee(…, feeRecipient, …)
//   and OP_UNWRAP; mtxTransferWithFee is unchanged
// ERC20MetaTx / MetaTokenBase (all kinds), domain ("SCaaS MetaToken", "1", chainId, clone, chain_uid):
//   mtxExecute, the named functions and the trade entry points — metatx.md#interfaces, dex.md#CTR-DEX-15
function mtxSelectors() external view returns (bytes4[] memory, uint8[] memory, uint8[] memory);   // per kind, CTR-MTX-19
// MetaTokenBase: kind(), creator(), version(), supportsInterface(bytes4), IS_HEDERA; ITokenAdmin: features(), lockedFeatures(), owner(),
//   pendingOwner(), hasRole(uint8,address), grantRole, revokeRole, renounceRole, disableFeature, transferOwnership, acceptOwnership, renounceOwnership
// NormalToken
function mint(address to, uint256 amount) external;  function burn(uint256 amount) external;
// WrappedToken (CTR-TOK-21), 1–8 legs: the single-asset ABI reverts UnderlyingRequired unless exactly one leg
function wrap(uint256 amount) external payable returns (uint256 minted);
function unwrap(uint256 wrapped, address recipient) external returns (uint256 out);                   // minOut = 0; not allowlisted
function unwrap(uint256 wrapped, address recipient, uint256 minOut) external returns (uint256 out);
function addReserve(address underlying, uint256 amount) external payable;
function proposeRate(address underlying, uint96 num, uint96 den) external;   // rateAdmin; one pending per token; RateFixed if fixed
function cancelRate() external;                                              // rateAdmin
function executeRate() external;                                             // rateAdmin only, eta ≤ now ≤ eta + 7 days
function underlyings() external view returns (address[] memory);
function legOf(address u) external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals, bool wrapEnabled);
function collateralValue() external view returns (uint256);                  // Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply
function wrap(address underlying, uint256 amount) external payable returns (uint256 minted);
function unwrap(address underlying, uint256 wrapped, address recipient, uint256 minOut)
    external returns (uint256 out, uint256 burned);
function mtxWrap(address underlying, TradeOrder calldata o, bytes calldata sig) external returns (uint256 minted);  // CTR-TOK-20
function disableWrap(address underlying, bytes32 reason) external;           // guardian, one-way
// errors: WrapPausedForRateChange(address), UnwrapBelowMin(uint256 out, uint256 minOut), UnwrapRecipientInvalid(address), NativeNotGasless(), WrapOrderInvalid(address), WrapReceivedMismatch(uint256,uint256)
```

| Contract | Events | Errors |
|---|---|---|
| `ERC20MetaTx` | `MetaTransactionExecuted`, `MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce)`, `TradeFilled`, `OrderCancelled`, `NoncesInvalidated` | `MetaTx*`, `Mtx*` gateway errors, `SpenderNotContract`, `CallerNotContract`, `FeeRecipientIsPayee()`, the `mtxTrade` errors ([dex.md](dex.md#CTR-DEX-15)) |
| `MetaTokenBase` | `PaymentSettled` | `PayToZero()`, `MtxModeShape(uint32 mode)`, `MtxBatchEmpty()`, `MtxBatchLengthMismatch()`, `NotFactory()`, `AlreadyInitialized()`, `UnderlyingCountInvalid(uint256)` |
| `ITokenAdmin` (on `MetaTokenBase`) | `RoleGranted`, `RoleRevoked`, `FeatureDisabled`, `OwnershipTransferStarted`, `OwnershipTransferred` | `FeatureInvalidForKind`, `FeatureNotBuilt`, `LockedNotSubset`, `RoleWithoutFeature`, `RoleNotContract`, `NoSuchRole`, `FeatureLocked`, `FeatureNotSet`, `NotOwner`, `NotPendingOwner`, `MissingRole`, `RoleAccountZero(uint8)` |
| `NormalToken` | — (no `MinterRenounced`) | — (no `NotMinter`) |
| `WrappedToken` (events and errors declared in `IWrappedToken`) | `Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted)`, `Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned, uint256 underlyingOut)`, `ReserveAdded(address indexed from, address indexed underlying, uint256 amount)`, `RateChangeProposed(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen, uint64 eta)`, `RateChangeCancelled(address indexed underlying)`, `RateChanged(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen)`, `WrapDisabled(address indexed underlying, address indexed guardian, bytes32 reason)` | `UnderlyingInvalid(address)`, `DecimalsUnreadable(address)`, `RateInvalid(uint256,uint256)`, `RateConfigInvalid()`, `WrapTooSmall()`, `UnwrapTooSmall()`, `UnwrapBelowMin(uint256 out, uint256 minOut)`, `UnwrapRecipientInvalid(address)`, `InsufficientReserve(address,uint256,uint256)`, `ReserveShortfall(address,uint256,uint256)`, `UnderlyingTransferMismatch(address,uint256,uint256)`, `UnknownUnderlying(address)`, `RateFixed()`, `NotRateAdmin()`, `RateChangePending()`, `NoRateChangePending()`, `RateChangeNotReady(uint64)`, `RateChangeExpired(uint64)`, `RateStepTooLarge()`, `RateChangeUndercollateralized(uint256,uint256)`, `WrapPausedForRateChange(address)`, `WrapDisabledFor(address)`, `DuplicateUnderlying(address)`, `RateDecreaseWithDisabledLeg()`, `UnderlyingRequired()`, `NotGuardian()`, `NativeValueMismatch(uint256 value, uint256 expected)`, `NativeNotGasless()`, `WrapOrderInvalid(address)`, `WrapReceivedMismatch(uint256,uint256)`, `FailedCall()`, `SafeERC20FailedOperation(address)`, `InsufficientBalance(uint256,uint256)`, `HtsQueryFailed(address u, int64 responseCode)`, `AssociateFailed(int64)` |
| `OpenFactory` | `TokenCreated(…)` ([CTR-TOK-25](#CTR-TOK-25)); built; the v1 factory keeps `TokenDeployed(…)` (Zether) | as [above](#factory-interface) |

The node's event normaliser adds `Wrapped`, `Unwrapped`, `ReserveAdded`, `RateChange*`, `WrapDisabled`,
`MetaNonceCancelled`, `TokenCreated`, `TradeFilled`; `PaymentSettled` and `MetaTransactionExecuted` keep their
fields. A gasless unwrap emits the same `Unwrapped` as a direct unwrap, plus `MetaTransactionExecuted`.

## 8. Storage layout (clones)

<a id="CTR-TOK-24"></a>**CTR-TOK-24** — **Libraries, namespaces and size budget.** Heavy logic lives in **external**
libraries, linked at deploy and called by `DELEGATECALL` (≈ 2.6 k gas on the first call of a transaction, 100 after);
each library ≤ 24,576 B.

| Library | Content | Kinds |
|---|---|---|
| `TradeLib` (built, 3,104 B) | `TradeOrder` checks, `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces`, `restorePulled` (CTR-DEX-27), the token side of fills; `scaas.trade` | all |
| `AdminLib` | flag validation, roles, owner, `disableFeature` (built, 3,406 B); later freeze / force / pause / allowlist | all |
| `WrappedLib` (built, 11,658 B) | legs; the core of wrap and unwrap **without a destination** (pull, rate, reserve; pay out); rate changes with timelock; `disableWrap`; the reserve invariant | `WRAPPED*` |
| `ZetherLib` (built, 15,662 B) | statements, verifier calls, account updates, roll-over, shield / unshield, disclosure entries | `*_ZETHER` |
| `HederaLib` | HIP-632 signature path (`requireValid`, public view, linked; 753 B), HTS associate | all (branch on `IS_HEDERA`, [CTR-TOK-23](#CTR-TOK-23)) |

- **Pay stays inline** (controller ruling, pending the owner): `mtxPay`, `payWithFee` and `mtxPayReceiverFee` are thin builders over the inline `MetaTransfer` core, which a library cannot call; each checks the `PAYABLE` flag.
- **Inline in the token**, never behind a library: ERC-20 `transfer`/`transferFrom`, the core of a `MetaTransfer`, and
  the per-transfer administration check (a bit test plus a mapping read, cheaper than a `DELEGATECALL`).
- **Signature check:** one internal `SigCheck` for every contract ([CTR-MTX-25](metatx.md#CTR-MTX-25)).
- **Storage:** every module keeps its state in its own ERC-7201 namespace: `scaas.metatx`, `scaas.token` (features,
  roles, kind, version), `scaas.trade`, `scaas.pay`, `scaas.admin`, `scaas.underlying`, `scaas.zether`. A library gets
  its storage pointer from the fixed slot, so libraries never overlap; a test proves that a write through one library
  never changes another namespace.
- **Size budget:** each token implementation ≤ 20,480 B (≈ 4 KB left for later streams); CI fails the build when a
  contract exceeds its budget. **Transitional (BUILT, P1e):** `scripts/size_gate.py` runs in CI over
  `forge build src --sizes --json` as a ratchet (controller ruling, pending the owner): token implementations ≤ 20,480 B,
  other contracts ≤ 24,576 B, init code ≤ 49,152 B, and a contract named in `smartcontracts/evm/size-baseline.json`
  may exceed its limit but never its recorded size (UA-4, with the UA ledger: `NormalToken` 31,770 B, `WrappedToken` 39,189 B, `NormalZetherToken` 40,067 B, `WrappedZetherToken` 49,778 B, and its init code 51,473 B as the entry `WrappedZetherToken.init` over EIP-3860; owner decision 2026-10-11: optimise
  later, wait for the Glamsterdam fork, code size is not a concern); the baseline does not tighten itself, so a smaller contract's entry is lowered by hand.
  Every token implementation now needs a chain with 64 KiB code (anvil `--code-size-limit 65536`, SCaaS testnet), and
  `deploy.sh` and the node e2e pass `--code-size-limit 65536` to `forge script` (`deploy.sh` also `--slow`: one tx per block; parallel broadcast can strand a deploy tx that doesn't fit the block's remaining gas).
  **Flag:** with P2a `NormalToken` is over its 20,480 B budget (still under EIP-170).

**Transitional (BUILT, P1d).** `MetaTokenBase` state is in `scaas.token`, the legs in `scaas.underlying`
(`0x38d6f7ed…cd1000`); the rest is OpenZeppelin ERC-20 slots 0–4 only.

Each clone has its own storage, `DELEGATECALL`ing a never-upgraded implementation, so there is no cross-version layout
constraint. The layout is still pinned (indexers and storage proofs read `reserve`) by `test_storageLayoutIsPinned`,
which compares the solc `storageLayout` in the build artifact (`extra_output`) with `test/v2/layout/*.json` per
implementation (the same data as `forge inspect <Contract> storageLayout`, without enabling `ffi` in tests). Order
(OpenZeppelin 5.2, non-namespaced):

| Slot | Owner | Variable |
|---|---|---|
| 0–4 | `ERC20` | `_balances`, `_allowances`, `_totalSupply`, `_name`, `_symbol` (last two unused; getters overridden); nonces live in ERC-7201 `scaas.metatx` |
| NS+0 | `WrappedLib` (`scaas.underlying`) | `legs` `mapping(uint256 ⇒ Leg)` at `keccak256(abi.encode(i, NS))`: slot a `token ‖ decimals ‖ wrapEnabled ‖ adjustable`, +1 `num ‖ den`, +2 `reserve` |
| NS+1, NS+2 | 〃 | `legIndex` `mapping(address ⇒ uint256)` (index + 1); `pending` `PendingRate` (one per token) |
| NS+3 | 〃 | `legCount ‖ rateDelay ‖ maxRateStepBps` (roles and flags are in `scaas.token`) |

```solidity
struct Leg { address token; uint8 decimals; bool wrapEnabled; bool adjustable;   // slot a (adjustable copied here so a
                                                                                  //   fixed-rate wrap reads no config)
             uint96 num; uint96 den;                                              // slot b
             uint256 reserve; }                                                   // slot c
struct PendingRate { uint8 leg; uint96 num; uint96 den; uint56 eta; }           // one slot; eta == 0 ⇒ none
```

Immutables (implementation): `FACTORY`, `_SELF`, `SMART_KEY_ACCOUNT_IMPL`, `_SMART_KEY_CLONE_CODEHASH`, `CHAIN_UID`, `IS_HEDERA`;
constant `KIND`. The ticket and sender live in transient storage, never in a slot.
The constructor sets `scaas.token.initialized` on the implementation's own storage (it cannot be initialized). Renouncing
the rate admin sets `rateAdjustable = false`, `rateAdmin = 0` and drops the pending change; the per-leg `adjustable`
copy stays set (wrap then reads an empty `_pending`, one extra SLOAD), so fixed-at-creation tokens keep the cheap path.
The controls of flags 5–8 live in the `scaas.admin` namespace ([asset-suite.md](asset-suite.md#storage), [CTR-TOK-24](#CTR-TOK-24)).

## 9. Gas

- Hot path (transfer, `pay`, fees, named functions) touches no kind-specific storage: the same SLOAD/SSTORE set as the measured
  built path, plus the payee comparison (< 100 gas); the `PAYABLE` gate adds one cold SLOAD of `scaas.token.features`
  to every pay entry (`mtxPay` on a fresh lane 56,182 vs 53,568, +2.6 k). Budget: every row of the gas table
  ([metatx.md](metatx.md#gas)) within **+300 gas** on the generic path; named `mtxTransfer` is +9 execution gas over
  `mtxExecuteTransfer` (33,681 vs 33,672): logged, not asserted.
- `mtxPay` adds one `keccak256` of 46 bytes (~40 gas) and saves the dynamic `data` and two words of calldata.
- `mtxBatch` saves the 21 000 intrinsic gas per item after the first, plus warm re-reads of shared slots (the fee
  recipient's balance, the relayer's own lane state), minus the ABI overhead of `MetaTransaction[]`/`bytes[]`. The
  token address itself is pre-warmed in a single transaction too (EIP-2929 `tx.to`), so there is no cold-account
  saving. The first use of a lane (+17 k) is unchanged.
- Wrap/unwrap: leg slots a–c (6 300 cold) + reserve SSTORE + one `balanceOf` before and one after the transfer + the
  transfer itself. No length SLOAD (legs are a mapping), and fixed-rate tokens read no rate-config slot (the
  `adjustable` flag lives in leg slot a); adjustable tokens add one `_pending` SLOAD (2 100). Multi adds one
  `_legIndex` SLOAD. Rate functions are rare: a multi `executeRate` reads every leg (≤ 8 × 3 cold slots) plus one
  `balanceOf` per leg.
- Gasless unwrap (estimate): envelope (≈ 35 k warm lane, plus the self-call and ticket ≈ 3 k) + fee if any (≈ 8 k) + leg reads, burn and reserve write
  (≈ 15 k) + the underlying's `transfer` and two `balanceOf` (≈ 30–40 k for a plain ERC-20). For a proxied stablecoin
  and a fresh recipient add its 0 → non-zero balance SSTORE (+20 k), the cold implementation hop (+2.6 k) and blacklist
  reads (+4.2 k): expect **≈ 110–130 k** for USDC to a new address, ≈ 85–100 k for a plain token to an existing
  holder.
- Size: each implementation ≤ 20,480 B and each library ≤ 24,576 B, enforced in CI ([CTR-TOK-24](#CTR-TOK-24)); the rate
  timelock lives in `WrappedLib` (clone → implementation → library delegatecall keeps the clone's storage).

## 10. Hedera

<a id="CTR-TOK-23"></a>**CTR-TOK-23** — **Hedera is a per-chain variant, not a creator's choice, and has no child
contracts.** Each implementation is deployed with an immutable `IS_HEDERA`. When set, the signature check takes the
HIP-632 path and `WrappedLib` associates HTS underlyings fail-closed (`HederaLib`); the rules are
[NET-HED-14](../networks/hedera.md#NET-HED-14). The four copies of the HIP-632 override become one `IS_HEDERA` branch in `MetaTokenBase`
calling `HederaLib.requireValid`; every implementation carries the ≈ 0.5–1 KB of Hedera branches.

**Transitional (BUILT, P1c).** `IS_HEDERA` is built (kind `NORMAL` on Hedera is `NormalToken`; its Hedera child is
deleted). P1d deletes the wrapper children too: the fail-closed HTS check and association run in `WrappedLib` init under `IS_HEDERA`.
The signature rule is one `IS_HEDERA` branch in `MetaTokenBase` calling `HederaLib.requireValid` (`src/hedera/HederaLib.sol`),
not a per-child override or an abstract mixin on the base (a diamond with the tier); it serves `mtxTrade` too. Domain (with `salt` = the relay's block-0
hash, confirmed stable across mirror-node and relay restarts before it is fixed), ABI, events and tests are the EVM
ones. A plain transfer to `address(0)` fails at the shape step with OpenZeppelin's `ERC20InvalidReceiver` (as built: at
step 6 instead of step 8, "step 8 must not fail"; `mtxUnwrapWithFee` is decoded in `MetaTokenBase.fallback`, `dataEnd` too deep).

## 11. No migration

Nothing is deployed, so the one base and the one factory replace the built lines in place: there is no version
coexistence and no migration path. Clients still read the domain (`eip712Domain()`) and the pay lane (`payLane(payId)`)
per token, never from a constant ([CTR-MTX-02](metatx.md#CTR-MTX-02)). Client token records carry `kind`
(`NORMAL`, `WRAPPED`, `NORMAL_ZETHER`, `WRAPPED_ZETHER`), `features` and `lockedFeatures`, the underlying list, the per-leg rates (a read-only mirror of
`legOf`) and the pay-lane tag (`pay_lane_tag`); the node token table adds `kind` and reads `payLane`. A later bug fix
is a new implementation version in the factory and a voluntary move of value by its holders
([CTR-GEN-02](README.md#CTR-GEN-02)).

## <a id="conformance"></a>12. Conformance

Unit (forge, `test/v2/`):

| Area | Tests |
|---|---|
| Base | both typehashes pinned (`test_metaTxTypehashIsPinned`, `test_metaTransferTypehashIsPinned`, [CTR-MTX-15](metatx.md#CTR-MTX-15)); salted-domain KATs `test/vectors/metatx_kat.json` (v3 `MetaTransaction`, `MetaTxBase`; with the relayed calldata, P5; the v1 vector is in `legacy/p5/`) and `metatransfer_kat.json` plus an `mtxpay` vector with `batch = payLane(payId)`, `nonce = 0` and `mtxExecute` calldata vectors per allowlisted selector, all checked by Solidity, node and the client library (its lane derivation already equals `payLane`); `MetaNonceCancelled`; the allowance rule on every kind (EOA caller and EOA spender of `approve` refused); ERC-1271 400 k only for `SmartKeyAccount` clones; `chainUid()` equals the implementation's; the factory refuses an implementation with another `chainUid()` |
| Fees | percent on the basis, fee on top, 1 % cap on transfer, payment and `AMOUNT` selectors; `ABSOLUTE` selectors uncapped and `PERCENT` refused; `FeeRecipientIsPayee` for transfer, `pay`, `payWithFee`, bound and relayer-default |
| Gasless unwrap and wrap | `mtxExecute(unwrap(…))`: fee in wrapped units after the call; `UnwrapRecipientInvalid` for 0 and `address(this)`; `UnwrapBelowMin`; underlying revert (blacklist mock) reverts fee and nonce; sender-pays fee-on-transfer ⇒ `UnderlyingTransferMismatch`; ERC-777 mock whose hook re-enters (`cancelNonce`, `transfer`) mid-unwrap ⇒ `Reentrancy`; not allowlisted on tier 1; works on a disabled leg and during a pending rate change. `mtxExecute(wrap(…))` pays its fee from minted units. `mtxWrap` on `WrappedToken` (built, P2a; `WRAPPED_ZETHER` P3): price, minimum, fee to the relayer, `WrapReceivedMismatch`, unknown underlying refused |
| Named | `testFuzz_namedDigestEqualsGeneric` over random struct fields for every named function; a signature consumed by a named call fails on the generic path and vice versa; every `MtxModeShape` case; a no-fee struct signed with a leftover `fee ≠ 0` fails through `mtxTransfer`; `mtxPay` lane equals `payLane`; second `mtxPay` of a `payId` reverts `MetaTxBadNonce`; `payWithFee` with the same `entryRef` still emits `PaymentSettled` (documents the per-path limit); `mtxBatch` atomic (one bad item reverts all), length mismatch, empty |
| `NORMAL` | init mint to `initialHolder`; `mint` with `MINTABLE` and `MissingRole`; `burn` with `BURNABLE`; fixed supply without `MINTABLE`; `disableFeature(MINTABLE)` |
| `WRAPPED`, one leg | rate 1:1 equals the removed v1 wrapper's behaviour; rounding down on wrap/unwrap; `burned = ⌈out·q⌉`; `previewWrap` `used`; `WrapTooSmall`/`UnwrapTooSmall`/`UnwrapBelowMin`; two-argument `unwrap` = `minOut 0`; fee-on-transfer inbound measured; sender-pays fee-on-transfer reverts `UnderlyingTransferMismatch`; donation not counted; `ReserveShortfall` after a negative-rebase mock stops wrap and not unwrap; `addReserve`; decimals snapshot; init refusals |
| Rates | fixed ⇒ `RateFixed`; propose/cancel/execute; only the admin executes (`NotRateAdmin` for anyone else); delay and window bounds; an expired change counts as none for `proposeRate`, `pendingRate()` and the pause; step bound both directions at the exact edge; decrease refused without collateral, accepted after `addReserve`; execute refused with `ReserveShortfall` when any leg's balance is below its reserve (shock, then decrease); `collateralValue` saturates and `executeRate` exits early on a huge leg; revoking or renouncing the rate role leaves the rate, `disableFeature(RATE_ADJUSTABLE)` cancels a pending change; EOA admin refused at init; wrap paused on **every** leg while anything is pending, reopens on execute/cancel/expiry, unwrap and `addReserve` open |
| `WRAPPED`, several legs | 2–8 legs, duplicates, zero; per-leg reserves; unwrap bounded by `reserve_i`; guardian disable one-way and idempotence error; unwrap open on a disabled leg; `addReserve` refused on it; `RateDecreaseWithDisabledLeg`; the cross-leg scenario (pending decrease on leg `i`, flash-wrap of leg `j`) reverts `WrapPausedForRateChange` and a third-party `executeRate` reverts `NotRateAdmin`; single-asset ABI reverts `UnderlyingRequired` with more than one leg |
| Factory (`Factory.t.sol`) | zero `chain_uid` refused; envs (registrar, versioned, never changed, the factory's own; a release names a published one, an older env stays usable); library code hashes; deployment checks `kind()`, `factory()` and `chainUid()`, bubbles a constructor's revert, refuses reserved kinds, emits the release hashes; notice period; kind gate; `deprecate` refuses new tokens of that version; one `TokenCreated` with provenance; every leg indexed, native included; leg count by kind (`NORMAL` 0, `WRAPPED` 1–8); unknown version; salt scoped by creator and not reusable; `createTokenUnregistered` checked and recorded as version 0; the factory only forwards, the token validates flags and fields (`ConfigFieldForOtherKind`); only the factory initialises, once; `kind()` constant; sizes |
| Features | every invalid combination of [CTR-TOK-22](#CTR-TOK-22) reverts with its error (`FeatureInvalidForKind`, `LockedNotSubset`, `RoleWithoutFeature`); owner grant/revoke, holder `renounceRole`, `renounceOwnership` (holders keep roles), `disableFeature` on a locked, a disableable and an already-clear bit; `PAYABLE` off ⇒ `supportsInterface(IERC20Payment)` false and pay reverts; rate fixed vs adjustable; guardian; the four regulated flags (existing asset-suite cases on the ordinary kinds) |
| Layout | `test_storageLayoutIsPinned` per implementation; library storage isolation (a write through one library never changes another namespace); the size gate ([CTR-TOK-24](#CTR-TOK-24)) |
| Hedera | HIP-632 path under `IS_HEDERA` (mocked precompile, as in `test/hedera/`); association at init; fail-closed custom-fee check: `isToken` rc ≠ SUCCESS, `getTokenCustomFees` rc ≠ SUCCESS, and a non-empty fee list each refuse the underlying |

Invariant / fuzz (`test/v2/WrapperInvariant*.t.sol`, `[invariant] runs = 64, depth = 32, fail_on_revert = true`, with
handlers that bound inputs so expected reverts do not count as failures). One invariant contract per rate setup:
`1:1`, `10¹²:1`, `1:10⁴`, `(2⁹⁶−1):1`, `1:(2⁹⁶−1)`, `3:7`.

- Handlers: wrap / unwrap (direct and gasless) / `addReserve` on random legs with random actors; plain
  donations; fee-on-transfer and plain underlyings; meta-tx transfers with fees; propose / cancel / execute rate
  changes; `warpToEta`, which jumps exactly to `eta` or to `eta + 7 days`; guardian disables; negative-rebase shocks
  on a mock leg; a ghost attacker that trades only through wrap/unwrap.
- Invariants:
  - `collateralValue() ≥ totalSupply()` and `Σ balances == totalSupply()`;
  - **slack never decreases**: `C − S` (ghost of the previous value) is non-decreasing across every handler call
    except a rate execution;
  - per-leg conservation: `Σ received_i + Σ addReserve_i − Σ out_i == reserve_i`; `balanceOf_i ≥ reserve_i` for
    well-behaved legs;
  - **profit oracle**: the ghost attacker's holdings valued at nominal par never increase over a sequence that
    contains no rate execution (catches the cross-leg class);
  - every executed rate change satisfied the step bound, waited `rateDelay` and was sent by the admin; no wrap
    succeeds while a change is pending; a disabled leg is never re-enabled.
- Fuzz: `testFuzz_wrapUnwrapNeverProfits(amount, num, den)`; cross-leg `testFuzz_wrapIUnwrapJNeverProfitsAtPar`;
  `testFuzz_stepBoundExact(num, den, num', den', bps)` against a reference in 512-bit arithmetic;
  `testFuzz_feeConservesSupply`.

Cross-family vectors: `test/vectors/wrap_rate_vectors.json` — `(num, den, in) → (minted, used)` and
`(num, den, w) → (out, burned)` incl. edge cases (`2^96 − 1`, `den = 1`, zero outputs), written by
`test_writeRateVectors` and later replayed by the Cosmos, Soroban and GRAM wrappers. `metatx_kat.json` (v3, `MetaTxBase`) and `metatx_v1_kat.json` (built v1) are EVM/Hedera
only.

## 13. Limitations

- Non-EVM wrappers: Cosmos, Soroban and GRAM keep their standalone (`NORMAL`) tokens; wrappers there (a bank denom or CW20 on Cosmos,
  a Stellar Asset Contract on Soroban, third-party jettons through a wrapper minter on GRAM) are **PLANNED** with the
  same rate/reserve rules and the shared rate vectors; Move and Solana need no wrapper for gaslessness
  ([NET-ALL-19](../networks/README.md#NET-ALL-19)).
- Gasless wrap: **SPECIFIED** (`mtxExecute(wrap)`, [CTR-TOK-20](#CTR-TOK-20)).
- Non-fungible in-app assets (ERC-721/1155 with meta-tx): new kinds, **PLANNED**.
