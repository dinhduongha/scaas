# Token wrappers v2: three tiers, conversion rates, multi-underlying, named meta-tx functions

Status: draft rev 1.2, 2026-10-06. Rev 1.1 folded in the owner's answers to the two rev-1 open questions (adjustable
Multi rates, R147; gasless unwrap, R148). Rev 1.2 folds in independent review 1 (FIX-THEN-GO: H1–H2, M1–M6,
L1–L13, over-engineering list) and the owner's decision on H1/H2; disposition in §17. Code at `scaas` `main` fc6e3d0 (after the
`bamboo` → `scaas` rename). **Build status:** T1–T6 and T8 built (EVM + Hedera contracts, tests, docs); T7 (node,
Odoo, SDK) open. Implementation notes and deviations: §18.
Rulings: **R129–R149** (§2). Owner rulings of 2026-10-06 (three tiers, rates as an issuer option, multi-underlying
with a guardian that can only disable wrap, named functions as thin entry points, requirement trace) are folded in.
**Naming:** the code rename has landed: v1 is `("SCaaS MetaToken", "1")` with `scaas.pay.lane` and
`scaas.metatx.reentrancy.v1`. v2 uses `("SCaaS MetaToken", "2")`, the same `scaas.pay.lane` tag, and
`scaas.metatx.reentrancy.v2`.

Amends:

| Short | File | How |
|---|---|---|
| SCaaS | `docs/SCaaS.md` | §4.1–4.3, §4.9, §5.4, §5.5, §5.7, §5.8, §14.1, §14.2, §15 updated to point here |
| PD | `docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` | R2 amended (named `mtxPay` exists, still no second typehash); R9 amended (v2 derives the pay lane on chain) |
| R3D | `docs/superpowers/specs/2026-10-03-blockchain-round3-design.md` | none; R26 and R35 are inherited unchanged |
| research | `blockchain-research/01-token-factory.md` §1.6–1.7 | `WRAP_1_1` accounting adopted (internal reserve); "no basket in v1" kept, since tier 3 here is *any-of*, not a basket |
| SCaaS §5.8 | proposed `PAY_TYPEHASH` fast path | **superseded** by R140 (no second typehash) |

Inputs: owner requirement trail `Grok3_Continued.md` (user turns only; the other AI's code is non-normative), the
code under `smartcontracts/evm/src` (`metatx/`, `factory/`, `common/FeePolicy.sol`, `common/MetaTxLib.sol`,
`hedera/HederaMetaToken.sol`) and the non-EVM token contracts.

---

## 1. Scope and summary

v2 replaces the single `MetaToken` implementation (one contract, tier picked by `underlying == 0`) with three
contracts in a parent/child tree, adds per-underlying **conversion rates**, a **multi-underlying** (any-of)
wrapper, a **gasless unwrap** op, and **named** meta-tx functions that are thin entry points over the existing
nine-step pipeline. The
`MetaTransaction` struct, its typehash and the digest rule do not change, so every signature format, KAT and
client builder stays valid. Only the domain (`name`, `version`, `verifyingContract`) differs per implementation,
as it already does today.

Out of scope: baskets (proportional, weighted multi-asset redemption; research §1.7.6 recommendation kept), oracle
rates, rebasing/share wrappers (ERC-4626 style), controlled tokens (SCaaS §4.5), Zether (unchanged), receiver-pays
(SCaaS §5.9).

```
IERC20MetaTx ── IERC20Payment ── IMetaTokenV2 (named functions, §7)
                                     │
MetaTxCore (abstract)  ← nine-step pipeline over a memory struct, R26 lockdown, FeePolicy, 2D nonces
 └── MetaTokenBase (abstract)  ← ops pay/trade/approve(/unwrap), payWithFee, named functions, init, provenance
      ├── NoUnderlyingToken          kind META_NONE    issuer-minted (initialSupply, optional minter, burn)
      └── SingleUnderlyingToken      kind META_SINGLE  one underlying, rate, reserve, optional rate timelock
           └── MultiUnderlyingToken  kind META_MULTI   2..8 underlyings, per-leg rate + reserve, guardian
Hedera children: HederaNoUnderlyingToken, HederaSingleUnderlyingToken, HederaMultiUnderlyingToken (§11)
```

---

## 2. Rulings

Format: **ruling — reason — cost if wrong.**

- **R129** (owner) Three tiers, parent/child: `NoUnderlyingToken`, `SingleUnderlyingToken`,
  `MultiUnderlyingToken is SingleUnderlyingToken`, all on `MetaTokenBase is MetaTxCore`. Each is its own
  implementation and factory kind — the transcript asks for the tree (turns 4145, 5867), and one contract per tier
  keeps each implementation's audit surface to what it holds — if wrong: one combined implementation like v1, more
  code per clone, same ABI.
- **R130** Factory v2 is a **new `OpenFactory` deployment**; `TokenKind` appends `META_NONE = 2`,
  `META_SINGLE = 3`, `META_MULTI = 4` (values never reused; `META = 0` stays the v1 combined kind). New
  `createTiered`/`createTieredUnregistered` take `address[] underlyings`; `registerImplementation` checks
  `tokenKind()` of the implementation (`VersionKindMismatch`). Factory v1 is immutable and its enum cannot decode new
  values; v1 tokens keep their provenance there — if wrong: tiers would hide inside `META` versions and the catalogue
  could not say which tier a version is.
- **R131** v2 meta-tx base `MetaTxCore`: same `MetaTxLib` struct, typehash, `canon` and nine-step order; domain
  `("SCaaS MetaToken", "2", chainId, clone)` for all three tiers; pipeline runs over a **memory** struct so that named
  functions can build one (§7.1); v1 sources (`ERC20MetaTx.sol`, `MetaToken.sol`) are frozen. Adds the planned
  `MetaNonceCancelled` event — R5 already puts replay safety on `verifyingContract`, and the version string tells
  wallets which ABI they face — if wrong: wallets show one name for three tiers (they read `name()` for the token
  name anyway).
- **R132** (owner) **The fee never goes to the payee.** For the transfer and `pay` ops and for `payWithFee`,
  `feeAmount != 0 && resolvedFeeRecipient == to` reverts `FeeRecipientIsPayee` at step 6. Applies whether the
  recipient was bound by the signer or defaulted to `msg.sender` (a payee self-relaying with a fee is refused). The
  fee mode, amount and recipient stay the signer's choice through `mode` (turn 3293); the 1 % cap (`MAX_FEE_PPM`) and
  "percent of the sender's amount, charged on top" (turn 5296) are unchanged — if wrong: a payee could collect a fee
  that its invoice does not show; the check costs ~100 gas.
- **R133** Conversion rate = `(num, den)`, `uint96` each, `1 ≤ num, den < 2^96`, meaning **wrapped raw units per
  underlying raw unit**. Every output rounds **down** (in the contract's favour): `minted = ⌊in·num/den⌋`,
  `out = ⌊w·den/num⌋`, and unwrap burns only `⌈out·num/den⌉ ≤ w` (the holder keeps the dust). Zero output reverts
  (`WrapTooSmall`, `UnwrapTooSmall`). Wrap dust (the part of `in` that mints less than one wrapped unit, i.e. less
  than `⌈den/num⌉` raw underlying) stays in the reserve; `previewWrap` returns `(minted, used = ⌈minted·den/num⌉)` and
  clients round `in` down to `used` — if wrong: dust is lost to the reserve instead of to the holder; either way
  never to a third party.
- **R134** Reserve accounting is internal: `reserve_i` changes only through `wrap`, `unwrap`, `addReserve`. The
  token's solvency invariant is **`collateralValue() := Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()`**, plus
  `underlying_i.balanceOf(this) ≥ reserve_i` while the underlying behaves. Wrap mints the **measured** balance delta;
  unwrap requires the balance to drop by exactly `out` (`UnderlyingTransferMismatch`); wrap and `addReserve` refuse
  while `balanceOf < reserve_i` (`ReserveShortfall`); unwrap never checks that, so exits stay open — research §1.6.1
  (donations and rebases break the `==` form; internal accounting does not) — if wrong: donations or rebases would
  move the redemption price.
- **R135** (owner option) Rate mode is chosen **at creation**: `fixed` (default; no setter exists) or `adjustable`.
  Adjustable: a `rateAdmin` that **has code** (same `_isContract` as R26; meant to be a multisig or timelock, which
  the contract cannot prove); propose → wait `rateDelay` (default 7 days, bounds [2 days, 30 days]) → **only the
  `rateAdmin` executes**, within a 7-day window (owner, rev 1.2: no third party can bundle the execution with its own
  wraps); **one pending change per token**, and while it is pending **wrap is paused on every leg** (unwrap stays
  open); each step ≤ `maxRateStepBps` (default 100 = 1 %, bounds [1, 1 000]); every execution requires
  `balanceOf_i ≥ reserve_i` on every leg and `collateralValue() ≥ totalSupply()` afterwards; balances never change
  (no rebase). `rateAdmin` can renounce (one-way, drops a pending change, the rate becomes fixed); it cannot be
  transferred. Delay, step and admin are set once — if wrong: a holder who disagrees has at least `rateDelay` to
  unwrap at the old rate, bound by `minOut` (R148), and loses at most one step per delay.
- **R136** (owner) Multi-underlying = **any-of**: the underlying set (2–8, no duplicates) and each leg's initial
  rate are set at creation and never added to or removed (rates themselves may be adjustable, R147); a user wraps one chosen underlying and unwraps into one
  chosen underlying, bounded by that leg's reserve (`InsufficientReserve`). A `guardian` (set at creation, optional,
  may be an EOA) has exactly one power: `disableWrap(underlying, reason)` — one-way; unwrap from a disabled leg stays
  open. A disabled leg refuses `addReserve`, and no rate change that lowers `collateralValue()` executes while any leg
  is disabled — if wrong: a re-enable power would let a compromised guardian reopen a depegged inflow and drain the
  good legs.
- **R137** Decimals are display only. `decimals()` of every v2 token is the issuer's choice at creation; rates are in
  raw units, so `1 human unit of U_i = num_i/den_i × 10^(D − d_i)` wrapped human units (`D` = wrapper decimals,
  `d_i` = underlying decimals, snapshot at init). Underlyings without a readable `decimals()` are refused
  (`DecimalsUnreadable`) — if wrong: a UI could not show the human rate.
- **R138** (owner) Named functions `mtxTransfer`, `mtxTransferWithFee`, `executeMetaTransactionWithFee`, `mtxPay`,
  `mtxUnwrap`, `mtxUnwrapWithFee` (R148) and the batch `mtxBatch` live in `MetaTokenBase` (so every tier has them, turn 4667) and **only build a
  `MetaTransaction` and run the same pipeline**. Each enforces a mode shape (`MtxModeShape`), nothing else. The
  digest of a named call equals the digest of `executeMetaTransaction` with the same struct, so one signature works on
  both paths and one lane is consumed once — if wrong: nothing breaks, the names are ABI sugar.
- **R139** `mtxPay(…, payId, …)`: `payId` **is** the R9 `entryRef` (`PaymentSettled.entryRef`), and the lane is
  derived **on chain**: `batch = payLane(payId) = uint256(keccak256("scaas.pay.lane" ‖ payId))`, `nonce = 0`, so
  `mtxPay` pays a given `(payer, payId)` at most once **through `mtxPay`**. The same `entryRef` can still appear in a
  `PaymentSettled` from `payWithFee`, from the generic `pay` op on another lane, or after `cancelMetaNonce` on a later
  nonce (as in v1): reconcilers match `(payer, payee, amount, entryRef)` and treat a second event for the same
  `entryRef` as an exception, never as a second payment — if wrong: a client that wants a different lane for a
  payment uses `executeMetaTransaction` with the `pay` op (still valid).
- **R140** No second typehash. The SCaaS §5.8 proposal (`PAY_TYPEHASH`, `batchMtxPay` with a partial-success bitmap)
  is withdrawn: R2's reason holds (one type, one wallet display), and the owner ruled thin entry points. `mtxBatch` is
  **atomic** (all items or none) — partial success would need a non-reverting copy of steps 1–6 — if wrong: one
  failing item costs the relayer the whole batch's gas; the node batches only items bound to its own lane (§7.5).
- **R141** `NoUnderlyingToken` keeps v1 tier-1 semantics (`initialSupply` to `creator`, optional `minter`,
  `minter == 0` ⇒ fixed supply) and adds `burn(amount)` by the holder and `renounceMinter()` (one-way) — HANDOFF
  GA 2.2 #1 — if wrong: issuers keep the supply alive with a minter they cannot retire.
- **R142** "No one alters a deployed token" holds with exactly two creation-time, visible exceptions: the R135
  rate admin (only if the issuer chose `adjustable`) and the R136 guardian (only `disableWrap`). Neither can mint,
  move balances, touch reserves, pause unwrap, or add/remove an underlying. The factory and its registrar have no
  power over any token. `rateAdjustable()`, `rateAdmin()` and `guardian()` are public so wallets and indexers flag
  them — if wrong: holders would have to read code to learn a token has an admin. (The R147 wrap pause is a
  consequence of a pending rate change, not a separate power.)
- **R143** Fee-on-transfer underlyings: inbound handled (measured delta), outbound must be exact (sender-pays fee
  designs revert on unwrap and are therefore **unsupported**; UI refuses them). Rebasing underlyings are
  **unsupported**: a positive rebase is a locked donation; a negative rebase stops wrap (R134) and leaves a
  first-come exit — disclosure §6.6 — if wrong: an unsupported underlying can lock or socialise a loss; the contract
  cannot detect one at creation.
- **R144** Hedera children (§11) inherit everything and add HIP-632 signatures (R63); `initialize` associates every
  HTS leg and refuses, **fail-closed**, any HTS underlying whose custom-fee query does not return SUCCESS with an
  empty fee list.
- **R145** Non-EVM (§12): **EVM and Hedera only in this version.** Cosmos, Soroban and TON keep their tier-1 tokens;
  wrappers there are PLANNED with the same rate/reserve rules and the shared rate vectors (§10.4). Move and Solana do
  not need wrappers for gaslessness (the subject account holds any coin/asset), so no v2 there. Named functions are
  EVM-only (non-EVM ops are already named). Relayer fees stay `NONE` off EVM (R10/R75).
- **R146** Migration: v2 is a new implementation per kind in factory v2; v1 clones and factory v1 are untouched;
  moving value is voluntary (`unwrap` v1, `wrap` v2). Clients read the domain (`eip712Domain()`) and the pay lane
  (`payLane(payId)` on v2; the off-chain R9 derivation for v1) per token, never from a constant — if wrong: a tag
  change in a later version would make that version's payments unsignable.
- **R147** (owner, rev 1.1, tightened rev 1.2) **Multi-underlying rates may be adjustable per leg**: issuer option at
  creation, default **off**, same timelock as R135 (admin-only execution, one pending change per token, wrap paused on
  **all** legs while it is pending, `minOut` on every unwrap). Changing one leg's `q_i` changes the price of that leg
  against every other leg, in either direction: a raise makes wrapping `i` and redeeming another leg profitable; a
  decrease makes wrapping another leg and redeeming `i` profitable (review H1). The guards remove the front-run at the
  old rate (no leg can be wrapped while a change is pending) and the third-party flash bundle around the execution
  (only the admin executes). They do **not** remove the value shift itself: once a change has landed, a leg priced
  off its market value is an arbitrage from the next transaction on, and holders who exit through different legs end
  up with different value. Residual risk §8.5; recommendation: fixed rates, or a multisig/timelocked `rateAdmin`
  that only moves legs toward their market value. The rev-1.1 share cap (`maxLegShareBps`) is **deleted**: anyone
  could switch it off or trip it atomically with a flash loan (review H2) — if wrong: the literal reading of ruling 3
  (Multi rates immutable) removes the channel entirely; fixed remains the default.
- **R148** (owner, rev 1.1; `minOut` rev 1.2) **Gasless unwrap.** New op `unwrap(address underlying, address
  recipient, uint256 minOut)` (100 bytes, `OP_UNWRAP = bytes4(keccak256("unwrap(address,address,uint256)"))`),
  amount = `m.value` (wrapped units offered), `m.to == recipient`. Step 6 checks it fully (leg known,
  `recipient ∉ {0, address(this)}`, `0 < out ≤ reserve`, `out ≥ minOut`); step 7 takes the fee **in wrapped units**
  and writes the nonce; step 8 burns `⌈out·q⌉`, debits `reserve` (effects), then transfers the underlying with the
  R134 exact-amount check (interaction, CEI, under the contract-wide guard). Named entry points `mtxUnwrap` and
  `mtxUnwrapWithFee`; direct `unwrap` overloads take `minOut` too. The underlying's own transfer is the **only** thing
  allowed to fail after step 7; it reverts the whole transaction (fee and nonce included), so "fee collected ⇔ op
  completed" still holds. R132 does not apply (there is no payee). Fee-on-transfer-out underlyings stay unsupported
  (R143). The node's simulation covers the external call, never batches unwrap items, and exempts from the grief
  score only failures that do not depend on the recipient (§7.6) — if wrong: a holder without native gas can still
  exit only through a contract wallet.
- **R149** Gasless **wrap** stays a normal transaction in v2 (it needs an allowance on the underlying). A meta-tx wrap
  that carries an EIP-2612 `permit` or a Permit2 signature-transfer of the underlying (spender = the wrapper, a
  contract, so R26-compatible) is **PLANNED** only (§7.7) — if wrong: nothing is lost; wrapping is rare next to
  payments.

---

## 3. `MetaTxCore` (the v2 base)

### 3.1 What changes against `ERC20MetaTx` v1

| Item | v1 | v2 |
|---|---|---|
| Struct, `METATX_TYPEHASH`, `hashStruct`, `canon` | `MetaTxLib` | **same library, unchanged** |
| Domain | `("SCaaS MetaToken", "1", chainId, clone)` | `("SCaaS MetaToken", "2", chainId, clone)` |
| Pipeline input | `MetaTransaction calldata` | internal `_execute(MetaTransaction memory m, bytes calldata sig)`; `executeMetaTransaction` passes its calldata struct (one copy — v1 already copies it to memory inside `hashStruct`) |
| `_checkOp` / `_executeOp` | calldata slices, `abi.decode` | memory; arguments read with `mload` at fixed offsets after the length check; an address word with any of its upper 96 bits set ⇒ `MetaTxUnknownOp` (as `abi.decode` would revert), so one op has exactly one encoding and one digest |
| Reentrancy slot | `keccak256("scaas.metatx.reentrancy.v1")` | `keccak256("scaas.metatx.reentrancy.v2")` (transient; the guard covers meta-tx, wrap, unwrap, `addReserve`, `mtxBatch`) |
| Step 6 | balance, fee, recipient non-zero, `_checkOp` | + R132 payee check |
| Step 8 | must not fail | must not fail, except the underlying's transfer inside the R148 unwrap op (reverts everything) |
| Nonce write | step 9 | step 7, with the fee, so no external call (R148) runs while the nonce is unspent; the event stays at step 9 |
| `cancelMetaNonce` | no event | emits `MetaNonceCancelled(from, batch, newNonce)` |
| R26 | `approve` spender contract, `transferFrom` caller contract | unchanged |
| ERC-1271 gas | 50 k; 400 k for `SubjectAccount` clones | unchanged (`SUBJECT_ACCOUNT_IMPL` immutable) |

`MetaTxCore` is a new file; v1's `ERC20MetaTx.sol` and `MetaToken.sol` stay byte-identical (a v1 implementation
built from changed sources would not be v1).

### 3.2 Pipeline (unchanged order)

| Step | Check / action | Error |
|---|---|---|
| 1 | `MODE_RESTRICT_RELAYER` ⇒ `msg.sender == m.relayer` | `MetaTxUnauthorizedRelayer` |
| 2 | `block.timestamp ≤ m.validUntil` | `MetaTxExpired` |
| 3 | `validateMode(m.mode)` | `ModeUnknownBits` / `ModeFeeInvalid` |
| 4 | `m.nonce == metaNonce(from, batch)` | `MetaTxBadNonce` |
| 5 | signature (EOA ECDSA / ERC-1271) over `_hashTypedDataV4(hashStruct(m))` | `MetaTxBadSignature` |
| 6 | resolve `feeRecipient` (`0` ⇒ `msg.sender`), `FeePolicy.compute` on `m.value`, `validateRecipient`, **R132**, balance ≥ value + fee, `_checkOp` | `FeeExceedsCap`, `FeeRecipientRequired`, `FeeRecipientIsPayee`, `MetaTxInsufficientForFee`, op errors |
| 7 | transfer fee; `metaNonce = expected + 1` | — |
| 8 | `_executeOp` | — (must not fail; R148 unwrap: only the underlying's transfer may revert, undoing the whole tx) |
| 9 | `MetaTransactionExecuted(from, relayer, batch, nonce, digest, feeRecipient, fee)` | — |

"Payee" for R132 = `m.to` when `m.data` is empty (transfer) or is the `pay` op. For `trade` the `to` is the
settlement contract and for `approve` the value is 0 (a `FIXED` fee there already fails the 1 % cap, a `PERCENT`
fee computes to 0), so the check does not apply to them.

### 3.3 Ops (`MetaTokenBase`, all tiers)

Same table as v1 (SCaaS §5.4): empty ⇒ transfer; `pay(bytes32)` (36 bytes, `to ≠ 0`) ⇒ transfer +
`PaymentSettled`; `trade(address,uint256,address)` (100 bytes, restricted relayer, `to == msg.sender`);
`approve(address,uint256)` (68 bytes, `value == 0`, `to == spender`, spender a contract). Unknown ⇒
`MetaTxUnknownOp`. Wrapper tiers add `unwrap(address,address,uint256)` (R148, §5.3); on `NoUnderlyingToken` it is
`MetaTxUnknownOp`.

`payWithFee(to, amount, feeMode, fee, feeRecipient, entryRef)` (direct path, `msg.sender` pays gas) is kept and gets
the R132 check.

---

## 4. Tier 1 — `NoUnderlyingToken` (kind `META_NONE`)

`initData = abi.encode(string name, string symbol, uint8 decimals, uint256 initialSupply, address minter)` (v1 ABI).
`underlyings.length == 0`.

| Function | Rule |
|---|---|
| `initialize` | mints `initialSupply` to `creator`; stores `minter` (0 ⇒ fixed supply) |
| `mint(to, amount)` | `msg.sender == minter != 0`, else `NotMinter` |
| `renounceMinter()` | minter only; sets `minter = 0`; `MinterRenounced()`; one-way |
| `burn(amount)` | any holder, own balance; `Transfer(from, 0, amount)` |

Invariant: `Σ balances == totalSupply`. A supply cap or mint-rate limit, if an issuer wants one, belongs in the
minter contract it controls (research §1.6.2), not in this tier.

---

## 5. Tier 2 — `SingleUnderlyingToken` (kind `META_SINGLE`)

### 5.1 Init

`underlyings.length == 1`. `initData = abi.encode(string name, string symbol, uint8 decimals, uint96 num, uint96 den,
RateConfig cfg)`, with

```solidity
struct RateConfig { bool adjustable; address rateAdmin; uint32 rateDelay; uint16 maxRateStepBps; }
```

Checks (all revert at init, so a bad token is never born):

| Check | Error |
|---|---|
| underlying `≠ 0`, `≠ address(this)`, has code | `UnderlyingInvalid(u)` |
| `decimals()` returns a `uint8` (staticcall) | `DecimalsUnreadable(u)` |
| `1 ≤ num, den < 2^96` | `RateInvalid(num, den)` |
| `adjustable == false` ⇒ `rateAdmin == 0 && rateDelay == 0 && maxRateStepBps == 0` | `RateConfigInvalid()` |
| `adjustable == true` ⇒ `rateAdmin` is a contract (R26 `_isContract`), `2 days ≤ rateDelay ≤ 30 days`, `1 ≤ maxRateStepBps ≤ 1000` | `RateAdminNotContract(a)`, `RateConfigInvalid()` |

Client defaults (UI and Odoo wizard): `decimals = d_u`, `num = den = 1` (exactly v1 behaviour), `adjustable = false`;
when the issuer turns on `adjustable`: `rateDelay = 7 days`, `maxRateStepBps = 100`.

### 5.2 Wrap, unwrap, reserve

```
wrap(uint256 amount) returns (uint256 minted)                  // v1 selector kept
    require leg.wrapEnabled                                    // always true in tier 2
    require leg.adjustable ⇒ no pending rate change            // WrapPausedForRateChange (R135/R147; leg slot a)
    before = U.balanceOf(this)
    require before ≥ reserve                                   // ReserveShortfall (one balanceOf serves both)
    U.safeTransferFrom(msg.sender, this, amount); received = U.balanceOf(this) − before
    minted = mulDiv(received, num, den)                        // floor
    require minted > 0                                         // WrapTooSmall
    reserve += received; _mint(msg.sender, minted); emit Wrapped(msg.sender, U, received, minted)

unwrap(uint256 wrapped, address recipient) returns (uint256 out)                    // v1 selector kept: minOut = 0
unwrap(uint256 wrapped, address recipient, uint256 minOut) returns (uint256 out)    // rev 1.2 (review M4)
    require recipient ∉ {0, address(this)}                     // UnwrapRecipientInvalid
    out    = mulDiv(wrapped, den, num)                         // floor
    require out > 0                                            // UnwrapTooSmall
    require out ≥ minOut                                       // UnwrapBelowMin(out, minOut)
    require out ≤ reserve                                      // InsufficientReserve(U, out, reserve) (Multi only;
                                                               //   tier 2 cannot hit it: w ≤ S ≤ ⌊R·q⌋)
    burned = mulDiv(out, num, den, Ceil)                       // ≤ wrapped
    _burn(msg.sender, burned); reserve −= out
    before = U.balanceOf(this); U.safeTransfer(recipient, out)
    require before − U.balanceOf(this) == out                  // UnderlyingTransferMismatch
    emit Unwrapped(msg.sender, U, recipient, burned, out)

addReserve(address u, uint256 amount)                          // anyone; no mint
    same measured pull as wrap, require leg.wrapEnabled and no shortfall; reserve += received; emit ReserveAdded
```

`mulDiv` is OZ `Math.mulDiv` (512-bit intermediate). `addReserve` exists so an issuer can over-collateralise before a
rate change that needs it (§6.3); it is otherwise a donation that raises every holder's backing.

Why the invariant holds (R134), per operation, with `C = Σ⌊reserve·num/den⌋`:

- wrap: `⌊(R+r)·q⌋ ≥ ⌊R·q⌋ + ⌊r·q⌋ = ⌊R·q⌋ + minted` (floor is superadditive), supply rises by `minted`.
- unwrap: `out·q ≤ burned` (ceil), so `(R−out)·q ≥ R·q − burned` and `⌊(R−out)·q⌋ ≥ ⌊R·q⌋ − burned` (burned is an
  integer); supply falls by `burned`.
- `addReserve`: `C` rises, supply unchanged. Transfers, meta-tx and fees: supply unchanged.
- rate change: §6.3.

The plain `underlying.balanceOf(this)` is **not** used for pricing anything; donations sent with a plain transfer are
outside `reserve` and stay locked (no sweep: no owner).

### 5.3 Gasless unwrap op (R148)

| Step | `data = unwrap(address underlying, address recipient, uint256 minOut)`, `value = wrapped`, `to = recipient` |
|---|---|
| 6 | `len == 100`, clean address words (§3.1); leg known (`UnknownUnderlying`; tier 2: the single underlying); `recipient ∉ {0, address(this)}` (`UnwrapRecipientInvalid`); `m.to == recipient` (`UnwrapRecipientMismatch`, so the wallet's "to" is who receives the underlying); `out = ⌊value·den/num⌋ > 0`; `out ≥ minOut` (`UnwrapBelowMin`); `out ≤ reserve`; balance ≥ value + fee (generic) |
| 7 | fee in wrapped units from `from` to the fee recipient; nonce written (generic) |
| 8 | `burned = ⌈out·num/den⌉ ≤ value`; `_burn(from, burned)`; `reserve −= out`; then `safeTransfer(recipient, out)` + exact-decrease check (`UnderlyingTransferMismatch`); `Unwrapped(from, u, recipient, burned, out)` |
| 9 | `MetaTransactionExecuted` (generic) |

Works on disabled Multi legs (exits stay open) and during a pending rate change (at the current rate; `minOut`
protects the signer if the intent lands after the change). The holder keeps `value − burned` (dust) and pays the fee
on `value`.

### 5.4 Views

`underlying()` (tier 2: the single underlying), `underlyings() returns (address[])`, `legOf(address u) returns (uint96
num, uint96 den, uint256 reserve, uint8 decimals, bool wrapEnabled)`, `collateralValue()` (saturates at
`type(uint256).max` instead of overflowing, review L1), `previewWrap(u, amount) returns (minted, used)`,
`previewUnwrap(u, wrapped) returns (out, burned)`, `rateAdjustable()`, `rateAdmin()`, `rateDelay()`,
`maxRateStepBps()`, `pendingRate() returns (address u, uint96 num, uint96 den, uint64 eta)` (all zero when nothing is
pending or the pending change has expired). Previews ignore fee-on-transfer (they assume `received == amount`).

---

## 6. Rates: fixed or adjustable (R133, R135)

### 6.1 Terms

`q = num/den` = wrapped raw units per underlying raw unit. Raising `q` means each wrapped unit redeems for **less**
underlying; lowering `q` means each wrapped unit redeems for **more**.

### 6.2 Adjustable-rate lifecycle

One pending change per token (`PendingRate` in one slot, §10.1). A change is **pending** from `proposeRate` until it
is executed, cancelled, dropped by `renounceRateAdmin`, or its window (`eta + 7 days`) has passed; an expired change
counts as no change everywhere (`proposeRate`, `pendingRate()`, the wrap pause).

```
proposeRate(address u, uint96 num, uint96 den)   // rateAdmin; nothing pending (RateChangePending); RateInvalid;
                                                  //   step bound against the current rate (RateStepTooLarge)
    eta = now + rateDelay; emit RateChangeProposed(u, oldNum, oldDen, num, den, eta)
cancelRate()                                      // rateAdmin; emit RateChangeCancelled(u)
executeRate()                                     // rateAdmin only (rev 1.2); eta ≤ now ≤ eta + 7 days
                                                  //   (RateChangeNotReady / RateChangeExpired)
    every leg: U_i.balanceOf(this) ≥ reserve_i    // ReserveShortfall(u_i, balance, reserve) — no phantom reserve (review M1)
    C' with the new rate, summed with early exit once ≥ totalSupply (review L1)
    require C' ≥ totalSupply                       // RateChangeUndercollateralized(C', supply)
    Multi: a change that lowers C' while any leg is disabled ⇒ RateDecreaseWithDisabledLeg
    apply; delete pending; emit RateChanged(u, oldNum, oldDen, num, den)
renounceRateAdmin()                               // rateAdmin; drops the pending change; rateAdmin = 0 forever; emit RateAdminRenounced()
```

While a change is pending, `wrap` reverts `WrapPausedForRateChange(u)` **on every leg** of the token; unwrap (direct
and R148 op, both with `minOut`) and `addReserve` stay open. The step bound is checked once, at proposal: the current
rate cannot change while a change is pending.

Step bound, exact in integers (`uint96` inputs keep every product below 2^207):

```
|num'·den − num·den'| · 10_000 ≤ num·den' · maxRateStepBps          // RateStepTooLarge
```

Fixed-rate tokens have no pending storage in use and every function above reverts `RateFixed()`.

### 6.3 Safety analysis

| Direction | Effect on holders | Solvency | Control |
|---|---|---|---|
| Raise `q` | Redemption value of every outstanding unit falls by ≤ one step (dilution). New wrappers get more units per underlying. | `C` rises: always solvent. The extra backing stays in the reserve; nobody can withdraw it. | Timelock: every holder sees `RateChangeProposed` and can unwrap at the old rate for `rateDelay`, bound by `minOut`. |
| Lower `q` | Redemption value rises. | `C` falls: could go below `totalSupply` (insolvency = a run where the last holders get nothing). | `executeRate` refuses phantom reserve and reverts `RateChangeUndercollateralized(C', supply)` unless `C' ≥ totalSupply`. The issuer funds it first with `addReserve`. |

Consequences, stated for issuers and holders:

1. A fixed-rate token has no admin and its redemption price never moves. This is the default and the only form the
   catalogue templates offer without an explicit opt-in.
2. An adjustable token's worst case for a holder who never reacts: one step of dilution per `rateDelay`, so after a
   year the redemption value can be `(1 + maxRateStepBps/10⁴)^−(365 days / rateDelay)` of the start: ≈ 59 % at the
   defaults (1 % per 7 days), ≈ 0 at the bounds (10 % per 2 days). Wallets compute it from the token's actual parameters
   and show `rateAdjustable()` as a warning; issuers who promise a stable value should not choose `adjustable`.
3. Insolvency through a rate change is impossible (real balances and `C' ≥ totalSupply` checked at execution);
   insolvency through a failing underlying is not preventable by any rate rule (§6.6).
4. `rateAdmin` must have code; that proves only that it is not an EOA. A forwarder owned by one key passes, so wallets
   must not call it a multisig or a timelock unless they verified it.
5. Only the admin executes. A third party cannot bundle `executeRate` with its own wraps and unwraps in one
   transaction; the admin itself could (it controls the execution), which is one more reason to use a multisig.
6. Rounding never favours the caller (R133), so repeated wrap/unwrap cycles cannot extract value at any rate.
7. Nobody can wrap at a rate that is about to change: wrap is paused on every leg for the whole window, while holders
   keep the unwrap exit at the current rate (`minOut` protects intents that land late).

### 6.4 Decimals (R137)

Rates are raw. Examples (wrapper `D = 18`):

| Underlying | `d_i` | Intended human rate | `num` / `den` |
|---|---|---|---|
| xDAI / WXDAI | 18 | 1 : 1 | 1 / 1 |
| USDC, USDT | 6 | 1 : 1 | 10^12 / 1 |
| loyalty: 1 USDC → 100 points (`D = 0`) | 6 | 1 : 100 | 1 / 10^4 |

With integer rates (`den = 1`) wrap has no rounding; unwrap pays `⌊w/10^12⌋` and burns a multiple of `10^12`, the
holder keeps the rest. The wizard computes `num/den` from the human rate and the two decimals and shows the result
back; it refuses a rate whose `num` or `den` reaches 2^96. For wraps it rounds the amount down to `used` from
`previewWrap` (a multiple of `den/gcd(num, den)`), so no wrap leaves dust in the reserve: in the loyalty row, wrapping
15 000 raw would mint 1 point and leave 5 000 raw behind (review L2).

### 6.5 Minimum amounts

Only the zero-output rule (R133). Anything else (minimum ticket sizes) is the issuer's front-end policy; on chain it
would only block small exits.

### 6.6 Underlying behaviour (R134, R143)

| Underlying behaviour | Effect | Handling |
|---|---|---|
| Fee on transfer, charged from the amount | wrap credits what arrived; unwrap recipient gets `out − fee` | supported; UI discloses |
| Fee charged to the sender on top (incl. HTS fractional fee with `netOfTransfers`) | unwrap reverts `UnderlyingTransferMismatch` ⇒ that reserve is stuck | **unsupported**; UI refuses; Hedera init refuses (§11) |
| Positive rebase / donation | `balance > reserve` | excess locked; harmless |
| Negative rebase, confiscation, blacklist burn | `balance < reserve` | wrap and `addReserve` refuse (`ReserveShortfall`); unwrap stays first-come until the balance runs out |
| Underlying blacklists the wrapper | unwrap of that leg reverts in the underlying | Multi: holders exit through other legs; Single: stuck until lifted — disclosure |
| Upgradeable underlying (USDC, USDT) | behaviour can change after creation | disclosure; node alert on implementation `EXTCODEHASH` change (research §1.6.1 item 4) |
| Hooks (ERC-777) | reentrancy | contract-wide transient guard |

---

## 7. Named functions (R138–R140)

### 7.1 Mapping

All live in `MetaTokenBase`, are `nonReentrant`, return `bool`, and call the same internal `_execute(m, sig)`. Mode
bits are the `MetaTxLib` constants.

| Function | Struct it builds | Mode shape required (else `MtxModeShape(mode)`) | Adds |
|---|---|---|---|
| `mtxTransfer(from, to, amount, batch, nonce, validUntil, mode, relayer, sig)` | `data = ""`, `fee = 0`, `feeRecipient = 0` | `mode & ~MODE_RESTRICT_RELAYER == 0` (fee `NONE`) | typed ABI |
| `mtxTransferWithFee(from, to, amount, batch, nonce, validUntil, mode, relayer, fee, feeRecipient, sig)` | `data = ""` | fee nibble `PERCENT` or `FIXED`, `MODE_RESTRICT_FEE_RECIPIENT` set, `feeRecipient ≠ 0` (the sender names who is paid, turn 3293) | typed ABI; R132 applies |
| `executeMetaTransactionWithFee(m, sig)` | `m` as given (any op) | fee nibble ≠ `NONE`; recipient bound **or** relayer-default (turn 4667: "relayer or a third party") | a selector that says "this intent pays a fee" |
| `mtxPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient, sig)` | `data = OP_PAY ‖ payId`, `batch = payLane(payId)`, `nonce = 0` | any valid mode (fee optional) | on-chain lane derivation (R139); `PaymentSettled(…, entryRef = payId)` |
| `mtxUnwrap(from, underlying, wrapped, recipient, minOut, batch, nonce, validUntil, mode, relayer, sig)` | `to = recipient`, `value = wrapped`, `data = OP_UNWRAP ‖ underlying ‖ recipient ‖ minOut`, `fee = 0`, `feeRecipient = 0` | only `MODE_RESTRICT_RELAYER` may be set | gasless exit (R148) |
| `mtxUnwrapWithFee(from, underlying, wrapped, recipient, minOut, batch, nonce, validUntil, mode, relayer, fee, feeRecipient, sig)` | as `mtxUnwrap`, fee fields from parameters | fee `PERCENT`/`FIXED`, `MODE_RESTRICT_FEE_RECIPIENT` set, `feeRecipient ≠ 0` | fee paid in wrapped units before the burn |
| `mtxBatch(MetaTransaction[] ms, bytes[] sigs)` | each `ms[i]` as given | as `executeMetaTransaction` per item | atomic; one outer tx for many items |
| `payLane(bytes32 payId) view returns (uint256)` | — | — | the lane clients must use for `payId` on this token |

Exact equivalences (each is a test, §10.1):

```
mtxTransfer(f,t,a,b,n,v,mode,r,s)              ≡ executeMetaTransaction({f,t,a,"",b,n,v,mode,r,0,0}, s)
mtxTransferWithFee(f,t,a,b,n,v,mode,r,x,R,s)   ≡ executeMetaTransaction({f,t,a,"",b,n,v,mode,r,x,R}, s)
executeMetaTransactionWithFee(m,s)             ≡ executeMetaTransaction(m,s)            (plus the shape check)
mtxPay(f,t,a,p,v,mode,r,x,R,s)                 ≡ executeMetaTransaction({f,t,a,pay(p),payLane(p),0,v,mode,r,x,R}, s)
mtxUnwrap(f,u,w,t,o,b,n,v,mode,r,s)            ≡ executeMetaTransaction({f,t,w,unwrap(u,t,o),b,n,v,mode,r,0,0}, s)
mtxUnwrapWithFee(f,u,w,t,o,b,n,v,mode,r,x,R,s) ≡ executeMetaTransaction({f,t,w,unwrap(u,t,o),b,n,v,mode,r,x,R}, s)
```

So: same digest, same events (`MetaTransactionExecuted`; `PaymentSettled` for `mtxPay`), same nonce space (a
signature consumed through one path fails `MetaTxBadNonce` on the other), same KAT. A named function never accepts an
intent that the generic path would refuse, and refuses some the generic path accepts (wrong shape), never the other
way round.

`fee` is not canonicalised under fee mode `NONE` (only `relayer`/`feeRecipient` are, by `canon`): a struct signed
with fee `NONE` and a leftover `fee ≠ 0` is valid on the generic path but not through `mtxTransfer`/`mtxUnwrap`,
which put `fee = 0`. Clients MUST sign `fee = 0` and `feeRecipient = 0` for every no-fee intent (review L5).

### 7.2 What the names do not do

- No second typehash, no `chainId` or `wrapper` field in the struct (turns 227 and 1726 are met by the EIP-712
  domain: `chainId` + `verifyingContract` = the wrapper clone).
- No decoding of `data` to find "the amount" (turn 5296): the amount is `m.value`, already the base of the percent fee.
- No gas promise. R2's "≈ 4 k gas" was for a fast path with its own short typehash; the names hash the same
  11-field struct. They save only calldata (no dynamic `data`, and for `mtxPay` no `batch`/`nonce`), measured in §10.3.

### 7.3 `payLane` and the tag

`payLane(p) = uint256(keccak256(abi.encodePacked("scaas.pay.lane", p)))` — the same value v1 clients derive off
chain (R9, `dms_blockchain/lib/eip712.py`), so the lane of a payment does not depend on the token version. v1 has no
`payLane`; clients call it on v2 (`eip712Domain().version == "2"`) and keep the off-chain derivation for v1 (R146). The node's job API and Odoo store the
derived lane with the job, so a pay job never changes lanes after it is signed. "At most once" holds per path
(R139): Odoo and the node book the first `PaymentSettled` for an `entryRef` and raise any later one as a
reconciliation exception.

### 7.4 `mtxBatch`

- `ms.length == sigs.length` (`MtxBatchLengthMismatch`), `≥ 1` (`MtxBatchEmpty`); no explicit cap (the block gas
  limit is the cap).
- Items run in order through `_execute`; `msg.sender` is the relayer for every item (restricted-relayer intents keep
  working). Any item reverting reverts the batch: fee collected ⇔ op completed holds per item and per batch.
- Items may mix ops and payers but never tokens or chains (it is a function of one token).

### 7.5 Node usage

The node batches per `(chain_key, token)` only items whose `relayer` is bound (`MODE_RESTRICT_RELAYER`) to the
submitting lane, so no other relayer can consume an item between simulation and inclusion; a subject's
`cancelMetaNonce` remains the only race, and a failing batch is re-simulated and resubmitted without the item (the
`origin_grief_score` of R70-series mesh rules applies). Flush rule from SCaaS §5.8 (50 items or 3 s) stays as the node
default.

### 7.6 Unwrap jobs in the node (R148)

- The simulation gate runs the full outer transaction (`eth_call`/`eth_estimateGas` at `pending`), so it executes the
  underlying's transfer, `balanceOf` reads and the exact-amount check; it re-simulates immediately before signing the
  outer transaction, as for every job.
- A revert after simulation is a **terminal** job error reported with the decoded reason, not a retry.
- The signer chooses the recipient and can change its state between simulation and inclusion (Hedera dissociation or
  KYC removal, a recipient hook that reverts on block context, a blacklist the signer controls). So a revert is
  exempt from the subject's `origin_grief_score` **only** when it does not depend on the recipient:
  `InsufficientReserve`, `ReserveShortfall`, `UnwrapBelowMin` after a rate change, or an underlying revert that the
  node reproduces with the recipient replaced by its own lane address (paused underlying, wrapper blacklisted). Every
  other post-simulation revert counts, as for transfers (review M3). For underlyings known to call recipient hooks
  (ERC-777, ERC-1363) the node may refuse gasless unwraps to recipients that have code.
- Unwrap items are **never batched** (`mtxBatch`): their failure modes are outside the signer's and the relayer's
  control. Gas limit for the outer transaction comes from the simulation plus the usual margin; the node's
  `max_gas_per_tx` breaker applies unchanged.

### 7.7 Gasless wrap (PLANNED, R149)

Not in v2. Shape for a later version: op `wrap(address underlying, uint256 amount, bytes permit)` where `permit` is an
EIP-2612 `permit(from, wrapper, amount, deadline, v, r, s)` or a Permit2 `permitTransferFrom` signature for the
underlying; step 6 cannot prove the permit valid without calling the underlying, so the op would accept a revert in
step 8 (as R148 does); the fee is taken from the minted units. Needs its own ruling and KAT.

---

## 8. Tier 3 — `MultiUnderlyingToken` (kind `META_MULTI`, R136)

### 8.1 Init

`2 ≤ underlyings.length ≤ 8` (`UnderlyingCountInvalid(n)`), each checked as tier 2, no duplicates
(`DuplicateUnderlying(u)`). `initData = abi.encode(string name, string symbol, uint8 decimals, uint96[] nums,
uint96[] dens, RateConfig cfg, address guardian)`; array lengths equal `underlyings.length`. `guardian` may be 0
(no guardian) or any address — its only power stops inflow, so an on-call key is acceptable and speed matters in a
depeg. The leg order is the factory's `underlyings` order and never changes.

### 8.2 ABI

| Function | Rule |
|---|---|
| `wrap(address u, uint256 amount) returns (uint256 minted)` | tier-2 wrap on leg `u`; `UnknownUnderlying(u)`, `WrapDisabledFor(u)`, `WrapPausedForRateChange(u)` while any change is pending |
| `unwrap(address u, uint256 wrapped, address recipient, uint256 minOut) returns (uint256 out, uint256 burned)` | tier-2 unwrap on leg `u`, bounded by `reserve_u` and `minOut`; works on disabled legs and during a pending change |
| `addReserve(address u, uint256 amount)` | tier 2; refused on disabled legs |
| `disableWrap(address u, bytes32 reason)` | guardian; one-way; `WrapDisabled(u, guardian, reason)`; second call reverts `WrapDisabledFor(u)` |
| `renounceGuardian()` | guardian; `GuardianRenounced()` |
| `wrap(uint256)`, `unwrap(uint256,address)`, `unwrap(uint256,address,uint256)` (inherited single-asset ABI) | revert `UnderlyingRequired()` |
| `underlying()` | returns `address(0)`; clients use `underlyings()` |
| rate functions | §6.2 with the leg named in `proposeRate` (default fixed; adjustable is the R147 option); one pending change per token; admin-only execution; `RateDecreaseWithDisabledLeg()` if a change lowers `C` while any leg is disabled |
| unwrap op / `mtxUnwrap` | R148 with the leg chosen by the signer; works on disabled legs |

### 8.3 Invariant and solvency

`C = Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()` is the aggregate invariant; §5.2's per-operation argument holds
leg by leg. There is **no** per-leg invariant: the backing is pooled and redemption is any-of.

### 8.4 Depeg risk (disclosure text for issuers and holders)

At fixed nominal rates the token treats its underlyings as equal. When one depegs (say USDT trades at 0.95 while the
rate says 1:1), anyone can wrap the cheap asset and unwrap a good one: the good reserves drain first and the
remaining holders end up backed by the weakest asset. This is the expected behaviour of an any-of wrapper, not a bug.

- The guardian's `disableWrap` stops new inflow of the depegged asset; it does **not** stop the exit into good legs
  (that would trap holders) and cannot restore drained legs.
- Holders carry the risk of the worst underlying in the set. More than that: **each leg's admin key can take the
  whole basket.** An upgradeable or compromised underlying that fakes a `transferFrom`/`balanceOf` delta mints
  without limit and drains every good leg in one transaction, before any guardian can react (review L12). Plus each
  underlying issuer's freeze power (§6.6). The reserve composition is public (`legOf`) and the node/ERP should alert on composition drift.
- Issuers should list only assets they would accept at par, keep a guardian on call, and expect the composition to
  move toward the cheapest leg during stress. `disableWrap` can be front-run like any transaction, so the guardian
  should submit it privately (a private relay or a builder bundle).
- No re-enable: a mistaken disable is permanent for that leg. Holders lose nothing by it; the issuer creates a new
  token if the leg must come back.
- **A shortfall on one leg does not stop wrapping into the others** (owner decision 2026-10-06, implementation review
  L3; R134 unchanged). `wrap(A)` checks only leg A's `balanceOf ≥ reserve`. If leg B loses backing (a blacklist burn,
  a negative rebase, a confiscation), new deposits into A still mint at par into a pool that is now under-backed, and
  early exiters through A take the good assets those deposits brought. `disableWrap(B)` does not prevent this. The
  node/ERP should alert when any leg's `balanceOf < reserve` and the issuer should pause intake by communication; a
  wallet that shows a Multi token should show the per-leg backing before a wrap.

### 8.5 Adjustable Multi rates: residual risk (R147)

Stated plainly for issuers and holders (this text goes into the wizard and wallet disclosure):

1. **A per-leg rate change moves value between holders.** After a change to `q_i`, a unit redeemed through leg `i` is
   worth a different amount of market value than a unit redeemed through another leg. If the new rate is off the
   market price, arbitrageurs wrap the leg that is now cheap and redeem the leg that is now dear, starting in the
   transaction after the execution, until that leg's reserve is gone or the guardian disables wrap. Holders who exit
   through the dear leg first gain; holders left with the cheap leg lose. A decrease that the issuer funded with
   `addReserve` can be captured the same way (wrap another leg, redeem `i`).
2. **What the guards remove:** nobody can wrap at the old rate while a change is pending (all legs paused), nobody but
   the admin can execute (no third-party flash bundle of wrap → execute → unwrap), and every unwrap carries `minOut`.
   So there is no front-run of a pending change and no same-transaction drain around the execution by a third party.
3. **What they do not remove:** the shift in item 1, and the admin's own ability to order its execution with its
   own trades. A change moved **toward** a leg's market value removes an existing arbitrage instead of creating one;
   only such changes are safe.
4. A rate admin can keep wrap paused on the whole token for long periods by proposing changes back to back. That
   denies new wraps (never exits) and is visible on chain.
5. **Recommendation:** keep Multi rates fixed (the default). If an issuer needs adjustable legs, the `rateAdmin`
   should be a multisig behind a timelock that only re-pegs legs toward their market value; wallets show the rate
   admin and every pending change. All of §8.4 still applies.

---

## 9. Factory v2 (R130)

```solidity
enum TokenKind { META, ZETHER, META_NONE, META_SINGLE, META_MULTI }   // append only

interface IFactoryTokenV2 {
    function tokenKind() external pure returns (IOpenFactory.TokenKind);
    function initialize(address creator, address[] calldata underlyings, uint64 version, bytes calldata initData) external;
}

// new in OpenFactory v2 (all v1 functions kept, same semantics)
function createTiered(TokenKind kind, uint64 version, address[] calldata underlyings,
                      bytes calldata initData, bytes32 salt) external returns (address token);
function createTieredUnregistered(TokenKind kind, address implementation, address[] calldata underlyings,
                                  bytes calldata initData, bytes32 salt) external returns (address token); // version 0
```

| Rule | Detail |
|---|---|
| Kind ⇒ count | `META_NONE` 0, `META_SINGLE` 1, `META_MULTI` 2–8, else `UnderlyingCountInvalid(n)` (the token re-checks; the factory checks so its indexes are meaningful) |
| Registration | `registerImplementation(kind, v, impl)` for the three new kinds calls `impl.tokenKind()` and `impl.factory()` (try/catch) and reverts `VersionKindMismatch(kind, got)` on a kind mismatch or no answer, `ImplementationFactoryMismatch(impl)` unless `factory() == address(this)` (the catalogue is append-only, so a wrong entry would be dead forever) |
| Kind ⇔ entry point | `createMetaToken`/`createZetherToken`/`createUnregistered` refuse the three new kinds, and `createTiered*` refuse `META`/`ZETHER` (`VersionKindMismatch`), so neither the count check nor `tokenKind()` can be bypassed |
| Creation | same as v1: CREATE2 salt `keccak256(abi.encode(msg.sender, salt))`, `Clones.cloneDeterministic`, `initialize` in the same call; emits **only** `TieredTokenDeployed(token, creator, kind, version, implementation, underlyings)` (no second `TokenDeployed`) |
| Provenance | every underlying of a tier-2/3 token is indexed: `_wrappers[creator][u]`, `_byUnderlying[u]`. `getWrapper(creator, u)` can now return a Multi token, whose single-asset ABI reverts: clients read `versionOf(token).kind` first |
| Unregistered | `createTieredUnregistered` requires code at `implementation`, records `version == 0`, also checks `tokenKind()` |
| Registrar | unchanged powers (`registerImplementation`, `deprecate`, `setZetherEnabled`); none over tokens |
| Deploy script | `Deploy.s.sol` gains factory v2 + three implementations registered as version 1 of their kind (the version number is per kind; `version()` of a clone is the catalogue version, the domain version string `"2"` is the contract generation) |

Factory v1 stays deployed for v1 tokens; factory v2 does not register `MetaToken` v1. Factory v2 is a new source file
(`factory/OpenFactoryV2.sol`); `OpenFactory.sol` stays byte-identical so deployed v1 factories remain
source-verifiable (as R131 does for the tokens).

---

## 10. Storage, events, errors, gas, tests

### 10.1 Storage layout (clones)

Each clone has its own storage, `DELEGATECALL`ing a never-upgraded implementation, so there is no cross-version
layout constraint. The layout is still pinned (indexers and storage proofs read `reserve`) by
`test_storageLayoutIsPinned`, which compares `forge inspect <Contract> storageLayout` with a committed JSON per
implementation. Intended order (OZ 5.2, non-namespaced):

| Slot | Owner | Variable |
|---|---|---|
| 0–4 | `ERC20` | `_balances`, `_allowances`, `_totalSupply`, `_name`, `_symbol` (last two unused; getters overridden) |
| 5–6 | `EIP712` | `_nameFallback`, `_versionFallback` (unused: name < 32 bytes lives in immutables; the separator is rebuilt for each clone because `address(this) != _cachedThis`) |
| 7 | `MetaTxCore` | `_metaNonce` `mapping(address ⇒ mapping(uint256 ⇒ uint256))` |
| 8 | `MetaTokenBase` | packed: `creator` (20) ‖ `version` u64 ‖ `_tokenDecimals` u8 ‖ `_initialized` bool ‖ `_legCount` u8 (31 bytes; 0 on tier 1) |
| 9–10 | `MetaTokenBase` | `_tokenName`, `_tokenSymbol` |
| 11 | `NoUnderlyingToken` | `minter` |
| 11 | `SingleUnderlyingToken` | `_legs` `mapping(uint256 ⇒ Leg)` (a mapping, not an array: no length SLOAD for a bounds check; leg 0 is read directly) |
| 12 | 〃 | `_legIndex` `mapping(address ⇒ uint256)` (index + 1) |
| 13 | 〃 | `_pending` `PendingRate` (one per token) |
| 14 | 〃 | packed `RateConfig`: `rateAdmin` (20) ‖ `rateDelay` u32 ‖ `maxRateStepBps` u16 ‖ `adjustable` bool (27 bytes; read only by rate functions) |
| 15 | `MultiUnderlyingToken` | `guardian` |

```solidity
struct Leg { address token; uint8 decimals; bool wrapEnabled; bool adjustable;   // slot a (adjustable copied here so a
                                                                                  //   fixed-rate wrap reads no config)
             uint96 num; uint96 den;                                              // slot b
             uint256 reserve; }                                                   // slot c
struct PendingRate { uint8 leg; uint96 num; uint96 den; uint56 eta; }           // one slot; eta == 0 ⇒ none
```

Immutables (implementation): `FACTORY`, `_SELF`, `SUBJECT_ACCOUNT_IMPL`, `_SUBJECT_CLONE_CODEHASH`; constant
`KIND`. The constructor sets `_initialized = true` on the implementation's own storage (it cannot be initialized).

### 10.2 Events and errors

| Contract | Events | Errors |
|---|---|---|
| `MetaTxCore` | `MetaTransactionExecuted` (v1), `MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce)` | v1 `MetaTx*`, `SpenderNotContract`, `CallerNotContract`, `FeeRecipientIsPayee()` |
| `MetaTokenBase` | `PaymentSettled` (v1) | v1 op errors, `UnwrapRecipientMismatch()`, `MtxModeShape(uint32 mode)`, `MtxBatchEmpty()`, `MtxBatchLengthMismatch()`, `NotFactory()`, `AlreadyInitialized()` |
| `NoUnderlyingToken` | `MinterRenounced()` | `NotMinter()` |
| `SingleUnderlyingToken` | `Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted)`, `Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned, uint256 underlyingOut)`, `ReserveAdded(address indexed from, address indexed underlying, uint256 amount)`, `RateChangeProposed(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen, uint64 eta)`, `RateChangeCancelled(address indexed underlying)`, `RateChanged(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen)`, `RateAdminRenounced()` | `UnderlyingInvalid(address)`, `DecimalsUnreadable(address)`, `UnderlyingCountInvalid(uint256)`, `RateInvalid(uint256,uint256)`, `RateConfigInvalid()`, `RateAdminNotContract(address)`, `WrapTooSmall()`, `UnwrapTooSmall()`, `UnwrapBelowMin(uint256 out, uint256 minOut)`, `UnwrapRecipientInvalid(address)`, `InsufficientReserve(address,uint256,uint256)`, `ReserveShortfall(address,uint256,uint256)`, `UnderlyingTransferMismatch(address,uint256,uint256)`, `UnknownUnderlying(address)`, `RateFixed()`, `NotRateAdmin()`, `RateChangePending()`, `NoRateChangePending()`, `RateChangeNotReady(uint64)`, `RateChangeExpired(uint64)`, `RateStepTooLarge()`, `RateChangeUndercollateralized(uint256,uint256)`, `WrapPausedForRateChange(address)` |
| `MultiUnderlyingToken` | `WrapDisabled(address indexed underlying, address indexed guardian, bytes32 reason)`, `GuardianRenounced()` | `DuplicateUnderlying(address)`, `WrapDisabledFor(address)`, `UnderlyingRequired()`, `NotGuardian()`, `RateDecreaseWithDisabledLeg()` |
| Hedera children | — | `HtsQueryFailed(address u, int64 responseCode)`, `AssociateFailed(int64)` (v1) |
| `OpenFactoryV2` | `TieredTokenDeployed(address indexed token, address indexed creator, TokenKind kind, uint64 version, address implementation, address[] underlyings)` | `UnderlyingCountInvalid(uint256)`, `ImplementationFactoryMismatch(address)` (+ v1 errors) |

The node's event normaliser (SCaaS §7.8) adds `Wrapped`, `Unwrapped`, `ReserveAdded`, `RateChange*`, `WrapDisabled`,
`MetaNonceCancelled`, `TieredTokenDeployed`; `PaymentSettled` and `MetaTransactionExecuted` are unchanged, so payment
reconciliation needs no change. The R148 unwrap op emits the same `Unwrapped` as a direct unwrap, plus
`MetaTransactionExecuted`.

### 10.3 Gas notes (estimates; measured numbers replace them in `MetaTxGas.t.sol` v2)

- Hot path (transfer, `pay`, fees, named functions) touches no tier storage: same SLOAD/SSTORE set as v1, plus the
  R132 comparison (< 100 gas). Budget: every row of the v1 gas table (SCaaS §5.6) within **+300 gas** on the generic
  path; the named functions equal or below the generic path.
- `mtxPay` adds one `keccak256` of 46 bytes (~40 gas) and saves the dynamic `data` and two words of calldata.
- `mtxBatch` saves the 21 000 intrinsic gas per item after the first, plus warm re-reads of shared slots (the fee
  recipient's balance, the relayer's own lane state), minus the ABI overhead of `MetaTransaction[]`/`bytes[]`. The
  token address itself is pre-warmed in a single transaction too (EIP-2929 `tx.to`), so there is no cold-account
  saving (review L3). The first use of a lane (+17 k) is unchanged.
- Wrap/unwrap: leg slots a–c (6 300 cold) + reserve SSTORE + one `balanceOf` before and one after the transfer + the
  transfer itself. No length SLOAD (legs are a mapping), and fixed-rate tokens read no rate-config slot (the
  `adjustable` flag lives in leg slot a); adjustable tokens add one `_pending` SLOAD (2 100). Multi adds one
  `_legIndex` SLOAD. Rate functions are rare: a Multi `executeRate` reads every leg (≤ 8 × 3 cold slots) plus one
  `balanceOf` per leg.
- Gasless unwrap (R148): envelope (≈ 35 k warm lane, SCaaS §5.6) + fee if any (≈ 8 k) + leg reads, burn and reserve
  write (≈ 15 k) + the underlying's `transfer` and two `balanceOf` (≈ 30–40 k for a plain ERC-20). For a proxied
  stablecoin and a fresh recipient add its 0 → non-zero balance SSTORE (+20 k), the cold implementation hop (+2.6 k)
  and blacklist reads (+4.2 k): expect **≈ 110–130 k** for USDC to a new address, ≈ 85–100 k for a plain token to an
  existing holder.
- Size: CI fails if any implementation exceeds 24 576 bytes (`forge build --sizes`); if Multi does, the rate
  timelock moves into a linked external library (clone → implementation → library delegatecall keeps the clone's
  storage).

### 10.4 Test plan

Unit (forge, `test/v2/`):

| Area | Tests |
|---|---|
| Base | typehash still pinned (`test_metaTxTypehashIsPinned` unchanged); v2 domain KAT `test/vectors/metatx_v2_kat.json` (same struct as `metatx_kat.json`, same `struct_hash`, new digest) plus an `mtxpay` vector with `batch = payLane(payId)`, `nonce = 0` and an `mtxunwrap` vector, all checked by Solidity, node and Odoo `lib/eip712.py` (`lane_batch` already equals `payLane`); `MetaNonceCancelled`; R26 on all three tiers; ERC-1271 400 k only for SubjectAccount clones; an op whose address word has dirty upper bits ⇒ `MetaTxUnknownOp` |
| Fees | percent on `value`, fee on top, 1 % cap PERCENT and FIXED; `FeeRecipientIsPayee` for transfer, `pay`, `payWithFee`, bound and relayer-default; not raised for `trade`/`approve`/`unwrap` |
| Unwrap op | equivalence with `mtxUnwrap`/`mtxUnwrapWithFee`; fee in wrapped units before burn; `UnwrapRecipientMismatch`; `UnwrapRecipientInvalid` for 0 and `address(this)` at step 6; `UnwrapBelowMin`; underlying revert (blacklist mock) reverts fee and nonce; sender-pays FoT ⇒ `UnderlyingTransferMismatch`; ERC-777 mock whose hook calls `cancelMetaNonce` and `transfer` mid-unwrap (nonce already written, state consistent); `MetaTxUnknownOp` on tier 1; works on a disabled leg and during a pending rate change |
| Named | `testFuzz_namedDigestEqualsGeneric` over random struct fields for every named function; a signature consumed by a named call fails on the generic path and vice versa; every `MtxModeShape` case; a no-fee struct signed with a leftover `fee ≠ 0` fails through `mtxTransfer` (L5); `mtxPay` lane equals `payLane`; second `mtxPay` of a `payId` reverts `MetaTxBadNonce`; `payWithFee` with the same `entryRef` still emits `PaymentSettled` (documents R139's per-path limit); `mtxBatch` atomic (one bad item reverts all), length mismatch, empty |
| Tier 1 | init mint to creator, `mint`/`NotMinter`, `renounceMinter`, `burn`, fixed supply with `minter = 0` |
| Tier 2 | rate 1:1 equals v1 behaviour; rounding down on wrap/unwrap; `burned = ⌈out·q⌉`; `previewWrap` `used`; `WrapTooSmall`/`UnwrapTooSmall`/`UnwrapBelowMin`; v1 two-argument `unwrap` = `minOut 0`; FoT inbound measured; sender-pays FoT reverts `UnderlyingTransferMismatch`; donation not counted; `ReserveShortfall` after a negative-rebase mock stops wrap and not unwrap; `addReserve`; decimals snapshot; init refusals |
| Rates | fixed ⇒ `RateFixed`; propose/cancel/execute; only the admin executes (`NotRateAdmin` for anyone else); delay and window bounds; expired change counts as none for `proposeRate`, `pendingRate()` and the pause; step bound both directions at the exact edge; decrease refused without collateral, accepted after `addReserve`; execute refused with `ReserveShortfall` when any leg's balance is below its reserve (M1: shock, then decrease); `collateralValue` saturates and `executeRate` exits early on a huge leg (L1); renounce drops pending; EOA admin refused at init; wrap paused on **every** leg while anything is pending, reopens on execute/cancel/expiry, unwrap and `addReserve` open |
| Tier 3 | 2–8 legs, duplicates, zero; per-leg reserves; unwrap bounded by `reserve_i`; guardian disable one-way and idempotence error; unwrap open on a disabled leg; `addReserve` refused on it; `RateDecreaseWithDisabledLeg`; the H1 scenario (pending decrease on leg `i`, flash-wrap of leg `j`) reverts `WrapPausedForRateChange` and a third-party `executeRate` reverts `NotRateAdmin`; inherited single-asset ABI reverts |
| Factory v2 | kind ⇒ count; v1 entry points refuse the new kinds and `createTiered*` refuse `META`/`ZETHER`; `VersionKindMismatch`; `ImplementationFactoryMismatch`; append-only catalogue; `createTieredUnregistered` version 0; salt scoped by creator; every underlying indexed; exactly one `TieredTokenDeployed` |
| Layout | `test_storageLayoutIsPinned` per implementation |
| Hedera | HIP-632 path on each tier (mocked precompile, as `test/hedera/` today); association at init; fail-closed custom-fee check: `isToken` rc ≠ SUCCESS, `getTokenCustomFees` rc ≠ SUCCESS, and a non-empty fee list each refuse the underlying |

Invariant / fuzz (`test/v2/WrapperInvariant*.t.sol`, `[invariant] runs = 64, depth = 32, fail_on_revert = true` as
today, with handlers that bound inputs so expected reverts do not count as failures). One invariant contract per rate
setup: `1:1`, `10¹²:1`, `1:10⁴`, `(2⁹⁶−1):1`, `1:(2⁹⁶−1)`, `3:7`.

- Handlers: wrap / unwrap (direct and R148 op) / `addReserve` on random legs with random actors; plain donations; FoT
  and plain underlyings; meta-tx transfers with fees; propose / cancel / execute rate changes; `warpToEta`, which
  jumps exactly to `eta` or to `eta + 7 days`; guardian disables; negative-rebase shocks on a mock leg; a ghost
  attacker that trades only through wrap/unwrap.
- Invariants:
  - `collateralValue() ≥ totalSupply()` and `Σ balances == totalSupply()`;
  - **slack never decreases**: `C − S` (ghost of the previous value) is non-decreasing across every handler call
    except a rate execution;
  - per-leg conservation: `Σ received_i + Σ addReserve_i − Σ out_i == reserve_i`; `balanceOf_i ≥ reserve_i` for
    well-behaved legs;
  - **profit oracle**: the ghost attacker's holdings valued at nominal par never increase over a sequence that
    contains no rate execution (catches the H1 class);
  - every executed rate change satisfied the step bound, waited `rateDelay` and was sent by the admin; no wrap
    succeeds while a change is pending; a disabled leg is never re-enabled.
- Fuzz: `testFuzz_wrapUnwrapNeverProfits(amount, num, den)`; cross-leg `testFuzz_wrapIUnwrapJNeverProfitsAtPar`;
  `testFuzz_stepBoundExact(num, den, num', den', bps)` against a reference in 512-bit arithmetic;
  `testFuzz_feeConservesSupply` (v1 test ported).

Cross-family vectors: `test/vectors/wrap_rate_vectors.json` — `(num, den, in) → (minted, used)` and
`(num, den, w) → (out, burned)` incl. edge cases (`2^96 − 1`, `den = 1`, zero outputs), written by
`test_writeRateVectors` and later replayed by the Cosmos, Soroban and TON wrappers (R145). `metatx_v2_kat.json` is
EVM/Hedera only.

---

## 11. Hedera (R144)

`HederaNoUnderlyingToken`, `HederaSingleUnderlyingToken`, `HederaMultiUnderlyingToken` each inherit their tier and an
abstract `HederaSigMixin is MetaTxCore` that overrides `_requireValidSignature` exactly as `HederaMetaToken` does
(64-byte signature from an account without code ⇒ HIP-632 `isAuthorizedRaw`). Wrapper tiers check every underlying
in `initialize`, **fail-closed**, through the HTS precompile `0x167`:

1. `isToken(u)` → `(rc, isHts)`; `rc ≠ SUCCESS` ⇒ `HtsQueryFailed(u, rc)`.
2. If `isHts`: `getTokenCustomFees(u)` with `rc ≠ SUCCESS` or an undecodable result ⇒ `HtsQueryFailed(u, rc)`; any
   fixed, fractional or royalty fee entry ⇒ `UnderlyingInvalid(u)`.
3. If `isHts`: `associateToken(this, u)`; anything but SUCCESS or `TOKEN_ALREADY_ASSOCIATED_TO_ACCOUNT` ⇒
   `AssociateFailed(rc)`. There is no separate `associateUnderlying` function: a token whose legs cannot be associated
   is never born.

A fee-schedule key can still add a fee later. It is not refused on chain (major HTS stablecoins may carry one); the
wizard and wallets read `getTokenKey(u, FEE_SCHEDULE)` and warn (§6.6). Domain, ABI, events and tests are the EVM ones.

---

## 12. Non-EVM families (R145)

| Family | Today | v2 here |
|---|---|---|
| Cosmos | `scaas-token`: CW20 + meta-op, `minter`, `initial_balances` (tier 1) | tier 1 unchanged (gets `Burn` and minter renounce with its next version). Wrapper of a bank denom (`info.funds`) or a CW20 (`Receive`) with the same rate/reserve rules and `wrap_rate_vectors.json`: **PLANNED** |
| Soroban | SEP-41 token + `pay`, admin `mint`, `burn` (tier 1) | tier 1 unchanged. Wrapper of a Stellar Asset Contract (e.g. USDC) with the same rules: **PLANNED** |
| TON | Tact jetton + custom wallet + `SignedOp`, admin `Mint` (tier 1) | tier 1 unchanged. Third-party jettons (USDT) cannot carry `SignedOp`, so a wrapper minter (receive `transfer_notification`, mint; unwrap with bounce handling) is the only gasless route: **PLANNED**, highest value of the three |
| Move (Aptos, Sui) | subject `Account` holds any FA / `Coin<T>`; gasless for every asset | **none**: no wrapper needed for gaslessness; a rate product would be a separate design |
| Solana | SubjectAccount PDA owns SPL token accounts for any mint | **none**, same reason |

Common to all: fees `NONE` off EVM, so R132 is EVM/Hedera; named functions are EVM/Hedera (non-EVM ops are already
named — `pay`, `Relay{payload}`, `SignedOp`); the multi-underlying guardian and rate timelock, when built elsewhere,
follow §6 and §8 verbatim.

---

## 13. Open questions (owner)

None. The rev-1 questions were answered on 2026-10-06 (R147, R148, R149).

---

## 14. Migration (R146)

- v1 `MetaToken` clones, `OpenFactory` v1 and the v1 KAT are untouched and stay supported by node, Odoo and SDKs
  (they read the deployed domain).
- New tokens are created through factory v2. Value moves voluntarily: a holder unwraps v1 and wraps the v2 token of
  the same issuer; tier-1 v1 tokens move only by an issuer-run swap (the issuer's minter on the v2 token), not
  specified here.
- Odoo `blockchain.token` adds `kind` (`meta`, `meta_none`, `meta_single`, `meta_multi`), the underlying list, the
  per-leg rates (read-only mirror of `legOf`) and `pay_lane_tag`; the node token table adds `kind` and reads
  `payLane` for v2. Typed-data builders are unchanged (same struct); only the function selector differs when a
  client uses a named function.

---

## 15. Stream plan

One heavy forge job at a time (`forge test --match-path` scoped to the step; the full suite once at the end), at most
three sub-agents, reviews by Claude sub-agents.

| Step | Content | Gate |
|---|---|---|
| T1 | `MetaTxCore` (memory pipeline, R132, `MetaNonceCancelled`), `MetaTokenBase` (ops, `payWithFee`, named functions incl. `mtxUnwrap*` stubs routed to the tier hook, `mtxBatch`, `payLane`), `metatx_v2_kat.json` | `test/v2/Base*.t.sol`, v1 tests untouched and green |
| T2 | `NoUnderlyingToken`, `SingleUnderlyingToken` (legs, reserve, rates, timelock, wrap pause, R148 unwrap op), `wrap_rate_vectors.json` | `test/v2/Tier*.t.sol`, `Rates.t.sol`, `UnwrapOp.t.sol` |
| T3 | `MultiUnderlyingToken` (legs 2–8, guardian, all-leg wrap pause) | `test/v2/Multi.t.sol` |
| T4 | `OpenFactory` v2, `IFactoryTokenV2`, `Deploy.s.sol` | `test/v2/FactoryV2.t.sol`, sizes ≤ 24 576 |
| T5 | Hedera children + mixin (fail-closed HTS checks, association at init) | `test/hedera/*V2*.t.sol` |
| T6 | Invariant suite, layout pins, gas table v2 | `WrapperInvariant.t.sol`, `MetaTxGas` v2 vs v1 budget |
| T7 | Node (`kind`, `payLane`, new events, batching rule §7.5, unwrap jobs and the narrowed grief exemption §7.6, `entryRef` dedupe), Odoo fields, SDK typed ABIs | node `cargo test` for the token table and normaliser; Odoo unit tests |
| T8 | Docs: SCaaS §4/§5/§14 statuses to BUILT, `integration.md` | — |

---

## 16. Requirement trace (owner turns in `Grok3_Continued.md`)

| Line | Owner requirement | Status | Where | Changed by later rulings |
|---|---|---|---|---|
| 71 | Smart contract with meta-transaction support | **BUILT** | `ERC20MetaTx` (native mixin, SCaaS §5.1); v2 `MetaTxCore` | No forwarder ever; nine-step pipeline (canon §04.6.1) |
| 227 | Add `chainId` to tell chains apart | **BUILT** | EIP-712 domain `chainId` (`MetaTxLib` header: domain fields, not struct fields) | The transcript put `chainId` in the struct; it lives in the domain |
| 416 | The contract must be a wrapper of an ERC-20 | **BUILT** (1:1) | `MetaToken` v1 tier 2; v2 `SingleUnderlyingToken` (§5) | Gasless unwrap added (owner 2026-10-06, R148); gasless wrap PLANNED (R149) |
| 641 | Disable approve/revoke for EOAs; only smart-contract accounts | **BUILT** | `ERC20MetaTx.approve`/`transferFrom` (SCaaS §4.4); inherited by v2 | R4 first rejected it; **R26** (owner) reinstated it as "spender must be a contract, only contracts call `transferFrom`", EIP-7702 designators count as EOAs; no `increaseAllowance`, no `permit` |
| 850 | Factory to create many wrappers for many ERC-20s | **BUILT** | `OpenFactory` (EIP-1167 clones, catalogue, per-creator wrappers); v2 §9 | Open factory, no upgrades, versioned implementations (IOpenFactory header) |
| 1116 | Wrappers with different conversion rates | **SPECIFIED** here | R133, R135, R147, §6 | Issuer chooses fixed or adjustable at creation, also per Multi leg; admin-only execution, all-leg wrap pause, `minOut` (owner 2026-10-06, rev 1.2) |
| 1408 | An `mtxTransfer` function | **SPECIFIED** here | R138, §7.1 | Thin entry point over the pinned struct, no own `Transfer` typehash |
| 1726 | Add the wrapper contract address against replay | **BUILT** | domain `verifyingContract` = the clone (R5) | Domain field, not a struct field |
| 2055 | A wrapper with several underlyings (xDAI or USDC or USDT) | **SPECIFIED** here | R136, §8 | Owner add/remove dropped: set fixed at creation; guardian may only disable wrap; leg rates optionally adjustable with R147 guards (owner 2026-10-06) |
| 2452 | Transfer that pays a fee to the relayer or a third party, per mille, max 0.1 % | **BUILT** (fee); named form **SPECIFIED** | `FeePolicy`, `mode` fee nibble; §7.1 | Unit ppm (per mille cannot express 0.05 %); cap raised to **1 %** (turn 3725); fee never to the payee (turn 2848, R132) |
| 2848 | Keep `mtxTransfer`, add `mtxTransferWithFee`; the fee goes to someone other than the recipient | **SPECIFIED** here | R132, R138 | R132 adds the on-chain payee check v1 lacks |
| 3293 | Fee amount and fee recipient are parameters, the sender's option | **BUILT** in the struct (`fee`, `feeRecipient`, `MODE_RESTRICT_FEE_RECIPIENT`); **SPECIFIED** as typed parameters | `MetaTxLib`; §7.1 | Unbound recipient defaults to the relayer and is normalised by submitters (R84/R100) |
| 3725 | Cap at 1 % of the total | **BUILT** | `FeePolicy.MAX_FEE_PPM = 10_000`, PERCENT and FIXED | Not on confidential ops (RS2-6) |
| 4145 | `MultiUnderlying` is a child of the single wrapper | **SPECIFIED** here | R129 | — |
| 4667 | `mtxTransferWithFee` in the parent; add `executeMetaTransactionWithFee` | **SPECIFIED** here | R138 (`MetaTokenBase`, all tiers) | Fee to relayer (default) or third party (bound) |
| 5296 | Fee in `executeMetaTransactionWithFee` based on the sender's amount | **BUILT** | `FeePolicy.compute(…, m.value, …)`, fee on top | No `data` decoding needed: the amount is `m.value` |
| — | (owner answers 2026-10-06, rev 1.1/1.2) Adjustable Multi rates with admin-only execution, all-leg wrap pause and `minOut`; gasless unwrap via a meta-tx op and `mtxUnwrap`/`mtxUnwrapWithFee`; wrap via permit optional | **SPECIFIED** here (unwrap, guards); **PLANNED** (permit wrap) | R147, R148, R149; §5.3, §7.6, §7.7, §8.5 | — |
| 5867 | Three types parent/child (none, single, multi); factory creates all three; an inheriting class with `mtxPay` and a sender-supplied `payId` | **SPECIFIED** here | R129, R130, R139 | `payId` = `entryRef` (R9), lane derived on chain; event is `PaymentSettled`, not `Payment`; no second typehash (R140); tier 1 gains `burn` (R141) |

---

## 17. Review disposition (independent review 1 of rev 1.1, FIX-THEN-GO)

| # | Finding | Disposition | Where |
|---|---|---|---|
| H1 | Per-leg Multi rate changes are MEV-extractable in both directions; leg-only pause and permissionless execute allow a flash bundle | **Accepted, owner variant**: per-leg adjustable rates kept (not a global scale); only the `rateAdmin` executes; any pending change pauses wrap on **all** legs; `minOut` on unwrap; the value shift that remains is stated plainly | R135, R147, §6.2, §6.3 items 5, 7, §8.5 |
| H2 | Share cap can be flash-bypassed or tripped | **Accepted**: share cap deleted (`maxLegShareBps`, `legShareBps`, `LegShareExceeded`, the RateConfig field) | R147, §5.1, §10 |
| M1 | `executeRate` counts phantom reserve | **Accepted**: every leg must have `balanceOf ≥ reserve` at execution (`ReserveShortfall`) | §6.2, §10.4 |
| M2 | "Pays at most once, enforced by the contract" is false | **Accepted**: reworded to "once through `mtxPay`"; reconcilers dedupe on `entryRef`; test documents `payWithFee` | R139, §7.3, §10.4 |
| M3 | Grief exemption ignores signer-controlled recipient | **Accepted**: exemption only for recipient-independent reverts (reproduced with the lane address as recipient) | §7.6 |
| M4 | Unwrap without `minOut` | **Accepted** (owner): op `unwrap(address,address,uint256)`, `mtxUnwrap*` and direct overloads take `minOut`; v1 two-argument `unwrap` = `minOut 0` | R148, §5.2, §5.3, §7.1, §8.2 |
| M5 | HTS fee detection must fail closed | **Accepted**: `isToken` / `getTokenCustomFees` non-SUCCESS ⇒ refuse; fee-schedule key warned off chain, not refused | R144, §11 |
| M6 | Invariant suite blind to H1/H2/M1 | **Accepted**: slack-never-decreases, per-leg conservation, profit oracle, `warpToEta`, per-rate setups, digest fuzz, cross-leg fuzz, M1 shock case, recipient = self, ERC-777 hook | §10.4 |
| L1 | `collateralValue` overflow DoS | **Accepted**: early exit in `executeRate`, saturating view | §5.4, §6.2 |
| L2 | Wrap dust up to one wrapped unit | **Accepted**: `previewWrap` returns `used`; UI rounds; bound stated | R133, §6.4 |
| L3 | Gas claims | **Accepted**: legs as mapping, `adjustable` in leg slot a, one `balanceOf` before the pull, no cold-token saving in batches, 110–130 k for USDC unwrap | §5.2, §10.1, §10.3 |
| L4 | v2 KAT cannot reuse the v1 struct for `mtxPay` | **Accepted**: `mtxpay` and `mtxunwrap` vectors | §10.4 |
| L5 | `fee` not canonicalised under NONE | **Accepted**: clients MUST sign `fee = 0`; test | §7.1, §10.4 |
| L6 | Dirty address bits in `mload` decoding | **Accepted**: `MetaTxUnknownOp` | §3.1, §10.4 |
| L7 | Recipient = self; nonce after external call | **Accepted**: refused at step 6; nonce written at step 7 for every op | R148, §3.1, §3.2, §5.3 |
| L8 | Pending-state semantics, dead re-check, item-5 contradiction | **Accepted**: expiry defined everywhere; step re-check removed; item 5 rewritten (admin-only execute) | §6.2, §6.3 |
| L9 | Factory checks | **Accepted**: `factory()` check at registration, kind ⇔ entry point, v1 `OpenFactory.sol` frozen, v2 in a new file | §9 |
| L10 | Admin "contract" ≠ multisig; worst case at bounds | **Accepted** | R135, §6.3 items 2, 4 |
| L11 | `associateUnderlying` restriction | **Superseded** by over-engineering 5: association happens in `initialize`, fail-closed; the function is deleted | §11 |
| L12 | One compromised leg drains every leg | **Accepted**: disclosure reworded; guardian submits privately | §8.4 |
| L13 | `getWrapper` may return a Multi; two events per create | **Accepted**: clients read `versionOf().kind`; only `TieredTokenDeployed` | §9 |
| OE1–5 | Delete: share cap; per-leg `_pending`; step re-check at execution; R132 on unwrap; `associateUnderlying` | **All done**: one `PendingRate` per token (leg index inside); unwrap has no payee check; association at init | §3.2, §6.2, §10.1, §11 |

---

## 18. Implementation notes (T1–T6)

Where the code differs from the text above, and why. Everything else is as specified.

| # | Spec | Code | Why |
|---|---|---|---|
| I1 | `TokenKind` appended in `IOpenFactory` (§9) | `IOpenFactoryV2.TokenKind` (same values) in `src/common/IOpenFactoryV2.sol`; `IOpenFactory.sol` untouched | Appending to the v1 enum changes the bytecode (enum range check) and metadata of `OpenFactory` v1, which would no longer source-verify (R131's reason, applied to the factory) |
| I2 | `mtxUnwrapWithFee` a normal external function | Decoded by hand in `MetaTokenBase.fallback` (same selector, ABI and checks as the ABI decoder: 13 head words, clean address/`uint32` words, `bytes` in bounds); declared in `IMetaTokenV2UnwrapWithFee`, not in `IMetaTokenV2` | 13 parameters overflow the non-via-IR ABI decoder (`dataEnd` too deep); via-IR would change every v2 artifact and the build cost. Solidity callers (also legacy codegen) cannot ABI-encode 13 values either and build the calldata by hand; Rust/Python clients are unaffected |
| I3 | `abstract HederaSigMixin is MetaTxCore` (§11) | `library HederaSig` + a 4-line `_requireValidSignature` override in each Hedera child (`src/hedera/HederaV2Lib.sol`, `HederaTokensV2.sol`) | A mixin on `MetaTxCore` forms a diamond with the tier and forces seven unrelated overrides per child |
| I4 | Errors `WrapDisabledFor`, `DuplicateUnderlying`, `RateDecreaseWithDisabledLeg` listed under `MultiUnderlyingToken`; `UnderlyingCountInvalid` under `SingleUnderlyingToken` | Declared in `SingleUnderlyingToken` (the leg/rate code that raises them lives there; tier 2 cannot reach them) and `UnderlyingCountInvalid` in `MetaTokenBase` (every tier checks its count) | One code path for legs; the ABI of every tier that can raise them contains them |
| I5 | `tokenKind()` mismatch ⇒ `VersionKindMismatch(kind, got)` | "No answer" reports `got = META`; a wrong entry point reports `expected = META` (v1 path) or `META_NONE` (tiered path) | The error has enum arguments; these are the defined fallbacks |
| I6 | `executeMetaTransactionWithFee` ≤ generic gas | ≈ 85 gas above the generic path (dispatch position + shape check); every other named function is below | Not worth contorting an alias; recorded in `MetaTxGasV2.t.sol` |
| I7 | Layout test "compares `forge inspect` output" | Compares the solc `storageLayout` in the build artifact (`extra_output`) with `test/v2/layout/*.json` | Same data without enabling `ffi` in tests |
| I8 | Renounce makes the rate fixed | `rateAdjustable = false`, `rateAdmin = 0`, pending dropped; the per-leg `adjustable` copy stays set (wrap then reads an empty `_pending`, one extra SLOAD) | Smallest correct change; fixed-at-creation tokens keep the cheap path |
| I9 | (review 2, L1/L2) | `fallback` checks the selector before the reentrancy guard (a TSTORE in a STATICCALL halts and burns the caller's gas); a plain transfer to `address(0)` fails at step 6 with OZ's `ERC20InvalidReceiver` instead of at step 8 | §3.2 "step 8 must not fail"; integrators probe unknown selectors with `staticcall` |

**Open for the owner (review 2, L3):** in a Multi token, `wrap` on leg A checks `balanceOf ≥ reserve` only on leg A
(R134 is per leg). If leg B has a shortfall (blacklist burn, negative rebase), new deposits on A still mint at par into
a pool whose real backing is below supply, and early exiters through A take them; `disableWrap(B)` does not stop it.
Options: check every leg on Multi `wrap`/`addReserve` (≤ 8 `balanceOf`, as `executeRate` already does), or state it
in the §8.4 disclosure. Not changed in code (it would amend R134).

