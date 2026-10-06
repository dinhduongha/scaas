# Token wrappers v2: three tiers, conversion rates, multi-underlying, named meta-tx functions

Status: draft rev 1, 2026-10-06, not yet reviewed. Code at `scaas` `main` fc6e3d0 (after the `bamboo` → `scaas`
rename). Nothing here is built.
Rulings: **R129–R146** (§2). Owner rulings of 2026-10-06 (three tiers, rates as an issuer option, multi-underlying
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
wrapper, and **named** meta-tx functions that are thin entry points over the existing nine-step pipeline. The
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
 └── MetaTokenBase (abstract)  ← ops pay/trade/approve, payWithFee, named functions, init plumbing, provenance
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
  (`WrapTooSmall`, `UnwrapTooSmall`) — if wrong: dust is lost to the reserve instead of to the holder; either way
  never to a third party.
- **R134** Reserve accounting is internal: `reserve_i` changes only through `wrap`, `unwrap`, `addReserve`. The
  token's solvency invariant is **`collateralValue() := Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()`**, plus
  `underlying_i.balanceOf(this) ≥ reserve_i` while the underlying behaves. Wrap mints the **measured** balance delta;
  unwrap requires the balance to drop by exactly `out` (`UnderlyingTransferMismatch`); wrap and `addReserve` refuse
  while `balanceOf < reserve_i` (`ReserveShortfall`); unwrap never checks that, so exits stay open — research §1.6.1
  (donations and rebases break the `==` form; internal accounting does not) — if wrong: donations or rebases would
  move the redemption price.
- **R135** (owner option) Rate mode is chosen **at creation**: `fixed` (default; no setter exists) or `adjustable`.
  Adjustable: a `rateAdmin` that **is a contract** (multisig/timelock, same `_isContract` as R26); propose → wait
  `rateDelay` (default 7 days, bounds [2 days, 30 days]) → anyone executes within a 7-day grace; one pending change per
  underlying; each step ≤ `maxRateStepBps` (default 100 = 1 %, bounds [1, 1 000]); a change that lowers
  `collateralValue()` executes only if the invariant still holds afterwards; balances never change (no rebase).
  `rateAdmin` can renounce (one-way, the rate becomes fixed); it cannot be transferred. Delay, step and admin are set
  once — if wrong: a holder who disagrees has at least `rateDelay` to unwrap at the old rate, and loses at most one
  step per delay.
- **R136** (owner) Multi-underlying = **any-of**: the underlying set (2–8, no duplicates) and each leg's initial
  rate are set at creation and never added to or removed; a user wraps one chosen underlying and unwraps into one
  chosen underlying, bounded by that leg's reserve (`InsufficientReserve`). A `guardian` (set at creation, optional,
  may be an EOA) has exactly one power: `disableWrap(underlying, reason)` — one-way; unwrap from a disabled leg stays
  open. A disabled leg refuses `addReserve`, and no rate change that lowers `collateralValue()` executes while any leg
  is disabled — if wrong: a re-enable power would let a compromised guardian reopen a depegged inflow and drain the
  good legs.
- **R137** Decimals are display only. `decimals()` of every v2 token is the issuer's choice at creation; rates are in
  raw units, so `1 human unit of U_i = num_i/den_i × 10^(D − d_i)` wrapped human units (`D` = wrapper decimals,
  `d_i` = underlying decimals, snapshot at init). Underlyings without a readable `decimals()` are refused
  (`DecimalsUnreadable`) — if wrong: a UI could not show the human rate.
- **R138** (owner) Named functions `mtxTransfer`, `mtxTransferWithFee`, `executeMetaTransactionWithFee`, `mtxPay` and
  the batch `mtxBatch` live in `MetaTokenBase` (so every tier has them, turn 4667) and **only build a
  `MetaTransaction` and run the same pipeline**. Each enforces a mode shape (`MtxModeShape`), nothing else. The
  digest of a named call equals the digest of `executeMetaTransaction` with the same struct, so one signature works on
  both paths and one lane is consumed once — if wrong: nothing breaks, the names are ABI sugar.
- **R139** `mtxPay(…, payId, …)`: `payId` **is** the R9 `entryRef` (`PaymentSettled.entryRef`), and the lane is
  derived **on chain**: `batch = payLane(payId) = uint256(keccak256("scaas.pay.lane" ‖ payId))`, `nonce = 0`. Each
  `(payer, payId)` pays at most once per token, enforced by the contract rather than by the client — if wrong: a
  client that wants a different lane for a payment uses `executeMetaTransaction` with the `pay` op (still valid).
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
  them — if wrong: holders would have to read code to learn a token has an admin.
- **R143** Fee-on-transfer underlyings: inbound handled (measured delta), outbound must be exact (sender-pays fee
  designs revert on unwrap and are therefore **unsupported**; UI refuses them). Rebasing underlyings are
  **unsupported**: a positive rebase is a locked donation; a negative rebase stops wrap (R134) and leaves a
  first-come exit — disclosure §6.6 — if wrong: an unsupported underlying can lock or socialise a loss; the contract
  cannot detect one at creation.
- **R144** Hedera children (§11) inherit everything and add HIP-632 signatures (R63) and
  `associateUnderlying(address)` per leg; at init they refuse HTS underlyings that carry custom fees.
- **R145** Non-EVM (§12): **EVM and Hedera only in this version.** Cosmos, Soroban and TON keep their tier-1 tokens;
  wrappers there are PLANNED with the same rate/reserve rules and the shared rate vectors (§10.4). Move and Solana do
  not need wrappers for gaslessness (the subject account holds any coin/asset), so no v2 there. Named functions are
  EVM-only (non-EVM ops are already named). Relayer fees stay `NONE` off EVM (R10/R75).
- **R146** Migration: v2 is a new implementation per kind in factory v2; v1 clones and factory v1 are untouched;
  moving value is voluntary (`unwrap` v1, `wrap` v2). Clients read the domain (`eip712Domain()`) and the pay lane
  (`payLane(payId)` on v2; the off-chain R9 derivation for v1) per token, never from a constant — if wrong: a tag
  change in a later version would make that version's payments unsignable.

---

## 3. `MetaTxCore` (the v2 base)

### 3.1 What changes against `ERC20MetaTx` v1

| Item | v1 | v2 |
|---|---|---|
| Struct, `METATX_TYPEHASH`, `hashStruct`, `canon` | `MetaTxLib` | **same library, unchanged** |
| Domain | `("SCaaS MetaToken", "1", chainId, clone)` | `("SCaaS MetaToken", "2", chainId, clone)` |
| Pipeline input | `MetaTransaction calldata` | internal `_execute(MetaTransaction memory m, bytes calldata sig)`; `executeMetaTransaction` passes its calldata struct (one copy — v1 already copies it to memory inside `hashStruct`) |
| `_checkOp` / `_executeOp` | calldata slices | memory; arguments read with `mload` at fixed offsets after the length check |
| Reentrancy slot | `keccak256("scaas.metatx.reentrancy.v1")` | `keccak256("scaas.metatx.reentrancy.v2")` (transient; the guard covers meta-tx, wrap, unwrap, `addReserve`, `mtxBatch`) |
| Step 6 | balance, fee, recipient non-zero, `_checkOp` | + R132 payee check |
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
| 7 | transfer fee | — |
| 8 | `_executeOp` | — (must not fail) |
| 9 | `nonce++`, `MetaTransactionExecuted(from, relayer, batch, nonce, digest, feeRecipient, fee)` | — |

"Payee" for R132 = `m.to` when `m.data` is empty (transfer) or is the `pay` op. For `trade` the `to` is the
settlement contract and for `approve` the value is 0 (a `FIXED` fee there already fails the 1 % cap, a `PERCENT`
fee computes to 0), so the check does not apply to them.

### 3.3 Ops (`MetaTokenBase`, all tiers)

Same table as v1 (SCaaS §5.4): empty ⇒ transfer; `pay(bytes32)` (36 bytes, `to ≠ 0`) ⇒ transfer +
`PaymentSettled`; `trade(address,uint256,address)` (100 bytes, restricted relayer, `to == msg.sender`);
`approve(address,uint256)` (68 bytes, `value == 0`, `to == spender`, spender a contract). Unknown ⇒
`MetaTxUnknownOp`. No wrap/unwrap op in v2 (§13 Q2).

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
    require U.balanceOf(this) ≥ reserve                        // ReserveShortfall
    before = U.balanceOf(this); U.safeTransferFrom(msg.sender, this, amount); received = U.balanceOf(this) − before
    minted = mulDiv(received, num, den)                        // floor
    require minted > 0                                         // WrapTooSmall
    reserve += received; _mint(msg.sender, minted); emit Wrapped(msg.sender, U, received, minted)

unwrap(uint256 wrapped, address recipient) returns (uint256 out)   // v1 selector kept, now returns out
    require recipient ≠ 0                                      // UnwrapToZero
    out    = mulDiv(wrapped, den, num)                         // floor
    require out > 0                                            // UnwrapTooSmall
    require out ≤ reserve                                      // InsufficientReserve(U, out, reserve)
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

### 5.3 Views

`underlying()` (tier 2: the single underlying), `underlyings() returns (address[])`, `legOf(address u) returns (uint96
num, uint96 den, uint256 reserve, uint8 decimals, bool wrapEnabled)`, `collateralValue()`,
`previewWrap(u, amount)`, `previewUnwrap(u, wrapped) returns (out, burned)`, `rateAdjustable()`, `rateAdmin()`,
`rateDelay()`, `maxRateStepBps()`, `pendingRate(u) returns (num, den, eta)`. Previews ignore fee-on-transfer (they
assume `received == amount`).

---

## 6. Rates: fixed or adjustable (R133, R135)

### 6.1 Terms

`q = num/den` = wrapped raw units per underlying raw unit. Raising `q` means each wrapped unit redeems for **less**
underlying; lowering `q` means each wrapped unit redeems for **more**.

### 6.2 Adjustable-rate lifecycle

```
proposeRate(address u, uint96 num, uint96 den)   // rateAdmin; no pending change for u; step bound; RateInvalid
    eta = now + rateDelay; emit RateChangeProposed(u, oldNum, oldDen, num, den, eta)
cancelRate(address u)                             // rateAdmin; emit RateChangeCancelled(u)
executeRate(address u)                            // anyone; eta ≤ now ≤ eta + 7 days (RateChangeNotReady / RateChangeExpired)
    step bound re-checked against the current rate; if collateral falls: invariant check (§6.3)
    apply; delete pending; emit RateChanged(u, oldNum, oldDen, num, den)
renounceRateAdmin()                               // rateAdmin; drops any pending change; rateAdmin = 0 forever; emit RateAdminRenounced()
```

Step bound, exact in integers (`uint96` inputs keep every product below 2^207):

```
|num'·den − num·den'| · 10_000 ≤ num·den' · maxRateStepBps          // RateStepTooLarge
```

Fixed-rate tokens have no pending storage in use and every function above reverts `RateFixed()`.

### 6.3 Safety analysis

| Direction | Effect on holders | Solvency | Control |
|---|---|---|---|
| Raise `q` | Redemption value of every outstanding unit falls by ≤ one step (dilution). New wrappers get more units per underlying. | `C` rises: always solvent. The extra backing stays in the reserve; nobody can withdraw it. | Timelock: every holder sees `RateChangeProposed` and can unwrap at the old rate for `rateDelay`. |
| Lower `q` | Redemption value rises. | `C` falls: could go below `totalSupply` (insolvency = a run where the last holders get nothing). | `executeRate` recomputes `C` with the new rate and reverts `RateChangeUndercollateralized(C', supply)` unless `C' ≥ totalSupply`. The issuer funds it first with `addReserve`. |

Consequences, stated for issuers and holders:

1. A fixed-rate token has no admin and its redemption price never moves. This is the default and the only form the
   catalogue templates offer without an explicit opt-in.
2. An adjustable token's worst case for a holder who never reacts: one step (≤ `maxRateStepBps`) of dilution per
   `rateDelay`. Compounding at the defaults (1 % per 7 days) is ≈ 40 % per year; issuers who promise a stable value
   should not choose `adjustable`, and wallets must show `rateAdjustable()` as a warning.
3. Insolvency through a rate change is impossible (`C' ≥ totalSupply` checked at execution); insolvency through a
   failing underlying is not preventable by any rate rule (§6.6).
4. `rateAdmin` must be a contract: a single EOA key that moves everyone's redemption price is the threat R26 removed
   for allowances.
5. Executing is permissionless so a renounced or absent admin cannot strand an approved change; it expires after the
   grace instead of hanging forever.
6. Rounding never favours the caller (R133), so repeated wrap/unwrap cycles cannot extract value at any rate.

### 6.4 Decimals (R137)

Rates are raw. Examples (wrapper `D = 18`):

| Underlying | `d_i` | Intended human rate | `num` / `den` |
|---|---|---|---|
| xDAI / WXDAI | 18 | 1 : 1 | 1 / 1 |
| USDC, USDT | 6 | 1 : 1 | 10^12 / 1 |
| loyalty: 1 USDC → 100 points (`D = 0`) | 6 | 1 : 100 | 1 / 10^4 |

With integer rates (`den = 1`) wrap has no rounding; unwrap pays `⌊w/10^12⌋` and burns a multiple of `10^12`, the
holder keeps the rest. The wizard computes `num/den` from the human rate and the two decimals and shows the result
back; it refuses a rate whose `num` or `den` reaches 2^96.

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
| `mtxBatch(MetaTransaction[] ms, bytes[] sigs)` | each `ms[i]` as given | as `executeMetaTransaction` per item | atomic; one outer tx for many items |
| `payLane(bytes32 payId) view returns (uint256)` | — | — | the lane clients must use for `payId` on this token |

Exact equivalences (each is a test, §10.1):

```
mtxTransfer(f,t,a,b,n,v,mode,r,s)              ≡ executeMetaTransaction({f,t,a,"",b,n,v,mode,r,0,0}, s)
mtxTransferWithFee(f,t,a,b,n,v,mode,r,x,R,s)   ≡ executeMetaTransaction({f,t,a,"",b,n,v,mode,r,x,R}, s)
executeMetaTransactionWithFee(m,s)             ≡ executeMetaTransaction(m,s)            (plus the shape check)
mtxPay(f,t,a,p,v,mode,r,x,R,s)                 ≡ executeMetaTransaction({f,t,a,pay(p),payLane(p),0,v,mode,r,x,R}, s)
```

So: same digest, same events (`MetaTransactionExecuted`; `PaymentSettled` for `mtxPay`), same nonce space (a
signature consumed through one path fails `MetaTxBadNonce` on the other), same KAT. A named function never accepts an
intent that the generic path would refuse, and refuses some the generic path accepts (wrong shape), never the other
way round.

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
derived lane with the job, so a pay job never changes lanes after it is signed.

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
| `wrap(address u, uint256 amount) returns (uint256 minted)` | tier-2 wrap on leg `u`; `UnknownUnderlying(u)`, `WrapDisabledFor(u)` |
| `unwrap(address u, uint256 wrapped, address recipient) returns (uint256 out, uint256 burned)` | tier-2 unwrap on leg `u`, bounded by `reserve_u`; works on disabled legs |
| `addReserve(address u, uint256 amount)` | tier 2; refused on disabled legs |
| `disableWrap(address u, bytes32 reason)` | guardian; one-way; `WrapDisabled(u, guardian, reason)`; second call reverts `WrapDisabledFor(u)` |
| `renounceGuardian()` | guardian; `GuardianRenounced()` |
| `wrap(uint256)`, `unwrap(uint256,address)` (inherited single-asset ABI) | revert `UnderlyingRequired()` |
| `underlying()` | returns `address(0)`; clients use `underlyings()` |
| rate functions | per leg, §6.2; `RateDecreaseWithDisabledLeg()` if a change lowers `C` while any leg is disabled |

### 8.3 Invariant and solvency

`C = Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply()` is the aggregate invariant; §5.2's per-operation argument holds
leg by leg. There is **no** per-leg invariant: the backing is pooled and redemption is any-of.

### 8.4 Depeg risk (disclosure text for issuers and holders)

At fixed nominal rates the token treats its underlyings as equal. When one depegs (say USDT trades at 0.95 while the
rate says 1:1), anyone can wrap the cheap asset and unwrap a good one: the good reserves drain first and the
remaining holders end up backed by the weakest asset. This is the expected behaviour of an any-of wrapper, not a bug.

- The guardian's `disableWrap` stops new inflow of the depegged asset; it does **not** stop the exit into good legs
  (that would trap holders) and cannot restore drained legs.
- Holders carry the risk of the worst underlying in the set, plus each underlying issuer's freeze/upgrade power
  (§6.6). The reserve composition is public (`legOf`) and the node/ERP should alert on composition drift.
- Issuers should list only assets they would accept at par, keep a guardian on call, and expect the composition to
  move toward the cheapest leg during stress.
- No re-enable: a mistaken disable is permanent for that leg. Holders lose nothing by it; the issuer creates a new
  token if the leg must come back.

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
| Registration | `registerImplementation(kind, v, impl)` for the three new kinds calls `impl.tokenKind()` (try/catch) and reverts `VersionKindMismatch(kind, got)` on a mismatch or no answer |
| Creation | same as v1: CREATE2 salt `keccak256(abi.encode(msg.sender, salt))`, `Clones.cloneDeterministic`, `initialize` in the same call, `TokenDeployed(token, creator, underlyings[0] or 0, kind, version, impl, 0)` |
| Provenance | every underlying of a tier-2/3 token is indexed: `_wrappers[creator][u]`, `_byUnderlying[u]`; new event `TieredTokenDeployed(token, creator, kind, version, implementation, underlyings)` carries the full list |
| Unregistered | `createTieredUnregistered` requires code at `implementation`, records `version == 0`, also checks `tokenKind()` |
| Registrar | unchanged powers (`registerImplementation`, `deprecate`, `setZetherEnabled`); none over tokens |
| Deploy script | `Deploy.s.sol` gains factory v2 + three implementations registered as version 1 of their kind (the version number is per kind; `version()` of a clone is the catalogue version, the domain version string `"2"` is the contract generation) |

Factory v1 stays deployed for v1 tokens; factory v2 does not register `MetaToken` v1.

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
| 8 | `MetaTokenBase` | packed: `creator` (20) ‖ `version` u64 ‖ `_tokenDecimals` u8 ‖ `_initialized` bool |
| 9–10 | `MetaTokenBase` | `_tokenName`, `_tokenSymbol` |
| 11 | `NoUnderlyingToken` | `minter` |
| 11 | `SingleUnderlyingToken` | `_legs` `Leg[]` |
| 12 | 〃 | `_legIndex` `mapping(address ⇒ uint256)` (index + 1) |
| 13 | 〃 | `_pending` `mapping(uint256 leg ⇒ PendingRate)` |
| 14 | 〃 | packed `RateConfig`: `rateAdmin` (20) ‖ `rateDelay` u32 ‖ `maxRateStepBps` u16 ‖ `adjustable` bool |
| 15 | `MultiUnderlyingToken` | `guardian` |

```solidity
struct Leg { address token; uint8 decimals; bool wrapEnabled;   // slot a
             uint96 num; uint96 den;                             // slot b
             uint256 reserve; }                                  // slot c
struct PendingRate { uint96 num; uint96 den; uint64 eta; }      // one slot; eta == 0 ⇒ none
```

Immutables (implementation): `FACTORY`, `_SELF`, `SUBJECT_ACCOUNT_IMPL`, `_SUBJECT_CLONE_CODEHASH`; constant
`KIND`. The constructor sets `_initialized = true` on the implementation's own storage (it cannot be initialized).

### 10.2 Events and errors

| Contract | Events | Errors |
|---|---|---|
| `MetaTxCore` | `MetaTransactionExecuted` (v1), `MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce)` | v1 `MetaTx*`, `SpenderNotContract`, `CallerNotContract`, `FeeRecipientIsPayee()` |
| `MetaTokenBase` | `PaymentSettled` (v1) | v1 op errors, `MtxModeShape(uint32 mode)`, `MtxBatchEmpty()`, `MtxBatchLengthMismatch()`, `NotFactory()`, `AlreadyInitialized()` |
| `NoUnderlyingToken` | `MinterRenounced()` | `NotMinter()` |
| `SingleUnderlyingToken` | `Wrapped(address indexed account, address indexed underlying, uint256 underlyingIn, uint256 minted)`, `Unwrapped(address indexed account, address indexed underlying, address recipient, uint256 burned, uint256 underlyingOut)`, `ReserveAdded(address indexed from, address indexed underlying, uint256 amount)`, `RateChangeProposed(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen, uint64 eta)`, `RateChangeCancelled(address indexed underlying)`, `RateChanged(address indexed underlying, uint96 oldNum, uint96 oldDen, uint96 newNum, uint96 newDen)`, `RateAdminRenounced()` | `UnderlyingInvalid(address)`, `DecimalsUnreadable(address)`, `UnderlyingCountInvalid(uint256)`, `RateInvalid(uint256,uint256)`, `RateConfigInvalid()`, `RateAdminNotContract(address)`, `WrapTooSmall()`, `UnwrapTooSmall()`, `UnwrapToZero()`, `InsufficientReserve(address,uint256,uint256)`, `ReserveShortfall(address,uint256,uint256)`, `UnderlyingTransferMismatch(address,uint256,uint256)`, `UnknownUnderlying(address)`, `RateFixed()`, `NotRateAdmin()`, `RateChangePending(address)`, `NoRateChangePending(address)`, `RateChangeNotReady(uint64)`, `RateChangeExpired(uint64)`, `RateStepTooLarge()`, `RateChangeUndercollateralized(uint256,uint256)` |
| `MultiUnderlyingToken` | `WrapDisabled(address indexed underlying, address indexed guardian, bytes32 reason)`, `GuardianRenounced()` | `DuplicateUnderlying(address)`, `WrapDisabledFor(address)`, `UnderlyingRequired()`, `NotGuardian()`, `RateDecreaseWithDisabledLeg()` |
| `OpenFactory` v2 | `TieredTokenDeployed(address indexed token, address indexed creator, TokenKind kind, uint64 version, address implementation, address[] underlyings)` | `UnderlyingCountInvalid(uint256)` (+ v1 errors) |

The node's event normaliser (SCaaS §7.8) adds `Wrapped`, `Unwrapped`, `ReserveAdded`, `RateChange*`, `WrapDisabled`,
`MetaNonceCancelled`; `PaymentSettled` and `MetaTransactionExecuted` are unchanged, so payment reconciliation needs no
change.

### 10.3 Gas notes (estimates; measured numbers replace them in `MetaTxGas.t.sol` v2)

- Hot path (transfer, `pay`, fees, named functions) touches no tier storage: same SLOAD/SSTORE set as v1, plus the
  R132 comparison (< 100 gas). Budget: every row of the v1 gas table (SCaaS §5.6) within **+300 gas** on the generic
  path; the named functions equal or below the generic path.
- `mtxPay` adds one `keccak256` of 46 bytes (~40 gas) and saves the dynamic `data` and two words of calldata.
- `mtxBatch` saves the 21 000 intrinsic gas and the cold token access (2 600) per item after the first, i.e. ≈ 23.6 k
  per item before calldata; the first use of a lane (+17 k) is unchanged.
- Wrap/unwrap: three cold leg slots (6 300) + reserve SSTORE + two `balanceOf` calls on the underlying + the
  transfer; Multi adds one `_legIndex` SLOAD. Rate functions are rare and unoptimised.
- Size: CI fails if any implementation exceeds 24 576 bytes (`forge build --sizes`); if Multi does, the rate
  timelock moves into a linked external library (clone → implementation → library delegatecall keeps the clone's
  storage).

### 10.4 Test plan

Unit (forge, `test/v2/`):

| Area | Tests |
|---|---|
| Base | typehash still pinned (`test_metaTxTypehashIsPinned` unchanged); v2 domain KAT `test/vectors/metatx_v2_kat.json` (same struct as `metatx_kat.json`, same `struct_hash`, new digest) checked by Solidity, node, Odoo `lib/eip712.py`; `MetaNonceCancelled`; R26 on all three tiers; ERC-1271 400 k only for SubjectAccount clones |
| Fees | percent on `value`, fee on top, 1 % cap PERCENT and FIXED; `FeeRecipientIsPayee` for transfer, `pay`, `payWithFee`, bound and relayer-default; not raised for `trade`/`approve` |
| Named | each equivalence of §7.1 (same digest, same events); a signature consumed by a named call fails on the generic path and vice versa; every `MtxModeShape` case; `mtxPay` lane equals `payLane`; second `mtxPay` of a `payId` reverts `MetaTxBadNonce`; `mtxBatch` atomic (one bad item reverts all), length mismatch, empty |
| Tier 1 | init mint to creator, `mint`/`NotMinter`, `renounceMinter`, `burn`, fixed supply with `minter = 0` |
| Tier 2 | rate 1:1 equals v1 behaviour; rounding down on wrap/unwrap; `burned = ⌈out·q⌉`; `WrapTooSmall`/`UnwrapTooSmall`; FoT inbound measured; sender-pays FoT reverts `UnderlyingTransferMismatch`; donation not counted; `ReserveShortfall` after a negative-rebase mock stops wrap and not unwrap; `addReserve`; decimals snapshot; init refusals |
| Rates | fixed ⇒ `RateFixed`; propose/cancel/execute; delay and grace bounds; step bound both directions at the exact edge; decrease refused without collateral, accepted after `addReserve`; renounce drops pending; non-admin refused; EOA admin refused at init |
| Tier 3 | 2–8 legs, duplicates, zero; per-leg reserves; unwrap bounded by `reserve_i`; guardian disable one-way and idempotence error; unwrap open on a disabled leg; `addReserve` refused on it; `RateDecreaseWithDisabledLeg`; inherited single-asset ABI reverts |
| Factory v2 | kind ⇒ count; `VersionKindMismatch`; append-only catalogue; `createTieredUnregistered` version 0; salt scoped by creator; every underlying indexed; `TieredTokenDeployed` |
| Layout | `test_storageLayoutIsPinned` per implementation |
| Hedera | HIP-632 path on each tier (mocked precompile, as `test/hedera/` today); `associateUnderlying(u)` per leg; HTS custom-fee refusal |

Invariant / fuzz (`test/v2/WrapperInvariant.t.sol`, `[invariant] runs = 64, depth = 32, fail_on_revert = true` as
today, with handlers that bound inputs so expected reverts do not count as failures):

- Handlers: wrap / unwrap / `addReserve` on random legs with random actors; plain donations; FoT and plain
  underlyings; meta-tx transfers with fees; propose / warp / execute / cancel rate changes with random targets;
  guardian disables; negative-rebase shocks on a mock leg.
- Invariants: `collateralValue() ≥ totalSupply()`; `Σ balances == totalSupply()`; `balanceOf_i ≥ reserve_i` for
  well-behaved legs; every executed rate change satisfied the step bound and waited `rateDelay`; a disabled leg is
  never re-enabled; no wrapped unit is minted without reserve growth.
- Fuzz: `testFuzz_wrapUnwrapNeverProfits(amount, num, den)` — a wrap then full unwrap never returns more underlying
  than went in; `testFuzz_stepBoundExact(num, den, num', den', bps)` against a reference in 512-bit arithmetic;
  `testFuzz_feeConservesSupply` (v1 test ported).

Cross-family vectors: `test/vectors/wrap_rate_vectors.json` — `(num, den, in) → minted` and
`(num, den, w) → (out, burned)` incl. edge cases (`2^96 − 1`, `den = 1`, zero outputs), written by
`test_writeRateVectors` and later replayed by the Cosmos, Soroban and TON wrappers (R145). `metatx_v2_kat.json` is
EVM/Hedera only.

---

## 11. Hedera (R144)

`HederaNoUnderlyingToken`, `HederaSingleUnderlyingToken`, `HederaMultiUnderlyingToken` each inherit their tier and an
abstract `HederaSigMixin is MetaTxCore` that overrides `_requireValidSignature` exactly as `HederaMetaToken` does
(64-byte signature from an account without code ⇒ HIP-632 `isAuthorizedRaw`). Wrapper tiers add
`associateUnderlying(address u)` (permissionless, idempotent, any leg) and at `initialize` read
`getTokenCustomFees(u)` from the HTS precompile `0x167` for HTS underlyings: any custom fee ⇒ `UnderlyingInvalid(u)`
(a fee schedule key can still add one later — disclosure §6.6). Domain, ABI, events and tests are the EVM ones.

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

1. **Adjustable rates on Multi.** Ruling 2 says rates are an issuer option "per underlying for Multi"; ruling 3 says
   the set and per-underlying rates are "fixed at creation". This spec reads ruling 3 as "set at creation, never
   added or removed" and allows the ruling-2 timelock on Multi legs, default off. The literal reading (Multi rates
   immutable) is safer, because a raised rate on one leg is a cross-leg drain channel, bounded only by the step and
   the exit window. Confirm one of the two.
2. **Gasless wrap/unwrap.** v2 has no meta-tx op for `unwrap` (or `wrap`): step 8 would call the underlying, a
   foreign contract, which the no-foreign-CALL design avoids, and a blacklisting underlying would turn it into a
   relayer-griefing op. A holder without native gas exits by transfer or through a contract wallet. Add `OP_UNWRAP`
   in v2 (simulation-gated) or leave it to a later version?

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
| T1 | `MetaTxCore` (memory pipeline, R132, `MetaNonceCancelled`), `MetaTokenBase` (ops, `payWithFee`, named functions, `mtxBatch`, `payLane`), `metatx_v2_kat.json` | `test/v2/Base*.t.sol`, v1 tests untouched and green |
| T2 | `NoUnderlyingToken`, `SingleUnderlyingToken` (legs, reserve, rates, timelock), `wrap_rate_vectors.json` | `test/v2/Tier*.t.sol`, `Rates.t.sol` |
| T3 | `MultiUnderlyingToken` (legs 2–8, guardian) | `test/v2/Multi.t.sol` |
| T4 | `OpenFactory` v2, `IFactoryTokenV2`, `Deploy.s.sol` | `test/v2/FactoryV2.t.sol`, sizes ≤ 24 576 |
| T5 | Hedera children + mixin | `test/hedera/*V2*.t.sol` |
| T6 | Invariant suite, layout pins, gas table v2 | `WrapperInvariant.t.sol`, `MetaTxGas` v2 vs v1 budget |
| T7 | Node (`kind`, `payLane`, new events, batching rule §7.5), Odoo fields, SDK typed ABIs | node `cargo test` for the token table and normaliser; Odoo unit tests |
| T8 | Docs: SCaaS §4/§5/§14 statuses to BUILT, `integration.md` | — |

---

## 16. Requirement trace (owner turns in `Grok3_Continued.md`)

| Line | Owner requirement | Status | Where | Changed by later rulings |
|---|---|---|---|---|
| 71 | Smart contract with meta-transaction support | **BUILT** | `ERC20MetaTx` (native mixin, SCaaS §5.1); v2 `MetaTxCore` | No forwarder ever; nine-step pipeline (canon §04.6.1) |
| 227 | Add `chainId` to tell chains apart | **BUILT** | EIP-712 domain `chainId` (`MetaTxLib` header: domain fields, not struct fields) | The transcript put `chainId` in the struct; it lives in the domain |
| 416 | The contract must be a wrapper of an ERC-20 | **BUILT** (1:1) | `MetaToken` v1 tier 2; v2 `SingleUnderlyingToken` (§5) | — |
| 641 | Disable approve/revoke for EOAs; only smart-contract accounts | **BUILT** | `ERC20MetaTx.approve`/`transferFrom` (SCaaS §4.4); inherited by v2 | R4 first rejected it; **R26** (owner) reinstated it as "spender must be a contract, only contracts call `transferFrom`", EIP-7702 designators count as EOAs; no `increaseAllowance`, no `permit` |
| 850 | Factory to create many wrappers for many ERC-20s | **BUILT** | `OpenFactory` (EIP-1167 clones, catalogue, per-creator wrappers); v2 §9 | Open factory, no upgrades, versioned implementations (IOpenFactory header) |
| 1116 | Wrappers with different conversion rates | **SPECIFIED** here | R133, R135, §6 | Issuer chooses fixed or adjustable at creation (owner 2026-10-06) |
| 1408 | An `mtxTransfer` function | **SPECIFIED** here | R138, §7.1 | Thin entry point over the pinned struct, no own `Transfer` typehash |
| 1726 | Add the wrapper contract address against replay | **BUILT** | domain `verifyingContract` = the clone (R5) | Domain field, not a struct field |
| 2055 | A wrapper with several underlyings (xDAI or USDC or USDT) | **SPECIFIED** here | R136, §8 | Owner add/remove dropped: set fixed at creation; guardian may only disable wrap (owner 2026-10-06) |
| 2452 | Transfer that pays a fee to the relayer or a third party, per mille, max 0.1 % | **BUILT** (fee); named form **SPECIFIED** | `FeePolicy`, `mode` fee nibble; §7.1 | Unit ppm (per mille cannot express 0.05 %); cap raised to **1 %** (turn 3725); fee never to the payee (turn 2848, R132) |
| 2848 | Keep `mtxTransfer`, add `mtxTransferWithFee`; the fee goes to someone other than the recipient | **SPECIFIED** here | R132, R138 | R132 adds the on-chain payee check v1 lacks |
| 3293 | Fee amount and fee recipient are parameters, the sender's option | **BUILT** in the struct (`fee`, `feeRecipient`, `MODE_RESTRICT_FEE_RECIPIENT`); **SPECIFIED** as typed parameters | `MetaTxLib`; §7.1 | Unbound recipient defaults to the relayer and is normalised by submitters (R84/R100) |
| 3725 | Cap at 1 % of the total | **BUILT** | `FeePolicy.MAX_FEE_PPM = 10_000`, PERCENT and FIXED | Not on confidential ops (RS2-6) |
| 4145 | `MultiUnderlying` is a child of the single wrapper | **SPECIFIED** here | R129 | — |
| 4667 | `mtxTransferWithFee` in the parent; add `executeMetaTransactionWithFee` | **SPECIFIED** here | R138 (`MetaTokenBase`, all tiers) | Fee to relayer (default) or third party (bound) |
| 5296 | Fee in `executeMetaTransactionWithFee` based on the sender's amount | **BUILT** | `FeePolicy.compute(…, m.value, …)`, fee on top | No `data` decoding needed: the amount is `m.value` |
| 5867 | Three types parent/child (none, single, multi); factory creates all three; an inheriting class with `mtxPay` and a sender-supplied `payId` | **SPECIFIED** here | R129, R130, R139 | `payId` = `entryRef` (R9), lane derived on chain; event is `PaymentSettled`, not `Payment`; no second typehash (R140); tier 1 gains `burn` (R141) |
