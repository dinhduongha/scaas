# TW2 rev 1.1 — adversarial design review 1

Spec: `scaas/docs/superpowers/specs/2026-10-06-token-wrappers-v2.md` (R129–R149). Code read: `metatx/ERC20MetaTx.sol`,
`metatx/MetaToken.sol`, `common/MetaTxLib.sol`, `common/FeePolicy.sol`, `factory/OpenFactory.sol`,
`factory/IFactoryToken.sol`, `hedera/HederaMetaToken.sol`, `test/Invariants.t.sol`, `test/MetaTxKat.t.sol`,
`test/MetaToken.t.sol`, `dms_blockchain/lib/eip712.py`. Read-only, no builds. Owner rulings were not re-argued.

## Verdict: **FIX-THEN-GO**

The core reserve invariant holds: I could not break `C = Σ⌊R_i·num_i/den_i⌋ ≥ S` with any user operation. In
fact something stronger holds. The slack `C − S` never decreases under wrap, unwrap (direct and R148), `addReserve`,
fees, FoT-in or donations (proof in §A). No finding is Critical. Two findings are High, and both sit in the
**Multi adjustable-rate** design (R147). Per-leg rate changes open a cross-leg arbitrage in **both** directions. The
guards cover only one direction, and only at the moment of execution, so a pending decrease lets anyone take the
issuer's top-up in one transaction with no capital. The share cap (b) can be pushed either way with a flash loan.
Both are fixed by a spec change that stays inside the owner rulings (H1 fix). The meta-tx side is sound. The named
functions really do produce the same digest. The remaining items are claims that need correcting, gas
under-estimates, and gaps in the test plan.

---

## §A. The invariant: what I checked

With `q = num/den`. Every user op leaves `Δ(C − S) ≥ 0`:

| Op | ΔC | ΔS | Δslack |
|---|---|---|---|
| wrap `r` | `⌊(R+r)q⌋ − ⌊Rq⌋ ≥ ⌊rq⌋` | `+⌊rq⌋` | ≥ 0 (floor is superadditive) |
| unwrap `out` (direct / R148) | `≥ −⌈out·q⌉` | `−⌈out·q⌉` (`burned`) | ≥ 0 |
| `addReserve` | ≥ 0 | 0 | ≥ 0 |
| fee / transfer / `payWithFee` | 0 | 0 | 0 |
| FoT in | measured `received` on both sides | — | ≥ 0 |
| donation (plain transfer) | 0 (outside `reserve`) | 0 | 0 |
| raise `q` | ≥ 0 | 0 | ≥ 0 |
| lower `q` | < 0 | 0 | guarded by `C' ≥ S` |

Also checked:
- `burned ≤ w`: `out ≤ w/q` ⇒ `out·q ≤ w` ⇒ `⌈out·q⌉ ≤ w`.
- `out > 0` ⇒ `burned ≥ 1`.
- Single can never hit `InsufficientReserve`: `w ≤ S ≤ ⌊Rq⌋` ⇒ `⌊w/q⌋ ≤ R`.
- Recipient `= address(this)` cannot pass the exact-drop check.
- Two addresses that share one balance (dual-entry tokens) stay consistent, because accounting is internal.
- No caller can **block** a decrease. Pre-execute wrap/unwrap at the old rate cannot reduce `C' − S`.

What breaks is **not solvency**. It is *who gets the slack* (H1), and whether `reserve` is real (M1).

---

## High

### H1 — §2 R147, §6.3, §8.5: per-leg rate changes on Multi are atomically MEV-extractable in both directions. The wrap pause and share cap do not stop it

**Problem.** In an any-of wrapper, changing `q_i` alone changes the *relative* price of leg `i` against every other
leg. R147 and §8.5 analyse only the raise (wrap `i`, redeem `j`). A **decrease** of `q_i` creates the mirror
arbitrage: wrap `j`, redeem `i`. Guard (c) pauses wrap only into leg `i`, so wrapping `j` stays open. Execution is
permissionless, so wrap `j`, `executeRate(i)` and unwrap `i` all fit in one transaction. §6.3 item 7 ("Nobody can wrap
at a rate that is about to change") and R147(c)'s stated purpose (stop front-running of the issuer's top-up) are
both false for n ≥ 2.

**Attack (default 1 % step).** Setup: legs `i`, `j` at 1:1, `R_i = R_j = 1000`, `S = 2000`. The admin proposes
`q_i = 100/101`, which passes the step bound (`|100−101|·10⁴ = 10 000 ≤ 101·100 = 10 100`). For `C' ≥ S` the issuer
needs `⌊R_i·100/101⌋ ≥ 1000`, so it calls `addReserve(i, 10)`, giving `R_i = 1010`. After `eta`, one transaction:

1. Flash-borrow 1 000 000 `U_j`, then `wrap(j, 1e6)` (open, since only leg `i` is paused). This mints 1 000 000.
2. `executeRate(i)`. `C' = ⌊1010·100/101⌋ + 1 001 000 = 1 002 000 ≥ S = 1 002 000`, so it executes.
3. `unwrap(i, 1000)`. `out = ⌊1000·101/100⌋ = 1010` and `burned = ⌈1010·100/101⌉ = 1000`.
4. `unwrap(j, 999 000)`, then repay the loan.

Net result: the attacker is +1010 `U_i` − 1000 `U_j` = **+10, which is the whole top-up**. Holders end at `S = 2000`
with `R_j = 2000` and none of the 10 the issuer paid them. At the maximum step (10 %), the bot takes ≈ 11 % of `R_i`
on every decrease. Step 1 can even come after step 2, so making `executeRate` admin-only would not help: a bot
back-runs in the same block. If the token already had slack (from an earlier raise, dust or third-party
`addReserve`), a decrease needs no top-up, and the bot takes the **holders'** surplus instead.

The raise case (§8.5.1) is worse than §8.5 says. It is not "until the guardian disables": it happens in the
execution block, atomically (`executeRate` → flash-wrap `i` → drain `R_j`). That is `step × R_j` taken in one
transaction, and the guardian can never react in time.

**Fix (stays inside "rates adjustable by issuer option, incl. Multi").** On Multi, adjustable means **one global
scale** `(sNum, sDen)` applied to every leg (`q_i_eff = q_i·s`). The per-leg relative rates stay fixed at creation.
A global change leaves every cross-leg price ratio the same, so the cross-leg arbitrage disappears in both
directions. The rules then reduce exactly to the Single rules:
- one pending change pauses wrap on **all** legs;
- the check is `C' ≥ S`;
- `RateDecreaseWithDisabledLeg` is kept.

This also removes guard (b), `maxLegShareBps`, `legShareBps`, `LegShareExceeded` and the per-leg `_pending` mapping
(one slot). If the owner really needs per-leg changes (for example to re-peg one leg), then any pending change must
pause wrap on all legs, and §8.5 must state the post-execution drain for both directions, `step × R_other` in one
block. The guardian is the only re-peg tool.

### H2 — R147(b), §6.2, §10.4: the share cap can be pushed past with a flash loan, or blocked by any holder

**Problem.** `v_i'/C' ≤ maxLegShareBps` is evaluated against the composition *at the instant of execution*. Anyone
can change that composition atomically, in either direction.

**Bypass.** n = 2, cap 7 500. Start with `R_i = 800`, `R_j = 200`, all at 1:1. A +1 % raise on `i` gives
`v_i' = 808` and `C' = 1008`, a share of 80.2 %, so it reverts. In one transaction:
1. Flash 2000 `U_j`, `wrap(j, 2000)`.
2. `executeRate(i)`. The share is now 808/3008 = 26.9 %, so the raise lands.
3. `unwrap(j, 2000)` and repay.

Cost: the flash fee (0 on Balancer) plus gas. The composition is back at 80 %.

**Block.** Start with `R_i = 700`, `R_j = 300`; a +1 % raise passes at 70.2 %. A holder of 100 units unwraps `j`
before execution. The share becomes 707/907 = 77.9 %, so it reverts. Wrap of `i` stays paused until expiry (up to
37 days), and the holder can wrap back in afterwards.

The planned invariant ("every executed raise left share ≤ cap") **passes** under the bypass, so the test plan
cannot see this.

**Fix.** Delete (b). It is subsumed by the H1 fix. If per-leg changes stay, still delete it: a guard that anyone can
switch off atomically is worse than none, because issuers and wallets will rely on it.

---

## Medium

### M1 — §6.2 `executeRate`, R134: the solvency check counts phantom reserve

**Problem.** `C'` uses the internal `reserve_i`. After a negative rebase, confiscation or blacklist-burn on any leg,
`reserve_i > balanceOf_i`. A decrease on another leg then passes `C' ≥ S` with backing that does not exist. Wrap and
`addReserve` already refuse in this state (`ReserveShortfall`); `executeRate` does not.
`RateDecreaseWithDisabledLeg` covers this only if a guardian exists and has already acted.

**Attack.** Legs `i`, `j` at 1:1, `R = 1000` each, `S = 2000`. Leg `j` is confiscated down to `balance_j = 500`.
The admin lowers `q_i` 1 % after `addReserve(i, 10)`: `C' = 1000 + 1000 ≥ 2000`, so it executes. The real backing is
1510 against 2000 of claims, and leg `i` now pays out at a premium, so the first to exit take more of the loss
away from the last holders. The check exists to stop exactly this insolvency-by-rate-change, and here it fails.

**Fix.** In `executeRate`, for every leg, revert `ReserveShortfall(u, bal, reserve)` if `balanceOf_i < reserve_i`
(or compute `C'` from `min(reserve_i, balanceOf_i)`). This is one `balanceOf` per leg on a rare operation. Add the
case to the invariant handlers: a negative-rebase shock, then a decrease.

### M2 — R139, §7.3: the claim "each `(payer, payId)` pays at most once, enforced by the contract" is false

**Problem.** `mtxPay` consumes `(payLane(p), nonce 0)`, but the same `payId` can be settled again through other
paths:
- `payWithFee(…, entryRef = p)`: the direct path, with no nonce at all;
- the generic `pay` op on any other lane, or on nonce ≥ 1 of `payLane(p)` after a `cancelMetaNonce`;
- through `mtxBatch`.

Each path emits `PaymentSettled(entryRef = p)`. A reconciler built on R139's wording would accept a second, smaller
`PaymentSettled` that carries a leaked invoice reference. This is already possible in v1 through `payWithFee`; the
new wording makes it look as if the contract excludes it.

**Fix.** Reword: "`mtxPay` pays a `payId` at most once *through `mtxPay`*". Reconcilers must match
`(payer, payee, amount, entryRef)` and dedupe on `entryRef`; Odoo and the node must not treat a second event as a
payment. Add a test that `payWithFee` with the same `entryRef` still emits, which documents the gap.

### M3 — R148, §7.6: unwrap reverts are exempt from the grief score, but the signer controls the recipient

**Problem.** §7.6 treats reverts inside the underlying as "the cause is the underlying, not the signer". But the
signer picks `recipient`, and can flip it between the node's simulation and inclusion. Ways to do that:
- Hedera: dissociate or remove KYC on the recipient account (an HTS transfer to an unassociated account reverts);
- a hooked underlying (ERC-777 `tokensReceived`, or ERC-1363) whose recipient hook reverts on `gasleft()`,
  `block.coinbase` or `block.number` patterns that `eth_call` at `pending` does not reproduce;
- moving the recipient onto a blacklist the signer controls (an issuer-side contract).

Each failed outer transaction costs the relayer the full gas, roughly 85–100 k or more (see L3), and with the
exemption the signer can repeat it for free.

**Fix.** Exempt only reverts whose cause is independent of the recipient: `InsufficientReserve`, a paused
underlying, or the **wrapper** being blacklisted. Count every other post-simulation revert of an unwrap job toward
`origin_grief_score`, as for transfers. Optionally have the node refuse gasless unwrap to a recipient that has code
when the underlying is known to be hooked.

### M4 — R135, R148: unwrap has no `minOut`, so "exit at the old rate during `rateDelay`" does not hold for pending intents

**Problem.**
- A signed gasless unwrap has only `value`. Its `out` is computed at execution, and `validUntil` can be days away.
  A relayer, or anyone for an unrestricted intent, can hold it until after a permissionless `executeRate` lands:
  the holder gets one step less, up to 10 %.
- A direct `unwrap` sent in the execution block can be ordered after `executeRate` (anyone can call it at `eta`).

R135's "if wrong" line ("a holder who disagrees has at least `rateDelay` to unwrap at the old rate") only holds if
`out` is bound.

**Fix.**
- Op `unwrap(address underlying, address recipient, uint256 minOut)` (100 bytes; step 6 checks `out ≥ minOut`);
  `mtxUnwrap*` take `minOut`.
- Direct `unwrap(…, minOut)` overloads (or `minOut` on the Multi signature, with the v1 `unwrap(uint256,address)`
  kept as `minOut = 0`).

This is about 3 lines and one KAT field, and it is only possible now, before the op tag is fixed.

### M5 — R144, §11: HTS custom-fee detection must fail closed

**Problem.** "At init they refuse HTS underlyings that carry custom fees" does not say:
- how an HTS token is detected (long-zero address? `isToken(u)` on `0x167`?);
- what happens when the precompile returns a response code other than SUCCESS or an undecodable result.

An implementation that treats "call failed" as "no fees" accepts a token with a sender-pays fractional fee
(`netOfTransfers`), and every unwrap of that leg then reverts `UnderlyingTransferMismatch`: the reserve is stuck.
Also, `getTokenCustomFees` shows only today's fees. A token with a fee-schedule key can add one later, which the
spec mentions only as a disclosure.

**Fix.** Specify:
1. `isToken(u)` → (rc, bool); rc ≠ SUCCESS ⇒ `UnderlyingInvalid`.
2. If it is HTS: `getTokenCustomFees` with rc ≠ SUCCESS **or** any fee entry ⇒ `UnderlyingInvalid`.
3. Optionally, `getTokenKey(u, FEE_SCHEDULE)` non-empty ⇒ refuse, or emit a flag event that wallets show.

Test each of the three failure modes with the mocked precompile.

### M6 — §10.4: the invariant suite cannot detect H1, H2 or M1 as designed

**Problem.** `C ≥ S` holds in all three attacks, so the headline invariant passes. "Executed raise left share ≤ cap"
also passes under the H2 bypass. The plan has no slack, conservation or profit oracle. A single fixed setup also
leaves the extreme rates untested, and with `depth = 32` and no warp-to-`eta` handler, `executeRate` is almost never
reached.

**Fix.** Add the following.
- Invariant: `C − S` never decreases across any handler call except a rate execution (a ghost variable holds the
  previous value).
- Per-leg conservation ghost: `Σ received_i + Σ addReserve_i − Σ out_i == reserve_i`.
- A profit oracle: a ghost attacker actor whose underlying value at nominal par must not increase over a sequence.
  This catches H1.
- A `warpToEta(leg)` handler that jumps exactly to `eta` or `eta + grace`.
- Separate invariant contracts per rate setup: `1:1`, `10¹²:1`, `1:10⁴`, `(2⁹⁶−1):1`, `1:(2⁹⁶−1)`, `3:7`.
- Fuzz `testFuzz_namedDigestEqualsGeneric` over random struct fields, not only fixed examples.
- Cross-leg `testFuzz_wrapIUnwrapJNeverProfitsAtPar`.
- The M1 shock-then-decrease case.
- Recipient `== address(this)`.
- An ERC-777 hook that calls `cancelMetaNonce` and `transfer` during a gasless unwrap.

---

## Low

### L1 — §5.4 `collateralValue`: overflow DoS
`mulDiv` reverts when `R_i·q_i ≥ 2²⁵⁶`, and the checked `Σ` can overflow too. With `q = 2⁹⁶`, that takes
`R ≥ 2¹⁶⁰` raw, which anyone can donate via `addReserve` on a large-supply leg. Every `executeRate` and the views
then revert. **Fix:** in `executeRate`, accumulate with an early exit once `acc ≥ S`, and have the view saturate at
`type(uint256).max`.

### L2 — R133: wrap dust goes to the reserve, up to one wrapped unit's worth per wrap
In the §6.4 loyalty example (`num = 1`, `den = 10⁴`), wrapping 15 000 raw (0.015 USDC) mints 1 point and donates
5 000 raw, a 33 % loss on that ticket. R133's "if wrong" line discusses only unwrap dust. **Fix:** `previewWrap`
returns `(minted, used = ⌈minted·den/num⌉)`. The UI and wizard round the amount down to a multiple of
`den/gcd(num, den)`. State the loss bound in R133.

### L3 — §10.3: gas claims
- Wrap and unwrap pay extra cold SLOADs that the spec does not count:
  - the `_legs.length` bounds check (+2 100);
  - the RateConfig slot read just to learn `adjustable` (+2 100, even on fixed tokens);
  - the §5.2 pseudo-code calls `balanceOf` twice before the pull: reuse `before` for the shortfall check.
  
  **Fix:** pack `adjustable` and a `pending` bit into leg slot a (10 free bytes); read leg 0 with no bounds check.
- `mtxBatch` "saves … 2 600 per item": wrong, because `tx.to` is pre-warmed (EIP-2929) on a separate transaction.
  The saving is 21 000 plus warm shared slots (the relayer's fee balance), minus the ABI overhead of `bytes[]`.
- The 85–100 k gasless-unwrap estimate leaves out:
  - the underlying's 0→non-zero SSTORE for a fresh recipient (+20 k);
  - proxy hops for USDC/USDT (+2.6 k cold implementation);
  - blacklist reads (+4.2 k).
  
  Expect 110–130 k for a fresh USDC recipient.

### L4 — §10.4: the v2 KAT cannot reuse the v1 struct for `mtxPay`
`metatx_kat.json` uses `batch = keccak256("scaas.pay.lane")` (`MetaTxKat.t.sol:22`), not `payLane(0x42)`. A v2 KAT
"with the same struct" therefore cannot test `mtxPay ≡ generic`. **Fix:** add an `mtxpay` vector with
`batch = payLane(payId)`, `nonce = 0`, checked by Solidity, the node and `lib/eip712.py`. `lane_batch` there already
matches `payLane`.

### L5 — §7.1: `fee` is not canonicalised under fee mode NONE
A struct signed with `mode` fee NONE and a leftover `fee ≠ 0` is valid on the generic path. `mtxTransfer` and
`mtxUnwrap` force `fee = 0`, so their digest differs and the result is `MetaTxBadSignature`. This is fail-closed and
consistent with the "named refuses a superset" rule, but it is an integration trap. **Fix:** state in §7.1 that
clients MUST sign `fee = 0` and `feeRecipient = 0` for named no-fee calls, and add a test.

### L6 — §3.1: manual `mload` op decoding must reject dirty address bits
v1 uses `abi.decode`, which reverts on non-canonical addresses. If v2 masks instead, two different `data` blobs (two
digests) give one op, and the wallet display stops matching the KAT. **Fix:** revert `MetaTxUnknownOp` when
`word >> 160 != 0`.

### L7 — R148 ordering details
- Refuse `recipient == address(this)` at step 6. Today it reverts at step 8, which costs relayer gas.
- Step 9's nonce write comes after the external transfer, while `cancelMetaNonce` is unguarded. The absolute write
  (`expected + 1`) makes this harmless, but write the nonce before the transfer for plain CEI, and test it with the
  ERC-777 mock.

### L8 — §6.2 pending-state semantics
- Define "expired ⇒ no pending change" for `proposeRate` (`RateChangePending`), `pendingRate()` and the views, not
  only for wrap.
- §6.3 item 5's rationale ("a renounced admin cannot strand a change") contradicts `renounceRateAdmin`, which drops
  the pending change.
- Re-checking the step bound at execution is dead code: the rate cannot change while a change is pending.

### L9 — §9: factory v2 checks
- `registerImplementation` should also require `impl.factory() == address(this)`. The catalogue is append-only, so
  a mismatched entry is dead forever.
- The v1 entry points (`createMetaToken`, `createUnregistered`) must refuse `META_NONE`, `META_SINGLE` and
  `META_MULTI`, and `createTiered*` must refuse `META` and `ZETHER`. Otherwise the kind ⇒ count and `tokenKind()`
  checks are bypassed, and `_info` records a "META_MULTI" with one underlying.
- Keep v1 `OpenFactory.sol` byte-identical, as R131 does for the tokens, so deployed v1 factories stay
  source-verifiable. Put v2 in a new file.

### L10 — R135 and R142 disclosure
- `_isContract(rateAdmin)` proves only that the admin has code. A one-line forwarder owned by one EOA passes, so
  wallets must not call it "multisig/timelock".
- §6.3 item 2 quotes the worst case at the defaults only. At the bounds (10 % per 2 days) it is about 100 % per
  year. Wallets should compute the worst case from the actual `maxRateStepBps` and `rateDelay`.

### L11 — §11: `associateUnderlying(u)`
Restrict `u` to known legs (`UnknownUnderlying`), and attempt the association once inside `initialize`, keeping the
function only for retries.

### L12 — §8.4: one compromised leg can drain every leg, in one transaction
A malicious or compromised upgradeable leg (fake `transferFrom`/`balanceOf` delta) mints without limit and drains
all the good legs in one transaction, before the guardian can act. The text "holders carry the risk of the worst
underlying" understates this. Reword to "each leg's admin key can take the whole basket". Also note that
`disableWrap` can be front-run, so the guardian should submit it privately.

### L13 — §9 provenance
- `getWrapper(creator, u)` can now return a Multi, whose `wrap(uint256)` reverts `UnderlyingRequired`. Document
  that clients must read `versionOf().kind` first.
- Two events per create (`TokenDeployed` + `TieredTokenDeployed`) could be one.

---

## Over-engineering (things to delete)
1. R147(b) and everything that serves it: `maxLegShareBps`, `legShareBps()`, `LegShareExceeded`, and the
   RateConfig field that must be 0 on Single (H2).
2. Per-leg `_pending` mapping and per-leg proposals on Multi. One global pending slot is enough (H1 fix).
3. The step-bound re-check in `executeRate` (L8).
4. R132 on the unwrap op. There is no invoice or payee, `feeRecipient == recipient` is not a harm, and the check is
   only a comparison, but dropping it makes the "payee" definition in §3.2 simpler.
5. A separate `associateUnderlying` call path, once initialisation associates the legs (L11).

## Checked and fine
- **Digest equivalence (§7.1).** Every named function builds the same 11-field struct, and `canon` zeroes the
  relayer and fee recipient by mode bits, so the digests are identical and there is one shared nonce space.
- **Mode shapes.** They are strict subsets of `validateMode`.
- **v1/v2 replay.** Blocked by `verifyingContract` and `chainId`: each clone address is unique per factory and
  implementation.
- **`payLane`.** It equals `lib/eip712.py:lane_batch`.
- **R132 checks.** The R132 check at step 6 covers `payWithFee`, the bound recipient and the relayer default.
- **Gasless unwrap order** (fee → burn/reserve → transfer → exact check). It runs under the contract-wide transient
  guard, any revert undoes the fee and the nonce, and the 63/64 rule cannot produce partial success because
  SafeERC20 bubbles the revert.
- **Clone initialisation.** It happens in the same call as CREATE2, and the salt is scoped by creator.
- **Storage slot plan.** It is consistent: slot 8 is 30 bytes, slot 14 is 29 bytes, `PendingRate` is 256 bits.
- **EIP-712 on clones** rebuilds the domain separator, as in v1.
- **ERC-777 reentrancy.** Every value-moving path is guarded. Unguarded ERC-20 `transfer` and `cancelMetaNonce`
  calls from hooks are harmless.
