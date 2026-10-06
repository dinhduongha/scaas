# AS (asset suite) rev 1 — adversarial design review 1

Spec: `scaas/docs/superpowers/specs/2026-10-06-asset-suite-design.md` (R200–R216).
Code read: `metatx/MetaTxCore.sol`, `MetaTokenBase.sol`, `NoUnderlyingToken.sol`, `SingleUnderlyingToken.sol`,
`MultiUnderlyingToken.sol`, `hedera/HederaTokensV2.sol`, `factory/OpenFactoryV2.sol`, `common/IOpenFactoryV2.sol`,
`dex/MetaTxDex.sol`, `dex/OrderBookDex.sol`, `test/v2/Layout.t.sol`, `script/Deploy.s.sol`, `foundry.toml`;
TW2 rev 1.2 rulings; A2 R124/R128. Read only, no builds. Sizes come from existing artifacts in
`.claude/worktrees/{tw2,p1fix}/smartcontracts/evm/out`.

## Verdict: **FIX-THEN-GO**

The architecture holds up: separate `*_REG` implementations, ERC-7201 storage, order-gated forced transfer, clones
per grant, Merkle claims, and the token acting as the on-chain arbiter for managed markets. I found nothing that
needs a redesign. Five money-safety holes still need fixing in the spec before AS1/AS3–AS5 start. Each one is a
path where funds get locked for good, or a path where one role or a small slip defeats a bound the spec promises:
H1 counterfactual funding into an address nobody can ever deploy, H2 renounce with frozen accounts, H3 a freeze
that the issuer alone can leave in place forever, H4 the sweep rug on splits and redemptions, H5 the allowlist on
the unwrap recipient closing exits. There are also three compile or behaviour blockers in "keyword-only" changes to
built code (M1, M2, M3).

---

## High

### H1. §4.1/§5.1/§5.2 — counterfactual funding can lock a pool for good (an address nobody can ever deploy)
**Problem.** The clone address commits to `params`. If `initialize(params)` reverts for any reason other than
`Underfunded`, the funded address can never hold code, and the funds stay there with nobody able to move them.
`Distribution` has a check that depends on time: `claimStart ≥ now`. Suppose the issuer funds `dist`, and then
`createDistribution` lands after `claimStart`. That happens if the relayer is down, the job sits in a queue, gas
spikes, or the ERP schedules funding at T-1h with `claimStart` = T. From then on every init reverts, and the
dividend pool is gone. The same applies to any params that fail a check that does not depend on state:
`ScheduleInvalid`, Σ tranches ≠ total, `expiry < claimStart + 30 d`, `sweepTo == 0`, `root == 0`. The SDK builds
`p`, and nothing on chain stops it from predicting an address for invalid `p` and funding it.
**Attack/accident.** An ERP job retries the deploy after `claimStart`, so the pool is lost. Or a client bug sends
a tranche array whose sum is off by one, so the grant is lost.
**Fix.** (a) `predictGrant/predictDistribution/predictOffer` must **revert** unless `p` passes every check that
does not depend on state. The SDK must only fund an address that `predict*` returned. (b) Init must never revert on
time. Treat the review window as `[create, max(claimStart, create))`, and allow a zero review window when the
deploy is late, rather than reverting. Or let `cancel()` stay open until `max(claimStart, createdAt + 1 h)`.
After this, the only reason init can revert is `Underfunded`, which a top-up fixes. Tests: fund then deploy after
`claimStart`; `predict*` refuses every invalid shape.

### H2. §3.3/R202 — `renounceRole()` by `issuer`, or an issuer multisig that has died, leaves frozen accounts frozen forever
**Problem.** A freeze has no time limit (R204), and only `issuer` can call `unfreeze`. If the issuer renounces
while any account is frozen, or loses its multisig quorum, those balances are trapped forever. Holders of wrapper
tiers cannot unwrap either (R208). Nothing in §3 prevents this.
**Fix.** Make renounce a relaxation. When `issuer` renounces, clear `FREEZE|FORCE|PAUSE` from `controls`, which
already sits in the hot slot. After that, `F(a)` reads false and the pause is over. This only removes restrictions,
so R201/I6 ("no power added") still hold. Restate I6 as "`controls()` only loses bits". Test: freeze, renounce, then
the frozen holder transfers and unwraps.

### H3. R204/§3.10 A1 — a compromised `issuer` acting alone can freeze every holder with no end date; the 7-day pause bound (R205) is decoration
**Problem.** R205 limits pauses so that "back-to-back pauses would [not] be an indefinite freeze of everyone". But
`freeze(account, ref)` needs nothing from `compliance`, has no expiry, and costs about 27 k gas per account. A1
says "freezes anyone". So one compromised issuer multisig can freeze every holder for good: about 27 M gas for
1 000 holders, cheap on most chains. Wrapper exits close too, because a frozen holder cannot unwrap. The two-role
separation (R202) protects forced transfer but does nothing for freeze.
**Fix.** Do it at no extra cost per transfer: change the `mapping(address ⇒ bool) frozen` to
`mapping(address ⇒ uint64 frozenUntil)`. That is still one SLOAD, compared against `now`. The issuer alone may
freeze for at most `MAX_ISSUER_FREEZE`, for example 30 days, renewable once, which is enough to get an order
recorded. A longer or open-ended freeze needs a live `compliance` record that names the subject:
`freeze(account, ref, recordId)`. That freeze lasts while the record is not revoked, and the check runs only when
the freeze is written. This keeps "issuer executes, compliance records" for every power that lasts. A4 (the
issuer submits privately) is unchanged. The disclosure text in §3.9 changes to match. (This does not reopen the
owner rulings: R202 assigns freeze to the issuer, and R204's "no time limit" is a ruling of this spec.)

### H4. §6.2/§6.3 — `sweep()` after `closesAt` takes holders' new shares (split/reverse split) or redemption money; a live old minter dilutes the pool
**Problem.** For a split, the issuer pre-mints `⌈S_old·k⌉` new shares into the offer, sets `closesAt`, and calls
`sweep()` afterwards. That sends the new-token remainder to `sweepTo`, which is the issuer. Every holder who did not
migrate in time loses their entire position in the new token, and the issuer collects it. Nothing on chain enforces
the "long" in "window: long". A one-day window is a legal rug. The same applies to a bond redemption offer with
`closesAt = maturity + claim period`. Separately, if the old token's `minter` is still live, the issuer, or a
compromised minter, can mint more old tokens, exchange them, and drain the new pool. Late real holders then get
`InsufficientOut`.
**Fix.** (a) For `closable == false`, `sweep()` may return only the **excess** over the live obligation
`quote(tokenIn.totalSupply())`. With a burn sink, `totalSupply` is exactly the unexchanged supply. Nothing beyond
that can be swept, ever. (b) If the issuer wants prescription (`closesAt ≠ 0` on a non-closable offer), the wizard
must enforce a minimum window, for example ≥ 365 days for splits and the claim period stated in `termsHash` for
bonds, and show a blocking "unexchanged holders forfeit after X" notice. (c) `createOffer` with a burn sink and
`closable == false` should require `NoUnderlyingToken(tokenIn).minter() == address(0)`. If that is too strict for
a bond (minter renounced after issuance), make it a check at exchange time on the split preset only. Add an offer
invariant: `balanceOf(tokenOut) ≥ quote(outstanding)` or `InsufficientOut` is flagged, and sweep never goes below it.

### H5. R204/R206/§3.4 unwrap row — the allowlist on the **unwrap recipient** closes the exits that R205/R206 promise stay open, and buys no security
**Problem.** The unwrap row requires `R(recipient)`, checked against the regulated token's registry for an address
that receives the **underlying** (for example USDC), not the regulated token. Two consequences. (1) A holder whose
attestation has lapsed cannot redeem to themselves. This is exactly the "attester is slow" case that R206 is meant
to protect. (2) If the registry fails or is compromised (A7: an admin-controlled registry, or an admin that loses
its keys so every attestation expires), **every** unwrap fails. That breaks "exits never close" (R205). The check
also achieves nothing: an eligible, unfrozen holder can unwrap to itself and then send the unregulated underlying
to anyone. `F(recipient)` is equally pointless, because `F(from)` is the only check that matters, and the burn in
`_update` already applies it.
**Fix.** Unwrap checks only `F(from)`, through the `_update` burn row, plus the TW2 recipient rules. Drop
`!R(recipient)` and `F(recipient)`. That also removes the `_checkRecipient` `private → internal virtual` change to
`SingleUnderlyingToken`: one fewer edit to built code. Remove A10, or restate it as "out of scope: the underlying
is a different asset". If the owner insists on `F(recipient)` (R204 is not marked owner on that clause), keep it,
but **never** `R(recipient)`.

---

## Medium

### M1. §3.1/R207 — the list of "keyword-only" changes is incomplete; as written the children do not compile
Each item below was checked against the source.
- `NoUnderlyingToken.tokenKind()` is `external pure override`, **not virtual** (l.21). `MultiUnderlyingToken.tokenKind()`
  is the same (l.32). `NoUnderlyingToken._init` (l.27) and `MultiUnderlyingToken._init` (l.38) are
  `internal override`, **not virtual**. The `Reg*` children override all four (`tokenKind()` and `_init` per
  §3.1). Only `SingleUnderlyingToken` has `virtual` on both. So four more `virtual` keywords are needed.
- §3.1 has `RegulatedControls` "declare the hooks `_isContract(a)`" with no base contract. But
  `MetaTxCore._isContract` (l.125) is an implemented, **non-virtual** `internal view`. A child that is
  `NoUnderlyingToken, RegulatedControls` then inherits two functions with the same signature. solc requires an
  `override(MetaTxCore, RegulatedControls)`, and that is illegal on a non-virtual base. Rename the hook
  (`_regIsContract`, implemented by the child as `return _isContract(a)`) instead of making `MetaTxCore` virtual.
- `payWithFee` is `external`. A child override cannot call `super.payWithFee(...)`, because external functions
  cannot be called internally. Changing it to `public` changes calldata handling and the TW2 gas pins. So the
  `virtual` buys nothing: the override has to copy the 10-line body. State that, and add an event-equality test
  against the base. Alternatively, do the `F(feeRecipient)` check without an override, for example with a transient
  "fee leg" flag read in `_update`, which also serves M7.
- With H5 applied, the `_checkRecipient` change goes away.
Keep the "TW2 gas and layout pins identical" test. Note that every source edit, the enum included, changes the CBOR
metadata hash of **all** v2 implementations, so bytecode is not byte-identical. That is fine only because no v2
factory or implementations are deployed yet. `deployments/` is gitignored, so confirm this on the operator hosts
before O3.

### M2. R200/§11 — appending enum values changes factory **behaviour**: `_createTiered` puts `*_REG` into the Multi branch
`OpenFactoryV2._createTiered` l.248:
`kind == META_NONE ? n != 0 : kind == META_SINGLE ? n != 1 : n < 2 || n > MAX_LEGS`.
`META_NONE_REG` and `META_SINGLE_REG` land in the last branch, so they would require 2–8 underlyings, and a
`META_NONE_REG` with 0 legs would revert `UnderlyingCountInvalid(0)`. `_isTiered` (`kind >= META_NONE`) and
`_checkKind` are fine. **Fix:** write the count map as a function of a base kind (`_baseOf(kind)`). Say in R200 that
`OpenFactoryV2` gets a code change, not only an enum change. Add `FactoryV2.t.sol` cases (each `*_REG` with counts
0/1/2/8/9, kind mismatch REG↔base) to the AS1 gate, which today lists only `Regulated*`/`Registry`. Also: node and
Odoo decoders of `versionOf().kind` must know 5–7 before the first `*_REG` token exists. AS7 ordering is "after AS1",
so add "before the first production `*_REG` create" to O3.

### M3. §3.1 size — Single/Multi children will exceed 24 576; the library fallback is the design, not a contingency
Measured runtime sizes: `SingleUnderlyingToken` 21 637, `MultiUnderlyingToken` 22 561, `HederaMultiUnderlyingToken`
23 885 bytes (headroom 2 939 / 2 015 / 691). The control surface (about 14 external functions, an order struct,
pause logic, registry calls, three overrides) is several KB. `RegulatedSingle`, `RegulatedMulti` and both Hedera
equivalents will exceed the limit. Caveats the spec does not state: `forceTransfer` needs `ERC20._update` (internal
to the token), so it cannot move to a library without writing OZ balance slots by hand. The library adds
link-time addresses to `Deploy.s.sol`/`DeployHedera.s.sol`, and the library must be deployed per chain. **Fix:**
make the split the base design. Keep in the token: the `_update`/`_checkOp` overrides, `forceTransfer`, and cheap
getters. Move to a linked library that reads the ERC-7201 slot: `recordOrder/revokeOrder/freeze/unfreeze/pause/
unpause/renounceRole`, `checkTransfer`, `canReceive`. Or move `checkTransfer`/`canReceive` to a stateless lens
contract (see over-engineering). Gate AS1 on `--sizes` for all six regulated implementations.

### M4. R208/§3.8 — a `*_REG` token used as the **underlying** of a wrapper breaks the TW2 reserve invariant, and `ELIGIBLE_CONTRACT` on that wrapper bypasses the allowlist
R208's "no regulated power touches `reserve_i`" covers only the regulated token's own reserves. If someone wraps a
regulated equity in an ordinary `META_SINGLE`/`META_MULTI`:
1. The wrapper contract needs `R` to receive at wrap. Once it is attested, wrapper units trade freely to ineligible
   parties. That is a full allowlist bypass.
2. The equity issuer can freeze the wrapper address, which kills every unwrap of that leg. It can also
   force-transfer out of it, which leaves `balanceOf < reserve`. That trips `ReserveShortfall`, stops all wraps, and
   makes `Σ⌊reserve·q⌋ ≥ supply` a fiction. In a Multi, it is a first-come run on the other legs.
**Fix.** State the rule: `ELIGIBLE_CONTRACT` is never granted to a TW2 wrapper or any contract that pays out to
arbitrary parties without re-checking. The wizard refuses, or shows a blocking warning for, a `*_REG` kind as an
underlying (read `versionOf(u).kind`). Narrow R208 to "the token's own reserves". Add an AS6 test that shows
freezing a wrapper that holds a REG underlying blocks only that leg, and document the result.

### M5. §3.7 — `ELIGIBLE_CONTRACT` is a master key that overrides every token's `requiredFlags` across the whole registry, and the spec suggests giving it to Safes
`hasFlags` returns true for `ELIGIBLE_CONTRACT` whatever `required` is. Consequences: (a) a contract attested for
token A also satisfies an `ACCREDITED`-only token B on the same registry. (b) §3.7 lists "escrow Safes, venue fee
recipients". A Safe is controlled by its owners, so giving it the flag lets unvetted owners hold any token on that
registry. (c) Any attester, such as a KYC vendor, can set it on an EOA. **Fix:** only `admin` may set
`ELIGIBLE_CONTRACT`. Restrict it to **pass-through** contracts whose every outflow is re-checked by the token: grant,
distribution, offer, `MetaTxDex`. Safes and venue fee recipients get ordinary flags for their controller. Also
`MetaTxDex` is the `to` of every `trade` leg, so it needs this flag too. §3.8 mentions only `OrderBookDex`, which
never holds funds. Lifetime: an `ExchangeOffer` keeps receiving `tokenIn` until maturity. If its attestation
lapses, bondholders cannot redeem. Mandate `validUntil = type(uint64).max` for protocol clones, and have the node
raise an alert 30 days before any protocol clone's attestation expires.

### M6. §3.5 + R209/§4.4 — forced transfer from a grant or distribution clone (A13 says this is supported) breaks their math
After a partial seizure from a `VestingGrant`, `balance < obligation`. `release()` pays `releasable`, so it reverts
every time, and the beneficiary's unseized remainder is stuck. `revoke()` sends `total − cap` and reverts.
`sweepExcess()` computes `balance − (cap_or_total − released)` and underflows. `Distribution` does fine
(first-come, the last claimants lose), but the spec should say so. **Fix:** `release` pays
`min(releasable, balance)`. `revoke` returns `min(total − cap, balance − min(balance, cap − released))`.
`sweepExcess` saturates at 0. State who bears a seizure (beneficiary-first is natural: the order names that
person). Tests: seize half of a grant, then release, revoke and sweep.

### M7. R205/§3.9/§6.3 — the pause blocks bond redemption and fee-bearing unwrap ops, while the mandatory disclosure says "never redemptions"
(a) Tier-1 redemption is an `ExchangeOffer`, which is a transfer to the offer, so a pause refuses it (§6.3 admits
this). The mandatory text in §3.9, "pause transfers ... never redemptions", is therefore false for the bond and
equity templates. A misleading disclosure is a legal problem for issuers. Change the text per tier: wrapper tiers
say "never unwraps"; tier-1 says "redemption and buyback offers are paused too; only burn stays open". (b) The R148
unwrap op with a fee: step 7 does `_transfer(from, feeRecipient, fee)` → `_update` → `P` → revert. So a gasless
paid exit is closed during a pause, which contradicts "every meta-tx op except unwrap". Either say "sponsored
(`FEE_NONE`) unwraps only during a pause" and have the node sponsor them, or set a transient "unwrap-op" flag in the
`_checkOp` override that `_update` reads to skip `P` for that tx's fee leg. Test: a fee-bearing unwrap op during a
pause.

### M8. §5.4 — dividends to protocol-clone leaves are stuck: no clone can move a foreign token
A `VestingGrant` (or an unexecuted counterfactual grant address with no `GrantCreated` yet), an `ExchangeOffer`
holding pre-minted new equity, or a `Distribution` holding the record token, becomes a leaf when the policy does not
exclude or attribute it. Any balance the snapshot assigns it is then paid in `payoutToken`, which those contracts
cannot move. That money is locked for good. The policy treats this as "issuer's choice", with examples. **Fix:**
(a) the snapshot builder **must** exclude or attribute every `AssetFactory` clone (from its events) and the token's
own address, and must fail the build when a leaf is a contract it cannot classify unless the policy lists it. (b)
Give each action contract `rescue(token)` for `token ≠ its own token(s)`, paying the creation-time
`sweepTo`/grantor. That is about 10 lines and closes the whole stray-token class, including stray `payoutToken`
sent to grants.

### M9. §3.7 — disabling a compromised attester does not revoke what it attested
The registry slot is `{flags, validUntil}` with no attester. After `setAttester(evil, false)`, every attestation
`evil` made stays valid, and the admin has to find and re-attest them from events in the middle of an incident.
**Fix:** pack `flags u64 ‖ validUntil u64 ‖ attesterId u32` (one slot). `hasFlags` also checks
`attesterEnabled[attesterId]`. That is one extra SLOAD, or none if the epoch is packed with it. Or document
`attest(..., flags 0)` sweeps as the runbook and add a node alert. The first option is the safer default.

### M10. §3.7/R201 — a dead registry permanently freezes a tier-1 REG token, and migration is impossible too
If the registry `admin` or all attesters lose keys, attestations expire. After that, no receiver passes `R`. This
blocks transfers, DEX trades, and even the `ExchangeOffer` migration, because the offer must pass `R` to receive
`tokenIn`. Tier-1 has no exit except burn. **Fix:** a one-way, relaxation-only `disableControl(CTRL_ALLOWLIST)` by
`issuer`, or by issuer and compliance together. It can only remove a restriction, so it fits R201. Also require the
registry admin to be a multisig (it already must be a contract) and say so in the disclosure.

---

## Low

- **L1 §5.4 tree shape is not pinned.** "OZ MerkleProof, sorted pairs" fixes how a proof is verified. It does not
  fix the root. OZ `StandardMerkleTree` sorts leaves **by hash** in a complete-tree array, while §5.4 says "sorted
  by account, index = position". Three implementations (Solidity tests, Rust node, Python ERP) need the exact
  layout and odd-node rule. Name the algorithm (for example OZ `StandardMerkleTree` v1 with `sortLeaves = true`,
  where `index` is the position in the account-sorted list and appears only in the leaf) and include an odd-count
  vector. The double-hashed leaf separates leaves from nodes properly. Reusing a root across two distributions is
  harmless, because each has its own bitmap and pool.
- **L2 §3.1 Hedera.** "Inherit the fail-closed HTS checks (R144)" is wrong. `_checkUnderlying` + `HederaHts` live in
  the sibling `HederaSingle/MultiUnderlyingToken`, not in the regulated parents. `HederaRegulatedSingle/Multi` must
  re-add the `_checkUnderlying` override as well as the signature override. Without it, HTS custom-fee legs are
  accepted and associations are skipped. Add `Layout` pins for the three Hedera regulated contracts.
- **L3 §3.2 init order.** If the child's `_init` calls `super._init` (tier-1 `_mint(creator)`) before it stores
  `RegulatedConfig`, the `_update` receiver check sees `controls = 0` and passes. Pin "config first, then tier
  init". Also, the initial supply goes to `creator` = the factory caller, so the Equity template's "to the issuer
  treasury Safe" means the Safe must call `createTiered` itself.
- **L4 §4.2.** "Strictly increasing `at`" contradicts milestones whose "`at` = earliest date, may be 0". Several
  undated milestones cannot all be 0. Use non-decreasing when `approver ≠ 0`.
- **L5 §8.2.** On a managed market, the `OrderBookDex` relayer fee recipient (`o.feeRecipient` or the settling
  `sender`) on a regulated leg needs `R` too. Only the market fee recipient is checked. Force relayer `feeMode =
  NONE` on regulated legs of managed markets, or check it before settle.
- **L6 §4.4.** The grantor can front-run a pending `approveMilestoneWithSig` with `revoke()`, which makes the
  milestone unvested. Disclose it, as "revocable bargain" already is. `revoke` pushes to the grantor: a
  frozen/ineligible grantor makes revoke impossible. Either accept that, or make the return pull-based (claimable by
  the grantor).
- **L7 numbers.** R209 says "≈ 45 k more per grant" and "~25 % more". §4.7 says 155 k vs 140 k (+15 k, about 11 %).
  Fix one of them.
- **L8 §3.8 grief exemption.** "Caused by an authority or attester transaction landing first" needs a defined test,
  for example re-simulating at the parent block. Otherwise a signer who arranges its own attestation revocation (a
  colluding attester) gets free failures. One sentence on how the node decides.
- **L9 §3.6.** `pause` checks both "not paused" and "now ≥ cooldownUntil". The second implies the first, so
  `AlreadyPaused` can never fire. Drop it, or keep it only for the error message.
- **L10 §5/§4 reentrancy.** `ExchangeOffer` has a transient guard. `Distribution.claim` (arbitrary `payoutToken`)
  and `VestingGrant` should state CEI (set the bit or `released` before the transfer) and have a test with a
  token that has a hook.

---

## (2) The `virtual` changes to built v2 code: safe?
They do not change behaviour, layout or gas once M1 is fixed. `private → internal` and adding `virtual` produce the
same internal-call codegen, and the TW2 slot pins are untouched because regulated state sits in ERC-7201. The list
in R207 is wrong, though. It needs `virtual` on `NoUnderlyingToken.tokenKind/_init` and
`MultiUnderlyingToken.tokenKind/_init`. The `_isContract` hook clash needs a rename. `payWithFee` cannot use
`super`. `_checkRecipient` is not needed if H5 is applied. Bytecode changes through the metadata hash, which is
acceptable only because nothing in v2 is deployed in production.

## (3) Timing of the factory enum change (R200)
Doing it before the O3 production deploy is correct, since OpenFactoryV2 is not deployed (no `deployments/` in the
repo; the file is gitignored, so check the hosts). It is not only an enum edit, though (M2). Ship the count map
change and its tests in AS1, and the node/ERP kind decoding before the first `*_REG` create.

## (4) Consistency with TW2 rev 1.2 and the node specs
- R201's third exception to R142 is consistent with TW2. The TW2 R142 text "neither can ... pause unwrap" still
  holds (R205).
- R208 contradicts TW2 R134 in the REG-as-underlying case (M4).
- TW2 R140 (atomic `mtxBatch`) is reflected correctly.
- TW2 step 8 "must not fail": with the `_update` re-check this still holds within one tx, because step 6 and
  step 8 read the same state.
- A2 R124/R128: managed markets are bound-only, with no auto-trust. Consistent. Unbound orders remain executable by
  anyone on the venue's own `OrderBookDex` (the contract is unchanged), as §8.4 admits. Eligibility is the only
  on-chain guarantee, and that is fine.
- TODO.md still lists TW2 as "rev 1.1, review in progress". Update the table.

## (5) Gaps in the test plan
Add these tests:
- factory counts for each `*_REG` kind (M2);
- `--sizes` for all six (M3);
- renounce with frozen accounts (H2);
- freeze expiry and the record-backed freeze (H3);
- fund then deploy after `claimStart`, and `predict*` refusing invalid params (H1);
- offer sweep limited to the obligation, plus an offer obligation invariant (H4);
- an unwrap by a holder whose attestation lapsed, and an unwrap when the registry reverts (H5);
- a fee-bearing unwrap op during a pause (M7);
- seizure from a grant followed by release, revoke and sweep (M6);
- a REG underlying inside a wrapper (M4);
- a leaf that is a protocol clone, and `rescue` (M8);
- attester disable (M9);
- init order under the allowlist (L3);
- the HTS checks on Hedera regulated children (L2);
- an odd-count Merkle vector (L1);
- managed-market relayer fee on a regulated leg (L5).

The invariant handlers should also call `renounceRole` and attestation changes by the registry admin.

## (6) Over-engineering (cuts)
- **Unwrap recipient checks and the `_checkRecipient` hook**: drop them (H5). That removes one edit to built code
  and the registry call on every unwrap.
- **`OrderRecord.orderId`, `documentHash`, `recordedAt` in storage**: `orderId` is already inside `recordId`, and
  the other two belong only in `OrderRecorded`. That saves 2–3 SSTOREs (about 45–65 k) per record and some code
  size. Keep `subject, beneficiary, maxAmount, executed, revoked`.
- **`checkTransfer` on chain**: the node and venue can compose it from `isFrozen` + `canReceive` + `pausedUntil` +
  `balanceOf`. It is under size pressure (M3), so drop it or move it to a lens.
- **`rolesSeparated()`**: wallets compare `issuer()` and `compliance()` themselves. A minor cut.
- **`approveMilestoneWithSig`**: an approver that is a Safe or `SubjectAccount` can already approve through a
  sponsored `call` job. The EIP-712 domain, ECDSA, 1271 and 7702 handling is a second signature surface for one
  bit. Keep it only if approvers are known to be bare EOAs.
- **Venue-level `registry`/`required_flags` for pairs of two unregulated tokens (§8.1)**: enforced only off chain,
  nobody has asked for it. Say PLANNED.
- **`AlreadyPaused`** (L9).
