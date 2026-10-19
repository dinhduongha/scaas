# V3: Claude, part 3 of 3: `common/`, `metatx/`, `factory/`, `dex/`, `trade/`, `hedera/` (+ `wallet/MandateWallet` for mandates)

Static reading only. Tree `/home/ha/work/ainative/scaas/.claude/worktrees/rev3` at `7aab1fe` (detached). Paths are
relative to `smartcontracts/evm/src/` unless they start with `docs/`. No build, no tests, no chain.

The worktree has no `lib/` (submodules not checked out). OpenZeppelin behaviour quoted below was read from the main
checkout, `smartcontracts/evm/lib/openzeppelin-contracts`. I assumed it is the same pinned version.

**Summary: no P0, P1 or P2 found in this scope.** Four P3 findings. The two root causes from part 1 were traced
through this scope:
- (a) the unbound direct-call mode does not recur here (see "Root-cause checks").
- (b) the factory trusts creator-supplied **legs** the same way it trusts creator-supplied verifiers. The spec
  already discloses this; see "Root-cause checks".

| id | sev | title |
|---|---|---|
| V3-01 | P3 | `mtxSettle` trusts revert data: a listed outside token, or an ERC-777 receive hook, can forge `SigCheckGasStarved` and revert every settlement in the call |
| V3-02 | P3 | Cancel signatures are bearer "bump once" tokens. They are not bound to the nonce they cancel, so a withheld cancel voids a *later* envelope |
| V3-03 | P3 | `MandateWallet.isValidSignature` is not bound to the wallet (ERC-7739 class): the owner's signature for its EOA or another wallet validates here too |
| V3-04 | P3 | Hygiene: DEX funds at rest are claimable, the exchange path allows `sellToken == receiveToken`, `_classify` is frozen at `setMarket`, factory doc drift, `Wrapped` event figures, guard coverage |

---

### V3-01 — P3 — `mtxSettle` trusts revert data: a forged `SigCheckGasStarved` / `UAVerifyGas` reverts the whole batch

**Locations**
- `dex/SCaaSDex.sol:268-295`:
  - each settlement is `call(gas(), address(), …settleOne…)` (`:276`);
  - a failure whose first 4 bytes are `SigCheckGasStarved.selector` or `UAVerifyGas.selector` re-reverts the
    **whole** call (`:287-289`);
  - every other failure only emits `MatchFailed`.
- Revert data from outside code reaches that check unchanged:
  - `dex/SCaaSDex.sol:403` → `dex/DexPuller.sol:25`: `safeTransferFrom` on an outside token;
  - `dex/SCaaSDex.sol:591-603`: `_send` / `_sendTo` → `safeTransfer` to a party's `destination`, or to the submitter
    / treasury.
- OZ `SafeERC20._callOptionalReturn` bubbles the callee's revert data verbatim (`lib/openzeppelin-contracts/…/SafeERC20.sol:177-183`).
- Intended source of these selectors:
  - `common/SigCheck.sol:63`: the ERC-1271 path inside a SCaaS token's `mtxTrade`;
  - `ua/UARegistry.sol:573`, `ua/UAKinds.sol:293, 372, 383`: the UA path.

**Trigger**
1. An admin-listed outside token answers `transferFrom` / `transfer` by reverting with
   `abi.encodeWithSelector(SigCheckGasStarved.selector, 0, 0)`.
   - Or: a maker (or taker) on an ERC-777-style outside token sets `destination` = its own contract, registered for
     `tokensReceived`, and that hook reverts with the same bytes. It can do so conditionally, for example only when
     the batch holds other relayers' settlements, or on `block.number` parity, so a simulation can miss it.
2. A relayer calls `mtxSettle([s_1 … s_n])` with one such settlement among them.
3. That settlement's revert data starts with the selector, so `:288-289` reverts `mtxSettle`. The other `n−1`
   settlements, which would have succeeded and paid their fees, are undone.

Related: `:276` forwards all gas, so one settlement that burns its gas (an outside token looping) leaves 1/64 for the
rest of the batch.

**Impact**
- Griefing only. A single counterparty escalates "my settlement fails" to "the relayer's whole batch fails".
- No funds move and no order state changes.
- Reach: outside tokens with callbacks (ERC-777) or a hostile outside token the admin listed. SCaaS tokens have no
  transfer hooks, and an ERC-1271 wallet's own revert is not bubbled (`common/SigCheck.sol:65-69`, staticcall result
  only).

**Confirmed or hypothesis:** confirmed by trace. Whether a live relayer's simulation catches the conditional variant
is not checked.

**Suggested fix (deployed bytecode only)**
- Do not decide starvation from bytes the callee controls. A real starvation leaves the DEX frame with little gas,
  because the inner check failed for lack of `cap·64/63 + margin`.
- Honour the two selectors only when that also holds, for example:
  `if ((sel == SigCheckGasStarved.selector || sel == UAVerifyGas.selector) && gasleft() < MAX_VERIFY_CAP * 64 / 63 + MARGIN) revert(...)`
  with `MAX_VERIFY_CAP` = the largest cap a leg can need (400 000 for `SmartKeyAccount`, the UA kinds' caps).
  Otherwise treat it as `MatchFailed`.
- Optionally give each `settleOne` a gas cap.
- No chainspec, gas-row or vector change.

---

### V3-02 — P3 — Cancel signatures are not bound to the nonce they cancel

**Locations**
- `metatx/ERC20MetaTx.sol:87-91` (`uaCancelDigest`):
  - it covers `(PURPOSE_METATX_CANCEL, chainid, CHAIN_UID, token, ua, batch, validUntil)` and no nonce;
  - `:339-349` (`uaCancelNonce`) bumps `nonce[ua][batch]` by one, from whatever value it has, and burns only the
    digest (`cancelUsed[d]`).
- `metatx/MetaTxBase.sol:130-133`: a relayed `cancelNonce(batch)` is a `MetaTransaction` on another lane. It, too,
  bumps lane `batch` from whatever it is.
- Spec, per design: `docs/contracts/accounts.md:257` ("each signature cancels once") and `docs/contracts/metatx.md:407`.

**Trigger**
1. A derived UA has envelope `E_n` (lane `b`, nonce `n`) pending at relayer R.
2. The UA signs a cancel `(b, validUntil = now + 1 day)` to kill it and hands it to R, the only party it talks to.
3. R executes `E_n` anyway and keeps the cancel.
4. The UA, seeing `E_n` done, signs `E_{n+1}`, for example a payment the payee is now waiting for.
5. R (or anyone R gave the cancel to) submits `uaCancelNonce(ua, b, validUntil, auth)`. The nonce goes to `n+2`, and
   `E_{n+1}` is dead with `MetaTxBadNonce`.

The native path is the same: the relayed `cancelNonce` meta-tx can be held until its `validUntil`.

**Impact**
- Griefing only: a signed payment or unwrap is silently voided and must be re-signed.
- Wallets that show "cancel = cancel envelope n" mislead the user.
- No theft.

**Confirmed or hypothesis:** confirmed (code matches the spec, so this is a design weakness).

**Suggested fix:** bind the cancel to the nonce it targets.
- Put `nonce` in `uaCancelDigest` and require `_nonce(ua, batch) == nonce` before `_bumpNonce`.
- Give the native path the same check, for example `cancelNonce(batch, expected)`.
- This changes deployed bytecode, the `metatx-cancel` digest, clients and the KAT vectors. No chainspec or gas change.
- If the owner keeps the design, wallets should use short `validUntil` on cancels (≤ the pending envelope's).

---

### V3-03 — P3 — `MandateWallet.isValidSignature` is not bound to the wallet (ERC-7739 class)

**Locations**
- `wallet/MandateWallet.sol:182-185`: `isValidSignature(hash, sig)` = "ECDSA of `hash` recovers `owner`", for any
  `hash`, with no wallet-specific rehash.
- `hedera/HederaMandateWallet.sol:15` inherits it unchanged.
- The class may also sit in part 2's `wallet/` scope; it is listed here because mandates are in part 3.

**Trigger** (outside SCaaS; hypothesis for a concrete loss)
1. The owner key `K` also acts as an EOA, or owns two `MandateWallet`s `W1`, `W2`.
2. `K` signs an off-chain permit for a third-party protocol whose signed struct does not name the account. Permit2's
   `PermitSingle(details, spender, sigDeadline)` is an example: the owner is not in the struct.
3. If `W1` approved Permit2 for that token (through `execute`), and `W1`'s Permit2 nonce equals the one signed (both
   start at 0), anyone can submit `Permit2.permit(W1, permitSingle, sig)`.
4. Permit2 calls `W1.isValidSignature(hash, sig)`, which recovers `K`, so the permit is accepted. `W1` now grants the
   same allowance to `spender`.

**Impact**
- An unintended allowance from the mandate wallet to a spender the owner named for another account.
- It becomes a loss only if that spender lets a third party pick the `from` it pulls from.
- **Inside SCaaS there is no exposure.** Every digest checked through ERC-1271 binds the account:
  - `MetaTransfer.from` (`common/MetaTxLib.sol:131-133`);
  - `TradeOrder.from` (`trade/TradeLib.sol:53-57`);
  - the wallet's own domain.
- The delegate cannot use ERC-1271 at all, because only `owner` is accepted. So the mandate caps cannot be bypassed
  through a token `MetaTransfer` with `from = wallet`. That was checked and it holds.

**Confirmed or hypothesis:** the missing binding is confirmed. The loss path is a hypothesis that depends on the
third-party spender.

**Suggested fix:**
- ERC-7739 nested typed-data (rehash with the wallet's domain before recovering).
- Or document "the owner key must not sign third-party permits as itself while the wallet holds approvals".
- Rehashing changes how owner hand-pays (`from = wallet`) are signed by clients and KATs; deployed bytecode only.

---

### V3-04 — P3 — Hygiene

**a. DEX funds at rest are claimable by any exchange-path submitter.**
- `dex/SCaaSDex.sol:531-543`: interactions run as the DEX.
- `:563-565`: conservation covers only the plan's tokens.
- Anything that lands in the DEX outside a plan can be swept by the next submitter: a mistaken transfer, or a fee
  minted to the DEX by an interaction calling `UnderlyingToken.mtxWrap` (`metatx/UnderlyingToken.sol:106`,
  `_mint(msg.sender, fee)`).
- The design says the DEX holds nothing, so this is documentation, not a fix.

**b. The exchange path does not refuse `sellToken == receiveToken`.**
- `dex/SCaaSDex.sol:498-512` checks only `listings`.
- The settle path refuses it (`_checkMarket`, `:336`).
- Only a confused signer is exposed. One line: `if (l.sellToken == rt) revert TokenMismatch();`.

**c. `_classify` is frozen at `setMarket`.**
- `dex/SCaaSDex.sol:156-157, 189-195`.
- A version that the registrar deprecates later stays `KIND_SCAAS` in an already-listed market until the admin calls
  `setMarket` again. The DEX keeps trusting that version's `mtxTrade` signature check.
- Conservation still protects counterparties, so the only effect is on that version's holders.

**d. Factory doc drift.**
- `docs/contracts/token-wrappers.md` §5 lists the registrar's powers as `registerImplementation`, `deprecate`,
  `setZetherEnabled`, and §6.2 says kinds 4–7 revert `KindReserved`.
- The code also has `setPqzEnabled` and `registerDexImplementation` (`factory/OpenFactory.sol:91-99, 156-169`), and
  builds kinds 4–5 (`:195`).

**e. `mtxWrap` / `uaWrap` event figures.**
- `metatx/UnderlyingToken.sol:105-107, 121-124` emit `Wrapped(o.from, u, received, minted)` / `UAWrapped` with the
  **gross** `minted`, while `minted − fee` goes to `o.destination` and `fee` to the submitter.
- An indexer crediting `account` with `minted` is wrong on both counts. The `Transfer` events are correct.

**f. Guard coverage.**
- These functions are not `nonReentrant`, although CTR-MTX-18 says one guard covers every entry point:
  - `payWithFee`, `payWithFeeToUA` (`metatx/MetaTokenBase.sol:364-394`);
  - `mint` / `mintToUA` (`metatx/NoUnderlyingToken.sol:30-39`);
  - the admin, role and rate functions (`metatx/MetaTokenBase.sol:126-132`, `metatx/UnderlyingToken.sol:152-172`).
- I checked each one: none makes an outside call other than the registry's `kindOf` view, and none is allowlisted.
  So there is no re-entry or self-call path today. Add the modifier, or narrow the spec sentence.

---

## Root-cause checks requested by the controller

**(a) Unbound mode or option on direct calls.**
- Only the confidential layers read `_ticketBinding()`: `zether/ZetherLayer.sol:154`,
  `zether/UnderlyingZetherToken.sol:118`, `pqz/PqzLayer.sol:190`, `pqz/UnderlyingPqzToken.sol:87`. Those belong to
  parts 1 and 2.
- In this scope every authorisation is either `msg.sender` itself, or an EIP-712 signature over the **full**
  calldata or struct:
  - `MetaTransaction` hashes `keccak256(data)`, selector included (`common/MetaTxLib.sol:97-102`);
  - `MetaTransfer` and `UAMetaTransfer` hash every field (`:129-134, 193-199`);
  - `TradeOrder` and `UATradeOrder` hash all 13 fields, including `dex`, `relayer` and `flags`
    (`trade/TradeLib.sol:53-63`);
  - `ReceiverFee` binds the payer's digest (`metatx/MetaTokenBase.sol:298-302`);
  - the mandate pay binds `epoch` in `data` (`wallet/MandateWallet.sol:114-120`).
- Entry pairs that build the same struct produce the same digest and the same effect:
  - `mtxTransfer` / `mtxTransferWithFee` / `mtxPay` / `mtxExecuteTransfer`;
  - `uaUnwrap` / `uaExecute`;
  - `mtxPayUnderMandate` / `mtxExecute`.

  The only differences are extra shape checks (`PAYABLE`, mode shape), which the spec says are not authority.
- A `TradeOrder` does not say whether it is filled by `mtxSettle`, `mtxExchange` or `mtxExchangeVia`. Each path
  enforces the signed price limit:
  - `trade/TradeLib.sol:124` on Path A;
  - `dex/SCaaSDex.sol:381-387` on Path B;
  - the signed `LISTED_POOLS` flag forces listed targets (`dex/SCaaSDex.sol:507, 540, 461`).

  So switching path gives the submitter nothing the signer did not grant.
- Stale binding across envelopes: tokens without a confidential layer never write the slot and never read it.
  - Zether tokens do not override `_uaEnvelopeBinding` (it stays 0, `metatx/ERC20MetaTx.sol:373-375`).
  - Their UA allowlists hold no Zether op (`zether/NoUnderlyingZetherToken.sol:74-76`,
    `zether/UnderlyingZetherToken.sol:158-160`), so no UA self-call reads a stale binding.

**(b) What the factory trusts from creator-supplied addresses.**

*Legs* (`metatx/UnderlyingLib.sol:102-128`):
- Any code-bearing address is accepted; only `decimals()` is read.
- `wrap` prices the leg's own `balanceOf` delta (`:155-171`).
- `mtxWrap` / `uaWrap` call the leg's `mtxTrade` / `uaTrade` and trust its delta (`:179-200, 219-229`).
- `unwrapToUA` trusts its ERC-165 answer and `transferToUA` (`:278-291`).
- So a hostile or upgradeable leg mints without limit and drains every good leg of an any-of basket. The factory
  still indexes the token under the genuine underlying (`factory/OpenFactory.sol:256-262`), and the DEX classifies
  it `KIND_SCAAS` (`dex/SCaaSDex.sol:190-195`).
- Spec-disclosed, so not re-reported as a finding: `docs/contracts/token-wrappers.md` §2.2 "each leg's admin key can
  take the whole basket" and CTR-TOK-16/17 "provenance, not gatekeeping".
- Note for the owner: this is the same pattern as V1-02. The index and `isToken` say "made here from a registered
  implementation", not "safe legs".

*Other creator inputs:*
- `owner`, `roles`, `initialHolder`: flag-checked in `metatx/AdminLib.sol:77-95`; `rateAdmin` must be a contract.
- `DexConfig.admin` / `treasury`: `dex/SCaaSDex.sol:131-140, 177-182`; admin by spec, with no setter (CTR-DEX-03).

*Unregistered implementations:*
- `createTokenUnregistered` (`factory/OpenFactory.sol:111-116`) bypasses the Zether / PQZ gates and the leg index's
  meaning. It is recorded with version 0, and the DEX treats it as `OUTSIDE`.
- Documented (token-wrappers.md §6.2, "trust the index only for registered versions").

*Routers, executors and interaction targets* are chosen by the submitter, not the creator. They are bounded by
balance-delta conservation:
- `dex/SCaaSDex.sol:522-527` (pulls);
- `:548-555` (floors);
- `:563-565` (end state);
- forbidden targets and selectors (`:533-539`);
- the approve reset (`:446-451`).

A lying router can only fail the plan.

---

## Checked and clean

### `metatx/` and `common/MetaTxLib`, `SaltedEIP712`, `SigCheck`, `FeePolicy`

**Domain**
- `SaltedEIP712.sol:36-69`:
  - name, version, `chainId` (read live, rebuilt when it changes), `verifyingContract = address(this)` (so each
    clone has its own domain);
  - `salt = chain_uid`, which is non-zero;
  - names longer than 31 bytes revert at deploy.

**Typehashes** (`MetaTxLib.sol:77-79, 120-122, 162-164, 181-183`)
- The type strings match the structs' field order.
- `canon` zeroes unbound `relayer` / `feeRecipient` identically in the verifier and the struct hash (`:92-102,
  185-199`).

**Pipeline** (`MetaTxBase.sol:138-224`)
- Envelope checks: relayer, expiry inclusive, mode bits, nonce, `from ≠ this`.
- Then the signature, then shape / allowlist / fee class (`:191-206`, basis offset `36 + 32·i` correct), then the
  nonce, then the self-call, then the fee, then the event.
- A failing self-call reverts everything, nonce included, so no "nonce burnt, call failed" state.
- `guarded` fails closed for an allowlisted function without `nonReentrant` (`:219-223`).

**Ticket**
- Only `_selfCall` makes `msg.sender == address(this)`, and no function in scope calls `address(this)` otherwise.
- `_msgSender` / `_ticketSubject` / `_ticketBinding` are therefore unspoofable (`:276-295`).
- A nested self-call (`MandateWallet.execute(this, …)`) hits `nonReentrant` with ticket = 2 and reverts (`:57-67`).

**Signatures** (`SigCheck.sol:26-70`)
- OZ `tryRecover`: 65 bytes, low-s, a zero address is never accepted.
- The EIP-7702 designator counts as an EOA.
- ERC-1271 runs under a gas cap with the 63/64 starvation check, at most 32 bytes of returndata, and an exact magic
  match.
- Nothing in scope keys state on signature bytes. Replay protection is digest- or nonce-based (`cancelUsed[d]`,
  `pulled[h]`, lanes).

**Fees** (`FeePolicy.sol:34-59`)
- The 1 % cap applies to both PERCENT and FIXED.
- `_callFee` (`ERC20MetaTx.sol:242-252`):
  - ABSOLUTE + PERCENT is refused at step 3 (`MetaTxBase.sol:199-201`);
  - ABSOLUTE + FIXED takes the signed amount, uncapped (CTR-MTX-20);
  - a fee to `UA_POOL` reverts.
- The typed path (`ERC20MetaTx.sol:212-226`) checks the payee ≠ fee recipient (CTR-MTX-08) and the balance
  `value + fee` before any move.

**UA ledger** (`ERC20MetaTx.sol:278-288, 413-487`)
- `UA_POOL` cannot receive by `_update`.
- A debit from `UA_POOL` requires a derived ticket subject. Without a ticket the subject is 0, which is native space,
  so it reverts.
- `_uaMove` keeps `balanceOf(UA_POOL) = Σ` UA balances (both sides derived: no ERC-20 move).
- A native id of 0 or `UA_POOL` can never authorise:
  - ECDSA never recovers 0;
  - `UA_POOL` has no key and is refused explicitly (`:448`);
  - on Hedera the HIP-632 precompile rejects unknown accounts.
- Receivers are checked as registered SIGNING (`:426-437`).

**Allowlists**
- `NoUnderlyingToken.sol:48-66`: `cancelNonce`, `burn`.
- `UnderlyingToken.sol:181-212`: static lengths match the ABI (36 / 100 / 68 / 132 / 68 / 100 / 132); the UA
  allowlist holds only unwraps.
- No `approve`, `transfer` or `transferFrom` is allowlisted (CTR-TOK-01).

**Receiver-pays** (`MetaTokenBase.sol:306-350`)
- The payer's envelope must bind the relayer, and runs on the pay lane, nonce 0.
- The payee co-signs `ReceiverFee` over the payer's digest; `fee ≤ value`; the recipient ≠ payee, the token or
  `UA_POOL`.

**AdminLib** (`AdminLib.sol:77-209`)
- Flags are validated per kind; regulated flags are refused.
- `locked ⊆ features`; PAYABLE and BURNABLE are always locked.
- Roles exist only for set flags; `rateAdmin` must be a contract.
- Ownership transfer is two-step; renounce clears the pending owner.
- `disableFeature` is one-way and respects locks.
- `_lowest` is only called with a non-zero argument.

**Init** (`MetaTokenBase.sol:55-81`, `UnderlyingLib.sol:80-100`)
- The implementation locks itself in its constructor.
- `initialize` is factory-only and once only.
- The registry's `chainUid` must equal `CHAIN_UID`.
- `rateDelay` is 2–30 days and the step 1–1000 bps only with `RATE_ADJUSTABLE`, otherwise 0 / 0.

**Wrap / unwrap** (`UnderlyingLib.sol:133-291`)
- Measured-delta pricing; the shortfall check comes before the pull.
- Rounding favours the contract: mint ⌊⌋, out ⌊⌋, burn ⌈⌉.
- CEI: burn and reserve debit happen before the one outside call.
- The pay-out must leave the balance down by exactly `out`; fee-on-transfer-out reverts.
- Native: `before = balance − value`; `value == amount`; an ERC-20 leg refuses `msg.value`; a relayed native wrap
  reverts.

**Rates** (`:314-389`)
- The step check is exact in integers (products < 2^207).
- While a change is pending, wrap is paused on every adjustable leg.
- Only the admin executes, inside the window.
- Collateral is checked over every leg's balance ≥ reserve, with the new rate; `_value` saturates.
- `disableFeature(RATE_ADJUSTABLE)` drops the pending change (`UnderlyingToken.sol:169-172`).

**Re-entry**
- ERC-777 `tokensToSend` / `tokensReceived` and native `sendValue` recipients can only reach unguarded
  ERC-20 / admin functions. State is consistent at those points: burned, reserve debited.

### `trade/`

**`TradeLib.precheck` (`TradeLib.sol:82-97`)**
- Checks, in order: caller == `o.dex`, which is a contract; not a self-order; the relayer; expiry; the `minNonce`
  floor; the flags (ESCROW ⇒ IOC); non-zero amounts; `minFill ≤ amount`; `fee ≤ 1 %`.

**`record` (`:101-135`)**
- Closed-order check; overfill check.
- The half-fill floor is written as halves, so it cannot overflow.
- Price `move·R ≤ receiveFill·amount` (checked arithmetic: an extreme order only fails itself).
- Fee ≤ ⌈receiveFill·fee/10⁶⌉.
- ESCROW: exact shape, first fill only.
- IOC closes the order.

**Cancels and nonces (`:138-155`)**
- A cancel uses the order's own signed `amount`.
- `invalidate` is strictly increasing and capped at 2^128.

**Signature handling in the token**
- `ERC20MetaTx.sol:131-173`: the signature is skipped only when `pulled[h] ≠ 0`, and `h` binds every field.
- UA and native orders have different `h` but one `minNonce` per id.

### `dex/`

**Settle path (`SCaaSDex.sol:298-332`)**
- Taker and makers trade the same token pair, which must be a listed market.
- No self-trade; no duplicate maker order.
- Each maker receives ⌈fill·R/amount⌉ (rounded in the maker's favour); the taker fill must equal Σ.
- Every bound is checked by the sell token (Path A), or by the DEX (Path B, `:379-388`, or outside legs `:400-403`).
- Both balances must be unchanged at the end.

**Fees**
- ⌈recv·fee/10⁶⌉, within the signed fee.
- The split floors the relayer share; the treasury gets the remainder.

**Exchange path (`:439-566`)**
- Pulls must raise each balance by exactly `sold + refunds`, which kills fee-on-transfer and rebasing sell tokens.
- Floors are checked against balances, not router answers.
- The surplus is split pro rata, with the remainder to the last leg; `floorsLeft == recv` is only hit by the last
  receiver, because every `recv ≥ 1`.
- End-state conservation over every plan token.

**Interaction and executor restrictions**
- Interactions may not target the DEX or its puller, and may not use `mtxTrade`, `uaTrade`, `increaseAllowance` or
  Permit2 `approve`.
- Every `approve` interaction is reset to 0 afterwards.
- `settleOne` is self-only, and the transient guard blocks re-entry from executors and hooks.

**Outside legs**
- Signed as `DexOrder` in the DEX's domain (`:223-225`; nested type string correct).
- The signature is checked through `SigCheck` with the codehash cap; ESCROW is refused.
- Pulled only through the DEX-only `DexPuller` (`DexPuller.sol:23-26`).

**Classification**
- From the factory's registered, non-deprecated version only (`:190-195`); see V3-04c.

**Initialisation**
- `initialize` is factory-only and once only; the implementation is locked (`:115-140`).

**Bounded revert copy**
- `MAX_REASON` limits the revert data copied (`:275-283`); but see V3-01.

### `factory/`

**Registration**
- `registerImplementation` / `registerDexImplementation` check code, `kind()`, `factory()` and `chainUid()`.
- The catalogue is append-only and version 0 is refused (`OpenFactory.sol:54-63, 156-169, 194-204`).

**Clones**
- `CREATE2` with the salt scoped by `msg.sender`, so nobody can squat another creator's address.
- The predicted address is refused if it is indexed or has code (this also covers an unregistered clone that
  self-destructs).
- `initialize` runs in the same call (`:240-265, 175-185`).

**Gates**
- Zether gate: dev chain plus the verifier's answer (`:208-218`).
- PQZ gate: see part 1, V1-02.

### `hedera/`

**HIP-632 path**
- Only a 64-byte signature from an address without code takes it.
- Plain CALL with a 100 k gas cap; fail-closed on revert, a short return or any value ≠ 1
  (`HederaAccountAuth.sol:23-27`).
- `HederaLib.requireValid` is a public library `view` function, so it is called by DELEGATECALL, never STATICCALL,
  and every caller is a non-view entry. No view entry in scope reaches it.

**Starvation**
- Gas starvation of the HIP-632 call only yields `MetaTxBadSignature`, with no state change.
- In the DEX a starved settlement becomes `MatchFailed`; nothing is consumed.

**HTS leg check** (`HederaLib.sol:33-56`)
- `isToken` must answer SUCCESS; the decoded custom-fee arrays must be empty; the association must succeed (or
  already exist).
- An absent precompile gives `-1` and is refused.
- Fees or freezes added to an HTS leg later are disclosed in the spec: unwraps then revert on the exact-delta check.

**`HederaMandateWallet`** (`:25-31`): the same 64-byte rule, ERC-1271 stays ECDSA.

### `wallet/MandateWallet.sol` (mandates)

**`payUnderMandate`** (`:114-135`)
- Checks the delegate as `_msgSender`, the current epoch, the expiry, an allowed payee, `0 < amount ≤ maxPerPayment`
  and the period cap with no overflow.
- Rolls the period, then marks `entryRef` used per wallet.
- Effects come before the one outside call, under the guard.

**Epochs and owner actions**
- `setMandate` keeps the running period only for the same delegate and period length (`:75-88`).
- Revoke bumps the epoch; a delegate's revoke is epoch-bound (`:139-145`).
- `execute` and the setters are owner-only, directly or through a ticket.

**ERC-1271**
- Answers for `owner` only, so the delegate cannot sign token `MetaTransfer`s with `from = wallet` to escape the caps.
- See V3-03 for the unbound-hash side.

### `common/` crypto helpers (part 2's verifiers call them)

**`MultiSig.requireQuorum`** (`MultiSig.sol:38-60`)
- `threshold ≥ 1` and `≤ owners`.
- Signers must be strictly increasing, which rules out duplicates.
- OZ `recover` rejects a zero address and high-s.
- Owner lookup is a binary search over sorted owners.

**`CurveSigs.schnorr`** (`CurveSigs.sol:28-48`)
- `z < r`, `e ≠ 0`, `R ≠ O`, `Y ≠ O`.
- bn254 points are checked canonical and on the curve in Solidity before the precompile.
- BLS12-381 subgroup checks are done by G1MSM.
- One MSM `zG − R − eY = O`.

**`CurveSigs` BLS**
- `blsBn254`: `sig` checked canonical, on the curve and ≠ O; `pk` is checked by the pairing precompile.
- `bls12381`: `sig ≠ O`, and PAIRING_CHECK validates both inputs.

**`Bls12381.sol`**
- Every wrapper checks input lengths and the output size.
- Success is judged by `returndatasize`, so an absent precompile is detected.

**`HashToCurve.sol`**
- `expand_message_xmd` matches RFC 9380 §5.3.1: Z_pad of 64 bytes; `l_i_b_str` 2-byte big-endian; a `0x00` byte;
  `DST ‖ len`; `ell ≤ 255`; DST ≤ 255.
- Reduction is MODEXP with exponent 1.
- Summing per-map cofactor-cleared points is valid because the map is a homomorphism.

**`WebAuthnClientData.parse`** (`:14-35`)
- The fixed prefix binds the type and the base64url challenge.
- Every index is bounds-checked before `hashSlice`.
- Only `}` or `,"crossOrigin":false` may follow the origin.

**`SSTORE2`** (`:11-29`)
- The runtime is prefixed with STOP; the init code length is correct (12 bytes, `PUSH2 len+1`).
- `read` of an empty pointer returns empty.

**`Ed25519.verify`** (`:34-51`)
- `S < L`; `y_A, y_R < p`; small-order `A` and `R` refused.
- `A` decompression refuses `x = 0` with the sign bit set.
- The `k` reduction (hi·2^256 mod L + lo) is correct.
- Comparing the encoding against `R` covers a non-canonical or off-curve `R`.
- `z = 0` is unreachable as an accept (`y_R = 0` is refused as small order).
- Every intermediate that is not reduced is < 2p and feeds only `mulmod`.

---

## Not checked

- **`common/Sha512.sol` (1 895 lines):** not verified round by round. I relied on its KATs. A bug there would make
  Ed25519 UA signatures fail, or worse, accept, so it deserves a vector-based check.
- **Constants not recomputed:**
  - the `Ed25519` constants (the 15 `jB` table entries, `D`, `D2`, `SQRT_M1`, `Y8`, `R256_MOD_L`) and the
    Straus–Shamir window logic, beyond the reading above;
  - `Bls12381.NEG_G2_GENERATOR` and `HashToCurve.P`;
  - the ERC-7201 / transient slot constants (`MetaTxBase.sol:36-50`, `ERC20MetaTx.sol:42`, `AdminLib.sol:65`,
    `UnderlyingLib.sol:63`, `TradeLib.sol:46`, `SCaaSDex.sol:82`). They are distinct values, so they cannot collide
    with each other or with OZ ERC20's slots 0–4, but I did not check that each equals its stated preimage.
- **Hedera behaviour on a live network:** HIP-632 / HTS answers, gas charging on rejection, the tinybar `msg.value`.
  This was not tested; I read it from the comments.
- **Parts 1 and 2 beyond their call edges:** `ua/` (registry, kinds, verifiers including `Ed25519Verifier`),
  `account/SmartKeyAccount`, `pqz/`, `zether/`. I only followed their calls to establish what this scope trusts.
- **Off-chain:** the relayer / node simulation behaviour assumed in V3-01 and V3-02, and client signing of cancels.
- **OpenZeppelin:** the worktree has no `lib/`. I read the main checkout's copy, not the exact pinned commit.
