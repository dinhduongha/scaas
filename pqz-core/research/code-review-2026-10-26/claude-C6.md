# C6 — Claude UltraCode review (64549aa4)

Unit: DEX and trade code (`smartcontracts/evm/src/dex/`, `smartcontracts/evm/src/trade/`). Specs: `docs/contracts/dex.md`, `docs/contracts/settlement.md`, `docs/decisions.md` CTR-DEX-*. Every finding below went through a refutation round with three votes. Duplicate reports are merged under one id. The final severity is the vote majority.

## Findings

| id | severity | file:line | claim | evidence | fix |
|---|---|---|---|---|---|
| C6-C1 | P3 (3+3+3 votes P3) | `smartcontracts/evm/src/dex/SCaaSDex.sol:283, :294-296, :331-336, :601, :621`; `src/dex/DexPuller.sol:27`; `src/common/SigCheck.sol:62-63`; `src/ua/UARegistry.sol:630`; `docs/contracts/dex.md:284-295, :313, :561-563` | The V3-01 fix is incomplete. A hook or a hostile outside token can no longer forge the starvation selector, but it can burn gas so that a later capped verify starves for real. `mtxSettle` then reverts the whole batch. | The settlement self-call is `call(gas(), …)` (:283). Token calls have no gas cap (`_bal` staticcall(gas()) :621, `_send` `trySafeTransfer` :601, puller `trySafeTransferFrom` DexPuller.sol:27). A real `SigCheckGasStarved` / `UAVerifyGas` is re-raised for the whole call (:294-296). See details. | Bound the gas the DEX hands to code it does not control. Either give each settlement a gas budget, or cap gas on outside-token calls. Also fix dex.md:284-285 and :313. |
| C6-C2 | P3 (proposed P2; 3 votes P3) | `scaas-node/src/guard.rs:61-62, :402-405` (vs `src/dex/ISCaaSDex.sol:49-56, :167-169`; `docs/node/job-api.md:385`) | The node's call table still holds the `mtxExchange` / `mtxExchangeVia` selectors from before tagged legs. The node therefore refuses every correctly encoded exchange `call` job. | The table has `0x1e69bcde` / `0xb21fe8bc` (old `(address,TradeOrder,bytes,uint256,uint256)` leg). The current tagged `ExchangeLeg` gives `0x67ab820c` / `0xb0e74c1b`. guard.rs:252-253 refuses any selector not in the table. The pin test hard-codes the old tuple. `SEL_MTX_SETTLE` `0x0403b13c` is current. | Derive both selectors from `ISCaaSDex::mtxExchangeCall::SELECTOR` / `mtxExchangeViaCall::SELECTOR` in `abi.rs`. Change the test to the tagged tuple. Add an `exchange_calldata` KAT row. |
| C6-C3 | P3 (3+3 votes P3) | `scaas-node/src/dex/venue.rs:779-787, :804-823`; `scaas-node/src/dex.rs:384-391, :467-476` | The DEX watcher acts on `LegSettled` / `UALegSettled` / `OrderCancelled` from any watched address, outside tokens included. It never checks which contract emitted the event. A listed outside token that is hostile or upgradeable can therefore delete any order from the venue book and release pending fills. | The filter address list is `self.kinds.keys()` (both sides of every market, KIND_OUTSIDE too, :224-227) plus the DEX. The arms at :804-813 never read `e["contract"]`. `Book::remove` searches every market. Only `NoncesInvalidated` is scoped to its emitter. | Accept leg events only when `contract == self.dex`. Accept `OrderCancelled` / `NoncesInvalidated` only from the DEX or a KIND_SCAAS token, and require that `h` sells that contract. The simplest form is to drop outside-token addresses from the filter. Add a forged-log test. |
| C6-C4 | P3 (3 votes P3) | `src/dex/SCaaSDex.sol:528-534, :554-573, :425-437, :600-602`; `docs/contracts/dex.md:311-314, :469, :538` | On the exchange path, a fee-on-transfer outside token that the plan only receives pays signers below their signed limit, and conservation does not catch it. | `_exchangeIn` checks `snap + sold + refunds` (:531), which is trivially true for a token no leg sells. `_exchangeOut` measures the DEX's own balance (:558-560). The fee on the payout comes out of what the recipient gets, so the final `_bal == snap` (:571) still passes. dex.md:311-314 and CTR-DEX-18 claim conservation as the backstop here. | Minimum: correct dex.md:311-314 and CTR-DEX-18/21 (a receive-only token has no backstop; delist a token as soon as it enables a fee). Optional: check recipient balances per address for outside receive tokens. |
| C6-C5 | P3 (3 votes P3) | `src/trade/TradeLib.sol:37, :91, :158-159`; `docs/contracts/dex.md:244-247`; `scaas-node/src/dex.rs:507-512, :532-534`; `clients/clientkeys/src/evm.js:510-519` | Lane invalidation can never reach an order with `nonce >= 2^128`, and nothing refuses such orders or warns about them. | `MAX_MIN_NONCE = 2**128` caps `newMin` (:159), but `precheck` only checks `o.nonce < minNonce` (:91). Node intake and clientkeys pass any uint256 nonce through, and clientkeys takes the nonce from the server. CTR-DEX-02 explains the cap only as anti-lock-out. | Refuse `o.nonce >= MAX_MIN_NONCE` in `precheck` (TradeLib ratchet and KAT). Or document the limit in CTR-DEX-02/13 and refuse such nonces in node intake and clientkeys `checkTradeOrder`. |
| C6-C6 | P3, doc only (2 votes P3, 1 refuted as intended design) | `docs/contracts/dex.md:425` (CTR-DEX-03) vs `:490`; `src/dex/SCaaSDex.sol:509-510, :341-345` | "Delisting a market stops that pair" is true only on `mtxSettle`. The exchange path checks only that each token is known, so a delisted X/Y still trades there while X and Y are each listed elsewhere. | `_checkMarket` → `listed[_pair]` (:344) on settle. `_exchangeIn` checks only `listings[token] != 0` (:509-510). Trading unlisted pairs on the exchange path is intended (DS-7 in `docs/history/specs/2026-10-08-dex-exchange-design.md:172-174`, CTR-DEX-20). | Fix the CTR-DEX-03 wording: delisting stops the pair on the book path only, and stopping a token on the exchange path requires delisting every market it is in. Do not add a pair check, because it would break exchange-only pairs. |
| C6-C7 | P3 (all votes P3; impact smaller than first claimed) | `src/trade/TradeLib.sol:155-162`; `src/metatx/ERC20MetaTx.sol:169-173, :448-456`; `scaas-node/src/dex/venue.rs:781-787, :815-823`; `docs/node/dex-venue.md:251-258`; `docs/contracts/settlement.md:58` | A native signer can raise its shared `minNonce` floor through `uaInvalidateNonces(pad(addr), …)`. That emits only `UANoncesInvalidated`, which the watcher does not read, so dead shape-0 orders stay in the book. Separately, settlement.md:58 says the exchange path is final at "tx, then the DEX watcher", but the watcher reads no `ExchangeLegSettled` / `UAExchangeLegSettled` (deferred to P7). | One bytes32 slot is shared by both order shapes (TradeLib.sol:42-43). The `ua=true` branch emits `UANoncesInvalidated` (:161). The filter lists only LegSettled, UALegSettled, MatchFailed, OrderCancelled and NoncesInvalidated. The book heals itself: on the first match, `fault()` / `healthy()` → `on_chain()` reads `minNonce` and evicts the order (venue.rs:294-363, :446-481). What remains is stale depth until that first touch. | Subscribe to `UANoncesInvalidated` and map a native-space id to `drop_below(addr, …)`. Add `UAOrderCancelled` when UA intake lands. Mark the watcher part of the exchange row in settlement.md:58 as P7 / SPECIFIED. |
| C6-C8 | P3, register hygiene (3 votes P3) | `docs/contracts/dex.md:400, :471, :538`; `docs/contracts/settlement.md:219-220`; `src/dex/SCaaSDex.sol:34-37, :441-445, :545-546`; `docs/decisions.md` CTR-DEX-16/-17/-18/-23 | Several DEX rulings are marked "controller ruling, pending the owner" but have no entry or Change line in decisions.md. | grep of decisions.md finds no DEX entry for increaseAllowance / Permit2 refusal, the approve reset, gross `receivedFloor`, `FeeSplitInvalid` instead of `FeeWouldStick`, no `checkOrder`, or the 256-byte `MatchFailed` cap. Header (:3-4): "Every ruling of SCaaS has one entry here". `TODO.md:247` lists only the increaseAllowance / Permit2 item. | Add Change lines to CTR-DEX-16/-17/-18/-23. Give each ruling in full, with status built and commit (`dbf27a5e` for the P2c rulings). Add the missing items to TODO.md:247. |

C6-C2, C6-C3 and C6-C7 are node / doc code outside the unit's contract scope. They were found while checking events and relayability, and none puts funds at risk.

### Finding details

**C6-C1: gas burn aborts a whole batch.** Merged from three reports.

**Reach.** Any of these triggers it:
- A listed hook token (ERC-777 `tokensToSend` on the taker pull, or `tokensReceived` on a contract `destination`). dex.md:292-293 says W-O "replaces the earlier ruling that hook tokens are never listed", while :313 still says hook tokens are not listed. The spec contradicts itself.
- An admin-listed outside token that is hostile or upgradeable.

**Call sequence.** `mtxSettle([s1, s2, …])`:
1. s1's hook or `balanceOf` (`_bal` at :331, before the pulls at :333-334) loops until s1 can only just finish, then returns.
2. The outer frame keeps a fraction of the gas.
3. s2 holds a SmartKeyAccount maker (needs 400000·64/63 + 5000 ≈ 411k) or a UA PQ leg (holds up to 5.95M). Its verify starves for real.
4. :294-296 re-raises that starvation and the whole call reverts, s1 and every other relayer's fill included.

The same thing works inside one settlement: the taker pull's hook burns gas, and the maker's capped verify in the same settlement then starves.

**Gas correction.** The frames above the hook each keep 1/64 and get it back, so about 3/64 of the gas is left, roughly 0.77M at 2^24, not G/64. Effect on each leg type:
- SmartKeyAccount leg: starves only at gas limits below about 9M. That still covers the usual estimate-based limit.
- mldsa65 UA leg: starves at any limit up to 2^24.
- No capped leg later in the batch: later settlements still run out of gas and become empty `MatchFailed`.

**Why it is hard to stop.** The hook can branch on `block.number`, `basefee` or `coinbase`, so `eth_call` simulation passes and the node's simulate-and-split step (dex-venue.md:218) misses it. The attacker's order never fills, so the attack costs it nothing.

**History.** The previous review raised this in V3-01 "Related" (`pqz-core/research/code-review-2026-10-19/V3-claude-common-metatx-dex.md:51-52`, ":276 forwards all gas … leaves 1/64 for the rest of the batch"). The W-O fix (decisions.md:2275) covers only the revert bytes. The test `test_starvedOutsideTokenCall_isAnEmptyMatchFailed` (`test/v2/DexOutside.t.sol:474-491`) puts the starving settlement last, so it never exercises a later leg.

**Likelihood note** (from a lens note, not separately voted): a listed exact-transfer pre-0.8 token whose failure path is INVALID burns 63/64 of the forwarded gas without any hook. USDT's SafeMath `assert` on a short allowance is an example. Any signer can trigger it for free by revoking its puller allowance after intake.

**Impact.** Griefing only: no funds move and no order state changes. Same class as V3-01, hence P3.

**Fix.**
1. Per-settlement gas budget: add `Settlement.gas`. Before each settlement require `gasleft() ≥ gas·64/63 + margin` (otherwise revert, because that is the submitter's fault), then call `settleOne` with exactly `gas`. A starvation inside a fully funded budget becomes `MatchFailed` with the selector kept in `reason`, so the node retries with more gas instead of dropping a valid order.
2. Additionally or instead: cap outside-token calls (`_bal`, `_send`, `DexPuller.pull`) at a fixed 100–300k for KIND_OUTSIDE tokens.
3. Fix the spec: dex.md:284-285 ("cannot forge it" covers bytes only) and :313 vs :292-293. Alternatively, keep `gas()` and document in CTR-DEX-16 / section 10 that a gas-burning callee aborts the whole batch.

Deployed bytecode and the node only. No vectors change, except the `mtxSettle` calldata KAT if a field is added.

**C6-C2: stale exchange selectors.** The call table came in `a4468b48`, tagged legs in `82569849`, and the UA-5b node commit `6dd9430c` updated only `mtxSettle`. A job sent with the old selector passes the guard and then reverts on chain, because SCaaSDex has no fallback. Effects:
- The exchange path cannot be relayed through the node's call-job path, although job-api.md:385 lists it.
- That breaks the "every mtx* relayable" rule for this path.

It is P3, not P2: the entries are permissionless on chain, other relayers can submit directly, no funds are at risk, and the node's TradeEngine (NODE-DEX-17) is not built yet.

**C6-C3: forged watcher events.** Order hashes are public through the book and depth API (venue.rs:145, :554). A hostile listed outside token can emit:
- `OrderCancelled(h)`: removes `h` from the book in every market.
- `LegSettled(…, h, …, sold)`: releases pending fills, so the matcher plans fills the chain will refuse.
- `NoncesInvalidated`: drops all resting orders that sell that token.

All of these are forwarded to `dex_fill_ingest`. The Odoo client outside the repo (`dms_blockchain_dex/models/dex_trade.py:161-162`) rejects events from non-DEX emitters, which would stall the cursor instead. That client is stale and does not protect the node. The chain still decides every fill, so the harm is to the off-chain book only.

**C6-C4: receive-only fee-on-transfer token.** Concrete case:
1. Leg L sells 1,000 X (SCaaS) and signs `receiveAmount` = 1,000 R, where R is an outside token that turns on a 0.2 % transfer fee after listing (for example USDT's `basisPointsRate`).
2. The submitter commits a floor of 1,000 R. The AMM pays the DEX 1,000 R net, so `excess` = 0.
3. The DEX sends 1,000 R, and the destination is credited 998 R.
4. `ExchangeLegSettled` still reports `receivedFloor` = 1,000.

The settle path is safe because both tokens are pulled there (:333-334, :337-338). The loss is bounded by the token's own fee rate.

## Refuted

| Finding | Reason |
|---|---|
| C6-3: `setFeeSplit` accepts the DexPuller as treasury, locking treasury shares (`SCaaSDex.sol:182-187, :435`) | The guard does what CTR-DEX-03 says (`treasury ∉ {0, DEX}`). The puller is just one of countless dead addresses a trusted admin could paste. The admin can redirect future fees at any time, and user funds are never touched. Adding `t == s.puller` would be optional hardening, not a defect. |
| C6-4: `exchangeCallback` does not pass the submitter, so anyone can drive a listed executor (`ISCaaSDex.sol:196-202`, `SCaaSDex.sol:466-474`) | Signers are protected by `_exchangeIn` / `_exchangeOut`. No production executor exists in the repo (only test mocks). An inventory executor can authenticate signed `data` or price what it receives without `tx.origin`. What remains is P3 interface and documentation hardening at most. |

## Checked and sound

**Order signatures cover every term; no replay, re-fill or wrong counter-order**
- `TRADE_ORDER_TYPEHASH` / `UA_TRADE_ORDER_TYPEHASH` hash all 13 fields, including amounts, `receiveAmount`, `minFill`, `fee`, `relayer`, `dex`, `destination`, `flags`, `batch`, `nonce` and `validUntil` (TradeLib.sol:17-27, :54-64). The strings match dex.md:95-97 / :198-199, clientkeys `evm.js:144-158` and the node's alloy structs (`abi.rs:27-57`).
- The SaltedEIP712 domain binds chainId, `verifyingContract` = the clone (rebuilt per address) and salt = chain_uid (SaltedEIP712.sol:58-69).
- `DexOrder(address sellToken,TradeOrder order)` is correct nested EIP-712 (SCaaSDex.sol:76-80, :228-230). `o.dex == address(this)` is enforced (:378), and the token checks `msg.sender == o.dex` (TradeLib.sol:86).
- TradeOrder, UATradeOrder, DexOrder, CancelOrder, InvalidateNonces and UAInvalidateNonces all have distinct typehashes. A cancel wraps the full order digest. No replay works across token, DEX, chain, message type or wrapper (UnderlyingLib.sol:179-200, where the wrapper is `o.dex`).
- Over-fill is impossible:
  - Path A: `p < amount`, `move ≤ amount − p`, effective minimum `max(minFill, ceil(amount/2))` unless the fill is the exact remainder, 512-bit `mulGt` price check, fee bound, IOC closes at its first pull (TradeLib.sol:106-133).
  - Path B: `p == 0` with the exact shape, and the DEX mirrors the checks (SCaaSDex.sol:386-395). ESCROW is refused for outside legs (:382).
- Skipping the signature when `pulled[h] != 0` is sound: `pulled` is written only by a verified `record` or a verified `cancel`, and `h` binds every field (:409; ERC20MetaTx.sol:135, :146).
- Wrong counter-order: `TokenMismatch` (:319), listed market (:312, :344), `SelfTrade` over bytes32 ids (:320, :511), `DuplicateOrder` (:325), `FillMismatch` (:329). A maker receives `ceil(fill·R/A)` (:322).
- The `core` / `_native` memory aliasing covers the same 13 words. It is reached only on shape 0, whose address words `abi.decode` validates (:350-370).
- ERC-7201 slots `scaas.dex` 0xb144…ac00 and `scaas.trade` 0x2c9c…2f00 match.

**Cancel and nonce invalidation**
- `cancel` sets `pulled[h] = amount` under the signer's signature. An already-closed order is a no-op, and a bad signature skips the item without reverting (TradeLib.sol:146-152; SCaaSDex.sol:244-253).
- `invalidate` is strictly increasing and capped at 2^128, so a replayed signature reverts (TradeLib.sol:155-163). `minNonce` is re-checked at every pull (:91). There is one floor per id across both shapes, and the DEX keeps its own floor for outside legs.
- Limit: nonces at or above 2^128 are out of reach, see C6-C5.

**Settlement is atomic and conserves value; pulls cannot be redirected**
- Each settlement is a reverting self-call (:283). Both tokens are snapshotted and must be unchanged at the end (:331-338).
- Fees: `dexFee = ceil(recv·fee/PPM)`, once per order on the aggregate (:385), equal to the token's `FeeAboveSigned` bound. Fee ≤ 1 %, so there is no underflow. The relayer share is floored and the remainder goes to the treasury (:431-432).
- Exchange path:
  - pull check `snap + sold + refunds` (:529-534);
  - `InsufficientOutput` against `snap + refunds + floors` (:555-562);
  - pro-rata surplus with the remainder to the last leg; `floorsLeft == recv` holds only on the last leg because `recv ≥ 1` is forced (:563-569);
  - final `== snap` over every plan token (:570-572).
  - Fee-on-transfer and rebasing sell tokens fail; receive-only tokens do not, see C6-C4.
- `mtxExchangeVia` hand-out (gap round): `_flows` sends Σ sold, keeps Path B remainders as refunds, and asks back Σ floors. That is exactly what `_exchangeOut` requires (:466-494, :559). Same-token cycles and opposite legs (A→B with B→A) were traced and close to `snap`.
- False-return and no-return tokens are handled by `trySafeTransfer` / `_tokenFailed` (:600-613). `_bal` requires ≥ 32 bytes of return data and uses scratch memory only.
- `DexPuller.pull` is DEX-only, pays only the immutable `dex` (the clone), and moves `amount` = `record`'s move after `precheck` and the signature check (DexPuller.sol:15-33; SCaaSDex.sol:405-411).
- Interactions:
  - Refused: target = the DEX or the puller; selectors `mtxTrade` / `uaTrade` / `increaseAllowance` 0x39509351 / Permit2 `approve` 0x87517c45 (:540-546).
  - Every `approve` is reset to 0 before the payouts (:453-458).
  - Only `mtxTrade` / `uaTrade` trust `msg.sender == o.dex`. Neither is in the `mtxExecute` allowlist, and no multicall or delegatecall forwarder exists in src.
- Reentrancy: every `mtx*` entry is `nonReentrant` (transient guard), and `settleOne` is self-only (:306).
- The DEX holds nothing across calls, so no funds can be locked.

**Batch abort and front-running beyond the signed floors**
- Forged selectors (W-O / V3-01) are closed. `_send`, `_bal` and the puller drop token revert data (SCaaSDex.sol:600-626; DexPuller.sol:27-32). SigCheck and `UARegistry._capped` read only 32 bytes and bubble nothing (SigCheck.sol:58-70; UARegistry.sol:624-636). The remaining bubbling calls reach only KIND_SCAAS tokens or the registry. `MatchFailed` copies at most 256 bytes and updates the free memory pointer (:282-290).
- The gas-burn half is open, see C6-C1.
- Front-running a `relayer = 0` settlement only takes the fee share (CTR-DEX-17). Floor and surplus choices stay within signed limits (CTR-DEX-21, NODE-DEX-18).

**Gas bounds on customer chains (2^24)**
- The only fixed gas figures are the ERC-1271 caps (50k / 400k by SmartKeyAccount codehash, :262-265) and the registry holds. SigCheck holds `cap·64/63 + 5000`, so a starved check is never a false verdict.
- The dex.md:355-382 packing table fits 16,777,216 (two mldsa65 legs ≈ 12.1M). Those figures were measured on osaka, not the pinned amsterdam profile, but the margin is wide.
- No gas-price or block-limit assumptions. The EIP-7976 calldata floor does not bind on these settlements.

**Relayability**
- `mtxSettle`, `mtxExchange`, `mtxExchangeVia`, `mtxCancelOrders` and `mtxInvalidateNonces` need no role. The relayer binding (`o.relayer ∈ {0, msg.sender}`) is checked by the DEX (:377) and again by the token (TradeLib.sol:89). fee = 0 is valid (zero sends are skipped, :601, :632).
- Gap round on the relay layer: token `mtxExecute` / `uaExecute` self-call only the token's own allowlist (MetaTxBase.sol:137-145), so they cannot reach the DEX. A SmartKeyAccount or MandateWallet forwarder simply becomes the submitter, consistently for both the binding and the relayer share (:434).
- Limit: the node call-job path is broken for the exchange entries, see C6-C2.

**Access control**
- `initialize` is factory-only and runs once; the implementation locks itself in its constructor (:118-145). The puller is created by the clone. The factory salt is bound to the creator (OpenFactory.sol:245).
- Only `setMarket`, `setFeeSplit`, `setExchangeTarget` and `setListedOnly` are admin-only, and none sets an amount. `FeeSplitInvalid` refuses treasury 0 or the DEX unless the share is 100 % (:183).
- Token kind comes from the factory at `setMarket`, never from the leg (:352). Deprecation is one-way.
- UA legs: shape 1 only on a SCaaS token with its ledger on (:356, :363-365). Derived payouts and refunds go through `transferToUA`, which keeps conservation. UA_POOL and SHIELD_POOL native senders are refused (ERC20MetaTx.sol:448-456).

**Spec and ABI consistency (gap round)**
- Struct layouts match across ISCaaSDex / ITradeToken, dex.md and `scaas-node/src/abi.rs:27-107`: `Leg`, `ExchangeLeg`, `Settlement`, `DexOrder`, `ExchangePlan`, `Interaction`, and the `IExchangeExecutor.exchangeCallback` signature.
- Event layouts and indexed fields match: `LegSettled` / `UALegSettled` (`received = recv − fee`, surplus 0 on settle), `ExchangeLegSettled` (gross `receivedFloor`, `limitReceive = ceil(sold·R/A)`), `TradeFilled`, `OrderCancelled`, `NoncesInvalidated`, `MatchFailed`. Library events are emitted from the DEX address via DELEGATECALL.
- The decisions.md CTR-DEX-08/-15/-18/-20/-21/-23/-24/-26 statuses match the code (W-O built, `mulGt`, ESCROW refused for outside legs, cycle legs allowed, `isDex` advisory only, shape tags and the `UAVerifyGas` re-raise).
- Missing register entries: see C6-C8.
- Previous-round items: V3-02 does not apply to orders (CancelOrder binds the full hash). V3-04 items (sweepable stray funds, same-token cycles, kind frozen at `setMarket`) remain documented choices. Since fe2faf0, only `0f88e66f` and `4fae6aba` touch dex/ or trade/.

## Not covered

- The off-chain KATs (`trade_kat.json`, `dex_order_kat.json`) were not cross-checked byte for byte, because computing hashes was not allowed. Only `cast sig` and `cast keccak` were used for selectors and slots.
- Not read: ERC20MetaTx beyond the trade entry points; UnderlyingLib wrap internals beyond their interaction with the DEX; PQZ / Zether token trade overrides (the DEX makes no precompile call and holds no ciphertexts); OpenFactory classification internals (`versionOf` / `isDeprecated`).
- Node packing and simulation (NODE-DEX-06/-18), node intake beyond the paths cited in C6-C2/C3/C5/C7, the registry's internal verifiers, the test suite, and the pinned OpenZeppelin commit (read from the main checkout's `lib/` only).
- `dex_fill_ingest` on the client side is not in the repo, so whether it books forged events as final (C6-C3) is unverified.
- Critic gaps: all five were covered in the gap round. They were the `mtxExchangeVia` hand-out, event arguments against the docs and the node, the ISCaaSDex / ITradeToken struct and ABI layouts, the generic relay layer, and the decisions.md / settlement.md statuses. That round produced C6-C2, C6-C7 and C6-C8, and the corresponding "Checked and sound" lines above.