# Order-book DEX

SCaaS runs an order-book exchange whose book lives off chain in the node ([node/dex-venue.md](../node/dex-venue.md))
and whose settlement contract checks every signed order on chain. Users never pay gas: orders, cancels and the one
`approve` the DEX needs are all signed messages that a relayer submits. Status: `OrderBookDex` **BUILT**
(`smartcontracts/evm/src/dex/OrderBookDex.sol`); the 1271 gas cap and the per-fill fee round-up **SPECIFIED** (a new
deployment); the legacy `MetaTxDex` **BUILT**, unrouted.

## Overview

| Layer | What exists | Replaces |
|---|---|---|
| Contract | `OrderBookDex`: checks two EIP-712 orders (ECDSA/ERC-1271), price limits, `filled[orderHash]`, partial fills, a batch that is atomic per pair, direct `transferFrom` person → person (the DEX holds no funds), a per-market DEX fee (on/off, maker/taker ppm, cap 1 %), the relayer fee through the existing `FeeMode`, on-chain cancel by signature | `MetaTxDex` (fill-or-kill, no allowance) **kept as legacy**, no gateway route |
| Token | the `MetaToken` meta-tx op `approve(address spender,uint256)` — spender must be a contract | — |
| Node | the book per market, price-time priority, limit + IOC/FOK, partial fills, settlement through `call` jobs, its own final-event watcher ([NODE-DEX-01](../node/dex-venue.md#NODE-DEX-01)) | an in-memory book |

<a id="orderbookdex"></a>
<a id="CTR-DEX-01"></a>**CTR-DEX-01** — **A complete DEX** (owner): an off-chain **persistent** book, markets per pair,
price-time priority, limit + IOC/FOK, partial fills, signed expiry, cancel by off-chain signature plus on-chain
nonce invalidation through a meta-tx, a public read API; the settlement contract checks **two** EIP-712 signed
orders, the price limits and `filled[orderHash]`, settles several pairs in one transaction (atomic per pair), is the
only spender (the allowance lockdown, [CTR-TOK-01](token-wrappers.md#CTR-TOK-01)) and keeps its own lane/nonce space
(no subject sequence); two independent fees: a DEX fee switched per market (maker/taker ppm, cap 1 %, inside the
signed order) and the relayer fee through the existing meta-tx modes; every user action is a meta-tx; client systems
configure markets, read the book and book the fees.

Interface summary (BUILT): `settle(Match[]) returns (bool[])` (atomic per pair; none ⇒ `NothingSettled`),
`cancel(CancelReq[])`, `invalidateNonces(maker, newMin, sig)`, `checkOrder`, `setMarket` (admin). The planned new
deployment's `_validSig` contract branch = assembly `staticcall` capped at 400 k for `SubjectAccount` clones by
codehash, else 50 k, ≤ 32 B returndata, and `gasleft() ≥ cap·64/63 + margin` or the whole tx reverts
([CTR-DEX-08](#CTR-DEX-08)).

## Signed orders

Domain: `name = "SCaaS OrderBookDex"`, `version = "1"`, `chainId`, `verifyingContract = DEX`. Orders are signed **on
the DEX**, not on a token: one signature covers both tokens of the pair, and the wallet shows one order type.

```
Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,
      uint256 nonce,uint256 expiry,uint32 maxFeePpm,uint8 flags,address relayer,uint8 feeMode,uint256 fee,
      address feeToken,address feeRecipient)
CancelOrder(bytes32 orderHash)
InvalidateNonces(address maker,uint256 minNonce)
```

| Field | Meaning |
|---|---|
| `maker` | the signer; EOA (ECDSA low-s) or contract (ERC-1271, e.g. a passkey/seed `SubjectAccount`) — told apart by code as in `ERC20MetaTx` (an EIP-7702 designator is an EOA) |
| `taker` | 0 = anyone; non-zero = only this counterparty (RFQ) |
| `sellAmount`, `buyAmount` | total to sell / minimum total to receive (gross, before the DEX fee). Limit price = `buyAmount/sellAmount` |
| `nonce` | unique per maker; an order is valid while `nonce >= minNonce[maker]` (bulk cancel). Clients use `unix_ms·2^20 + random20` |
| `expiry` | signed expiry, epoch seconds; `block.timestamp <= expiry` |
| `maxFeePpm` | the highest DEX fee the signer accepts (in any role). A market fee > `maxFeePpm` ⇒ the pair reverts. Raising the fee **never** touches signed orders |
| `flags` | bit0 `FOK`, bit1 `IOC`; an unknown bit or both set ⇒ revert (as `validateMode`) |
| `relayer` | 0 = any relayer may submit; non-zero = only this `msg.sender` |
| `feeMode`, `fee`, `feeToken`, `feeRecipient` | the **relayer** fee ([relayer fee](#relayer-fee)) |

There is no token lane/batch here: the DEX keeps its own nonce space (`minNonce`, `filled`).

## `settle(Match[] ms) returns (bool[] ok)`

`Match = {bytes32 ref; Order maker; bytes makerSig; Order taker; bytes takerSig; uint256 makerFill; uint256 takerFill}`
— `makerFill` is the amount of `maker.sellToken` the maker delivers, `takerFill` the amount of `taker.sellToken` the
taker delivers. `ref` is set by the relayer and only echoed in events (the client's trade key).

Each pair runs in `try this.settleOne(m, msg.sender)` (external, only `msg.sender == address(this)`): **atomic per
pair** — a failing pair reverts its own part, emits `MatchFailed(ref, reason)`, and the other pairs still run. **If no
pair succeeds the whole transaction reverts `NothingSettled`**, so the relayer's simulation catches it before gas is
spent. `settle` is `nonReentrant` (transient); `settleOne` has no guard but only the DEX itself can call it. The real
relayer is passed into `settleOne` as a parameter: inside the self-call `msg.sender == DEX`, and defaulting the
relayer fee to `msg.sender` would strand the fee in the DEX — exactly `FeeWouldStick`.

<a id="CTR-DEX-04"></a>**CTR-DEX-04** — **IOC is closed on chain.** After the loop, every `IOC` order that just filled
has its remainder **closed** (`filled = sellAmount`, emit `OrderCancelled`): IOC means "only in this transaction",
even when it matches several makers in the same batch. A short `expiry` is the second layer. The Move and Solana DEX
programs close IOC at the first match (one maker) instead; the book handles that per family
([NODE-DEX-01](../node/dex-venue.md#NODE-DEX-01)).

Checks (each order, then the pair), **before** any transfer:

1. `flags` valid; `block.timestamp <= expiry`; `nonce >= minNonce[maker]`; `relayer ∈ {0, sender}`;
   `taker ∈ {0, counterparty}`; correct signature (the DEX's EIP-712 digest).
2. Pair: `M.sellToken == T.buyToken`, `M.buyToken == T.sellToken`, `sellToken != buyToken`, `M.maker != T.maker`; the
   pair's market (unordered key) is listed.
3. Amounts: `makerFill > 0`, `takerFill > 0`; `filled[h] + fill <= sellAmount` (**never overfill**);
   `FOK` ⇒ `filled[h] == 0 && fill == sellAmount`.
4. Price (both sides, cross-multiplied, checked math — overflow reverts, never wrong):
   `takerFill · M.sellAmount >= makerFill · M.buyAmount` and `makerFill · T.sellAmount >= takerFill · T.buyAmount`.
5. DEX fee: `feeOn ⇒ makerPpm <= M.maxFeePpm && takerPpm <= T.maxFeePpm`.
6. Write `filled` (effects), then transfer (interactions); every transfer is a direct `transferFrom(payer → payee)`:

| From | To | Amount (token) |
|---|---|---|
| M | T | `makerFill − takerDexFee` (X) |
| M | market fee recipient | `takerDexFee = makerFill · takerPpm / 1e6` (X), rounded up per [CTR-DEX-11](#CTR-DEX-11), only when > 0 |
| T | M | `takerFill − makerDexFee` (Y) |
| T | market fee recipient | `makerDexFee = takerFill · makerPpm / 1e6` (Y), rounded up per [CTR-DEX-11](#CTR-DEX-11), only when > 0 |
| M / T | relayer fee recipient | each order's relayer fee, only when > 0 |

7. `emit OrderFilled(ref, hash, owner, Fill)` for **each** side (`Fill` = struct: sellToken, sold, buyToken, received
   net, dexFee, dexFeeRecipient, relayerFeeToken, relayerFee, relayerFeeRecipient, filledTotal) — clients book from
   each wallet's point of view; `emit Matched(ref, makerHash, takerHash)`.

The DEX fee is taken from the **received** side of the party that pays it (no extra balance needed). Each token is
conserved exactly: the payer loses exactly `fill` (+ its own order's relayer fee, **on top**), the rest is split
between receiver and fee collector, the DEX keeps nothing ⇒ **no dust**. A market with the fee off counts its ppm as
0 ⇒ no fee transfer at all (not a "zero fee transferred"). The execution price is chosen by the relayer within both
limits; the SCaaS book always fills at **the resting (maker) order's price**, rounded in the maker's favour
(`takerFill = ceil(makerFill · M.buy / M.sell)`), and only emits pairs through the same limit check as the contract.

<a id="CTR-DEX-05"></a>**CTR-DEX-05** — **FOK is checked on chain** as one pair that fills the order completely
(`filled[h] == 0 && fill == sellAmount`); the book matches a FOK order with one counterparty only. Partial fills are
the default.

<a id="CTR-DEX-11"></a>**CTR-DEX-11** — **The DEX fee per fill rounds up.** When `feeOn` and `ppm > 0`, fee =
`Math.mulDiv(fill, ppm, PPM, Math.Rounding.Ceil)` (non-EVM: `(fill·ppm + PPM − 1) / PPM` on a double-width integer).
A floor (`fill * ppm / PPM`, as built: `OrderBookDex.sol:216-217`; non-EVM likewise: Sui `dex.move:250-251`,
Aptos `dex.move:247-248`, Solana `dex.rs:208-210`, TON `dex.tact:208`) lets an order split into fills `< PPM/ppm` units (e.g. ≤ 333 units at 0.3 %) pay a
market fee of 0, and on a private chain with zero gas price splitting costs nothing. The signed `maxFeePpm` bounds the
**rate**; rounding up adds less than one smallest unit per fill — that is the cap's meaning, stated in NatSpec.
`ppm ≤ MAX_FEE_PPM` (1 %) < `PPM` ⇒ fee ≤ fill, so `amount − fee` cannot underflow; a 1-unit fill pays a fee of 1
(its receiver gets 0) — the price of a dust order. The relayer fee keeps rounding down ([CTR-DEX-06](#CTR-DEX-06)). The
node needs no change: its matcher computes no DEX fee (it only compares `maxFeePpm` with the market fee,
`dex.rs:565, 616-624`; the DEX fee is
deducted inside the transferred amount, so `fundable` is unchanged), and clients read `dexFee` from `OrderFilled`.
Tests: `ppm = 3_000`, fill 333 ⇒ fee 1 (was 0); fill 1 ⇒ fee 1, receiver 0; an exact multiple ⇒ fee as before; one
fill of 1 000 vs ten fills of 100 ⇒ the ten fees total ≥ the one; fuzz `fill`, `ppm ≤ MAX_FEE_PPM` ⇒ `fee ≤ fill`
and `fee · PPM ≥ fill · ppm`; `dexFee` in the event equals the amount sent to `feeRecipient`; `feeOn = false` ⇒ no fee
transfer; the old floor test `test_feeOnSplitsReceivedAmountsWithoutDust` (`OrderBookDex.t.sol:439-454`) is changed to
round up. Each non-EVM family
gets the equivalent test (a dust fill pays fee 1). Status **SPECIFIED** (EVM: new deployment; non-EVM: new program
versions).

## Cancel (meta-tx — no gas for the user)

- `cancel(CancelReq[] reqs)` with `CancelReq = {Order order; bytes sig}`: a `CancelOrder(hash(o))` signature of
  `o.maker` ⇒ `filled[h] = o.sellAmount` (closed forever: a cancelled order can **never** settle, even through
  another relayer that holds the signed order). Many orders per transaction; an item with a bad signature or already
  closed is skipped (no revert of the batch, no event). Replay is a no-op.
- `invalidateNonces(maker, minNonce, sig)`: `minNonce` must **increase** and be `<= 2^128 − 1`
  (`type(uint128).max`, `OrderBookDex.sol:89`; nonces are `uint256`, so room remains above) ⇒ replay is refused, and one mistaken signature of
  `2^256−1` cannot lock an address out forever; invalidates every order with `nonce < minNonce`.

<a id="cancel-no-expiry"></a>
<a id="CTR-DEX-02"></a>**CTR-DEX-02** — **Cancel signatures never expire** (`CancelOrder`, `InvalidateNonces`) — a
deliberate exception to "every signature expires": a cancel only moves one way, in the signer's favour, and replay is
a no-op; a `validUntil` would only create a window in which an order removed from the off-chain book could still
settle until its `expiry` because the on-chain cancel job expired.

## Markets, DEX fee and admin

<a id="admin"></a>
<a id="CTR-DEX-03"></a>**CTR-DEX-03** — `admin` is **immutable**, set at deployment; in production a Safe/multisig
(changing signers happens inside the Safe). The admin can do exactly one thing:
`setMarket(base, quote, listed, feeOn, makerPpm, takerPpm, feeRecipient)` — no access to funds, no upgrade, no
global pause (delisting a market stops that pair). The cap `FeePolicy.MAX_FEE_PPM` (1 %) is checked in `setMarket`;
`feeOn` with ppm > 0 requires `feeRecipient ∉ {0, DEX}`. The fee is adjustable rather than fixed per clone because
"switch on/off per market" means it *will* change; fixing it per instance would make every change a new DEX, every
user would re-sign `approve` for a new spender (allowances bind a spender) and every resting order would be lost.
User safety comes not from a frozen fee but from the `maxFeePpm` **in the signed order** plus the constant 1 % cap: if
the admin raises the fee, pairs with older orders revert; nothing is ever charged above what was signed. No
timelock: there is nothing to wait for — new orders sign at the current fee, old orders are protected by their
signature.

## Relayer fee

<a id="relayer-fee"></a>
<a id="relayer-fee-rounding"></a>
<a id="CTR-DEX-06"></a>**CTR-DEX-06** — The relayer fee is fully separate from the DEX fee and uses the existing
`FeeMode` (`NONE/PERCENT/FIXED`) and `FeePolicy`; each order declares its own:

| `feeMode` | Token that pays | Amount per fill |
|---|---|---|
| `NONE` | — | 0 (B2B) |
| `PERCENT` | `sellToken` (`feeToken ∈ {0, sellToken}`, otherwise revert) | `FeePolicy.compute(PERCENT, fill, fee)` — cap 1 % |
| `FIXED` | `feeToken` (0 = `sellToken`) | `fee · fill / sellAmount` (pro-rata, **rounded down** ⇒ total ≤ `fee`); paid in `sellToken` it requires `fee <= 1 % · sellAmount` (`FeePolicy.compute(FIXED, sellAmount, fee)`) |

Recipient: `feeRecipient` if non-zero, else the relayer that submitted the transaction (`sender`). `FeeWouldStick`:
a recipient ∈ {0, DEX} reverts (it cannot be 0 after resolution, but `feeRecipient = DEX` can happen). The relayer fee
is **added** to the delivered amount (not deducted from `fill`); intake requires `fundable >= remaining + remaining
relayer fee` when paid in `sellToken`, and `feeFundable >= remaining fee` when paid in a separate fee token. A
separate fee token has no 1 % cap (two different tokens cannot be compared without an oracle): the signer sees and
signs the exact absolute amount.

## Read function for intake

`checkOrder(Order o, bytes sig) view returns (bytes32 hash, uint8 status, uint256 remaining, uint256 fundable,
uint256 feeFundable)`: `status` ∈ `OK, BAD_FLAGS, EXPIRED, NONCE_INVALID, BAD_SIG, CLOSED, NOT_LISTED, BAD_FEE` (0–7,
`OrderBookDex.sol:93-100`;
`BAD_FEE` = unknown `feeMode`, `feeRecipient = DEX`, or above the cap); `fundable = min(balanceOf, allowance(DEX))` on
`sellToken`, `feeFundable` likewise on the relayer-fee token. One `eth_call` covers every door check (signature incl.
ERC-1271, balance, allowance, closed/cancelled, nonce).

<a id="erc1271-cap"></a>
<a id="CTR-DEX-08"></a>**CTR-DEX-08** — **`OrderBookDex` caps the ERC-1271 call by codehash.** `_validSig`'s contract
branch is an assembly `staticcall` with cap `_erc1271Gas(signer)` = 400 k if `signer.codehash` is the `SubjectAccount`
clone codehash (immutable at deployment, as `MetaToken._erc1271Gas` does, `MetaToken.sol:141-143`,
[CTR-ACC-05](accounts-mandates.md#CTR-ACC-05)), else 50 k;
at most 32 bytes of returndata are copied; before the call it requires `gasleft() ≥ cap · 64/63 + margin`, otherwise
the whole transaction reverts (EIP-150: a relayer must not starve the call to turn a valid signature into an invalid
one). `cancel` needs no `try`: a capped `_validSig` only returns `false` ⇒ the item is skipped. The node does not
restore an ERC-1271 order whose pair failed out of gas. Why: the built contract calls `SignatureChecker` without a cap (`OrderBookDex.sol:383-384`),
so a contract maker that answers correctly under `eth_call` but burns gas or returns huge returndata in the real block
breaks a whole `settle` batch (the remaining 1/64 gas is not enough for the next pairs) and **every** `cancel` batch.
The contract is immutable ⇒ the fix is a **new deployment** (dev chains; users `approve` the new spender again).
Status **SPECIFIED**.

## Allowance and lanes

- The DEX is the only spender. Users `approve` **gaslessly** through the `MetaToken` meta-tx op
  `data = approve(address spender,uint256 amount)` (68 bytes, selector-tagged like `pay`/`trade`); step 6 checks
  `m.value == 0`, `m.to == spender`, spender is a contract (`_isContract`; an EIP-7702 designator is an EOA ⇒ refused);
  step 8 runs `_approve(from, spender, amount)` instead of a transfer. The relayer fee of the approve meta-tx itself is
  always 0: the `FeePolicy` cap is computed on `value = 0` (`PERCENT` gives 0, `FIXED` > 0 reverts `FeeExceedsCap`) — the
  relayer sponsors the approve (once per token); test `test_approveOpRelayerFeeIsCappedToZero`. `transferFrom` is
  called only by contracts — the DEX is one.
- The DEX never reads or writes the token's `metaNonce`. Orders use the DEX's `filled`/`minNonce`; the `approve` uses
  its own random lane (`keccak("scaas.dex.approve" ‖ rand)`, nonce 0). Tested consequences: a hanging or cancelled DEX
  order never blocks a `pay`, and `pay`/`cancelMetaNonce` never invalidate a DEX order.

## Invariants

`filled[h] <= sellAmount` always; the DEX never holds a balance after `settle`; each token's Σ balances is unchanged;
a pair that violates price/overfill/expiry/cancel/nonce/signature ⇒ only that pair fails; fee off ⇒ exactly 0 fee
transfers; fee on ⇒ `received + fee == fill` per leg.

## Non-EVM DEX programs

The book, matcher, client booking and gateway are shared (nothing EVM-specific beyond addresses and hashes). Each
family provides a settlement program with the same invariants ([networks/README.md](../networks/README.md)): orders
signed with domain separation (network + DEX contract + every order field), checked on chain with the subject's key
(no account sequence; nonce/`filled` kept by the DEX program); `filled[orderHash]`, no overfill, cross-multiplied
price, `maxFeePpm` in the order, cap 1 %; cancel closes `filled` by the owner's signature and raises `minNonce`; funds
move person → person in the same transaction (Soroban two `require_auth`; Sui two `Account<T>` legs; Cosmos CW20
`TransferFrom` with an allowance to the DEX contract; TON escrow — the only one that holds funds briefly, because
jettons have no `transferFrom`); events equivalent to `OrderFilled/Matched/MatchFailed`.

<a id="bound-settler"></a>
<a id="CTR-DEX-09"></a>**CTR-DEX-09** — **Non-EVM settlement is bound to the relayer.** An order carries `relayer`
(0 = open) and the program checks the submitter. Sui, Aptos and Solana already do; **Cosmos** (`Settle` does not check
`info.sender`, `OrderParams` has no relayer), **Soroban** (`require_auth_for_args((order,))` binds only the order, not
the counterparty, `maker_fill` or the submitter) and **TON** (`receive(Match)` is open) do not, so a mempool observer
can copy an auth entry, insert its own pair and take the taker's price improvement. Fix: Cosmos adds `relayer` to
`OrderParams` and requires `info.sender == relayer` when set; Soroban adds `relayer: Address` to `Order` +
`relayer.require_auth()`; TON adds an optional `relayer` to `TradeParams`, compared with `sender()` at `Match` and on
the hint path. **Soroban has no open form** ([NET-SOR-10](../networks/soroban.md#NET-SOR-10)): `Order.relayer: Address`
is mandatory, because with an open form anyone who sees a pending `settle` can resubmit the two auth entries with
`maker_fill = 1` ⇒ two nonces burnt for a dust fill and the real `settle` fails. Tests: a third party settling on
Cosmos/Soroban/TON fails; a Soroban order without `relayer` cannot be built / is refused. Status **SPECIFIED**.

<a id="min-nonce-cap"></a>
<a id="CTR-DEX-10"></a>**CTR-DEX-10** — **`min_nonce` is capped by the family's nonce width**: `min_nonce < 2^(w−1)` with
`w` = the nonce width (Sui/Aptos `u128`, `w = 128`; Solana `u64`, `w = 64`), as on EVM. Today those three accept
`u128::MAX`/`u64::MAX`, so one mistaken signature locks a maker out of the market forever. Test per family. Status
**SPECIFIED**.

Accepted differences that the adapter, the matcher and clients must know:

| Difference | Family |
|---|---|
| No partial fills (FOK orders only) | Cosmos, TON |
| No `minNonce` (bulk cancel) | Cosmos, Soroban, TON |
| IOC closed at the first match (one maker) | Sui, Aptos, Solana |
| One fee recipient for the whole DEX, not per market | Cosmos (`InstantiateMsg`), Soroban (`Key::FeeRecipient`) |
| One `fee_ppm`, no maker/taker split | Solana |
| Minimum received computed **after** the DEX fee (EVM: `buyAmount` gross) | Cosmos, TON |
| No on-chain self-trade check (the node still skips them) | Cosmos, Soroban |

## Managed markets

<a id="managed-markets"></a>
<a id="CTR-DEX-12"></a>**CTR-DEX-12** — **A managed market is a market on an `OrderBookDex` instance whose `admin` is
the licensed venue operator's multisig** ([CTR-DEX-03](#CTR-DEX-03)): the operator deploys its own instance and lists
only managed pairs; its listing power covers only its venue; the contract is unchanged. On chain the regulated
token's own checks are the arbiter ([asset-suite.md](asset-suite.md#regulated)): a pair that slipped through intake
fails alone (`MatchFailed`). The node side (home-bound orders only, relayer fee `NONE` on regulated legs, eligibility
of both parties at intake, no gossip by default) is [NODE-DEX-11](../node/dex-venue.md#NODE-DEX-11).

- Node configuration per market: `dex_market.managed = 1`, `unbound = 0` (forced), `gossip = 0` (default),
  `eligibility_tokens` (the regulated legs; read from `versionOf(token).kind`). A venue-level registry for pairs of
  two unregulated tokens is PLANNED only (no requester).
- Wallets show managed markets with the venue name, the regulated legs' disclosures and the user's eligibility result
  before signing.
- Securities on such a market are regulated tokens; coupons and dividends are Merkle distributions; redemptions,
  buybacks and splits are exchange offers ([asset-suite.md](asset-suite.md)). The DEX already provides signed limit
  orders, price-time priority off chain, partial fills, IOC/FOK, `filled[orderHash]` and per-market fees capped at 1 %.

## Legacy `MetaTxDex`

<a id="legacy-metatxdex"></a>
<a id="CTR-DEX-07"></a>**CTR-DEX-07** — `MetaTxDex` stays deployed as **legacy** (no gateway route); `OrderBookDex` is
the gateway's DEX. It is an atomic two-leg settlement without allowance, kept for existing integrations:

- Each **order** is a `MetaTransaction` on the token sold, `data = trade(counterToken, minCounterValue,
  counterparty)`, `to = relayer = MetaTxDex`, flag `MODE_RESTRICT_RELAYER`. The signature says "only `MetaTxDex` may
  execute this transfer, and only into itself"; the token enforces that at step 6 (`relayer == to == msg.sender`), so a
  leaked order cannot be executed alone.
- `settle(Leg a, Leg b)` with `Leg = {IERC20MetaTx token; MetaTransaction m; bytes sig}`:
  1. decode both legs' terms; `a.token != b.token`, `a.m.from != b.m.from`;
  2. `termsA.counterToken == b.token`, `b.m.value >= termsA.minCounterValue` (and symmetrically); `counterparty` = 0
     or exactly the other leg's `from`;
  3. a leg with a fee (`feeMode != NONE`) must have `feeRecipient != 0` and `!= this` — otherwise the fee would land in
     the DEX (`ERC20MetaTx` defaults `feeRecipient = msg.sender`) and stick forever;
  4. call `executeMetaTransaction` on **both** tokens; the DEX's measured **balance delta** on each token must equal
     `m.value` exactly (strange or fee-on-transfer tokens are refused);
  5. pay `a.m.value` of token A to `b.m.from` and `b.m.value` of token B to `a.m.from` with `SafeERC20.safeTransfer`;
  6. `emit TradeSettled(a.m.from, b.m.from, a.token, b.token, a.m.value, b.m.value)`.
- Any failing step ⇒ the whole transaction reverts ⇒ no leg executes, no nonce is consumed.
- `ReentrancyGuardTransient`. No owner, no sweep, no upgrade. **Invariant:** the DEX's balance of every token is
  **unchanged across one `settle`** (tokens sent to the DEX directly stay there forever — no sweep on purpose; the
  invariant is stated as a delta, not an absolute value).
- **Fill-or-kill**: `value` is signed exactly, so there are no partial fills. The price surplus (`b.m.value >
  minCounterValue`) belongs to the seller of leg A — it is already inside B's signature.
- Relayer fee: each leg may pay a fee in its own token (`FIXED`/`PERCENT`, cap 1 %) to a `feeRecipient` that an
  outside relayer fills in (unbound) or the signer names.

## Conformance

| Layer | Tests |
|---|---|
| forge | no overfill (unit + fuzz + invariant), both price limits, FOK, fee on/off without dust, `maxFeePpm`, cancel (signature, replay, nonce), batch atomic per pair, ERC-1271 maker, allowance lockdown (approve op: EOA/7702 spender refused, value ≠ 0 refused), DEX ↔ pay independence, the three relayer fee modes + `FeeWouldStick`, EIP-712 KAT → `test/vectors/dex_kat.json` |
| forge (to add with the fixes) | a 1271 maker that burns gas / returns a returndata bomb inside a 3-pair `settle` (the other 2 pairs still settle) and inside a `cancel` batch (the other items still close); a passkey `SubjectAccount` clone under the 400 k cap; replay of DEX A's order/cancel signatures on DEX B (same chain) and on another chain id must fail (today only the positive KAT exists, `OrderBookDex.t.sol:667`); the invariants of `OrderBookDexInvariant.t.sol` extended to several asks/bids, relayer-fee conservation, IOC close, several makers; the fee round-up cases above; a third party settling on Cosmos/Soroban/TON fails; `min_nonce` above the cap refused |
| e2e (anvil 31950–31959, gateway 18650–18659) | approve meta-tx → two orders through the gateway → partial match → settle job → balances; cancel ⇒ settle never runs; venue restart ⇒ book intact |
| managed markets (forge) | one e2e with a regulated equity and an unregulated stablecoin: frozen maker, ineligible taker, relayer fee on the regulated leg, an eligible pair settles |
