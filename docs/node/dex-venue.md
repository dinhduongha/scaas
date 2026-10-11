# DEX venue

The DEX venue is the node's off-chain order book in front of `SCaaSDexV1` until P5, then `SCaaSDex` ([contracts/dex.md](../contracts/dex.md)):
it admits signed orders at the gateway, matches them price-time, and settles each match — one taker against one or
more makers — with `mtxSettle` jobs in `~dex`. The contracts are the arbiter of every fill; the venue only decides
which matches are worth sending. Status: book, matcher, intake, routes and watcher **BUILT** (book persisted in the
legacy client; DEX-domain orders settled pair by pair); token-verified orders and `mtxSettle`
([trade orders](#trade-orders)) **SPECIFIED**; store-backed book **SPECIFIED**; book gossip and managed markets
**SPECIFIED**; non-EVM books **PLANNED**.

**Contents**

1. [Order book](#1-order-book)
   - 1.1 [Markets and sides](#11-markets-and-sides)
2. [Matching](#2-matching)
3. [Token-verified orders](#3-token-verified-orders)
4. [TradeEngine](#4-tradeengine)
5. [Intake](#intake)
6. [Routes](#routes)
7. [Watcher](#7-watcher)
8. [Persistence](#persistence)
9. [Gossip](#gossip)
10. [Managed markets](#managed-markets)
11. [Tests](#tests)

## 1. Order book

<a id="order-book"></a><a id="NODE-DEX-01"></a>**NODE-DEX-01** — **A durable off-chain book, price-time priority,
partial fills.** The venue keeps one book per market, with limit (GTC), IOC and FOK orders and partial fills; the book
survives restarts ([NODE-DEX-14](#NODE-DEX-14)); settlement goes through the node's ordinary job path (claim CAS,
journal before send, replacement, gap-fill — no second send channel). The DEX contract itself is
[CTR-DEX-01](../contracts/dex.md#CTR-DEX-01); what the venue sends it is [NODE-DEX-15](#NODE-DEX-15).

**Single writer**: the node (one process per chain, book under a `tokio::Mutex`). A client never edits `remaining`; it
only mirrors order and trade states from feed items ([persistence](#persistence)).

### 1.1 Markets and sides

<a id="markets"></a>Markets `(base, quote)` are admin configuration (`/v1/admin/dex/markets`), cross-checked with the
on-chain `markets(key)` at load and on every poll.

<a id="NODE-DEX-08"></a>**NODE-DEX-08** — **The on-chain market is re-checked every poll** (≤ 30 s); a mismatch
(listing, fee, recipient) ⇒ the market stops being served (no matching, no intake) until it matches again. Test:
`setMarket` raises the ppm ⇒ the market stops being served within one poll. Status: today checked only at venue start;
the per-poll check is **SPECIFIED**. With token-verified orders the DEX holds no fee rate (the rate is each order's
signed `fee`), so the check covers the listing, each token's recorded kind and the fee split (`relayerSharePpm`,
`treasury`); a split the venue's configuration does not expect (e.g. a relayer share of 0 where the operator priced
one) also stops the market.

A sell order of `base` is an **ask**, price `buyAmount/sellAmount` (quote/base); a sell order of `quote` is a **bid**,
price `sellAmount/buyAmount` (for a `TradeOrder`, `sellAmount` = `amount` and `buyAmount` = `receiveAmount`). Prices are compared by `U256` cross-multiplication (amounts at intake `< 2^128` ⇒ no
overflow). Each side is a `Vec` sorted by (best price, increasing `seq`); `seq` is assigned monotonically at intake,
stored, and kept on reload (time priority survives restarts).

## 2. Matching

<a id="matching"></a>Pure, no I/O. An incoming order `O` walks the opposite side in order; against a resting order `R`
(maker) with `R.rem` left: `x = min(R.rem, floor(O.rem · R.sell / R.buy))`, `y = ceil(x · R.buy / R.sell)`; `x = 0` ⇒
stop; check `limits_ok(R, O, x, y)` **exactly** as the contract does (including FOK); if it fails (ceiling rounding
pushes `y` past O's limit at tiny amounts), never emit a pair the contract would refuse. Resting orders of the same
maker are **skipped** (self-trade prevention; the contract refuses them too).

<a id="NODE-DEX-05"></a>**NODE-DEX-05** — **Rounding dust: skip and remove dust makers.** Who is the dust decides the
next step: `x == R.rem` ⇒ the **maker** is dust ⇒ skip R (`i += 1; continue`) and keep matching deeper orders; `x <
R.rem` ⇒ the **taker** is dust ⇒ stop, O's remainder rests. A maker with `R.rem · R.buy < R.sell` (cannot buy one unit at
its own price) is **removed from the book** (state `filled`, note `dust`; on chain the remainder is worthless). Test: a
dust ask at the head + a deeper ask ⇒ an incoming bid matches the deeper ask; the dust is removed at first touch.

- **GTC limit:** the remainder rests in the book.
- **IOC:** match what can be matched, cancel the rest (never rests). On EVM the contract closes the IOC remainder at the
  end of the `settle` tx, also across several makers; a short `expiry` (≤ 60 s) is the second layer.
- **FOK:** checked **on chain**: a FOK order settles only in **one** pair that fills its whole `sellAmount`. The book
  matches FOK only against a single resting order (the first by price-time) that can fill it entirely; otherwise the
  whole order is cancelled. No aggregation of several counterparts for FOK: "all or nothing" across several pairs of a
  pair-atomic batch is not provable on chain. Partial fill is the default for every other kind. Target: a FOK order is
  a `TradeOrder` with `minFill = amount`, and one settlement (one taker, several makers) is atomic, so FOK **may**
  aggregate several makers inside that settlement ([NODE-DEX-15](#NODE-DEX-15)).
- Resting orders are never FOK/IOC (they do not rest).

<a id="NODE-DEX-09"></a>**NODE-DEX-09** — **IOC matches a single maker on Move and Solana.** Sui, Aptos and Solana close
an IOC at its **first** fill, so the matcher has a per-family flag `ioc_single_maker` (on for Sui/Aptos/Solana) that
treats IOC like FOK's single counterpart. Required before non-EVM books are served. Cargo test.

<a id="NODE-DEX-07"></a>**NODE-DEX-07** — **The committed balance includes unsettled fills.** At intake, Σ
`remaining` (+ the relayer fee in `sellToken`) of every open order of the same (maker, sellToken) **plus the new
order**, **plus fills already matched whose trade is not yet `settled`/`failed`** (funds not yet moved but `remaining`
already reduced) must be `<= fundable`; cleared when the trade completes. Otherwise a balance of 100 could place 50
orders of 100. Test: balance 100, ask #1 100 matched and pending ⇒ ask #2 100 refused. (Today `Book::committed`
counts only resting orders, `dex.rs:449-462`.)

The venue computes no DEX fee: the matcher only compares the signed `maxFeePpm` with the market fee; the DEX fee is
taken from the transferred amount (so `fundable` is unchanged) and rounds up per fill on chain
([CTR-DEX-11](../contracts/dex.md#CTR-DEX-11)). This is the built behaviour; with token-verified orders the fee is the
order's signed `fee` rate, charged once per order per settlement on what it receives, and the venue applies its
per-role rates at intake ([NODE-DEX-15](#NODE-DEX-15)).

## 3. Token-verified orders

<a id="trade-orders"></a><a id="NODE-DEX-15"></a>**NODE-DEX-15** — **The venue settles role-free `TradeOrder`s with
`mtxSettle`, one taker against one or more makers, and arranges the roles itself.** Status: **SPECIFIED**. The
contract side — the struct, the token's checks, the DEX's payout and conservation — is
[contracts/dex.md](../contracts/dex.md) and [contracts/metatx.md](../contracts/metatx.md); this rule is what the venue
does with it.

- **Two order forms, chosen by the DEX's listing.** When the sell token is a SCaaS token the order is a `TradeOrder`
  (`from`, `receiveToken`, `amount`, `receiveAmount`, `minFill`, `fee`, `relayer`, `dex`, `destination`, `flags`,
  `batch`, `nonce`, `validUntil`) signed in the **sell token's** EIP-712 domain (`salt = chain_uid`); the token verifies
  it and moves funds only into `dex`, with no allowance. When the sell token is an outside token the same struct is
  signed in the DEX's domain as a `DexOrder` (`dex` = the DEX, `ESCROW` refused) and pulled under the holder's
  allowance to the DEX's `DexPuller` ([CTR-DEX-22](../contracts/dex.md#CTR-DEX-22)); intake reads `allowance(from, puller)`. The venue takes each token's kind from the DEX's own market listing (re-checked every poll,
  [NODE-DEX-08](#NODE-DEX-08)), never from the order or the client.
- **No role in the order.** The book keeps price-time priority over orders as they arrive; an incoming order that
  crosses is the **taker** of the settlement the venue builds, the resting orders it crosses are its **makers**, and an
  order that rests may later be a maker. One settlement is atomic; one `mtxSettle` call carries one or more
  settlements, each tried on its own. The venue binds a settlement to its own lane: `relayer` of every leg is 0 or that
  lane (home-bound markets require the lane, [intake](#intake)).
- **Effective minimum fill.** In a settlement every order — taker and each maker — fills at least `m = max(minFill,
  ceil(amount / 2))` of its sold amount and receives at least half of its `receiveAmount` pro rata, unless the fill
  closes the order's remainder. The matcher therefore adds a maker only with a fill ≥ that maker's `m` (or its whole
  remainder), and emits a settlement only when the taker's total reaches the taker's `m`; otherwise an IOC taker is
  cancelled and a GTC taker rests. A resting order fills in at most two settlements. The dust rule
  ([NODE-DEX-05](#NODE-DEX-05)) still applies to remainders.
- **IOC, FOK, escrow.** `IOC` (flag 1): the token closes the order at its single pull, so nothing of it rests. FOK:
  `minFill = amount`. `ESCROW` (flag 2, implies IOC): the whole `amount` is pulled into the DEX and the unmatched part
  refunded in the same call; the DEX, not the token, enforces price, minimum and fee on it.
- **Fees.** An order signs one `fee` (ppm, ≤ 1 %): the DEX fee rate it accepts on what it receives, whatever role it
  plays. The DEX charges `ceil(receiveFill · fee / 10⁶)` once per order per settlement and pays it out in the same call
  per its admin's split — the relayer share to the lane that submitted, the rest to the treasury
  ([CTR-DEX-03](../contracts/dex.md#CTR-DEX-03), [CTR-DEX-11](../contracts/dex.md#CTR-DEX-11)). Maker and taker
  pricing is venue policy: per market `maker_fee_ppm` and `taker_fee_ppm`; an order whose signed `fee` is below the
  rate of the role it would play is not matched in that role (an incoming order below the taker rate that would cross
  is refused at intake, `FEE_TOO_LOW`; a resting order below the maker rate is never selected as a maker). There is no
  separate relayer fee: the lane's income is its share. On managed markets each split recipient must be eligible for
  the regulated legs ([NODE-DEX-11](#NODE-DEX-11)).
- **Fill state and cancels.** A `TradeOrder`'s fill state (`pulled[orderHash]`) and its cancels live on the sell
  token: `mtxCancelOrder` per order, `mtxInvalidateNonces` per order lane (`batch` of the order, which is not the
  meta-transaction lane of the same name); a `DexOrder`'s on the DEX (`mtxCancelOrders`, `mtxInvalidateNonces`).
  Cancels never expire. The venue removes a cancelled order from the book at once and submits the on-chain cancel on
  the right contract ([routes](#routes)); the watcher closes it on the mined event.
- **Committed balance.** [NODE-DEX-07](#NODE-DEX-07) counts `amount − pulled` of every open order of the same
  `(from, sell token)` plus unsettled fills; the fee is on the received side, so it adds nothing there.
- **Simulation and attribution.** Before the job is written the venue simulates the whole `mtxSettle` from its lane;
  token and DEX errors carry the `orderHash` (`BelowMinFill`, `PriceLimit`, `FeeAboveSigned`, `OrderClosed`,
  `NonceInvalidated`, `WrongRelayer`, …), so the order at fault is known ([NODE-DEX-02](#NODE-DEX-02)); a failing
  settlement in a multi-settlement call fails alone.

Why: the token verifies the signer's own limits against the fill figures, so a maker needs no allowance and an EOA
never grants one ([CTR-TOK-01](../contracts/token-wrappers.md#CTR-TOK-01)); orders without roles let the same signed
order rest and later take. Cost: two transfers per leg (into the DEX, out to the destination), and partial fills
below half an order are impossible.

Transitional (BUILT): the venue matches DEX-domain orders (`maker`/`taker` fields, `sellAmount`/`buyAmount`,
`maxFeePpm`, a separate relayer fee in `feeToken`) funded by an allowance to the DEX, and settles them pair by pair
with `settle(Match[])`; the legacy `MetaTxDex` is not served. Both go when the token-verified DEX is deployed.

<a id="NODE-DEX-16"></a>**NODE-DEX-16** — **The venue serves only DEXes on the chain profile's DEX list.** Status:
**SPECIFIED**. An order whose `dex` is not on the chain's DEX list ([NET-ALL-24](../networks/README.md#NET-ALL-24)) is
refused at intake (`422 DEX_NOT_LISTED`), whatever the market (a listed DEX is `isDex` and of a non-deprecated version, [CTR-DEX-24](../contracts/dex.md#CTR-DEX-24)); an order for a listed DEX that this venue does not run
is answered with that DEX's home ([gossip](#gossip)) or refused. The node never builds, simulates or submits
`mtxSettle` for an unlisted DEX, never relays an `mtxWrap` whose wrapper is not a registered wrapper of that
underlying, never routes or replicates a gossiped order naming an unlisted `dex` (validation V4, Ignore), and never
lists one in depth or homes. A cancel (`mtxCancelOrder`, `mtxInvalidateNonces`) is relayed whatever the `dex`, since it
only protects the signer. Why: the token requires only that `dex` is a contract, so a contract written to look like a
DEX can report any fill and take the signed `amount`; the owner accepted that residual risk (2026-10-08) and placed
the defence off chain — clients refuse to sign for an unlisted `dex` ([CLI-SGN-35](../clients/signers-clientkeys.md#CLI-SGN-35))
and the node never carries such an order. Cost: a new DEX needs a chain-profile entry before the venue serves it.

## 4. TradeEngine

<a id="trade-engine"></a><a id="NODE-DEX-17"></a>**NODE-DEX-17** — **The TradeEngine executes orders against AMMs through
`mtxExchange`/`mtxExchangeVia`** ([CTR-DEX-20](../contracts/dex.md#CTR-DEX-20)); off unless the chain enables it. Status:
**SPECIFIED**. Intake: an order on a listed market enters the book; one whose pair is no listed market, or whose
`receiveToken` is its sell token (a cycle), is **exchange-only** — never in the book, both tokens known to the DEX, else
`TOKEN_NOT_SERVED`. Each tick (every block or `trade_engine.tick`): (1) book matching first (`mtxSettle`: internal
liquidity pays no pool fee); (2) coincidences of wants among exchange-only orders, then AMM routes for the rest — quotes
by `eth_call` to the configured quoters, at most `trade_engine.max_hops` (3) hops, cycles for X→X orders; (3) a resting
book order is also filled through AMMs when a route reaches its limit (per market `amm_fill`, default on with the
engine); (4) floor `receiveFill` = quote × (1 − `trade_engine.buffer`), never below the signed limit (the buffer costs the
signer nothing: the surplus comes back, [CTR-DEX-21](../contracts/dex.md#CTR-DEX-21)); (5) path (a) when routers suffice,
(b) through the node's own listed executor for callbacks and flash swaps; (6) simulate the whole call, submit it as a
`call` job, watch the final event. Fees by role: an exchange-only order pays `taker_fee_ppm` (below ⇒ `FEE_TOO_LOW`), a
resting order filled through an AMM `maker_fee_ppm`. MEV: on a public chain submit through a private relay where one
exists (a sandwich takes only surplus, never below the signed limit); chain 7622 has no public mempool. Config per
chain: `trade_engine.enabled` (default `false`), `trade_engine.amm` (`{kind: univ2|univ3, factory, quoter, router}`),
`max_hops`, `executor`, `tick`, `buffer`. EVM only.

<a id="NODE-DEX-18"></a>**NODE-DEX-18** — **The node keeps no surplus: its income is the relayer share of the signed fee**
(owner). Every swap the engine builds sends its output to the DEX, so the contract pays all of it to the signers;
`GET /v1/dex/exchanges/{ref}` returns the quote at decision time beside the settled `ExchangeLegSettled` figures. With
`relayer = 0` another submitter may exchange the order; the signed limit still holds and only output it routes outside
the DEX depends on its honesty — clients therefore keep `relayer` = the venue node.

## <a id="intake"></a>5. Intake

Spam controls at the door: body ≤ 64 KiB; amounts `0 < amount < 2^128`; `expiry ∈ (now + 5 s, now + 30 days]`; a
per-market minimum (`min_base_amount`: an ask compares `sellAmount`, a bid compares `buyAmount`); at most
`MAX_OPEN_PER_MAKER = 50` open orders per maker per chain; a whole-book cap `MAX_RESTING = 10 000`; a duplicate hash ⇒
refused; `checkOrder` must answer `OK`; the committed-balance rule above.

- **Relayer binding**: by default (home-bound markets) an order must name this node's relayer; `relayer = 0` is refused
  at the door — an open order anyone can settle lets a mempool watcher insert its own pair at the worst price within
  the user's limit (MEV), and another relayer can settle an IOC remainder or an order cancelled off-chain. The contract
  still allows `relayer = 0` (open relayers); markets that opt in (`unbound = 1`) accept relayer-unbound resting GTC
  orders, whose makers accept that exposure ([gossip](#gossip)).
- **DEX listing**: `dex` must be on the chain's DEX list and run by this venue for the market
  ([NODE-DEX-16](#NODE-DEX-16)); a signed `fee` below the venue's rate for the order's role ⇒ `FEE_TOO_LOW`
  ([NODE-DEX-15](#NODE-DEX-15)).
- **On-chain cancel** (costs relayer gas): only for orders in the book; batched into **one** `cancel(...)` per poll
  (≤ 50 orders; target: one `mtxCancelOrders` call on the DEX, or a job per sell token for `mtxCancelOrder`); at most 20 on-chain cancels per maker per hour — beyond the cap the order is still removed from the
  book at once (this relayer is the only one that can settle it) but no gas is spent. Cancel-all only when the maker
  still has ≥ 1 open order.

<a id="fault-attribution"></a><a id="NODE-DEX-02"></a>**NODE-DEX-02** — **Failed matches are attributed by evidence,
and (as built) the relayer fee token is limited.** Target: an `mtxSettle` that fails in simulation is attributed from
the `orderHash` in the token's or the DEX's error ([NODE-DEX-15](#NODE-DEX-15)); an outside token's
`SafeERC20FailedOperation(token)` is attributed to the order that sells that token; the restore and removal rules below
are unchanged; with no separate relayer fee there is no fee token to limit. Transitional (BUILT): intake requires `feeToken ∈ {0, sellToken, buyToken}` (the two tokens of the
listed market); otherwise refused at the door (a fake fee token with `balanceOf`/`allowance` = 2^255 whose
`transferFrom` always reverts would pass `checkOrder` with a huge `feeFundable` and block every taker crossing it). A pair that fails in
simulation is attributed from the revert reason of `eth_call settleOne(m, relayer)` with `from = DEX`, never guessed: a
DEX error carries an `orderHash`; a token error (`SafeERC20FailedOperation(token)`) is attributed to the side that pays
that token in the pair (M pays X, T pays Y, each pays its own fee token). Only a reason that points at the new order
answers `400`; one that points at the maker ⇒ the maker is dropped (`invalid`) and matching retries (≤ 3 rounds). A
maker that fails in 2 pairs with 2 different takers is removed. Recovery after a failed settle (`sync_once`) uses the same
attribution: only the side at fault is not restored.

<a id="oog-pairs"></a><a id="NODE-DEX-06"></a>**NODE-DEX-06** — **ERC-1271 orders whose check ran out of gas are never
restored.** The contract caps an ERC-1271 signature check ([CTR-DEX-08](../contracts/dex.md#CTR-DEX-08)); a pair whose
reason is out-of-gas in that check ⇒ that ERC-1271 order is not restored to the book. (The contract's `_validSig`
branch uses a `staticcall` with cap `_erc1271Gas(signer)`: 400k when `signer.codehash` is the `SmartKeyAccount` clone
code hash, else 50k; at most 32 bytes of return data.)

## <a id="routes"></a>6. Routes

<a id="routes"></a>On the gateway listener (gateway auth applies, [gateway.md](gateway.md)); `dex_routes()` returns its
own `Router` merged into the gateway router, so the auth layer wraps it without knowing the DEX routes.

| Route | Does |
|---|---|
| `POST /v1/dex/orders` `{chain, order, signature}` | place ⇒ `{hash, status: resting/partial/filled/cancelled, fills[]}`; target: `order` is a `TradeOrder` (SCaaS sell token) or a `DexOrder` `{sellToken, order}` (outside sell token), per the DEX's listing |
| `POST /v1/dex/cancel` `{chain, orderHash, validUntil, signature}` | `CancelOrder` signature ⇒ removed from the book **at once** + on-chain `cancel` job (target: `CancelOrder` in the sell token's domain ⇒ `mtxCancelOrder` job on that token; a `DexOrder` ⇒ DEX `mtxCancelOrders`) |
| `POST /v1/dex/cancel-all` `{chain, maker, minNonce, validUntil, signature}` | `InvalidateNonces` ⇒ every order with `nonce < minNonce` removed + on-chain job (target: `{chain, token, from, batch, minNonce, signature}`, per sell token and order lane ⇒ `mtxInvalidateNonces`) |
| `GET /v1/dex/markets?chain` | markets + fees |
| `GET /v1/dex/depth?chain&market&levels` | aggregated price levels of both sides (levels ≤ 200); prices are decimal strings scaled by both tokens' `decimals`, never a raw integer division |
| `GET /v1/dex/trades?chain&market` | recent fills (ring of 200 in memory; history from the feed) |
| `GET /v1/dex/ticker?chain&market` | last price, best bid/ask, volume in the ring |
| `GET /v1/dex/orders?chain&maker` | open orders of one wallet |
| `GET /v1/dex/exchanges/{ref}` | an exchange plan's quote at decision time and its settled `ExchangeLegSettled` figures ([NODE-DEX-18](#NODE-DEX-18)); SPECIFIED |
| `GET /v1/dex/depth?…&scope=network`, `GET /v1/dex/homes?chain&market` | network depth and DEX homes ([gossip](#gossip)) |

<a id="NODE-DEX-03"></a>**NODE-DEX-03** — **No WebSocket; clients poll** `depth`/`trades`. A WebSocket server would add
a dependency for no need at the volumes served.

## 7. Watcher

<a id="watcher"></a><a id="NODE-DEX-04"></a>**NODE-DEX-04** — **The DEX watcher has its own cursor.** One task per
chain with the same finality helpers as the indexer (`finality::{safe_head, next_range, quorum_ok}`) and a **separate
cursor** (`dex_cursor`) reads the DEX contract's logs (`OrderFilled`, `Matched`, `MatchFailed`, `OrderCancelled`,
`NoncesInvalidated`; target: the DEX's `LegSettled`, `ExchangeLegSettled` and the listed tokens' `TradeFilled`, `OrderCancelled`,
`NoncesInvalidated`, [indexer-feeds.md#event-normalization](indexer-feeds.md#event-normalization)), writes `dex_range` feed items and advances `dex_cursor`, then removes from the book every order
closed on chain (cancelled through any relayer, too). `settled` is final: a later `MatchFailed` does not flip it. A
separate cursor means a DEX ingest fault never blocks payment booking and vice versa.

## <a id="persistence"></a>8. Persistence

<a id="persistence"></a><a id="book-store"></a><a id="NODE-DEX-14"></a>**NODE-DEX-14** — **The DEX book lives in the
node store** (`dex_market`, `dex_order`, `dex_trade`); markets are admin config; settle/cancel/invalidate are `job`
rows in `~dex`; client order/trade records are seq-guarded mirrors fed by `dex_*` feed items, kept for accounting
([INT-ERP-12](../integration.md#INT-ERP-12)). The venue is the book's only writer; persisting it next to its settle jobs
makes "matched but no job" impossible locally. A DEX chain cuts over with its markets paused
([runbooks.md#cutover](runbooks.md#cutover)).

```sql
CREATE TABLE dex_market (id INTEGER PRIMARY KEY, chain_key TEXT NOT NULL, namespace TEXT NOT NULL,
  base TEXT NOT NULL, quote TEXT NOT NULL, fee_ppm INTEGER NOT NULL, fee_recipient TEXT,
  state TEXT NOT NULL CHECK (state IN ('active', 'paused')), body TEXT NOT NULL,   -- MarketCfg (dex.rs:187)
  gossip INTEGER NOT NULL DEFAULT 0, unbound INTEGER NOT NULL DEFAULT 0,          -- book gossip
  managed INTEGER NOT NULL DEFAULT 0);                                            -- managed markets
CREATE TABLE dex_order (order_hash BLOB PRIMARY KEY, market_id INTEGER NOT NULL, seq BIGINT NOT NULL,
  state TEXT NOT NULL, remaining TEXT NOT NULL, row TEXT NOT NULL);              -- Row (dex.rs:229)
CREATE TABLE dex_trade (tag BLOB PRIMARY KEY, market_id INTEGER NOT NULL, maker BLOB NOT NULL, taker BLOB NOT NULL,
  maker_fill TEXT NOT NULL, taker_fill TEXT NOT NULL, job_uid BIGINT,
  state TEXT NOT NULL CHECK (state IN ('pending', 'settled', 'failed')), restored INTEGER NOT NULL DEFAULT 0);
CREATE TABLE dex_cursor (chain_key TEXT PRIMARY KEY, indexed_block BIGINT NOT NULL);           -- NODE-DEX-04
```

(`remaining`/fills are uint256 decimal text; they are never aggregated or ordered by the store.)

Transitional (BUILT): the book lives in the client database. At start `dex_book_load(chain)` loads every
`open/partial` order (signature, `remaining`, `seq`) and rebuilds price-time order; an order is matched on a **copy**
of the book, `settle` simulated, then `dex_book_commit` (orders + trade + job) runs; only on success is the in-memory
book replaced. A failed commit (a timeout included: the client may have committed) reloads the whole book and answers
`503`; `trade_ref` UNIQUE blocks double writes. A failed trade (job `dead/reverted`, or a final `MatchFailed`) is set
`failed` by the client and the node's `dex_sync` loop restores eligible orders (IOC/FOK never). The book-location
choice (<!-- example:odoo -->first phrased "Odoo hay SQLite"<!-- /example -->) was first recorded in the DEX design note `2026-10-03-dex-design.md`; the target is the node store.

Lifecycle in the venue:

1. **Start:** `Venue::start` loads markets from the config snapshot and the book from `dex_order` (every `open/partial`
   order with its signature, `remaining` and `seq`) ⇒ rebuilds price-time order (`seq` is the time); the on-chain market
   cross-check stays.
2. **Place:** door checks ([intake](#intake)) ⇒ match on a **copy** of the book ⇒ simulate `settle` ⇒ a pair that
   fails in simulation: `checkOrder` both sides, the faulty order is dropped (persisted `invalid`), retry (≤ 3 rounds)
   ⇒ **one transaction** (orders upsert + trades + settle `job` INSERT in `~dex` with origin key `keccak(calldata)` +
   `feed_item(dex_order/dex_trade)` in the market's namespace) ⇒ only then replace the in-memory book. A trade tag is
   unique, so a trade is never recorded twice.
3. **Failed trade** (settle job `dead`/`reverted`, or a final `MatchFailed`): the venue marks the trades `failed` and
   restores fills in the same transaction. IOC/FOK orders are **never** restored (they do not rest); a regular order
   still valid on chain (`checkOrder`) gets its `fill` back and **goes through the matcher again** with its old `seq`
   (time priority kept) — not inserted directly: if both sides are healthy (the job died for a relayer reason), a direct
   insert would leave a crossed book; through the matcher they match again into a **new** trade (tag salted per
   process + counter, never a replay of the old tag), simulated and committed. Otherwise the order is dropped. Orders
   cancelled on chain (also through another relayer) arrive as final `OrderCancelled/NoncesInvalidated` and are
   removed from the book.
4. **Final:** the watcher sees `OrderFilled/Matched/MatchFailed` in a final range ⇒ trade `settled` ⇒ booked by the
   client.

<a id="NODE-DEX-10"></a>**NODE-DEX-10** — **A late settled trade debits a restored order.** If a trade marked
`failed` and restored later turns out `settled` (a late `Matched` after recovery), the venue subtracts that amount from
the restored order's `remaining` on the next pass (a `dex_trade` item settled late ⇒ `remaining` reduced). Test: a late
`Matched` after recovery ⇒ no phantom liquidity left in the book.

Transitional (BUILT): the book is persisted in the legacy client over the pull protocol (`dex_markets`,
`dex_book_load`, `dex_book_commit` with a full reload on commit failure or timeout, `dex_sync` for failed trades,
`dex_fill_ingest` with the indexer key, `dex_cursor`); on cutover the transitional node imports open orders once
through the legacy `dex_book_load`, then resumes markets in the node.

## <a id="gossip"></a>9. Gossip

<a id="gossip"></a><a id="NODE-DEX-12"></a>**NODE-DEX-12** — **DEX book gossip, two order modes per market.**
**Home-bound** (default; `dex.rs` l.552–554): an order bound to relayer `r` is matched and settled **only by the home** that proved `r` in
its announce ([gossip.md#announce](gossip.md#announce)); `SCaaSDexV1._accept` (`relayer ∈ {0, sender}`, l.263) makes this
**hard**, and with `filled + fill ≤ sellAmount` (l.267) and each pair in `try settleOne` (`MatchFailed`) **no fill can be
settled twice in either mode**; the rules below only keep honest nodes from wasting gas and showing phantom fills. Other nodes keep read-only replicas — a home register (highest `home_seq` wins) joined with chain facts
(`filled = max`, `closed = or`) — and replicate/advertise only **DEX-trusted homes**. **Relayer-unbound**
(`dex_market.unbound = 1`, maker opts in per order with `relayer = 0`): resting GTC orders only; one deterministic
**claimant** may match during `claim_ms`, then any node matches its own (bound) takers against it; cancel is final only
when mined. In both modes `filled[orderHash]` (no overfill, pair-isolated `MatchFailed`) is the arbiter. Topics per
market. Bound liquidity is fragmented per home; unbound makers accept execution by **anyone** (not only nodes) within
their limit, and an off-chain cancel does not bind until mined.

Roles:

- **Home** of a home-bound order = the node that alone proved the order's `relayer` in its live announce. Only the home
  holds it in its venue (`dex_order`) and matches/settles it. Our venue accepts bound orders only for our relayer.
- **DEX-trusted homes** ([NODE-DEX-13](#NODE-DEX-13)): admin pre-trusted (`gossip_trusted.dex = 1`) or automatically
  trusted, and not blocked (`dex = -1`) or demoted. Untrusted homes are replicated only within their small caps (beyond
  them `UNTRUSTED_HOME`: forwarded, not stored) so their settles can be credited, and are never shown to wallets by
  default: a taker who signs an order bound to an untrusted home gives that home a free option until expiry.
- **Claimant** of an unbound order (`relayer = 0`, market `unbound = 1`) = the node that won the deterministic claim;
  every node may later match it.
- **Replica** = `dex_replica` rows ([store.md#gossip-tables](store.md#gossip-tables)) for orders we do not hold as
  home. Bound replicas are read-only; unbound replicas that passed our `checkOrder` are matchable in our venue.
- RPC-less nodes keep no replica: they forward dex traffic only (replicas need chain events).

Messages (`scaas-dex/1`, wire format in [gossip.md#wire](gossip.md#wire)):

| `type` | From | Effect at the home / claimant | Effect elsewhere |
|---|---|---|---|
| `route_order` | anyone: a gateway that received a **bound** order for another home | intake exactly as `POST /v1/dex/orders` (`checkOrder`, per-maker caps, cumulative commitment) | forward only |
| `route_cancel`, `route_invalidate` | anyone | bound: as `POST /v1/dex/cancel` / `cancel-all` (remove now, on-chain job). Unbound: stop matching it now, submit the on-chain cancel | bound: replica `closed` only after the home's `book` or the chain event. Unbound: stop matching it now (honest nodes); `closed` only when `OrderCancelled`/`NoncesInvalidated` is mined |
| `book` | home / claimant only, on every change: rest, partial fill, close (fill, cancel, expiry, IOC rest) | — | replica merge |
| `head` | home / claimant, every 30 s per market | — | compare `max_home_seq` then `digest` ⇒ `/scaas/sync/1` `book` when different |

`digest = SHA-256(concat over open orders sorted by order_hash of order_hash ‖ home_filled(32) ‖ u8(home_closed))`,
computed over the **home register only** (no chain facts, no wall clock), so a replica that has every update
reproduces it exactly. Immediately-filled taker orders are not published as `book` (only resting state is book state).
Publish-side rule: the gateway never publishes `route_*` for `sig_kind = erc1271` (receivers cannot verify it without
RPC); it answers the wallet with the home's gateway URL instead.

Merge and convergence:

```
on book(upd)  if upd.home_seq > rep.home_seq:            # home register: highest home_seq wins
                  rep.home_seq, rep.home_filled, rep.home_closed = upd.home_seq, upd.filled_total, upd.state == closed
on chain(ev)  rep.chain_filled = max(rep.chain_filled, ev.filledTotal)       # OrderFilled (DEX watcher)
              rep.chain_closed = rep.chain_closed or ev is OrderCancelled / NoncesInvalidated covering it
view          filled_total = max(rep.chain_filled, rep.home_filled)
              closed       = rep.chain_closed or rep.home_closed or now > expiry
```

The home register is last-writer-wins on a total order (`home_seq`, assigned by the single home); the chain part is
`max`/`or`. Both are commutative, associative and idempotent, so any two replicas that have seen the same set of
updates hold the same state whatever the delivery order; `head`/sync supplies missing updates. For **bound** orders the
home publishes a `book` for a fill when the settle job is `signed` (optimistic), and once more when it is `mined`; if
the settle fails (`dead`/`reverted`, restore) it publishes `state = resting` with the restored `filled_total` at a
higher `home_seq`. For **unbound** orders fills are published **only at `mined`** (several nodes may race; nobody shows
a phantom fill). A chain `closed` is final. `home_seq` is restart-safe: `home_seq = max(stored + 1, unix_ms)` (as the
announce `version`), so a restored store never goes backwards.

Validation (dex topic):

- V0 (8 KiB), V1 (canonical bytes), V2 (topic = chain/dex/market; the order's `base`/`quote` match the topic pair).
- V3: `book` with `home_seq ≤ stored` ⇒ Ignore; `route_*` whose `order_hash` is already in our venue or replica ⇒
  Ignore.
- V4 deterministic ⇒ Reject: maker EIP-712 recover for `sig_kind = eoa` (low-s); `pubkey ↔ home` and the Ed25519
  signature over `dexbook_msg`/`dexhead_msg`; `claim_until ≠ 0` on a bound order or `= 0` on an unbound one.
- V4 state-dependent ⇒ Ignore: `home` is not the sole prover of `order.relayer` (`NOT_HOME`); home not DEX-trusted
  (`UNTRUSTED_HOME`, forwarded, not stored); unbound order in a market that is not `unbound` for us; unbound claimant
  that loses the claim (`NOT_CLAIMANT`, forwarded, not stored); `erc1271` order outside a home/claimant `book`; an
  order whose `dex` is not on our chain profile's DEX list (`DEX_NOT_LISTED`, neither stored nor forwarded,
  [NODE-DEX-16](#NODE-DEX-16)).
- V6: per-maker 5/s; per home ≤ 10 000 replica orders, ≤ 50 open per (home, maker) (`MAX_OPEN_PER_MAKER`); per
  claimant ≤ 1 000 unbound orders.
- V7: market unknown to us ⇒ forward, do not store.

Matching, settling, routing (home-bound):

- Only the home matches and settles (settle `job` in `~dex`).
- Gateway `GET /v1/dex/depth?…&scope=network` aggregates our book and **DEX-trusted** replicas per home (levels tagged
  with `home`, `trusted` and the home's gateway URL from the announce); `GET /v1/dex/homes?chain&market` lists trusted
  homes with their relayer addresses. `&include_untrusted=1` adds untrusted homes, tagged `trusted: false` with their
  credit progress. A wallet that wants a replica's liquidity signs a taker order with `relayer =` that home's relayer
  and posts it to that home's gateway directly (preferred: not visible on gossip before matching) or to any gateway,
  which publishes `route_order`.
- **Routed expiries** (taker order bound to another home): trusted home — default and max 300 s; untrusted home —
  default 60 s, max 120 s (**arbitrary**); the gateway refuses longer ones. Wallet requirement: before signing for an
  untrusted home, show a blocking warning "this venue is not yet trusted; it holds a free option on your order until it
  expires (≤ 2 min)".
- A firm quote exists only at the home; replica depth is indicative (lag ≤ gossip latency, ≤ 30 s after a missed
  update via `head`).

Relayer-unbound orders (market option `unbound = 1`; requires `gossip = 1` and a public chain):

1. **What may be unbound.** Only resting GTC maker orders. Unbound IOC/FOK orders are refused at intake (they are
   takers: bound to the matching node) and are never gossiped. A maker chooses per order (`relayer = 0`) and only where
   the market allows it.
2. **Intake** at any node: the intake checks incl. `checkOrder` (RPC). The node then publishes a `book` with
   `claim_until = published_at + claim_ms` (default 10 s, arbitrary) and becomes a **candidate claimant**.
3. **Deterministic claim.** Several nodes may receive the same order (the wallet posted it twice). Every node keeps, per
   `order_hash`, the candidate with the **lowest** `claim_rank = SHA-256(order_hash ‖ peer_id)` among valid `book`s
   seen within `claim_grace = 2 s` (≥ gossip p99) of its own `first_seen_ms`. No node matches an unbound order before
   `first_seen_ms + claim_grace`. Each node independently computes the same winner from the same set of candidates; a
   candidate arriving after the grace is ignored.
4. **Claim window.** Until `claim_until`, only the claimant matches the order (honest nodes). After it, any node with
   the order in its replica and `checked_ok = 1` (its own `checkOrder`, within budget) loads it into its venue and
   matches its **own bound** takers against it; settle simulation (`eth_call settle`) must succeed before sending. Two
   nodes that match the same maker in one block: the second pair fails `Overfill`/`MatchFailed` on chain, the loser
   restores its taker; a batch with no surviving pair reverts `NothingSettled`, which the simulation usually catches.
5. **Cancel is on-chain only.** An unbound order is `closed` only when `OrderCancelled` (or `NoncesInvalidated`) is
   mined. On a maker-signed cancel every honest node stops matching at once and the receiving node submits the
   on-chain `cancel` at once; the per-maker 20/h cap does not apply to unbound orders (bounded by
   `MAX_OPEN_PER_MAKER`). The API and wallet say "cancel final when mined".
6. **What makers accept** (stated in the wallet before signing `relayer = 0`): `settle` is permissionless, so
   **anyone** — not only nodes — may settle the order at any price within its limit until it is cancelled on chain or
   expires; with `feeRecipient = 0` the relayer fee goes to whoever settles (target: whoever submits `mtxSettle` earns
   the relayer share of every fee in that settlement). The claim window binds only honest nodes.
7. Fees, `maxFeePpm` (target: the signed `fee`), partial fills and price checks are the contract's, unchanged.

<a id="home-trust"></a><a id="NODE-DEX-13"></a>**NODE-DEX-13** — **DEX homes become trusted automatically** after
`dex_trust_min_settles = 20` **credited settles** in a `dex_trust_window = 14 d` involving ≥
`dex_trust_min_counterparties = 5` distinct maker/taker addresses (all three **arbitrary**); admins may pre-trust or
block (block wins). Credit comes only from chain facts the home cannot fabricate for free. A determined farmer with 5
funded EOAs and 20 cheap settles in 14 days gains trust; bounded by demotion and short routed expiries. `# ponytail:
counterparty-count heuristic; add funding-graph analysis if farming shows up.`

Inputs come from our DEX watcher (`Matched`, `OrderFilled`, `MatchFailed`) plus one `eth_getTransactionByHash` per
settle tx of a candidate home (within the `checkOrder`-class RPC budget).

- **Credited settle** (one row per settled pair `ref` in `dex_home_credit`), all of: (1) the settle tx's `from` (=
  `msg.sender`) is a relayer address that **only** this home proves (a shared lane credits nobody); (2) the maker order
  of the pair appeared in a valid home-signed `book` we received ≥ 60 s before the settle block (liquidity was visible
  to the network before it was hit); (3) neither maker nor taker is one of the home's proved lane/relayer addresses,
  and maker ≠ taker (the contract already refuses `M.maker == T.maker`); (4) the pair settled (not `MatchFailed`) and
  the block is final.
- **Trusted** when, inside the window: credited settles ≥ 20 **and** distinct counterparty addresses (makers ∪ takers
  of credited pairs) ≥ 5. Re-evaluated hourly and on each credit; trust lapses when the window no longer satisfies the
  rule (no permanent trust from history alone).
- **Demotion** (30 d, counters cleared, `dex_home_state.demoted_until`, metric + audit), on proof only: (1) a
  home-signed `book` contradicted by the chain at finality — `home_closed = 0` for an order the chain shows closed, or
  `home_filled` below the chain's final `filledTotal` — and not corrected by a higher `home_seq` within 120 s; (2) ≥ 3
  `MatchFailed` in 24 h on settle txs sent by the home's relayer whose reason is a limit violation (price, overfill,
  FOK, expiry, nonce, `maxFeePpm`): matching outside order limits; (3) two valid home-signed `book`s with the same
  `home_seq` and different content (equivocation). An admin block (`dex = -1`) overrides everything; an admin
  pre-trust (`dex = 1`) skips the counters but not demotion by proof.
- Not provable, and therefore bounded rather than detected: a home that sits on a crossing routed taker (free option).
  Short routed expiries bound it.

Gossip of the book is built after the store-backed venue; non-EVM books (Sui, Aptos, Solana, Cosmos, Soroban, TON:
relayer-bound settlement, [networks/README.md](../networks/README.md)) are **PLANNED**.

## <a id="managed-markets"></a>10. Managed markets

<a id="managed-markets"></a><a id="NODE-DEX-11"></a>**NODE-DEX-11** — **Managed markets are home-bound and check
eligibility at intake.** A licensed operator runs its own `SCaaSDex` instance with managed pairs
([CTR-DEX-12](../contracts/dex.md#CTR-DEX-12)). Node config per market: `dex_market.managed = 1`, `unbound = 0`
(forced), `gossip = 0` (default), `eligibility_tokens` (the regulated legs, read from `versionOf(token).kind`).

| Point | Check | Refusal |
|---|---|---|
| Order intake | `relayer == our lane` (mandatory for managed); relayer `feeMode == NONE` on regulated legs (the relayer fee recipient would need an eligibility record); for each regulated leg: maker not frozen, `canReceive(maker)` for the token the maker buys, token not paused | `NOT_ELIGIBLE {reason}`, `UNBOUND_FORBIDDEN`, `FEE_FORBIDDEN`, `PAUSED` |
| Expiry | `expiry ≤ min(now + 30 d, receiver attestation validUntil)` | `ATTESTATION_SHORTER` |
| Before each settle simulation | the regulated-token pre-check for maker → taker and taker → maker on each regulated leg; market fee recipient `canReceive` | pair dropped, both orders re-checked |
| Events | `AccountFrozen` (maker ⇒ drop the maker's orders), `Paused` (stop matching the market until `pausedUntil`), `Attested` with flags 0 or `AttesterSet(…, false)` (drop affected makers) | — |

On chain the token is the arbiter regardless: a pair that slipped through fails alone (`MatchFailed`).

Gossip: managed markets are **not gossiped** by default: wallets post to the venue's gateway; `route_order` for a
managed market is refused (`MANAGED_LOCAL`). If the operator enables gossip (`gossip = 1`): home-bound replicas only,
listed only for homes with `gossip_trusted.dex = 1` (admin pre-trust); automatic trust ([NODE-DEX-13](#NODE-DEX-13)) is
not computed for managed markets (a settle history is not a licence); depth is indicative; `unbound` stays 0.
Private-profile chains: managed markets are never on gossip ([gossip.md#private-isolation](gossip.md#private-isolation)).

| Abuse | Outcome |
|---|---|
| Third party settles two eligible makers' signed unbound orders | our wallets never sign `relayer = 0` for managed markets and intake refuses them; a maker who signs one elsewhere accepts it; the token still enforces eligibility |
| KYC revoked between intake and settle | pre-settle re-check; else the pair fails on chain |
| Resting-order privacy | not gossiped by default; fills are public on chain as for any trade |
| Venue or relayer fee to an ineligible recipient | relayer fees `NONE` on regulated legs; the venue's market fee wallet carries ordinary eligibility flags for its operator |
| Wash trades by the venue | out of scope of the contract (venue licence, surveillance); every fill is on chain |

## <a id="tests"></a>11. Tests

<a id="tests"></a>cargo: price-time matching, partial fills, IOC, FOK, match limits == contract, snapshot/reload
(durable), spam controls, digest KAT, event decoding; dust maker at the head + deeper maker ⇒ the taker matches the
deeper maker; a poisoned-`feeToken` maker with "healthy maker, failed pair" blocks neither other takers nor recovery;
an OOG pair is not restored; `min_nonce < 2^(w−1)` per network (Sui/Aptos `w = 128`, Solana `w = 64`); over-commitment while a trade is pending; an on-chain market fee raise ⇒ the market stops
being served within one poll; IOC single maker on the Move/Solana families; a late `Matched` after recovery debits the
book. e2e (anvil ports 31950–31959, gateway 18650–18659): approve meta-tx → two orders through the gateway → partial
match → settle job → balances; cancel ⇒ settle never runs; venue restart ⇒ book intact. Token-verified orders
(SPECIFIED): one taker against three makers in one atomic settlement; a maker offered less than half its order is
skipped; FOK filled across two makers; an IOC remainder never rests; an `ESCROW` taker refunded in the same call;
signed `fee` below the taker rate ⇒ `FEE_TOO_LOW`; `dex` off the chain's list ⇒ `DEX_NOT_LISTED` at intake and never
replicated; cancel on the sell token closes the order on the mined `OrderCancelled`; the DEX's balances unchanged after
every settlement. TradeEngine: route finder (hops, cycles), coincidence of wants, quote → plan → simulation,
exchange-only intake split, `amm_fill` on resting orders, fee-by-role refusal, `/v1/dex/exchanges/{ref}`. Managed markets: intake refusals
per reason; drop on `AccountFrozen`/`Paused`/revocation/attester disable; pre-settle re-check; unbound and fee refusals;
gossip refusal and admin-trust-only listing. Book gossip: merge commutativity/idempotence (proptest over update orders ⇒
equal replicas and equal `head` digest); restore at higher `home_seq`; `home_seq` after store restore > before; spoofed
`book` (bad key ⇒ Reject; not the sole prover ⇒ Ignore); untrusted home stored within its small cap, not listed by
default, listed `trusted: false` with `include_untrusted=1`; credit rules (settle from a non-sole or foreign relayer,
order not seen in a book ≥ 60 s earlier, counterparty = home lane ⇒ no credit); 20 credited / 5 counterparties ⇒
trusted; each demotion proof ⇒ demoted 30 d; admin block wins over auto-trust; routed expiry caps 300 s / 120 s;
unbound claimant tie-break identical over permuted arrival orders within the grace, late candidate ignored; unbound
IOC/FOK refused at intake; unbound fills published only at `mined`.
