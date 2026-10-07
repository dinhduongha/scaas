# DEX venue

The DEX venue is the node's off-chain order book in front of `OrderBookDex` ([contracts/dex.md](../contracts/dex.md)):
it admits signed orders at the gateway, matches them price-time, and settles matched pairs with `settle` jobs in
`~dex`. The contract is the arbiter of every fill; the venue only decides which pairs are worth sending. Status: book,
matcher, intake, routes and watcher **BUILT** (book persisted in the legacy client); store-backed book **SPECIFIED**;
book gossip and managed markets **SPECIFIED**; non-EVM books **PLANNED**.

## Order book

<a id="order-book"></a><a id="NODE-DEX-01"></a>**NODE-DEX-01** — **A durable off-chain book, price-time priority,
partial fills.** The venue keeps one book per market, with limit (GTC), IOC and FOK orders and partial fills; the book
survives restarts ([NODE-DEX-14](#NODE-DEX-14)); settlement goes through the node's ordinary job path (claim CAS,
journal before send, replacement, gap-fill — no second send channel). The DEX contract itself is
[CTR-DEX-01](../contracts/dex.md#CTR-DEX-01).

**Single writer**: the node (one process per chain, book under a `tokio::Mutex`). A client never edits `remaining`; it
only mirrors order and trade states from feed items ([persistence](#persistence)).

### Markets and sides

<a id="markets"></a>Markets `(base, quote)` are admin configuration (`/v1/admin/dex/markets`), cross-checked with the
on-chain `markets(key)` at load and on every poll.

<a id="NODE-DEX-08"></a>**NODE-DEX-08** — **The on-chain market is re-checked every poll** (≤ 30 s); a mismatch
(listing, fee, recipient) ⇒ the market stops being served (no matching, no intake) until it matches again. Test:
`setMarket` raises the ppm ⇒ the market stops being served within one poll. Status: today checked only at venue start;
the per-poll check is **SPECIFIED**.

A sell order of `base` is an **ask**, price `buyAmount/sellAmount` (quote/base); a sell order of `quote` is a **bid**,
price `sellAmount/buyAmount`. Prices are compared by `U256` cross-multiplication (amounts at intake `< 2^128` ⇒ no
overflow). Each side is a `Vec` sorted by (best price, increasing `seq`); `seq` is assigned monotonically at intake,
stored, and kept on reload (time priority survives restarts).

## Matching

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
  pair-atomic batch is not provable on chain. Partial fill is the default for every other kind.
- Resting orders are never FOK/IOC (they do not rest).

<a id="NODE-DEX-09"></a>**NODE-DEX-09** — **IOC matches a single maker on Move and Solana.** Sui, Aptos and Solana close
an IOC at its **first** fill, so the matcher has a per-family flag `ioc_single_maker` (on for Sui/Aptos/Solana) that
treats IOC like FOK's single counterpart. Required before non-EVM books are served. Cargo test.

<a id="NODE-DEX-07"></a>**NODE-DEX-07** — **The committed balance includes unsettled fills.** At intake, Σ
`remaining` (+ the relayer fee in `sellToken`) of every open order of the same (maker, sellToken) **plus the new
order**, **plus fills already matched whose trade is not yet `settled`/`failed`** (funds not yet moved but `remaining`
already reduced) must be `<= fundable`; cleared when the trade completes. Otherwise a balance of 100 could place 50
orders of 100. Test: balance 100, ask #1 of 100 matched and pending ⇒ ask #2 of 100 refused. (Today `Book::committed`
counts only resting orders, `dex.rs:449-462`.)

The venue computes no DEX fee: the matcher only compares the signed `maxFeePpm` with the market fee; the DEX fee is
taken from the transferred amount (so `fundable` is unchanged) and rounds up per fill on chain
([CTR-DEX-11](../contracts/dex.md#CTR-DEX-11)); the relayer fee rounds down ([CTR-DEX-06](../contracts/dex.md#CTR-DEX-06)).

## Intake

Spam controls at the door: body ≤ 64 KiB; amounts `0 < amount < 2^128`; `expiry ∈ (now + 5 s, now + 30 days]`; a
per-market minimum (`min_base_amount`: an ask compares `sellAmount`, a bid compares `buyAmount`); at most
`MAX_OPEN_PER_MAKER = 50` open orders per maker per chain; a whole-book cap `MAX_RESTING = 10 000`; a duplicate hash ⇒
refused; `checkOrder` must answer `OK`; the committed-balance rule above.

- **Relayer binding**: by default (home-bound markets) an order must name this node's relayer; `relayer = 0` is refused
  at the door — an open order anyone can settle lets a mempool watcher insert its own pair at the worst price within
  the user's limit (MEV), and another relayer can settle an IOC remainder or an order cancelled off-chain. The contract
  still allows `relayer = 0` (open relayers); markets that opt in (`unbound = 1`) accept relayer-unbound resting GTC
  orders, whose makers accept that exposure ([gossip](#gossip)).
- **On-chain cancel** (costs relayer gas): only for orders in the book; batched into **one** `cancel(...)` per poll
  (≤ 50 orders); at most 20 on-chain cancels per maker per hour — beyond the cap the order is still removed from the
  book at once (this relayer is the only one that can settle it) but no gas is spent. Cancel-all only when the maker
  still has ≥ 1 open order.

<a id="fault-attribution"></a><a id="NODE-DEX-02"></a>**NODE-DEX-02** — **The relayer fee token is limited, and
failed pairs are attributed by evidence.** Intake requires `feeToken ∈ {0, sellToken, buyToken}` (the two tokens of the
listed market); otherwise refused at the door (a fake fee token with `balanceOf`/`allowance` = 2^255 whose
`transferFrom` always reverts would pass `checkOrder` and block every taker crossing it). A pair that fails in
simulation is attributed from the revert reason of `eth_call settleOne(m, relayer)` with `from = DEX`, never guessed: a
DEX error carries an `orderHash`; a token error (`SafeERC20FailedOperation(token)`) is attributed to the side that pays
that token in the pair (M pays X, T pays Y, each pays its own fee token). Only a reason that points at the new order
answers `400`; one that points at the maker ⇒ the maker is dropped (`invalid`) and matching retries (≤ 3 rounds). A
maker that fails in 2 pairs with 2 different takers is removed. Recovery after a failed settle uses the same
attribution: only the side at fault is not restored.

<a id="oog-pairs"></a><a id="NODE-DEX-06"></a>**NODE-DEX-06** — **ERC-1271 orders whose check ran out of gas are never
restored.** The contract caps an ERC-1271 signature check ([CTR-DEX-08](../contracts/dex.md#CTR-DEX-08)); a pair whose
reason is out-of-gas in that check ⇒ that ERC-1271 order is not restored to the book.

## Routes

<a id="routes"></a>On the gateway listener (gateway auth applies, [gateway.md](gateway.md)); `dex_routes()` returns its
own `Router` merged into the gateway router, so the auth layer wraps it without knowing the DEX routes.

| Route | Does |
|---|---|
| `POST /v1/dex/orders` `{chain, order, signature}` | place ⇒ `{hash, status: resting/partial/filled/cancelled, fills[]}` |
| `POST /v1/dex/cancel` `{chain, orderHash, validUntil, signature}` | `CancelOrder` signature ⇒ removed from the book **at once** + on-chain `cancel` job |
| `POST /v1/dex/cancel-all` `{chain, maker, minNonce, validUntil, signature}` | `InvalidateNonces` ⇒ every order with `nonce < minNonce` removed + on-chain job |
| `GET /v1/dex/markets?chain` | markets + fees |
| `GET /v1/dex/depth?chain&market&levels` | aggregated price levels of both sides (levels ≤ 200); prices are decimal strings scaled by both tokens' `decimals`, never a raw integer division |
| `GET /v1/dex/trades?chain&market` | recent fills (ring of 200 in memory; history from the feed) |
| `GET /v1/dex/ticker?chain&market` | last price, best bid/ask, volume in the ring |
| `GET /v1/dex/orders?chain&maker` | open orders of one wallet |
| `GET /v1/dex/depth?…&scope=network`, `GET /v1/dex/homes?chain&market` | network depth and DEX homes ([gossip](#gossip)) |

<a id="NODE-DEX-03"></a>**NODE-DEX-03** — **No WebSocket; clients poll** `depth`/`trades`. A WebSocket server would add
a dependency for no need at the volumes served.

## Watcher

<a id="watcher"></a><a id="NODE-DEX-04"></a>**NODE-DEX-04** — **The DEX watcher has its own cursor.** One task per
chain with the same finality helpers as the indexer (`finality::{safe_head, next_range, quorum_ok}`) and a **separate
cursor** (`dex_cursor`) reads the DEX contract's logs (`OrderFilled`, `Matched`, `MatchFailed`, `OrderCancelled`,
`NoncesInvalidated`), writes `dex_range` feed items and advances `dex_cursor`, then removes from the book every order
closed on chain (cancelled through any relayer, too). `settled` is final: a later `MatchFailed` does not flip it. A
separate cursor means a DEX ingest fault never blocks payment booking and vice versa.

## Persistence

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

## Gossip

<a id="gossip"></a><a id="NODE-DEX-12"></a>**NODE-DEX-12** — **DEX book gossip, two order modes per market.**
**Home-bound** (default): an order bound to relayer `r` is matched and settled **only by the home** that proved `r` in
its announce ([gossip.md#announce](gossip.md#announce)); `OrderBookDex._accept` (`relayer ∈ {0, sender}`) makes this
**hard**. Other nodes keep read-only replicas — a home register (highest `home_seq` wins) joined with chain facts
(`filled = max`, `closed = or`) — and replicate/advertise only **DEX-trusted homes**. **Relayer-unbound**
(`dex_market.unbound = 1`, maker opts in per order with `relayer = 0`): resting GTC orders only; one deterministic
**claimant** may match during `claim_ms`, then any node matches its own (bound) takers against it; cancel is final only
when mined. In both modes `filled[orderHash]` (no overfill, pair-isolated `MatchFailed`) is the arbiter. Topics per
market. Bound liquidity is fragmented per home; unbound makers accept execution by **anyone** (not only nodes) within
their limit, and an off-chain cancel does not bind until mined.

`OrderBookDex._accept` checks `relayer ∈ {0, sender}` and `filled + fill ≤ sellAmount`, and each pair runs in `try
settleOne` (`MatchFailed`): **no fill can be settled twice in either mode**; the rules below only keep honest nodes
from wasting gas and from showing phantom fills.

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
  that loses the claim (`NOT_CLAIMANT`, forwarded, not stored); `erc1271` order outside a home/claimant `book`.
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
   expires; with `feeRecipient = 0` the relayer fee goes to whoever settles. The claim window binds only honest nodes.
7. Fees, `maxFeePpm`, partial fills and price checks are the contract's, unchanged.

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

## Managed markets

<a id="managed-markets"></a><a id="NODE-DEX-11"></a>**NODE-DEX-11** — **Managed markets are home-bound and check
eligibility at intake.** A licensed operator runs its own `OrderBookDex` instance with managed pairs
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

## Tests

<a id="tests"></a>cargo: price-time matching, partial fills, IOC, FOK, match limits == contract, snapshot/reload
(durable), spam controls, digest KAT, event decoding; dust maker at the head + deeper maker ⇒ the taker matches the
deeper maker; a poisoned-`feeToken` maker with "healthy maker, failed pair" blocks neither other takers nor recovery;
an OOG pair is not restored; over-commitment while a trade is pending; an on-chain market fee raise ⇒ the market stops
being served within one poll; IOC single maker on the Move/Solana families; a late `Matched` after recovery debits the
book. e2e (anvil ports 31950–31959, gateway 18650–18659): approve meta-tx → two orders through the gateway → partial
match → settle job → balances; cancel ⇒ settle never runs; venue restart ⇒ book intact. Managed markets: intake refusals
per reason; drop on `AccountFrozen`/`Paused`/revocation/attester disable; pre-settle re-check; unbound and fee refusals;
gossip refusal and admin-trust-only listing. Book gossip: merge commutativity/idempotence (proptest over update orders ⇒
equal replicas and equal `head` digest); restore at higher `home_seq`; `home_seq` after store restore > before; spoofed
`book` (bad key ⇒ Reject; not the sole prover ⇒ Ignore); untrusted home stored within its small cap, not listed by
default, listed `trusted: false` with `include_untrusted=1`; credit rules (settle from a non-sole or foreign relayer,
order not seen in a book ≥ 60 s earlier, counterparty = home lane ⇒ no credit); 20 credited / 5 counterparties ⇒
trusted; each demotion proof ⇒ demoted 30 d; admin block wins over auto-trust; routed expiry caps 300 s / 120 s;
unbound claimant tie-break identical over permuted arrival orders within the grace, late candidate ignored; unbound
IOC/FOK refused at intake; unbound fills published only at `mined`.
