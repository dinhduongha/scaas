# DEX exchange settlement: `TradeOrder`s executed against AMMs, multi-hop and cycles

**Status:** DRAFT, design approved by the owner in chat 2026-10-08; written spec awaiting owner review.
Provisional ids `DS-n`; real ids are allocated in `docs/decisions.md` on acceptance (docs/README "Ids").
**Date:** 2026-10-08. **Scope:** `OrderBookDex` (EVM), the token side of `TradeOrder` (`ERC20MetaTx.mtxTrade`), a new
`DexPuller`, the node's DEX venue (a new TradeEngine), clients. Builds on the accepted meta-tx design
(`docs/history/specs/2026-10-07-metatx-generic.md`, rules in [contracts/dex.md](../../contracts/dex.md)); stream MT-5
grows by this draft. Non-EVM families: out of scope (the non-EVM meta-tx draft decides what they can do). Nothing is
deployed, so the design changes in place.

## 1. Why

The order book matches `TradeOrder`s only against each other ([CTR-DEX-16](../../contracts/dex.md#CTR-DEX-16)). On a
chain with AMM liquidity (Uniswap v2/v3 and their forks) an order that finds no counterpart in the book could still be
filled at or above its signed price, a route through several pools could beat a single pool, and a signer may want a
cycle — sell X, receive more X — when pools disagree. The owner asked for this without a new signed struct: the same
`TradeOrder`, executed by the node's own algorithm (a TradeEngine) instead of against `makers[]`.

## 2. Owner answers (2026-10-08)

| # | Question | Answer |
|---|---|---|
| S1 | Which AMM pools may the DEX use? | **Both** an admin allowlist and any pool; **default: any pool** |
| S2 | Who turns on "listed pools only"? | **Both**: the signer per order (a flag) and the DEX admin for the whole DEX |
| S3 | Approach | **Solver settlement** (CoW-style) in `OrderBookDex` itself, beside `mtxSettle`; the node's TradeEngine runs its own algorithm. `receiveToken` is whatever the order names — a cycle X→…→X is allowed, not required |
| S4 | Surplus (output above the signed limit) | **The signer's**; the contract enforces it for everything that reaches the DEX, the node's policy for the rest |
| S5 | Who performs the AMM calls? | **The DEX itself** (`interactions[]`) — and, in a **separate function**, a solver-named **executor** contract |
| S7 | Function names | `mtxSolve` renamed **`mtxExchange`** (owner); hence `mtxExchangeVia`, `ExchangePlan`, `ExchangeLeg`, `IExchangeExecutor.exchangeCallback`, `setExchangeTarget`, `ExchangeLegSettled`. Not to be confused with `ExchangeOffer.exchange` ([CTR-AS-13](../../contracts/asset-suite.md#CTR-AS-13)), a different contract |
| S6 | Node income | Only the `relayerShare` of the signed fee; the node never routes surplus to itself |

## 3. Design

### DS-1 — Two exchange entry points on `OrderBookDex`

```solidity
struct ExchangeLeg    { address sellToken; TradeOrder o; bytes sig; uint256 sellFill; uint256 receiveFill; }
struct Interaction { address target; bytes data; }          // no value: the DEX holds no native coin
struct ExchangePlan    { bytes32 ref; ExchangeLeg[] legs; address[] extraTokens; }

// (a) the DEX calls each interaction itself (CoW GPv2Settlement model)
function mtxExchange(ExchangePlan calldata s, Interaction[] calldata interactions) external nonReentrant;

// (b) the DEX hands the pulled funds to a solver-named executor (UniswapX filler model)
interface IExchangeExecutor {
    function exchangeCallback(bytes32 ref, address[] calldata tokensOut, uint256[] calldata amountsOut,
                           address[] calldata tokensIn, uint256[] calldata amountsIn, bytes calldata data) external;
}
function mtxExchangeVia(ExchangePlan calldata s, address executor, bytes calldata data) external nonReentrant;
```

`receiveFill` is the **floor** the solver commits to for that leg; what the leg finally receives is the floor plus its
share of the surplus (DS-3). A solution is atomic: any failure reverts it whole (no `try`, unlike `mtxSettle`'s
per-settlement isolation — one solution is one route). The `mtx` prefix holds: the authority of every leg is its
signer's signature ([CTR-MTX-21](../../contracts/metatx.md#CTR-MTX-21)).

Steps, identical for (a) and (b) except step 4:

1. **Check** each leg: `o.relayer == 0 || o.relayer == msg.sender` (`WrongRelayer`); `sellToken` and `o.receiveToken`
   are both **known** to the DEX — a token is known when it is a side of a listed market, and its kind (SCaaS or
   outside) is the one `setMarket` recorded ([CTR-DEX-18](../../contracts/dex.md#CTR-DEX-18)) (`TokenNotKnown`);
   `from`s pairwise distinct across legs (`SelfTrade`); the price limit
   `sellFill · o.receiveAmount ≤ receiveFill · o.amount` (`PriceLimit`); the effective minimum and received-side floor
   of [CTR-DEX-14](../../contracts/dex.md#CTR-DEX-14) (`BelowMinFill`); `dexFee = ceil(receiveFill · o.fee / 10⁶)`
   ([CTR-DEX-11](../../contracts/dex.md#CTR-DEX-11)), charged on the floor only.
2. **Snapshot** the DEX's balance of every leg token and every `extraTokens` entry (intermediate hop tokens).
3. **Pull** each leg into the DEX: a SCaaS sell token through its `mtxTrade` (Path A with `TradeFill{sellFill,
   receiveFill, dexFee, msg.sender}`; Path B `ESCROW` pulls all of `amount`), an outside sell token through the
   `DexPuller` (DS-4) after the DEX's own checks of the `DexOrder`, as in `mtxSettle`.
4. **Execute.**
   - (a) For each interaction: the blocklist and allowlist of DS-5, then `target.call(data)`; a failure reverts the
     solution with its revert data.
   - (b) The allowlist of DS-5 on `executor`; the DEX `transfer`s to `executor` the pulled amount of each sell token
     (`tokensOut`/`amountsOut`) and calls `exchangeCallback` with, per receive token, the **minimum** it needs back
     (`tokensIn`/`amountsIn` = Σ floors of the legs receiving that token). The executor does whatever it wants
     (pool callbacks, flash swaps, its own inventory) and transfers to the DEX before it returns.
5. **Settle surplus** (DS-3), then **pay**: each leg's `destination` (or `from`) receives `receiveFill − dexFee +
   surplusShare` in `o.receiveToken`; each `dexFee` is split per [CTR-DEX-17](../../contracts/dex.md#CTR-DEX-17)
   (relayer share to `msg.sender`); a Path B leg is refunded `amount − sellFill` in its sell token.
6. **Conservation**: the DEX's balance of every snapshotted token equals its snapshot (`ConservationBroken(token)`).
   Emit per leg `ExchangeLegSettled(ref, orderHash, from, destination, sold, receivedFloor, surplus, dexFee, refund,
   limitReceive)` with `limitReceive = ceil(sellFill · receiveAmount / amount)`, so a client checks what the signer got
   against what it signed without trusting the node.

`mtxSettle` is unchanged: the book still matches one taker against makers, and a pair with equal tokens can never be a
market. The same order can be matched by the book or solved, with no new signature.

### DS-2 — Token side: cycles and the new flag

`ERC20MetaTx.mtxTrade` ([CTR-DEX-15](../../contracts/dex.md#CTR-DEX-15)) changes in two places:

- **`o.receiveToken == address(this)` is allowed.** `SelfOrder` stays for `o.from == address(this)` and
  `o.dex == address(this)`. A cycle order sells X and names X as `receiveToken`; its price limit
  (`receiveAmount > amount` for a profit) is checked exactly like any other.
- **Known flags gain `LISTED_POOLS = 4`** (`IOC 1 | ESCROW 2 | LISTED_POOLS 4`). The token does not interpret it; it
  only must not refuse it as unknown (`BadFlags`). Outside-token `DexOrder`s take the same bit.

Everything else in `mtxTrade` is unchanged: the token checks the signer's bounds against the **floor** figures the DEX
passes, and moves funds only to `o.dex`.

### DS-3 — Surplus goes to the signers, on chain

After step 4, for each receive token `T` (a token at least one leg receives):

```text
excess_T = balance_T − snapshot_T − Σ receiveFill(legs receiving T) − Σ refund(Path B legs selling T)   // < 0 ⇒ revert InsufficientOutput(T)
share_i  = floor(excess_T · receiveFill_i / Σ receiveFill)            // the last such leg (by index) also takes the rounding remainder
```

For every other snapshotted token (sold only, or an intermediate hop in `extraTokens`) the balance after step 4 must
equal its snapshot plus what step 5 will pay out of it (Path B refunds), else `ConservationBroken(token)`: a solver
routes exact-input, and a leftover is a solver bug, not something to assign. Surplus carries no DEX fee (the signed
`fee` is charged on the floor). With (b) the executor may return more than `amountsIn`; everything that arrives is
distributed the same way. What the contract cannot see is a swap whose recipient the solver set outside the DEX — that
part of "surplus to the signer" is the node's policy (DS-7), and the event (DS-1 step 6) lets anyone measure it.

### DS-4 — `DexPuller`: the DEX holds no user allowance

With interactions, an allowance held by the DEX could be spent by an interaction (`outsideToken.transferFrom(victim,
attacker, x)`). Hence:

```solidity
contract DexPuller {                       // deployed by the DEX's constructor; immutable
    address public immutable dex;
    function pull(address token, address from, uint256 amount) external;   // msg.sender == dex; safeTransferFrom(from, dex, amount)
}
```

Holders of an **outside** token approve the **puller**, not the DEX; the DEX calls `pull` only after its own checks of
the `DexOrder` (for `mtxSettle` and both exchange functions alike). This changes
[CTR-DEX-18](../../contracts/dex.md#CTR-DEX-18) ("Pull" row) and every place that says "allowance to the DEX": node
intake reads `allowance(from, puller)`; clients and the app ask for an approval of the puller. SCaaS tokens are
unaffected (no allowance exists, [CTR-TOK-01](../../contracts/token-wrappers.md#CTR-TOK-01)).

### DS-5 — What an interaction may call

For (a), each interaction is refused unless:

- `target ≠ address(this)` and `target ≠ puller` (`ForbiddenTarget`);
- `data.length ≥ 4` and `bytes4(data) ≠ mtxTrade.selector` — **for every target**, since the DEX does not know every
  SCaaS token (`ForbiddenSelector`). Without it an interaction could call `mtxTrade` of a victim's resting order
  (which names this DEX) with an invented `receiveFill`, pull the victim's funds into the DEX and move the same amount
  out, and conservation would still balance;
- if any leg sets `LISTED_POOLS` **or** the DEX is in listed-only mode: `exchangeTarget[target]` (`TargetNotListed`).

Other `mtx…` selectors need no block: cancels need the signer's own signature and only close orders; `mtxExecute`
can be submitted by any relayer anyway. Interactions may `approve` routers (the DEX is a contract, and so is the
router, [CTR-TOK-01](../../contracts/token-wrappers.md#CTR-TOK-01)). A residual allowance left after a solution is
harmless: between calls the DEX holds no user funds (conservation over every declared token), and inside a call every
movement is checked at the end; tests prove it (DS-9).

For (b): an executor that calls back into the DEX hits `nonReentrant`; one that calls `mtxTrade` fails because it is
not `o.dex`; one that calls the puller fails because it is not the DEX. The allowlist (`exchangeTarget[executor]`) applies
under the same condition as for targets — the DEX cannot see what an executor calls inside.

### DS-6 — Admin: two new powers

| Function | Effect | Event |
|---|---|---|
| `setExchangeTarget(address target, bool listed)` | list or delist an interaction target or an executor | `ExchangeTargetSet(target, listed)` |
| `setListedOnly(bool on)` | DEX-wide listed-only mode; default `false` (any target) | `ListedOnlySet(on)` |

Neither touches funds or changes a fee amount. A signer who wants the guarantee whatever the admin does sets
`LISTED_POOLS`; with the mode off, the order's flag still applies. Both join the admin-powers list
([contracts/README.md](../../contracts/README.md#admin-powers-complete-list)) and [CTR-DEX-03](../../contracts/dex.md#CTR-DEX-03)
("exactly two things" becomes four).

### DS-7 — Node: the TradeEngine

Part of the DEX venue ([node/dex-venue.md](../../node/dex-venue.md)), off unless the chain enables it.

- **Intake split.** An order on a listed market enters the book as today. An order whose pair is not a listed market,
  or whose `receiveToken` equals its sell token, is **exchange-only**: it never rests in the book and only the
  TradeEngine handles it. Both tokens must be known to the DEX (DS-1 step 1), else `TOKEN_NOT_SERVED`.
- **Each tick** (every block or `trade_engine.tick`):
  1. book matching first (`mtxSettle`) — internal liquidity pays no pool fee;
  2. then: coincidences of wants among exchange-only orders, and AMM routes for the remainder — quotes by `eth_call` to
     the configured quoters, at most `trade_engine.max_hops` (default 3) hops, cycles for X→X orders;
  3. a resting book order is also filled through AMMs when an AMM route reaches its limit (per market `amm_fill`,
     default on when the solver is enabled);
  4. `receiveFill` floor = quote × (1 − `trade_engine.buffer`), never below the signed limit — the buffer costs the signer
     nothing, because the surplus comes back (DS-3);
  5. path (a) when routers suffice; path (b) through the node's own executor (listed) for callbacks or flash swaps;
  6. simulate the whole call (`eth_call`), submit through a `call` job, watch the final event.
- **Surplus and income (owner S4, S6).** Every swap the node builds sends its output to the DEX; the node's income is
  the `relayerShare` of the signed fee and nothing else. `GET /v1/dex/exchanges/{ref}` returns the quote at decision time
  next to the settled `ExchangeLegSettled` figures.
- **Fees by role.** A exchange-only order pays the market's `taker_fee_ppm` (orders below it are refused, `FEE_TOO_LOW`);
  a resting order filled through an AMM pays `maker_fee_ppm`.
- **MEV.** On a public chain the node submits through a private relay where one exists. A sandwich can only take
  surplus, never go below the signed limit. The private chain 7622 has no public mempool (and no AMM unless one is
  deployed).
- **Config per chain:** `trade_engine.enabled` (default `false`), `trade_engine.amm` (list of `{kind: univ2|univ3, factory,
  quoter, router}`), `trade_engine.max_hops`, `trade_engine.executor`, `trade_engine.tick`, `trade_engine.buffer`.
- **Call table** ([NODE-JOB-20](../../node/job-api.md#NODE-JOB-20)): `mtxExchange` and `mtxExchangeVia` on the chain
  profile's DEXes, like `mtxSettle`.
- **Relayer binding.** Clients keep defaulting `relayer` to the venue node ([CTR-DEX-17](../../contracts/dex.md#CTR-DEX-17)).
  With `relayer = 0` any solver may solve the order; the signed limit holds, and only the surplus outside the DEX
  (DS-3) depends on that solver's honesty.

### DS-8 — Clients

`clientkeys`, the app and the portal: show `LISTED_POOLS` (default off, a toggle "only audited pools"), allow
`receiveToken == sell token` with a "cycle" label and a warning when `receiveAmount ≤ amount`, ask outside-token
holders to approve the **puller**, and book a settled leg's `surplus` as price improvement
([integration.md](../../integration.md)).

## 4. Security notes

- The signed limit is the only price guarantee; every route, pool and executor is untrusted.
- Theft paths closed: an allowance held by the DEX (DS-4), a forged `mtxTrade` from inside the DEX (DS-5), re-entry
  into the DEX (`nonReentrant`), leftover funds between calls (conservation, DS-1 step 6).
- Residual: a solver can send part of a route's output elsewhere; bounded by the signed limit, visible in events,
  excluded for the node by policy (DS-7). Same class as the owner-accepted `dex` risk
  ([CTR-DEX-19](../../contracts/dex.md#CTR-DEX-19)).
- Exact-transfer tokens only (unchanged): a fee-on-transfer or rebasing token breaks conservation and reverts.
- Grief: a target or executor that burns gas or reverts fails only its own solution; the relayer pays.

## 5. Not in scope

Non-EVM families; native coin legs (the DEX holds no native coin, `value` is always 0 — wrapped native tokens are
ordinary ERC-20s); a solver auction among several nodes; RFQ market makers.

## 6. Changes to current rules (on acceptance)

| Rule | Change |
|---|---|
| [CTR-DEX-01](../../contracts/dex.md#CTR-DEX-01) | the overview gains the exchange path |
| [CTR-DEX-03](../../contracts/dex.md#CTR-DEX-03) | admin: + `setExchangeTarget`, `setListedOnly` |
| [CTR-DEX-15](../../contracts/dex.md#CTR-DEX-15) | `receiveToken == this` allowed; flag `LISTED_POOLS` |
| [CTR-DEX-16](../../contracts/dex.md#CTR-DEX-16) | outside legs pulled through the puller |
| [CTR-DEX-18](../../contracts/dex.md#CTR-DEX-18) | allowance to the puller, not the DEX |
| new CTR-DEX-20… | DS-1, DS-3, DS-4, DS-5, DS-6 |
| [contracts/README.md](../../contracts/README.md#admin-powers-complete-list) | admin-powers row of `OrderBookDex` |
| [NODE-DEX-15](../../node/dex-venue.md#NODE-DEX-15) | outside legs: allowance to the puller |
| new NODE-DEX-17… | DS-7 |
| [NODE-JOB-20](../../node/job-api.md#NODE-JOB-20) | call-table rows `mtxExchange`, `mtxExchangeVia` |
| [clients/signers-clientkeys.md](../../clients/signers-clientkeys.md) | DS-8 |
| `TODO.md` MT-5 | + puller, exchange functions, surplus, admin powers; node MT-8 + TradeEngine |

## 7. Tests (gate of the stream)

- **forge**: interaction calling `mtxTrade` of a resting order (refused); target = DEX or puller (refused);
  `transferFrom(victim, …)` by interaction (fails: no allowance); surplus split over several legs receiving one token,
  rounding remainder to the last; sold-only or intermediate leftover reverts; `InsufficientOutput`; a cycle X→X with
  profit; multi-hop through mock Uniswap v2/v3 and a fork test with the real Uniswap bytecode on anvil; `LISTED_POOLS`
  × `setListedOnly` (four combinations, both entry points); executor returning less (revert) and more (distributed);
  executor re-entering the DEX, calling `mtxTrade`, calling the puller (all fail); `receiveToken == this` on the token;
  unknown flag bits still refused; Path B leg in a solution (refund); outside-token leg through the puller in
  `mtxSettle` and in a solution; a reverting and a gas-burning target; invariant: between calls the DEX's balance of
  every token is 0 and residual allowances move nothing.
- **node**: route finder (hops, cycles), coincidence of wants, quote → solution → simulation, exchange-only intake split,
  `amm_fill` on resting orders, fee-by-role refusal, `/v1/dex/exchanges/{ref}`.

## 8. Open questions for the owner

None blocking. Interplay noted: the owner's 2026-10-08 remark that `MetaTransaction` is too token-centric (a generic
gasless call to any SCaaS contract) is a separate redesign; `TradeOrder` is its own struct
([CTR-MTX-11](../../contracts/metatx.md#CTR-MTX-11)) and is not affected by it.

## 9. Revision history

| Rev | Date | What |
|---|---|---|
| 1 | 2026-10-08 | First draft from the owner's chat answers S1–S6 |
| 2 | 2026-10-08 | Owner S7: `mtxSolve` → `mtxExchange` and the related names; file renamed from `…-dex-solver-design.md` |
