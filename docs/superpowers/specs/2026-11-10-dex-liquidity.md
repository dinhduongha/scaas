# DEX liquidity: signed `LiquidityOrder`s against AMM pools through `SCaaSDex` — design

**Status:** SPECIFIED, nothing built, **UNAUDITED**. Written 2026-11-10 at the owner's request, on the direction the owner
approved the same day (§2). Branch `ua-mtx-merge`. No gas or size figure here was measured for the new code: every such figure
is an [estimate] over the measured figures it cites. Tags: [measured] a build or forge run already in the repo; [estimate]
arithmetic over measured figures; [inference] follows from the EVM's or an AMM's rules and is checked at the build.

**The problem (owner 2026-11-10).** A SCaaS token refuses `approve` from an EOA or a UA
([CTR-TOK-01](../../contracts/token-wrappers.md#CTR-TOK-01), [CTR-UA-27](../../contracts/accounts.md#CTR-UA-27)): no subject
ever holds or grants an allowance. Every standard AMM router pulls by `transferFrom` under an allowance, so a user cannot create
a pool, deposit liquidity or withdraw it through a router.

**The answer in one paragraph.** The user signs one typed `LiquidityOrder` in the DEX's EIP-712 domain: up to eight ERC-20
inputs, each with a maximum; up to eight ERC-20 outputs, each with a minimum; optionally an ERC-721 position given or received;
a recipient, a fee rate, a relayer, a lane, a nonce and a deadline. Anyone submits `SCaaSDex.mtxLiquidity(plan, interactions)`.
The DEX checks the order, closes it, pulls each SCaaS input through the token's new DEX-only entry `mtxLiquidityPull` (the token
recomputes the digest and verifies the signature itself, exactly as `mtxTrade` does) and each outside input through the
`DexPuller`, runs the submitter's generic `Interaction`s under [CTR-DEX-23](../../contracts/dex.md#CTR-DEX-23)'s rules, and then
checks **outcomes only**: every output reached the recipient at or above its signed minimum (a balance delta), a received
position is owned by the recipient and has at least the signed liquidity in the signed pool and range, every leftover went back
to the signer, and the DEX holds exactly what it held before. No AMM-specific execution code; one small read-only position reader
per position-manager family for the ERC-721 case (§7, Q1). The body lives in a new DEX body module, `SCaaSDexLiquidityModule`
(§9).

**Rules this spec applies, not reopens:** CTR-TOK-01 and CTR-UA-27 (no allowance; a UA holds no outside token); the DEX's
machinery as built: [CTR-DEX-16](../../contracts/dex.md#CTR-DEX-16) (everything through the DEX, balances unchanged),
[-17](../../contracts/dex.md#CTR-DEX-17) and [-11](../../contracts/dex.md#CTR-DEX-11) (one signed fee rate, rounded up, split
by the DEX), [-18](../../contracts/dex.md#CTR-DEX-18) (outside tokens checked by the DEX, the kind from the listing),
[-19](../../contracts/dex.md#CTR-DEX-19) (the named DEX is a contract and nothing more), [-20](../../contracts/dex.md#CTR-DEX-20)
(the exchange path, its sweep rule), [-22](../../contracts/dex.md#CTR-DEX-22) (the puller is the only holder of user allowances),
[-23](../../contracts/dex.md#CTR-DEX-23) (what an interaction may call), [-25](../../contracts/dex.md#CTR-DEX-25) and
[-26](../../contracts/dex.md#CTR-DEX-26) (the UA form, one book on ids), [-28](../../contracts/dex.md#CTR-DEX-28)
(`InteractionFailed`); the T66b body-module rule ([CTR-TOK-30](../../contracts/token-wrappers.md#CTR-TOK-30),
[T66b spec](2026-11-09-t66b-library-organisation.md) §4 and §11); explicit parameters; every state-changing `mtx*` relayable at
fee 0 too; no EIP-7702 ([CTR-UA-24](../../contracts/accounts.md#CTR-UA-24)); nothing deployed is upgraded; all chains test-only.

## 1. Scope — SPECIFIED

**In scope (EVM):**
- **Deposit** into a pool whose share is an ERC-20 (a v2-style pair, any pool with an ERC-20 LP token) or an ERC-721 position
  (Uniswap v3's `NonfungiblePositionManager`, v4's `PositionManager`).
- **Withdraw**: the signer gives the LP token (or the position) for minimum amounts of the pool's tokens.
- **Change a position** with the same order shape: add to a position (give it, receive it with more liquidity), move a range
  (give one, receive another), collect a position's fees (give it, receive the fees and the position back).
- **Create a pool** as an interaction of a plan, or by anyone directly (§8.1).
- Signers: a native id (EOA ECDSA low-s, ERC-1271 under the DEX's cap) and a derived UA (any registered kind, PQ included) for
  SCaaS inputs; the node row; `clientkeys`, `ua-rs`, vectors.

**Not in scope:**
- An executor form (`mtxLiquidityVia`): the three target families need no callback (§8.2); Q3.
- A batch entry (`mtxLiquidityBatch`): add when a planner asks for it, as `mtxExchangeBatch` was.
- A per-order cancel struct: a liquidity order is short-lived; it cancels by its lane or expires (§4.4).
- Custody of LP (farms, staking, vaults that keep a user's LP): that is a service holding funds, the service pull's case
  ([service-pull spec](2026-11-09-service-pull.md)).
- Confidential balances (Zether, PQZ): public balances only; nothing here decrypts anything.
- The node's own liquidity planner (the `OrderRouter` building routes): PLANNED (§11).
- Non-EVM families: the exchange path is EVM only (CTR-DEX-20) and so is this. A family that adds AMM liquidity later follows the
  same rule (signed, bound to one DEX, outcome-checked) in its own round; nothing here is split by chain kind.

## 2. Owner rulings this spec applies (2026-11-10)

| # | Ruling | Where |
|---|---|---|
| R1 | **Reuse the SCaaSDex machinery; no adapter per AMM.** A new entry `mtxLiquidity(LiquidityPlan, Interaction[])` that follows `mtxExchange` (CTR-DEX-20): generic `Interaction {target, data}` calls under CTR-DEX-23 (`ForbiddenTarget`, `ForbiddenSelector`, listed targets and the listed-only mode); the contract checks outcomes only | §6 |
| R2 | **A signed typed `LiquidityOrder`** (EIP-712, explicit named parameters, one entry point per operation, the UA form of CTR-DEX-25 / -26): inputs with a maximum each; an ERC-20 output with a minimum or an ERC-721 position with a recipient; deadline, nonce, fee | §4 |
| R3 | **Pulls:** SCaaS tokens by the signed order through the token's trade pull path, as `mtxTrade` pulls; outside tokens, LP tokens included, through `DexPuller` | §5, §6 step 3 |
| R4 | **Outcome checks:** pulled ≤ the signed maximum; the recipient gets ≥ the minimum (balance delta) or owns the position; leftovers back to the signer; conservation as on the exchange path; the DEX holds no user funds between calls | §6 |
| R5 | **Withdraw** is a `LiquidityOrder` that gives the LP token or the position for minima of the pool's tokens; **create pool** needs no approve: say how the plan covers it | §8.1 |
| R6 | **Placement:** `SCaaSDex` is 32,991 B [measured, `size-baseline.json`] against its 33,594 B release margin, so `mtxLiquidity` goes into a new DEX body module under the T66b rule | §9 |
| R7 | **Module names (owner 2026-11-10).** The DEX's body modules are named by domain: the new module is **`SCaaSDexLiquidityModule`**, and the existing governance module **`SCaaSDexD` is renamed `SCaaSDexGovernanceModule`**. The shared hooks base `SCaaSDexGovernance` keeps its name; the token kinds' generated letter modules (P, T, A, W, Z, Q, Q2) keep theirs. **Why:** the DEX has few hand-written modules, so names by domain read better than letters, and the suffix `Module` says the contract is a `DELEGATECALL` body, not a base and not a library. The rename is the first build task (§17, task L0): no logic change, but the metadata hash, so the code hash and the CREATE2 address, change, and every old → new value is recorded | §9, §17 |

Controller calls the owner may override: C1 the order is signed in the DEX's domain and every verifier recomputes the digest
(§4.3); C2 the UA purpose `trade` covers it (§5); C3 the minimum of an output is net, measured at the recipient (§6 step 6);
C4 the fee applies to ERC-20 outputs only (§6 step 6); C5 cancel by lane and expiry only (§4.4); C6 tokens need no listing
for this entry, their kind is the DEX's record (§6 step 1); C7 the `DexPuller` pulls a position by its unchanged `pull` (§7.1);
C8 the rule ids of §16; C9 at most eight inputs and eight outputs (§4.1).

## 3. Why the DEX path, not the service pull — SPECIFIED

The [service pull](2026-11-09-service-pull.md) (proposed CTR-MTX-32, approved 2026-11-09) is the standard replacement of
`approve` for a contract that takes a payer's SCaaS tokens into **custody**. Its shape could carry a deposit: the DEX as the
service, one `UAMetaTransfer` per SCaaS input bound to the DEX, `entryRef` = the digest of an unsigned liquidity `<Op>`.

| | Service pull | DEX path (this spec) |
|---|---|---|
| Inputs per signature | one payer, one token per entry (its C2); a two-token deposit is two signatures | every input in one signature |
| Outside tokens (LP tokens, USDC, an ERC-721 position) | not covered: the pull is a SCaaS token's `mtxExecuteTransfer` | the `DexPuller`, under the DEX's check of the same signed order |
| What the wallet shows | "pay `value` to S" with `entryRef` opaque (its accepted blind-commitment residual) | the whole order as typed data: every input maximum, output minimum, recipient, position, fee |
| Who holds the funds | the service, as custody, by its own ledger | nobody: one atomic plan, the DEX ends at its snapshot (CTR-DEX-16, -20) |
| Execution against AMMs | the service's own code per AMM | the existing generic interactions, listed targets, approve reset, `InteractionFailed` |
| Outcome guarantee | the service's logic | on chain, AMM-agnostic: minima, ownership, refunds, conservation |
| Fee | `RelayFeeRouter` only | the DEX's signed fee rate (CTR-DEX-17); `RelayFeeRouter` around `mtxLiquidity` also works |
| Token change | none | one DEX-only entry in module T on every kind (§5): new token releases |
| Signature verifies | one per SCaaS input (one signature each) | one per SCaaS input (one signature, each token verifies it) |

**Verdict: the DEX path fits better.** Liquidity is a multi-token, atomic exchange against an outside contract, which is what the
DEX already does, while the service pull is single-token custody. The service pull cannot carry an outside input at all, so a
withdraw (the LP token is an outside token) or a SCaaS/USDC deposit would need the DEX's puller anyway, and its wallet view is
blind. The DEX path's cost is the token entry (§5), which is the owner's R3 made concrete: the token's trade path verifies a
`UATradeOrder` only, and a `UATradeOrder` per input does not fit (it has one receive token and a price limit per order, no way
to share one LP output between two orders, and no ERC-721 output), so the trade path needs one more DEX-only entry. Q2 asks the
owner to confirm that token change. The service pull stays the answer for a contract that keeps a user's LP afterwards.

## 4. The signed order and the plan — SPECIFIED

### 4.1 Structs

In `ITradeToken` (shared by the tokens and the DEX, as `UATradeOrder`):

```solidity
/// One ERC-20 of a liquidity order: an input's maximum, or an output's minimum.
struct LiquidityToken {
    address token;
    uint256 amount;
}

/// The UA form only (CTR-DEX-25 / -26 and the merge's one form on ids): a native signer is its address zero-padded.
struct LiquidityOrder {
    bytes32 from;              // the signer
    LiquidityToken[] inputs;   // ERC-20s the signer gives: each pulled at most `amount` (> 0); 0..8, distinct
    LiquidityToken[] outputs;  // ERC-20s the signer receives at `recipient`: each at least `amount`, net; 0..8, distinct
    address positionManager;   // the ERC-721 position contract; 0 = no position in this order
    address positionReader;    // the listed reader of `positionManager` (§7); set iff a position is received
    uint256 positionIn;        // a position the signer gives; 0 = none (position ids start at 1)
    bytes32 positionPool;      // the pool of the position the signer receives, in the reader's terms; 0 = none received
    int24 tickLower;           // its range; both 0 when none is received
    int24 tickUpper;
    uint128 minLiquidity;      // its liquidity after the plan, at least this; > 0 when a position is received
    bytes32 recipient;         // receives every output and the received position; 0 = from
    uint256 fee;               // DEX fee rate in ppm on every ERC-20 output (CTR-DEX-17); ≤ 10 000 (1 %)
    address relayer;           // the only submitter allowed (0 = anyone)
    uint8 flags;               // LISTED_POOLS (4) only
    uint256 batch;             // order lane: the DEX's and each SCaaS input token's `minNonce[from][batch]`
    uint256 nonce;             // valid while ≥ every lane floor it is checked against; < 2^128
    uint256 validUntil;
}
```

In `ISCaaSDex`:

```solidity
struct LiquidityPlan {
    bytes32 ref;                         // the submitter's, echoed in events only
    ITradeToken.LiquidityOrder order;
    IUARegistry.UASig auth;              // a derived signer's registry auth; a native signer's signature in auth.signature
    uint256[] pull;                      // per input, the amount pulled: 0 < pull[i] ≤ order.inputs[i].amount
    uint256 positionId;                  // the received position's id (a new mint's id exists only after signing); 0 = none
    address[] extraTokens;               // intermediate tokens of the route (a swap inside a zap); each must end at its snapshot
}
function mtxLiquidity(LiquidityPlan calldata p, Interaction[] calldata interactions) external;          // nonReentrant (stub)
function liquidityOrderDigest(ITradeToken.LiquidityOrder calldata o) external view returns (bytes32);
event LiquiditySettled(bytes32 indexed ref, bytes32 indexed orderHash, bytes32 indexed from, bytes32 recipient,
    uint256[] pulled, uint256[] refunded, uint256[] received, uint256[] dexFees, uint256 positionId, uint128 liquidity);
```

Every value the DEX or a token reads is a named field: no packed `bytes`. `Interaction.data` is the outside AMM's calldata,
exactly as on the exchange path (CTR-DEX-20); SCaaS's own parameters never travel in it. The bound of eight inputs and eight
outputs (C9) covers the widest common pools (eight tokens) and keeps the node's decode and the order's verify cost bounded;
`LiquidityShape(2)` refuses more.

### 4.2 Typehashes

```text
LIQUIDITY_TOKEN_TYPEHASH = keccak256("LiquidityToken(address token,uint256 amount)")
LIQUIDITY_ORDER_TYPEHASH = keccak256(
  "LiquidityOrder(bytes32 from,LiquidityToken[] inputs,LiquidityToken[] outputs,address positionManager,"
  "address positionReader,uint256 positionIn,bytes32 positionPool,int24 tickLower,int24 tickUpper,uint128 minLiquidity,"
  "bytes32 recipient,uint256 fee,address relayer,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
  "LiquidityToken(address token,uint256 amount)")

hashToken(t)  = keccak256(abi.encode(LIQUIDITY_TOKEN_TYPEHASH, t.token, t.amount))
hashArray(ts) = keccak256(abi.encodePacked(hashToken(ts[0]), …, hashToken(ts[n-1])))      // empty array: keccak256("")
hashOrder(o)  = keccak256(abi.encode(LIQUIDITY_ORDER_TYPEHASH, o.from, hashArray(o.inputs), hashArray(o.outputs),
                  o.positionManager, o.positionReader, o.positionIn, o.positionPool, o.tickLower, o.tickUpper,
                  o.minLiquidity, o.recipient, o.fee, o.relayer, o.flags, o.batch, o.nonce, o.validUntil))
```

`int24` is encoded as a sign-extended 32-byte word (EIP-712 and `abi.encode` agree); a client that zero-extends a negative tick
produces another digest, so the vectors carry a negative-tick row (§12). Every field is always signed: there is no unbound field
to zero (no `canon` as `MetaTxLib.canon` has); `relayer = 0` is signed as 0.

### 4.3 The domain, and who recomputes the digest (C1)

```text
domain = EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)
       = ("SCaaS Dex", "1", block.chainid, the DEX clone, chain_uid)            // the DEX's own domain (CTR-DEX-18)
h      = keccak256(0x1901 ‖ separator(domain) ‖ hashOrder(o))
```

One signature, one domain, the DEX's, because one order spans several tokens. The order has **no `dex` field**: the domain's
`verifyingContract` binds the DEX, and a second field would be a second, conflicting truth (CTR-DEX-18's reason for requiring
`o.dex == address(this)` on a `DexOrder`). **Every verifier computes `h` itself:** the DEX from its own domain; each SCaaS input
token from the same formula with `verifyingContract = msg.sender` and `salt` = its own `chain_uid` (the clone's env, the same
value as the DEX's on one chain). A token never takes the digest from the DEX, so a contract the signer did not sign for
cannot make any token pull: its address gives another separator, so another digest. That is CTR-DEX-15's `msg.sender ==
o.dex` in digest form. The type hash differs from `DexOrder`'s, `TradeOrder`'s and `UATradeOrder`'s, and the token domains
are named `"SCaaS MetaToken"` / `"SCaaS ZetherToken"` / `"SCaaS PqzToken"`, so no other signed struct's digest can equal `h`.

### 4.4 State, lanes, cancel (C5)

- **One-shot.** A liquidity order executes once, whole: the DEX sets `pulled[h] = 1` (its `TradeLib` map, the map of
  `DexOrder`s; a different type hash, so no collision) before any pull, and refuses a closed order (`OrderClosed(h)`). Each
  SCaaS input token keeps its own `pulled[h] = amount` and refuses a second pull of `h` (§5). No partial fill, no
  `restorePulled`.
- **Lanes.** Every verifier checks `nonce ≥ minNonce[from][batch]` in its own map: the DEX in its own (the `DexOrder` lanes), each
  SCaaS input token in its order lanes (the `UATradeOrder` lanes). Raising any one floor kills the order, because one refusal
  reverts the whole plan. So a cancel uses the entries that exist: `SCaaSDex.mtxInvalidateNonces` (a native signer, DEX
  domain) or a SCaaS input token's `mtxInvalidateNonces(bytes32 from, …, UASig)` (any signer, derived included, token domain).
  Clients put a liquidity order on a lane of its own, since a raised floor also voids the lane's trade orders below it.
- **Expiry.** `validUntil` is checked by the DEX and by every token. Clients default to a short deadline (minutes), because
  there is no per-order cancel. A per-order nested cancel (`CancelLiquidityOrder(LiquidityOrder order)`) is not built: it would
  need a DEX entry with UA authorisation, which the DEX does not have today, for a short-lived intent; add it if a book of resting
  liquidity orders ever appears.

## 5. The token side: `mtxLiquidityPull` — SPECIFIED

One new entry in module T (the trade group, CTR-TOK-30) of every token kind, beside `mtxTrade`:

```solidity
function mtxLiquidityPull(LiquidityOrder calldata o, IUARegistry.UASig calldata auth, uint256 amount, address submitter)
    external;                                                                        // nonReentrant (the stub's guard)
event LiquidityPulled(bytes32 indexed orderHash, bytes32 indexed from, address indexed dex, uint256 amount);
```

Checks, in order (errors from `ITradeToken`, each carrying `h` where it has one):

| # | Check | Error |
|---|---|---|
| T1 | `msg.sender` is a contract and not the token; `o.from ≠ pad(this)` | `DexNotContract(msg.sender)`, `SelfOrder(h)` |
| T2 | `o.relayer == 0 ‖ o.relayer == submitter` (the DEX reports its own caller, as `TradeFill.submitter`) | `WrongRelayer(h, submitter)` |
| T3 | `block.timestamp ≤ o.validUntil` | `OrderExpired(h)` |
| T4 | `o.nonce < 2^128`; `o.nonce ≥ minNonce[o.from][o.batch]` (this token's order lanes) | `NonceAboveCap(h)`, `NonceInvalidated(h)` |
| T5 | this token is exactly one of `o.inputs` (index `i`) | `LiquidityShape(6)` |
| T6 | `0 < amount ≤ o.inputs[i].amount` | `ZeroFill(h)`, `Overfill(h)` |
| T7 | `h` computed by the token (§4.3, `verifyingContract = msg.sender`); `_pipeAuthorize(ctx, o.from, PURPOSE_TRADE, h, auth)`: a native id signs `h` itself (ECDSA low-s, ERC-1271 under the token's cap, HIP-632 on Hedera), a derived id through `requireAuthorized` | the pipeline's signature errors, `UALedgerOff`, the registry's (`UAVerifyGas` included) |
| T8 | `pulled[h] == 0`; then `pulled[h] = amount` | `OrderClosed(h)` |
| T9 | move exactly `amount` from `o.from` to `msg.sender` by `_uaMove` (a derived signer: `Transfer(UA_POOL, dex)` + `UATransfer`); emit `LiquidityPulled` | the token's own (`_update` hooks: pause, freeze, eligibility on 8–13) |

- **The signature is always checked** (no `pulled[h] ≠ 0` skip as on a second trade fill): the order is one-shot.
- **No transient pull counter.** T9 does not bump `TradeLib`'s `_inTx` counter, so `restorePulled` can never lower anything
  here; `mtxCancelOrder` and `restorePulled` compute digests of `UATradeOrder`s and cannot name `h` either.
- **Not on any allowlist:** absent from `mtxSelectors`, so `mtxExecute` cannot self-call it (and T1's `msg.sender ≠ this` refuses
  the self-call anyway); a direct read of `msg.sender`, never `_msgSender()` (CTR-MTX-18), as `mtxTrade`.
- **Purpose (C2):** the UA purpose `trade`, whose row in the purposes table gains "and of `LiquidityOrder` in the DEX's domain".
  The type hash and domain already separate the digest; a new purpose would touch `kinds.json` and the six UA libraries for no
  separation gained.
- **Every kind:** the body is written once in `ERC20MetaTx` (rule 5), the face of each kind gets one stub through
  `script/t66b/entries.json` and `gen_faces.py`; the hashing is one internal library, `LiquidityLib` (type hashes,
  `hashOrder`, the separator), compiled into module T and into the DEX's liquidity module. Zether and PQZ kinds pull their
  public balance only. Regulated kinds (8–13) apply their checks to the move (`R(dex)`, the payer's freeze, pause); the DEX's
  next move into a pool needs the pool eligible, so a regulated input into an outside pool fails closed unless the registry
  admin made that pool eligible ([CTR-AS-16](../../contracts/asset-suite.md#CTR-AS-16)).
- **No storage change:** the `pulled` and `minNonce` maps exist; layouts and `namespaces.json` do not move.

## 6. The DEX side: `mtxLiquidity` — SPECIFIED

One plan, atomic, no `try`: any failure reverts the transaction, starvation errors included (nothing to isolate). The stub on
`SCaaSDex` holds the DEX's transient `nonReentrant` guard across the `DELEGATECALL` into `SCaaSDexLiquidityModule` (§9.2).
`submitter = msg.sender` of the stub.

1. **Check** (no state change before 1 ends; views only):
   - **Shape** (`LiquidityShape(code)`): (1) at least one input (an ERC-20 or `positionIn`) and at least one output (an ERC-20
     or a received position); (2) at most eight inputs and eight outputs; (3) no zero token, no zero input maximum, no token twice
     in `inputs`, twice in `outputs`, in both, or equal to `positionManager`; (4) the position fields agree: `positionManager ==
     0` ⇒ every other position field 0; a position received (`positionPool ≠ 0`) ⇒ `positionReader ≠ 0`, `tickLower <
     tickUpper`, `minLiquidity > 0`; none received ⇒ `positionReader`, the ticks and `minLiquidity` all 0; (5) the recipient after
     its default (`recipient == 0 ? from : recipient`) is neither the DEX nor its puller.
   - `relayer == 0 ‖ relayer == submitter` (`WrongRelayer(submitter)`); `validUntil` (`OrderExpired(h)`); `nonce < 2^128`
     (`NonceAboveCap(h)`); the DEX's lane (`NonceInvalidated(h)`); `flags & ~LISTED_POOLS == 0` (`BadFlags(h)`); `fee ≤ 10 000`
     (`FeeAboveCap(h)`); `pulled[h] == 0` (`OrderClosed(h)`); `p.pull.length == inputs.length` (`LengthMismatch`), each `0 <
     pull[i] ≤ inputs[i].amount` (`ZeroFill(h)`, `Overfill(h)`).
   - **Kinds (C6):** an input is SCaaS iff the DEX recorded it so at `setMarket` (`tokenKind == 1`, CTR-DEX-18: never from the
     plan); everything else is outside and goes through the puller. The record comes from the factory, so only one wrong
     direction exists, and it fails closed: a SCaaS token never listed (no record) goes to the puller, which has no allowance to
     spend (CTR-TOK-01); a contract that moved less than asked is refused by step 3's arrival check. No token must be a listed
     market side for this entry (an LP token is not one); under the
     listing condition every token an interaction calls is a target and must be listed, as on the exchange path.
   - **UA rules (CTR-UA-27):** a derived `from` may give only SCaaS inputs whose UA ledger is on and no position
     (`UALegNotLedger(token)`); a derived recipient may receive only SCaaS outputs with the ledger on and no position
     (`UAReceiveNotLedger(token)`). So a derived UA deposits its SCaaS tokens and names a native recipient for an LP token or a
     position (its Safe, its `SmartKeyAccount`); it never withdraws, since it never holds LP.
   - **The DEX's own verify:** when any input is outside or `positionIn ≠ 0`, the signer is native (above) and
     `SigCheck.isValid(addr(from), h, auth.signature, _cap(from))` must hold (`BadSignature(h)`; a starved ERC-1271 check
     `SigCheckGasStarved`). With SCaaS inputs only, the tokens verify `h` (§5) and the DEX does not repeat it: every input is
     verified by the token that moves it, each over the whole order, before step 4 runs.
   - **Effect:** `pulled[h] = 1`.
2. **Snapshot** the DEX's balance of every input, output and `extraTokens` entry (`_bal`, gas-capped); the DEX's balance of
   `positionManager` (ERC-721 `balanceOf`) when it is set; the recipient's balance of every output (`balanceOf`, or
   `balanceOfUA` for a derived recipient).
3. **Pull.** A SCaaS input: `token.mtxLiquidityPull(o, auth, pull[i], submitter)`. An outside input:
   `DexPuller.pull(token, addr(from), pull[i])`. A given position: `DexPuller.pull(positionManager, addr(from), positionIn)`,
   then `ownerOf(positionIn) == DEX` (`PositionNotReceived(positionIn)`). Then each input's balance equals its snapshot plus its
   pull (`ConservationBroken(token)`: a fee-on-transfer or rebasing input fails here, before any interaction).
4. **Route:** every interaction under CTR-DEX-23 (`_interact`): not the DEX or the puller (`ForbiddenTarget`); `data.length ≥
   4` and none of the forbidden selectors (`ForbiddenSelector`), which this spec extends for **every** DEX entry with
   `mtxLiquidityPull` and `setApprovalForAll` (0xa22cb465), and for this entry with `approve` (0x095ea7b3) whose target is
   `positionManager` (§10 T6); listed targets when `listedOnly` or `LISTED_POOLS` (`TargetNotListed`); a failure reverts
   `InteractionFailed(index, target, reason)`; every `approve` an interaction granted is reset to 0 after the last one.
5. **A received position, before any payout** (positionPool ≠ 0; `id = p.positionId`): `ownerOf(id) == DEX`
   (`PositionNotReceived(id)`); `exchangeTarget[positionReader]` and `reader.manager() == positionManager`
   (`PositionReaderNotListed(reader)`); `reader.position(id)` (a gas-capped `staticcall`, its revert data dropped:
   `PositionUnreadable(reader)`) returns the signed `positionPool`, `tickLower`, `tickUpper` and `encumbered == false`
   (`PositionMismatch(id)`) and `liquidity ≥ minLiquidity` (`PositionBelowMin(id, liquidity)`); then
   `positionManager.transferFrom(DEX, recipient, id)` (gas-capped; `transferFrom`, never `safeTransferFrom`, so no callback into
   the recipient) and `ownerOf(id) == recipient` (`PositionNotDelivered(id)`). A given position that still exists, is owned by
   the DEX and is not `id` goes back to `from` the same way (the rest of a partial withdraw, a fee collect).
6. **Outputs.** For each output `j`: `got = bal − snap` (below the snapshot ⇒ `ConservationBroken(token)`); `dexFee =
   ⌈got · fee / 10⁶⌉` (CTR-DEX-11); pay `got − dexFee` to the recipient (`_sendTo`: `transfer`, or `transferToUA` for a derived
   recipient); then the recipient's balance minus its snapshot must be at least `outputs[j].amount`
   (`InsufficientOutput(token)`); only then the fee shares, `⌊dexFee · relayerSharePpm / 10⁶⌋` to the submitter and the rest to
   the treasury (CTR-DEX-17). **The minimum is net and measured where it lands (C3):** it covers a fee-on-transfer LP token on the
   last hop, and a route that sends straight to the recipient (then `got = 0`, no fee, the delta still counts). Measuring before
   the fee shares keeps a recipient that is also the submitter or the treasury from counting its share. **The fee (C4)** is the
   DEX's model applied to what the signer receives in ERC-20s; a received position carries none; `fee = 0` is valid and the
   entry stays relayable (a relayer may also be paid through `RelayFeeRouter` around `mtxLiquidity`).
7. **Refunds.** For each input: `left = bal − snap`; below 0 or above `pull[i]` ⇒ `ConservationBroken(token)` (the route
   cannot hand back more than was pulled); `left` goes to `from`, fee-free.
8. **Conservation.** Every snapshotted token, and the `positionManager` balance, equal their snapshots (`ConservationBroken`).
   The DEX holds nothing of this plan after it; a stray balance in a plan token is neither paid out nor taken (the sweep rule of
   CTR-DEX-20 for other tokens is unchanged).
9. **Event** `LiquiditySettled(ref, h, from, recipient, pulled, refunded, received, dexFees, positionId, liquidity)`: a client
   checks every figure against the signed order without trusting the submitter.

```mermaid
sequenceDiagram
    autonumber
    participant R as Relayer
    participant D as SCaaSDex (stub, guard held)
    participant L as SCaaSDexLiquidityModule
    participant A as SCaaS token A
    participant P as DexPuller
    participant B as Outside token B
    participant X as v2-style pair
    R->>D: mtxLiquidity(plan, interactions)
    D->>L: DELEGATECALL of the calldata
    L->>L: check the order, verify h (an outside input), pulled[h] = 1, snapshot
    L->>A: mtxLiquidityPull(order, auth, pullA, R)
    A->>A: h with verifyingContract = caller; signature; pullA ≤ max; once
    A-->>L: pullA, from → DEX
    L->>P: pull(B, from, pullB)
    P->>B: transferFrom(from, DEX, pullB)
    L->>X: A.transfer(pair, a), B.transfer(pair, b), pair.mint(DEX)
    X-->>L: LP to the DEX
    L->>L: LP − fee to the recipient; its delta ≥ min LP; fee split; leftovers of A, B to from; conservation
```

## 7. Positions (ERC-721) and the reader — SPECIFIED

### 7.1 Why ownership alone is not enough, and the reader (Q1)

`ownerOf(position) == recipient` proves who owns a position, not what it holds. The DEX does not parse interactions, so a hostile
submitter can mint the deposit into a position of its own (`mint{recipient: attacker}`, a listed position manager, the DEX's
tokens) and mint a dust position to the DEX; the dust one reaches the recipient and passes an ownership check. An ERC-20 LP
output has a value bound (the minimum amount of that pool's LP); a position needs one too. So a received position is checked
against **the signed pool, range and minimum liquidity** through a reader:

```solidity
/// Read-only, one per position-manager family, no state, no admin; listed by a holder of LISTING (`setExchangeTarget`).
interface IPositionReader {
    function manager() external view returns (address);   // the one position manager it reads (immutable)
    /// `poolId`: v4 the PoolId (keccak256 of the PoolKey: currencies, fee, tick spacing, hooks); v3 the pool address as bytes32.
    /// `encumbered`: anything that lets a third party act on the position after a transfer (v4: a subscriber).
    function position(uint256 tokenId) external view
        returns (bytes32 poolId, int24 tickLower, int24 tickUpper, uint128 liquidity, bool encumbered);
}
```

- `V3PositionReader(npm, v3Factory)`: `npm.positions(id)` → `(token0, token1, fee, tickLower, tickUpper, liquidity)`, `poolId =
  bytes32(uint256(uint160(v3Factory.getPool(token0, token1, fee))))`; `encumbered = false` (v3's per-token approval, the
  position's `operator`, is cleared by the transfer [inference, checked by the fork test]).
- `V4PositionReader(positionManager)`: `getPoolAndPositionInfo(id)` → `PoolKey` and the packed info, `poolId =
  keccak256(abi.encode(key))`, the ticks from the info, `getPositionLiquidity(id)`, `encumbered = hasSubscriber` [inference,
  checked against v4-periphery at the fork block].
- The reader is **signed** (`positionReader`, the wallet shows it; clients default to the chain profile's reader for that manager)
  **and listed** (`exchangeTarget[reader]`, whatever `listedOnly` says): a phished signer is still protected unless a holder of
  `LISTING` listed the reader too. A reader is ≈ 40 lines of view code, not an execution adapter: execution stays generic.
- **Pool and range bind value:** in a fixed pool and range, liquidity determines the token amounts at every price, so
  `liquidity ≥ minLiquidity` in the signed `(poolId, tickLower, tickUpper)` is a value bound as strong as an LP minimum. A
  position the submitter brings from elsewhere that meets it is worth at least what the signer asked; the pool id includes v4's
  hooks address, so a hostile hook is a different pool.
- **The puller pulls a position by its unchanged `pull` (C7):** ERC-721 `transferFrom(address,address,uint256)` has ERC-20's
  selector, so `DexPuller.pull(positionManager, from, positionIn)` moves the position under the owner's `approve(puller, id)`;
  `TokenCall.ok` accepts its empty return. The DEX then checks `ownerOf(positionIn) == DEX` (step 3), so the selector's double
  meaning never decides anything. Changing `DexPuller` would grow `SCaaSDex` itself: `initialize` creates the puller, so the
  puller's creation code is part of the DEX's runtime [inference from `SCaaSDex.sol:191`].

### 7.2 What the order shapes express

| Operation | inputs | outputs | `positionIn` | received position |
|---|---|---|---|---|
| v2-style add | A ≤ a, B ≤ b | LP ≥ l | — | — |
| v2-style withdraw | LP ≤ l | A ≥ a, B ≥ b | — | — |
| v3 / v4 mint | A ≤ a, B ≤ b | — | — | pool, range, ≥ L (id from the plan) |
| v3 / v4 add to a position | A ≤ a, B ≤ b | — | id | the same id, ≥ L (its liquidity after) |
| v3 / v4 withdraw, whole | — | A ≥ a, B ≥ b | id | — (burnt, or returned empty) |
| v3 / v4 withdraw, part; fee collect | — | A ≥ a, B ≥ b | id | — (the rest comes back to `from`, step 5) |
| move a range | — (or top-ups) | — (or change) | old id | new pool / range, ≥ L |
| zap (one token in, a swap inside) | A ≤ a | LP ≥ l | — | — (`extraTokens` for the hop) |

## 8. Pool creation and the three target families — SPECIFIED

### 8.1 Create pool

Creating a pool moves no user token and needs no allowance: v2 `factory.createPair(A, B)`, v3 `factory.createPool` and
`pool.initialize(sqrtPriceX96)` (or the NPM's `createAndInitializePoolIfNecessary`), v4 `PoolManager.initialize(key,
sqrtPriceX96)` are open to anyone. The plan covers it both ways, with no new entry:
- **Directly:** anyone (the user, any relayer) sends the factory call as an ordinary transaction. SCaaS adds nothing to it.
- **As the first interaction of the depositor's plan:** the DEX calls the factory, then deposits. Its checks are unchanged.

The first deposit sets the price of a v2 pair, and the initialiser sets a v3 / v4 price. A front-runner can create or initialise
at another price; the signed bounds then decide: for a v2 pair, `min LP` with the input maxima bounds the band of prices at which
the deposit can land (LP = min over the sides of deposit / reserve × supply), and for a position the signed range is the band of
prices at which the signer agreed to provide liquidity. Clients quote the pool's state right before signing and keep the slack
small (§10 T1).

### 8.2 The families on path (a), with no callback [inference, each case a test]

- **v2-style:** add = `A.transfer(pair, a)`, `B.transfer(pair, b)`, `pair.mint(DEX)`; withdraw = `LP.transfer(pair, l)`,
  `pair.burn(DEX)`. No approval at all. Through `Router02`: `approve(router, …)`, `addLiquidity(…, to = DEX, …)`, reset after.
- **v3 `NonfungiblePositionManager`:** `approve(npm, …)` per input, `mint{recipient: DEX}` (or `increaseLiquidity`),
  `decreaseLiquidity`, `collect{recipient: DEX}`, `burn`; the DEX owns a given position during the plan, so it needs no approval
  of the NFT.
- **v4 `PositionManager`:** Permit2 `approve` is a forbidden selector (CTR-DEX-23), so the route pays from the manager's own
  balance: `A.transfer(posm, a)`, `B.transfer(posm, b)`, `modifyLiquidities([MINT_POSITION(owner = DEX), SETTLE(A, open,
  payerIsUser = false), SETTLE(B, …), SWEEP(A, DEX), SWEEP(B, DEX)])`; withdraw: `DECREASE_LIQUIDITY` / `BURN_POSITION`,
  `TAKE_PAIR(DEX)`. Native-currency pools are refused, as in `UniswapExecutor` (the DEX holds no native coin).

None needs a callback into the DEX, so the executor form is not built (Q3). A pool-level v3 `mint` (with
`uniswapV3MintCallback`) would need one and gives no transferable position; it is not a target.

## 9. Placement: the module, the stubs, the wiring — SPECIFIED

### 9.1 Contracts

| Contract | Change |
|---|---|
| `SCaaSDexCore` (new abstract base, `src/dex/SCaaSDexCore.sol`) | the DEX's state accessor (`scaas.dex`), constants and the shared bodies moved from `SCaaSDex.sol` unchanged (rule 5, written once): `_interact`, `_route`, `_send`, `_sendTo`, `_bal`, `_tokenFailed`, `_ledgerOn`, `_cap`; `_interact` gains the two selectors of step 4 |
| `SCaaSDexLiquidityModule` (new, `src/dex/SCaaSDexLiquidityModule.sol`) | group id **11** (`GROUP_LIQUIDITY`; 1–10 are taken, `gen_faces.py` `GROUP_ID`); `mtxLiquidity` and `liquidityOrderDigest`, each `onlyDelegated` (`NotDelegated()`); `moduleGroup()`, `factory()` answer a direct call; constructor `(factory_, bytes)` like the governance module (M1); no state of its own (M6), no guard (M3), no `SELFDESTRUCT` / `CALLCODE` (M5), never calls another module (M7) |
| `SCaaSDexGovernanceModule` (renamed from `SCaaSDexD`, R7) | the name only; group id 10 unchanged |
| `SCaaSDex` | inherits `SCaaSDexCore`; `implArgs = abi.encode(ImplArgs{modules: [governance, liquidity]})`: the constructor checks two modules (count and code: `ModuleMissing(i)`; `moduleGroup()` 10 and 11 and `factory()`: `ModuleMismatch(i)`); `modules()` lists both; two stubs (§9.2) |
| `IPositionReader`, `V3PositionReader`, `V4PositionReader` (new, `src/dex/`) | §7.1; no admin, immutables only; not body modules (called by `staticcall`), not pinned in the env: their trust is the listing |
| `ITradeToken`, `ERC20MetaTx`, module T of every kind, `LiquidityLib` (new internal library) | §5 |
| `DexPuller`, `OpenFactory` | no code change; the DEX env's `libs` / `libCodeHashes` pin the liquidity module beside the governance module, so `ModuleNotPinned` covers it |

### 9.2 Stubs

- `mtxLiquidity(LiquidityPlan, Interaction[]) external nonReentrant` forwards the unchanged calldata by `DELEGATECALL` to the
  liquidity module and reverts with its revert data verbatim; it **returns nothing**, so the stub keeps OpenZeppelin's
  `nonReentrant` and returns normally: S1's rule (never a modifier behind an assembly `return`) holds without a hand-written
  enter / exit, and a re-entry into any DEX entry during the plan reverts `ReentrancyGuardReentrantCall`.
- `liquidityOrderDigest(LiquidityOrder) view` forwards as the governance views do (`_forwardRaw` under the view cast, S2); the
  existing `_forwardView` takes the module address as a parameter instead of reading `_MD`.

### 9.3 Size [estimate]

| Contract | Today [measured] | After [estimate] | Line |
|---|---:|---:|---|
| `SCaaSDex` (release) | 32,991 B | 33,240–33,440 B (two stubs, the second module's immutable and `modules()` row, two selectors in `_interact`; the constructor's check is init code) | 33,594 B margin (≈ 57 M), 35,386 B hard (60 M) |
| `SCaaSDexLiquidityModule` | — | 8–13 KB (the body ≈ 5–7 KB, the shared bodies compiled in ≈ 3–5 KB, the plan's decoder ≈ 1–2 KB) | 33,780 B body-module margin |
| module T, per kind | 14,253–17,045 B | +1.0–1.8 KB (the body, the order's decoder with two dynamic arrays, the DEX separator) | 33,780 B |
| token releases, per kind | 13,734–27,713 B | +40–70 B (one stub) | 33,594 B |
| readers | — | 1.5–3 KB each | — |

**Stop rule:** if the built `SCaaSDex` passes 33,594 B, the build stops and reports the measured figure with the lever: forward
the DEX-domain signed entries that share the module's signature check (`mtxCancelOrders`, `mtxInvalidateNonces`, and their
digest views) into the liquidity module (≈ −0.5 to −0.9 KB [estimate]); the owner decides. No micro-optimisation, no `via_ir`.

## 10. Threat model — SPECIFIED

The submitter is untrusted unless the signer bound `relayer`; every interaction target is untrusted unless listed; the AMM is
untrusted. **What the signer is guaranteed is exactly its signed bounds:** each input at most its maximum, once; each output at
least its minimum at the recipient; a received position with at least the signed liquidity in the signed pool and range; every
leftover back. The slack between those bounds and the market can be taken by an open submitter, as above an exchange-path floor
(CTR-DEX-21, NODE-DEX-18): clients bind `relayer` to the venue node by default and keep the bounds tight.

| # | Threat | Defence |
|---|---|---|
| T1 | **A crafted interaction steals the pulled funds** (interactions run as the DEX: `A.transfer(attacker, x)`) | the DEX holds only this plan's funds (one signer, nothing between calls); the outputs must still reach the minima at the recipient (step 6) and the position its minimum (step 5), so a theft is bounded by the slack the signer signed; the leftovers are measured, not claimed (step 7); `ForbiddenTarget` (DEX, puller) and the forbidden selectors; `relayer` binding against an open submitter; sandwiching is bounded the same way (§8.1) |
| T2 | **An interaction pulls someone else's signed order** (`mtxTrade`, `mtxLiquidityPull` of a victim, which names this DEX) | both are `ForbiddenSelector` in every DEX entry (`mtxLiquidityPull` added by this spec to `mtxExchange`, `mtxHybrid`, the batch and `mtxLiquidity`): otherwise the victim's pull would land in the DEX mid-plan, the attacker would move it out and conservation would balance; the puller is a forbidden target, so no outside allowance can be spent |
| T3 | **LP or outputs sent to the wrong recipient** | the recipient is signed; the minimum is the recipient's balance delta, measured after its payout and before the fee shares (shared addresses do not count); recipient ∉ {DEX, puller}; a derived recipient only for SCaaS outputs with the ledger on |
| T4 | **NFT position spoofing** (dust position, foreign position, wrong pool, a position with a third party's rights on it) | §7.1: the reader check of pool, range, liquidity and `encumbered`; ownership by the DEX before the forward and by the recipient after; the reader signed and listed and bound to its manager; transfers clear per-token approvals; `setApprovalForAll` forbidden in every interaction, so no operator over the DEX's positions can be left for a later plan |
| T5 | **Fee-on-transfer or rebasing LP tokens and inputs** | inputs: the arrival check of step 3 refuses a short credit before any interaction; outputs: the recipient-side minimum covers a fee on the last hop; conservation backs both |
| T6 | **Residual allowances** | `approve` allowances reset to 0 after the last interaction (built); `increaseAllowance`, Permit2 `approve`, `setApprovalForAll` refused; an `approve` aimed at `positionManager` refused (ERC-721 `approve(address,uint256)` shares ERC-20's selector, and the reset `approve(spender, 0)` would name token id 0); the users' own allowances are to the puller only, which only the DEX calls after verifying a signed order for that amount; clients approve a position per id, never for all |
| T7 | **Reentrancy** | the stub's `nonReentrant` across the module; tokens' own guard on `mtxLiquidityPull`; positions forwarded by `transferFrom` (no `onERC721Received`); the reader is a `staticcall`; hook tokens are gas-capped (`TOKEN_GAS`) and their revert data dropped (W-O) |
| T8 | **Deadline and nonce replay** | `validUntil` at every verifier; lanes at every verifier (§4.4); `nonce < 2^128`; one-shot on the DEX (`pulled[h] = 1` before the pulls) and on every token (`pulled[h]`); another chain: `chainId` and `chain_uid` in the domain; another DEX: `verifyingContract`, recomputed by each token from its caller; another struct: the type hash and the domain name |
| T9 | **A phishing contract as the DEX** | it can only use a signature made for its own address (§4.3), the residual CTR-DEX-19 accepts; clients and the signer refuse a `verifyingContract` off the chain profile's DEX list |
| T10 | **Misclassified tokens** | the kind is the DEX's record, never the plan's; both wrong directions fail closed (step 1) |
| T11 | **Gas starvation** | no isolation, so a starved verify (`SigCheckGasStarved`, the registry's `UAVerifyGas`) reverts the whole transaction at the relayer's cost; interactions wrapped by `InteractionFailed` with at most 256 bytes; the reader gas-capped |
| T12 | **Pool price set by a front-runner** (creation, initialisation) | §8.1: the signed minima bound the price band; quotes right before signing |
| T13 | **The DEX's own funds or strays** | conservation of every plan token and of the position balance; strays in plan tokens are neither paid nor taken |
| T14 | **EIP-7702** | a designator signs by its own key only (SigCheck, the pipeline); the submitter and `relayer` are open roles, compared without a designator check (owner rulings D3 / D4) |

## 11. Node — SPECIFIED

- **The row.** `typed.rs` `PLAIN` gains `("mtxLiquidity", D, "LiquidityPlan p,Interaction[] interactions")`; the struct table
  gains `("LiquidityToken", "address token,uint256 amount")`, `("LiquidityOrder", "<the 17 fields of §4.1>")` and
  `("LiquidityPlan", "bytes32 ref,LiquidityOrder order,UASig auth,uint256[] pull,uint256 positionId,address[] extraTokens")`;
  `abi.rs` the `sol!` types and the function. Kind `dex`, target rule unchanged: a DEX on the chain profile's DEX list
  ([NODE-JOB-20](../../node/job-api.md#NODE-JOB-20), NET-ALL-24). The table row in `job-api.md`'s `dex, plain` line.
- **Equal to the contract's, both ways.** The generator writes the DEX's state-changing relayable entries (its ABI's non-view `mtx*`
  selectors) into the vectors (`dexEntries`); a forge test checks that list against `SCaaSDex`'s ABI, and a node test checks the
  node's `dex` rows against it in both directions (a contract entry without a row, a row without an entry: both fail). On the
  token side `mtxLiquidityPull` has **no row** (only a DEX calls it): a node test refuses a `call` job naming it on a token, and
  the token's `mtxSelectors` is checked not to contain it (both sides absent, as `mtxTrade`).
- **Bounded decode.** By type: `LiquidityPlan` → `LiquidityOrder` → `LiquidityToken[]` is three levels, `UASig` its existing two;
  `inputs` and `outputs` at most 8 (`BAD_PAYLOAD: p.order.inputs: more than 8`), `pull` exactly as long as `inputs`,
  `extraTokens` and `interactions` under the exchange rows' existing bounds; `int24` by range; addresses of exactly 20 bytes.
- **Pre-checks before simulation:** the node computes `h` (§4.3) and must equal `liquidityOrderDigest`; a native signer's
  signature over `h` (`valid_sig`, CTR-UA-24's rule); `relayer` 0 or this lane; `validUntil` ahead; `pulled(h) == 0` on the DEX.
- **Job example** (named fields only; `Interaction.data` is the AMM's calldata, `bytes`, as on `mtxExchange`):

  ```json
  {"entry": "mtxLiquidity", "contract": "dex", "token": "0x<DEX>",
   "args": {"p": {"ref": "0x…", "order": {"from": "0x…", "inputs": [{"token": "0x…", "amount": "1000"}],
                  "outputs": [{"token": "0x<LP>", "amount": "990"}], "positionManager": "0x0000000000000000000000000000000000000000",
                  "positionReader": "0x0000000000000000000000000000000000000000", "positionIn": "0",
                  "positionPool": "0x0000000000000000000000000000000000000000000000000000000000000000",
                  "tickLower": 0, "tickUpper": 0, "minLiquidity": "0", "recipient": "0x…", "fee": "0",
                  "relayer": "0x<lane>", "flags": 0, "batch": "7", "nonce": "0", "validUntil": "1790000300"},
                  "auth": {"keyData": "0x", "signature": "0x…", "members": []}, "pull": ["1000"], "positionId": "0",
                  "extraTokens": []},
            "interactions": [{"target": "0x<pair>", "data": "0x…"}]}}
  ```

- **Completion and state:** completion is the receipt's `LiquiditySettled` with `orderHash = h`; `consumed` once
  `pulled(h) ≠ 0`; the in-flight key is `h` plus the bytes sent. Never `dead` while the transaction may still land.
- **Indexer:** `LiquiditySettled` (DEX) and `LiquidityPulled` (tokens), by the registered contract's address as every DEX event.
- **Who builds plans (proposed NODE-DEX-19):** in this round the submitter (a client or a namespace with `allow_call`) builds the
  plan and the node relays it as named fields; the `OrderRouter`'s liquidity planner (quotes, routes, the default `relayer`
  binding) is PLANNED. The node keeps no surplus (NODE-DEX-18).
- **Operators' note** (a new job shape): the `mtxLiquidity` row on `dex`, its refusals, and that `mtxLiquidityPull` is never
  relayed directly.

## 12. Clients and vectors — SPECIFIED

- **Vectors:** `smartcontracts/vectors/ua/liquidity_kat.json` from a new generator `smartcontracts/vectors/ua/gen_liquidity.py`
  (stdlib, beside the service pull's `gen_servicepull.py` pattern). Each row: the DEX domain, the typed data, `hashToken` of
  each element, `hashArray` of both arrays, `hashOrder`, `h`, the `mtxLiquidity` calldata, the `mtxLiquidityPull` calldata a
  token receives, and the signature of a test key. Rows: a v2 add (two inputs, one output); a withdraw (one input, two outputs);
  a mint with a **negative `tickLower`** (sign extension); a withdraw of a position (empty `inputs`: `keccak256("")`); a
  derived signer (p256) with a native recipient; eight inputs (the bound); the `dexEntries` list (§11). Readers: the forge
  KAT test (a new `test/v2/LiquidityKat.t.sol`: the DEX's `liquidityOrderDigest` and every kind's token-side digest
  equal `h`), `clientkeys`, `ua-rs`, and the node's typed KAT. A change of a byte format changes every reader at once.
- **`clientkeys`** (`evm.js`, the JS reference): `buildLiquidityOrder`, `checkLiquidityOrder` (refuses: `verifyingContract` off
  the chain profile's DEX list (CTR-DEX-19), `nonce ≥ 2^128`, more than eight inputs or outputs, a duplicate or shared token, an
  outside input or a position under a derived `from`, an outside output or a position for a derived recipient, `fee` above 1 %,
  a `positionReader` off the profile's reader list for its manager, `tickLower ≥ tickUpper`), and a test reading the vectors.
- **`ua-rs`** (branch `ua-rs-sign`, the only signer): the builder with the same refusals, signing under the purpose `trade`;
  **display:** the DEX (name and address), every input with its maximum, every output with its minimum (net), the position
  (manager, reader, pool, range, minimum liquidity, or the id given), the recipient (a warning when ≠ `from`), the fee, the
  relayer (a warning when 0), the lane and the deadline. Proposed CLI-SGN-49 (48 is the service pull's; re-check at the build).
  The bindings (`ua-c`, `ua-cxx`, `ua-qt`, `ua-cs`, `ua-py`, `ua-go`, `ua-dart`) call `ua-rs` and gain a smoke row. `zether-prover`
  gets nothing.

## 13. Gas [estimate]

Bases [measured, cited]: `mtxExchange` one plan 294,421 (CTR-DEX-28); `mtxHybrid` 1 × 1 + one hop 407,134 and `mtxSettle` 1 × 1
306,813 (CTR-DEX-27); `uaTrade` first fill 92,625 with a `p256` verifier (CTR-DEX-25); a governance call through D +3.4 k (T66b
§11 (a)); the registry's verify caps per kind (CTR-DEX-26's table, `mldsa65` 5,950,000).

| Case (regular gas, one transaction) | Estimate |
|---|---:|
| `mtxLiquidityPull`, native ECDSA, first touch of the token by the plan (stub → T, `h` with two arrays, ecrecover, `pulled[h]` SSTORE 22.1 k, two balance writes, event) | 45–65 k |
| the stub's forward of a 2–3 KB plan (cold module, calldata copy) | +4–8 k |
| v2-style add, two SCaaS inputs, native signer, LP output, `fee > 0` | 380–520 k |
| v2-style add, one SCaaS + one outside input (the DEX's verify + the puller) | 400–540 k |
| v2-style withdraw, LP via the puller, two outputs | 300–400 k |
| v4 mock mint, two inputs, reader check and forward | 500–800 k (real v4: 650–950 k) |
| a derived signer: + its kind's verify **per SCaaS input** (each token verifies) | `p256` +≈ 35 k each; `mldsa65` up to 5.95 M each |

**PQ fit:** two `mldsa65`-signed SCaaS inputs ≈ 12.3–12.6 M, under the EIP-7825 cap of 16,777,216 (Hedera 15 M); three do not
fit, as CTR-DEX-26's three-leg case. A two-token pool, the common case, fits every kind. A shared per-transaction verify cache in
the registry would remove the repeat; it is a registry change with its own review and is not proposed here. `DexGas.t.sol`
gains bounded rows for the cases above at 1.5 × these figures; no existing gas pin moves except where the build measures a move
(old → new in the commit: the DEX's entries if `_interact`'s two new comparisons show up, the token's trade entries if the
module-T dispatcher shifts).

## 14. Tests and mutants — SPECIFIED

**Red first:** every test below is written and run against today's tree before the build (it must fail, red, for the reason
named), then turns green with the change it covers. Mocks (test only, `test/helpers/`): `MockV2LiquidityPair` (v2 math:
`sqrt`, `MINIMUM_LIQUIDITY`, `mint` / `burn` / `sync`, an ERC-20 LP), `MockV2Factory` (`createPair`), `MockPositionManagerV4` on
the existing `MockPoolManager` (an ERC-721, `modifyLiquidities` with the actions of §8.2, a subscriber flag), and the two
readers run against the mocks and the fork.

**Positive controls** (`test/v2/DexLiquidity.t.sol`, `DexLiquidityPosition.t.sol`; per kind through
`test/metatx/helpers/KindRigs.sol` for the token side): every row of §7.2; a native EOA, an ERC-1271 `SmartKeyAccount`, a derived
`p256` UA and an `mldsa65` UA (two inputs, the PQ fit); `fee = 0` and `fee > 0` with the split; a route straight to the recipient;
create pair / initialise as the first interaction; through `Router02`-style approve and reset; a zap with an `extraTokens` hop;
every token kind as an input (public balances of Zether and PQZ, regulated with the pool eligible).

**Checks, their errors, their mutants** (one mutant per check, each alone, in the T64-style harness; each must turn its named
negative red while the original stays green):

| Check | Negative (one change from the positive control) | Expected | Mutant |
|---|---|---|---|
| L1 an input and an output | no input; no output | `LiquidityShape(1)` | M-L1 drop it |
| L2 at most 8 | nine inputs; nine outputs | `LiquidityShape(2)` | M-L2 |
| L3 tokens distinct, disjoint, non-zero | a token twice; in both; zero; equal to the manager; a zero maximum | `LiquidityShape(3)` | M-L3 |
| L4 position fields | a reader without a pool; ticks reversed; `minLiquidity = 0` | `LiquidityShape(4)` | M-L4 |
| L5 recipient | the DEX; the puller | `LiquidityShape(5)` | M-L5 |
| L6 relayer | another submitter | `WrongRelayer` | M-L6 |
| L7 expiry | `validUntil` past | `OrderExpired` | M-L7 |
| L8 nonce cap | `nonce = 2^128` | `NonceAboveCap` | M-L8 |
| L9 DEX lane | floor raised by `mtxInvalidateNonces` on the DEX | `NonceInvalidated` | M-L9 |
| L10 flags | flag 1 or 2 set | `BadFlags` | M-L10 |
| L11 fee cap | `fee = 10 001` | `FeeAboveCap` | M-L11 |
| L12 one-shot | the same plan twice | `OrderClosed` | M-L12 |
| L13 pull bounds | `pull.length` short; `pull = 0`; `pull > max` | `LengthMismatch`, `ZeroFill`, `Overfill` | M-L13 |
| L14 derived `from` | an outside input; a position given | `UALegNotLedger` | M-L14 |
| L15 derived recipient | an outside output; a position received | `UAReceiveNotLedger` | M-L15 |
| L16 the DEX's verify | a bad signature with an outside input; a position given with a bad signature | `BadSignature` | M-L16 |
| L17 arrival | a fee-on-transfer input; a fake "SCaaS" contract that moves nothing | `ConservationBroken` | M-L17 |
| L18 position given arrived | a manager that does not move it | `PositionNotReceived` | M-L18 |
| L19 interactions | target DEX / puller; `mtxTrade`, `mtxLiquidityPull`, `restorePulled` ×2, `increaseAllowance`, Permit2 `approve`, `setApprovalForAll`; `approve` on the manager; an unlisted target under `LISTED_POOLS` and under `listedOnly` | `ForbiddenTarget`, `ForbiddenSelector`, `TargetNotListed` | M-L19a…h, one per selector or rule |
| L20 approve reset | a router left with an allowance | the allowance is 0 after the plan | M-L20 |
| L21 received position owned | the position minted elsewhere | `PositionNotReceived` | M-L21 |
| L22 reader listed and bound | an unlisted reader; a reader of another manager | `PositionReaderNotListed` | M-L22 |
| L23 pool, range, unencumbered | another pool; another range; a subscriber set | `PositionMismatch` | M-L23 |
| L24 minimum liquidity | a dust position | `PositionBelowMin` | M-L24 |
| L25 delivered | a manager whose `transferFrom` keeps it | `PositionNotDelivered` | M-L25 |
| L26 output minimum, net, before fee shares | LP one unit short; a fee-on-transfer LP; the recipient is the treasury | `InsufficientOutput` | M-L26a drop it, M-L26b measure after the fee shares |
| L27 fee | `⌈got · fee / 10⁶⌉`, split, dust fill pays 1 | the event and balances | M-L27 floor instead of ceil |
| L28 refunds | a route that hands back more than pulled | `ConservationBroken` | M-L28 |
| L29 the rest of a given position | a partial withdraw | `ownerOf == from` after | M-L29 |
| L30 conservation | a route that leaves a plan token or a position in the DEX | `ConservationBroken` | M-L30 |
| L31 module | a direct call to the module | `NotDelegated` | M-L31 |
| L32 wiring | a DEX built with one module; with a module of another group or factory | `ModuleMissing`, `ModuleMismatch` | M-L32 |
| L33 the stub's guard | an interaction target re-enters `mtxLiquidity` (the same order) and `mtxExchange` | `ReentrancyGuardReentrantCall` (without the guard the first would read `OrderClosed`, the second would run) | M-L33 drop `nonReentrant` on the stub |
| T1 token: caller | an EOA; the token itself through `mtxExecute`; `from = pad(token)` | `DexNotContract`, the pipeline's refusal, `SelfOrder` | M-T1 |
| T2 token: relayer | `submitter` ≠ `relayer` | `WrongRelayer` | M-T2 |
| T3 token: expiry | past | `OrderExpired` | M-T3 |
| T4 token: lane | floor raised by `mtxInvalidateNonces` on the token (a derived signer: `UAInvalidateNonces`) | `NonceInvalidated` | M-T4 |
| T5 token: an input once | not an input; twice | `LiquidityShape(6)` | M-T5 |
| T6 token: amount | 0; above its maximum | `ZeroFill`, `Overfill` | M-T6 |
| T7 token: signature over its own `h` | signed for another DEX, chain, token domain or struct; a digest taken from the caller | the pipeline's signature error | M-T7a skip the verify, M-T7b build the separator from an address the caller passes instead of `msg.sender` |
| T8 token: one-shot | the same DEX pulls twice | `OrderClosed` | M-T8 |
| T9 token: no restore | `restorePulled` after a liquidity pull | `RestoreExceedsPull` | M-T9 bump the transient counter |

**Invariant** (`DexInvariant.t.sol` gains an `mtxLiquidity` handler over the v2 mock and the v4 mock, SCaaS, outside and UA
inputs; runs 128, depth 64, 0 reverts in the handler): between calls the DEX holds 0 of every token and no position and no
allowance; for every executed order each token's `pulled[h] ≤` its signed maximum and the DEX's `pulled[h] = 1`; each recipient
received at least each signed minimum; each signer's balance plus refunds plus pulls balances.

**Node:** the row and its selector; both-ways equality with `dexEntries`; the token entry refused; decode bounds (nine inputs, a
nested struct where a field is atomic, `int24` out of range, a dirty address); the digest against every vector row, the
negative tick included; the relayer and deadline pre-checks; completion by `LiquiditySettled`. Node mutants: M-N1 / M-N2 drop
each direction of the equality; M-N3 drop the eight-input bound; M-N4 zero-extend `int24`.

**Wiring and layout:** `LinkClosure` (the DEX's closure ∪ both modules), the opcode scan of the new module (`module-opcodes.json`),
its storage layout row equal to the DEX's (`test/v2/layout/`), `selector_audit.json` rows for `mtxLiquidity` and every kind's
`mtxLiquidityPull`, the size gate (§9.3).

## 15. On-chain matrix rows — SPECIFIED

In `script/onchain/Dex.s.sol` (group `dex`; `groups.json` and `coverage.json` gain the module and the entries), one book per run.

| Row | Local (fresh anvil, the v2-style and v4 mocks deployed by the script) | SCaaS testnet (RPC only, the same mocks: no Uniswap there) | Another testnet (optional) |
|---|---|---|---|
| D-L1 create a v2-style pair as the first interaction, then add two SCaaS inputs, native signer; LP to a second address | yes | yes | Sepolia: real `Router02` |
| D-L2 add one SCaaS + one outside input (the puller), `fee > 0`, the split | yes | yes | Sepolia |
| D-L3 add by a derived UA (`p256`), native recipient | yes | yes | — |
| D-L4 withdraw the LP for both tokens | yes | yes | Sepolia |
| D-L5 v4 mock: initialise a pool, mint a position (reader check), NFT to the recipient | yes | yes | Sepolia: real v4 `PositionManager` |
| D-L6 v4 mock: a partial withdraw (the rest back), then a whole one (burn) | yes | yes | Sepolia |
| D-L7 negatives on chain: an unlisted reader, `mtxLiquidityPull` inside an interaction, a replay | yes | yes | — |
| D-L8 views and wiring: `liquidityOrderDigest` = the vectors' `h`, `pulled(h)`, `modules()` lists two, the module's direct call `NotDelegated`, a token's `mtxLiquidityPull` called by an EOA refused | yes | yes | — |

Another testnet runs only on its RPC from the environment (never in the repo, a commit or a log) with throwaway keys; the opt-in
fork test (`test/fork/UniswapFork.t.sol`, `SCAAS_FORK_RPC_URL`, `FORK_BLOCK`) gains real-bytecode cases (v2 `Router02`
`addLiquidity` / `removeLiquidity`, v3 NPM mint / decrease / collect with `V3PositionReader`, v4 `PositionManager` mint with
`V4PositionReader`) and is the preferred real-AMM check, since it needs no key. Runs notes record addresses, transaction hashes
and gas, no key and no absolute path.

## 16. Docs and `decisions.md` — SPECIFIED

One rule, one place; each lands SPECIFIED, BUILT only with code and tests.

| Id | Where | Content |
|---|---|---|
| **CTR-DEX-30** (new) | `contracts/dex.md`, a new section "Liquidity" after §7 | `LiquidityOrder`, `mtxLiquidity`, steps 1–9, the domain and the one-shot rule, the lanes |
| **CTR-DEX-31** (new) | `contracts/dex.md`, the same section | positions and `IPositionReader`, signed and listed |
| CTR-DEX-15 Change | `contracts/dex.md` §3 | the token's second DEX-only pull, `mtxLiquidityPull` (§5) |
| CTR-DEX-22 Change | `contracts/dex.md` §7 | the puller also pulls a position, by `pull` |
| CTR-DEX-23 Change | `contracts/dex.md` §7 | `mtxLiquidityPull` and `setApprovalForAll` forbidden in every interaction |
| CTR-TOK-01 Change | `contracts/token-wrappers.md` §5, `decisions.md` | "A user provides AMM liquidity by a signed `LiquidityOrder` (CTR-DEX-30), never an allowance." |
| CTR-TOK-30 Change | `contracts/token-wrappers.md` | the module table: `SCaaSDexGovernanceModule` (10, renamed, R7) and `SCaaSDexLiquidityModule` (11); T gains `mtxLiquidityPull` |
| CTR-UA-10 Change | `contracts/accounts.md`, the purposes table | `trade` also covers `LiquidityOrder` in the DEX's domain |
| NODE-JOB-20 row | `node/job-api.md` | `mtxLiquidity` on `dex`, plain |
| **NODE-DEX-19** (new) | `node/dex-venue.md` | §11's who-builds-plans rule |
| **CLI-SGN-49** (new) | `clients/signers-clientkeys.md` on `ua-rs-sign` | §12's checks and display |
| decisions | `decisions.md` | CTR-DEX-30, -31 with the owner's answers to §18 (`owner: yes` once approved); R7, the module names |

## 17. Tasks — SPECIFIED

| Task | Content | Depends on | Agent-days |
|---|---|---|---|
| **L0** | **Rename `SCaaSDexD` → `SCaaSDexGovernanceModule`** (R7), no logic change; `GROUP_D` → `GROUP_GOVERNANCE` (id 10 kept); the file `SCaaSDexAdmin.sol` keeps its name (it also holds the base `SCaaSDexGovernance`). The tracked references outside `legacy/` [measured, `git grep`, 35 in 17 files]: `src/dex/SCaaSDex.sol`, `src/dex/SCaaSDexAdmin.sol`, `script/DeployBase.sol` (the artifact id `SCaaSDexAdmin.sol:SCaaSDexGovernanceModule`), `script/KindModules.sol`, `script/t66b/gen_faces.py`, `script/onchain/Dex.s.sol`, `Misc.s.sol`, `groups.json`, `test/ua/UADexAdmin.t.sol`, `test/v2/LinkClosure.t.sol`, `test/v2/module-opcodes.json`, `docs/contracts/token-wrappers.md`; the key in `deployments/31337-releases.json`; `size-baseline.json` has no module row today (only `SCaaSDex` and its form), so it moves only if the gate's row for `SCaaSDex` does; run records under `runs/` keep the old name (they record what ran) and `coverage.json` is regenerated. **Old → new:** the module's runtime and init-code hashes, its CREATE2 address, and the same for `SCaaSDex` and every contract whose compilation imports `SCaaSDexAdmin.sol` (the metadata hash covers the sources), in the commit and a runs note; the SCaaS testnet's Step 5 deploy keeps the old address until its next deploy (test-only, no migration). Gates: the DEX suites (`test/v2/Dex*.t.sol`, `test/ua/UADex*.t.sol`), `LinkClosure`, the layout and opcode tests, the size gate, `python3 scripts/docs_check.py check` | after Step 5b's commits (it edits `script/onchain/` in this worktree) | 0.5–0.75 |
| R | Review of this spec: Fable (design and security) and Codex, findings applied | — | controller |
| L1 | Red tests and mocks (§14): every test red on today's tree, the reason recorded | R | 2.5 |
| L2 | Token side: `LiquidityLib`, `ITradeToken` structs and events, `_mtxLiquidityPullBody`, `entries.json` + `gen_faces.py` on 12 kinds, `selector_audit.json`; module-T sizes per kind | L1 | 2 |
| L3 | DEX side: `SCaaSDexCore` extraction, `SCaaSDexLiquidityModule`, the stubs, the two-module constructor, `_interact`'s selectors, `DeployBase` / env pins / `releases.json` / `LinkClosure` / opcode scan / layout row, the size gate and §9.3's stop rule | L0, L2 | 3–3.5 |
| L4 | `IPositionReader`, `V3PositionReader`, `V4PositionReader`; their listing in the deploy scripts where a manager exists | L1 | 1–1.5 |
| L5 | Vectors: `gen_liquidity.py`, `liquidity_kat.json`, the forge KAT, `clientkeys` builder, checks and test | L2, L3 | 1.5–2 |
| L6 | Node: `abi.rs`, `typed.rs` rows, `dexEntries` equality, refusals, pre-checks, completion, indexer, the operators' note, mutants | L5 | 1.5–2 |
| L7 | `ua-rs` (branch `ua-rs-sign`): builder, refusals, display, the vectors; bindings' smoke rows | L5 | 1–1.5 |
| L8 | `DexGas` rows, the mutant harness (§14), the invariant handler | L3, L4 | 1.5 |
| L9 | On-chain matrix rows (local, then SCaaS testnet through its RPC only), the fork cases (opt-in) | L3, L4, L0 | 1.5 |
| L10 | Docs share (§16), `decisions.md`; BUILT tags only with code and tests | L2–L9 | 1 |
| | **In all** | | **17–20** |

Order: L0 → R → L1 → (L2 ∥ L4) → L3 → L5 → (L6 ∥ L7) → L8 → L9 → L10. In this worktree the 3c and Step 5b streams run beside it:
every commit stages by explicit path (`git commit --only`). Heavy commands through `scripts/capped`, in the foreground.

## 18. Owner questions

**Q1. ERC-721 positions: how is a received position's value bound?** `ownerOf(position) == recipient` alone lets a submitter put
the deposit into its own position and hand over a dust one (§7.1).
- (A) A signed and listed read-only reader per position-manager family checks the signed pool, range and minimum liquidity
  (§7.1): one small view contract per family, no execution adapter.
- (B) ERC-20 LP outputs only in this round; positions later.
- (C) Ownership only, as the direction's text says, the deposit guaranteed only by a trusted bound `relayer`.
- **Recommendation: A.** It keeps the outcome-only design and makes a position as safe as an LP minimum; (C) leaves a full-loss
  path open to any open submitter.

**Q2. Confirm the token change: a DEX-only entry `mtxLiquidityPull` in module T of every kind** (new token releases; one
signature over all inputs, recomputed by each token in the DEX's domain), against composing service pulls (no token change; one
`UAMetaTransfer` per SCaaS input; a blind `entryRef`; no outside inputs, so no withdraw and no SCaaS/outside pool) (§3).
**Recommendation: the token entry.** It is R3 made concrete; reusing `mtxTrade` with a `UATradeOrder` per input cannot share one
LP output or express a position.

**Q3. The executor form `mtxLiquidityVia`: now or when needed?** v2-style pairs, the v3 NPM and the v4 `PositionManager` all work
on path (a) without a callback (§8.2); an executor form adds an entry, a stub, a callback interface and its tests.
**Recommendation: not now;** add it with the first AMM whose liquidity flow needs a callback, mirroring `mtxExchangeVia`.
