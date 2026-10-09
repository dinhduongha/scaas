# Indexer and feeds

The indexer turns chain data into **final, quorum-agreed, contiguous ranges** of normalized events and writes them to
the events feed; job state changes go to the jobs feed. Clients book only from these feeds (nothing is booked before
finality, [NODE-GEN-08](README.md#NODE-GEN-08)). Status: finality gate, ranges ≤ 1 000 blocks, normalization and
drift on EVM **BUILT** (written to the legacy client sink); store-backed feeds and the event-set quorum on every family
**SPECIFIED**.

**Contents**

1. [Finality](#finality)
   - 1.1 [Event-set quorum](#11-event-set-quorum)
2. [Event normalization](#event-normalization)
3. [Feeds](#feeds)
4. [Event items](#event-items)
   - 4.1 [Cursors](#cursors)
5. [Drift and readiness](#5-drift-and-readiness)
6. [Snapshots](#snapshots)
7. [Limitations](#limitations)

## <a id="finality"></a>1. Finality

<a id="finality"></a><a id="finality-gate"></a><a id="NODE-IDX-02"></a>**NODE-IDX-02** — **The node decides finality;
clients receive only final ranges.** Each chain has `finality = {mode, depth, quorum}` in the node store
([NODE-STO-05](store.md#NODE-STO-05)): mode `depth` (final head = `latest − depth`), `tag` (the chain's `finalized`
tag), or `instant` (the family finalizes at inclusion). A flow tied to a payment uses hard finality: the booking delay
equals the chain's finality depth (e.g. ~3 minutes on Gnosis). The indexer follows the chain by **polling** the RPC
endpoints (no WebSocket subscriptions): a missed push message cannot lose a range, and the cursor is the only state.

`rpc_urls.len() ≥ quorum` or the node refuses to start; ranges are at most 1 000 blocks (`MAX_SPAN`); `/readyz` fails
when `final_head − indexed > max_index_lag` (default 100). The indexer writes the `range` item and advances
`chain_index` in one transaction; no token registered ⇒ the cursor holds. A client refuses a range that is not
contiguous (`from_block != indexed + 1`), so a restarted or doubled indexer never creates a hole or a duplicate; events
are further deduplicated by `(chain, tx_hash, log_index)`. There is no "observed" state: a non-final log can never
become a booking.

```
cursor = chain_index.indexed_block
loop:
  head_final = mode == 'tag'   ? min over quorum of eth_getBlockByNumber('finalized').number
             : mode == 'depth' ? min over quorum of latest.number − depth
             : min over quorum of latest committed height                 # instant
  to = min(head_final, cursor + 1000);  if to <= cursor: sleep poll_ms
  quorum: ≥ quorum endpoints return the same hash at 'to'; else no progress, warning, /readyz red
  events = adapter.events(cursor+1, to, contracts) from ≥ quorum endpoints; must be the same normalized list
  one transaction: INSERT feed_item(range) + UPDATE chain_index
  cursor = to
```

Finality per family (values re-checked per chain before it is enabled, [runbooks.md#production-gates](runbooks.md#production-gates);
family details in [networks/](../networks/README.md)):

| Family | Mode | Final head | Height unit | Notes |
|---|---|---|---|---|
| EVM private (chain 7622, Clique 1 signer) | `depth`, 1 | `latest − 1` | block | Reorg-free by construction |
| EVM public (Gnosis) | `tag` `finalized`, quorum ≥ 2 | `eth_getBlockByNumber('finalized')` | block | ~160–240 s; quorum 2 required before `active` |
| EVM L2 (Celo OP Stack) | `l1_batch` | L1-finalized batch | block | **PLANNED** (tracker item 13); until then `tag` |
| Hedera | `instant` | latest record file via JSON-RPC relay | block | aBFT |
| Cosmos | `instant` | latest committed block (`/status`) | height | CometBFT |
| Soroban (Stellar, Pi) | `instant` | `getLatestLedger` | ledger | SCP closed ledger |
| Sui | `instant` | latest certified checkpoint (quorum on digest) | checkpoint | |
| Aptos | `instant` | committed `block_height` (bounded by indexer progress) | block | AptosBFT |
| TON | `depth`, 0 | `masterchainInfo.last` | masterchain seqno | |
| Solana | `tag` `finalized` | `getSlot(finalized)`, min slot over quorum | slot | ~12.8 s TowerBFT |

Transitional (BUILT) loop, with the cursor read from the client:

```
cursor = node_config(chain).indexed_block
loop:
  head_final = mode == 'tag' ? eth_getBlockByNumber('finalized').number : latest.number - depth
  to = min(head_final, cursor + 1000); if to <= cursor: sleep
  hash_to = block(to).hash on the primary endpoint; quorum on hash_to (now: on the event set, NODE-IDX-01)
  logs = eth_getLogs(from = cursor + 1, to, address = [tokens…, dex], topics = [MetaTransactionExecuted, PaymentSettled, TradeSettled])
  chain_event_ingest(chain, cursor + 1, to, hash_to, decoded(logs))   # atomic on the client
  cursor = to
```

The client refuses a non-contiguous batch (`from_block != indexed_block + 1`), so a restarted or doubled indexer never
leaves a hole or writes twice; dedup also by `UNIQUE(chain_id, tx_hash, log_index)`. The store feed keeps the same
property with `from_block = indexed + 1`.

Other EVM networks (Ethereum L1, Arbitrum, Base, Polygon, …) are **unsupported until configured**: a chain is a
profile only once its finality has been measured ([networks/evm.md](../networks/evm.md)). Soft finality (booking small
amounts before hard finality under an exposure cap) is **PLANNED** and never applies to payment-bound flows.

<a id="no-reorg-after-finality"></a><a id="NODE-IDX-03"></a>**NODE-IDX-03** — **No reorg handling after hard
finality.** A reorg below the finality gate is outside the model (Gnosis `finalized` and a one-signer Clique chain do
not reorg); a booked entry would need a manual reversal. Before finality a reorg is invisible to clients: only final
ranges are sent. A suspected violation is detected and held, never rewound automatically
([NODE-OPS-12](ops.md#NODE-OPS-12)).

### 1.1 Event-set quorum

<a id="event-set-quorum"></a><a id="quorum"></a><a id="NODE-IDX-01"></a>**NODE-IDX-01** — **Finality authenticates the
events, not one block hash, on every family.** `final_head` = the minimum height reported by ≥ `quorum` endpoints,
with the same block/ledger/checkpoint hash at that height (`tag` mode: min `finalized`; `depth` mode: min `latest`);
`events(from, to)` is evaluated against ≥ `quorum` independent endpoints and must return the **same normalized list**
(the adapter's own output, so one comparison serves every family; EVM: sorted `(block_number, block_hash, tx_hash,
log_index, address, topics, data)`); disagreement ⇒ no ingest, warning, `/readyz` red. `quorum = 1` is
single-provider trust: allowed, reported at start and as gauge `scaas_finality_quorum{chain}`. Receipt proofs
(`eth_getBlockReceipts` against `receiptsRoot`) may replace the set comparison where providers serve them; not
required. Per family: EVM/Hedera `eth_getLogs`; Aptos per-transaction agreement (**BUILT**; the Indexer-API hint may
omit transactions, which only delays booking); Sui event query per checkpoint range; Solana per-signature transaction
(`emit_cpi` inner data) agreement; Soroban `getEvents` per ledger range; **Cosmos and TON honour the configured
quorum**: Cosmos `status` + `block` at the min height and the tx events of that range, TON `masterchainInfo` + the
jetton wallets' transactions of the range, each from ≥ `quorum` endpoints. Why: a primary provider sees every pending
payment through the node's own simulate calls and could fabricate a `PaymentSettled` at a real token address or report
`finalized = latest`. Cost: `quorum ×` reads per range. Status: Aptos **BUILT**; the other families read one endpoint
today and are **SPECIFIED**.

RPC endpoints are independent providers listed in `rpc_urls` (toml-only, [NODE-STO-03](store.md#NODE-STO-03)); the
quorum is the failover: a failed or lagging endpoint costs liveness only while ≥ `quorum` agree; a lying one is outvoted
or holds the indexer ([runbooks.md#incidents](runbooks.md#incidents) RB-05). There is no latency-based routing
between endpoints. Residual trust: clients trust their node's feed (a compromised node can lie on `/v1/events`,
[threat-model.md#node](threat-model.md#node) T7).

At start and every 600 s the indexer re-reads the hash at `indexed_block` from ≥ quorum endpoints; a mismatch holds that
chain (`finality violated at <block>`, [NODE-OPS-12](ops.md#NODE-OPS-12)).

## <a id="event-normalization"></a>2. Event normalization

<a id="event-normalization"></a>Every adapter emits one normalized event object; the feed changes nothing in it:
`{event, contract, block_number, block_hash, tx_hash, log_index, from, to, amount, fee, fee_recipient, entry_ref |
digest}` with family-canonical addresses (EVM lowercase `0x`, bech32, `0x`+64, `G…/C…` strkeys, raw `wc:hex`,
base58) ([INT-ERP-10](../integration.md#INT-ERP-10)). Events: `PaymentSettled`, `MetaTransactionExecuted`, and on EVM
`Transfer` to watched receiving wallets (drift A). Heights: block / height / ledger / checkpoint / masterchain seqno /
slot.

| Family | Height = | `tx_hash` | Events | Family-specific keys |
|---|---|---|---|---|
| EVM | block | `0x`+64 | `PaymentSettled`, `MetaTransactionExecuted`, `Transfer` (watched wallets only, drift A) | `relayer`, `batch`, `nonce`, `fee_recipient` |
| Hedera | block (JSON-RPC relay) | `0x`+64 | as EVM, via `index_runner` | as EVM |
| Cosmos | block height | `0x`+64 | `PaymentSettled`, `MetaTransactionExecuted` | bech32 addresses |
| Sui | checkpoint | `0x`+64 | same two | `entry_ref`, `digest` from Move events |
| Aptos | block | `0x`+64 | same two | |
| TON | masterchain seqno | `0x`+64 | same two | raw `0:…` addresses |
| Solana | slot | `0x`+128 (first signature) | same two (`emit_cpi!`) | base58 (case-sensitive) |
| Soroban | ledger | `0x`+64 | same two | `G…`/`C…` strkeys (case-sensitive) |

Common keys: `event`, `contract`, `block_number`, `block_hash`, `tx_hash`, `log_index`, `from`, `to`, `amount`, `fee`,
`fee_recipient` (families with relayer fees), `entry_ref` (`PaymentSettled`), `digest` (`MetaTransactionExecuted`).
Clients validate addresses in their own decoder.

Further events, same object, same filters (decoders for a new kind ship before the first such token is created,
[CTR-TOK-25](../contracts/token-wrappers.md#CTR-TOK-25)):

- token wrappers: `Wrapped`, `Unwrapped`, `ReserveAdded`, `RateChangeProposed`, `RateChanged`, `RateChangeCancelled`,
  `RateAdminRenounced`, `WrapDisabled`, `GuardianRenounced`, `MinterRenounced`, `MetaNonceCancelled`; factory
  `TieredTokenDeployed` (built kinds 0–4), `ImplementationRegistered`, `ImplementationDeprecated`;
- token-verified trade orders (SPECIFIED, [dex-venue.md#trade-orders](dex-venue.md#trade-orders)): on the sell token
  `TradeFilled(orderHash, from, sellFill, receiveFill, dexFee)`, `OrderCancelled(orderHash, from)`,
  `NoncesInvalidated(from, batch, minNonce)`; on the DEX `LegSettled(ref, orderHash, from, destination, sold, received,
  dexFee, refund, relayerShare, treasuryShare)` (the accounting record of a settled leg), on the exchange path
  `ExchangeLegSettled(ref, orderHash, from, destination, sold, receivedFloor, surplus, dexFee, refund, limitReceive)`
  ([CTR-DEX-20](../contracts/dex.md#CTR-DEX-20)), `FeeSplitSet`, `MarketSet`, `ExchangeTargetSet`, `ListedOnlySet`.
  The DEX watcher reads them with its own cursor ([NODE-DEX-04](dex-venue.md#NODE-DEX-04)); a `TradeFilled` alone is
  never booked as a trade (a leg pulled into the DEX for escrow shows the whole amount with nothing received);
- `ReceiverFeePaid` and the tender events of `chain_contract` rows (indexed like token events; a namespace receives
  them when the contract is in its token subset);
- universal accounts: `UATransfer`, `UAMetaTransactionExecuted`, `UARegistered` (with key data), balances per 32-byte
  id; `Transfer` to/from `UA_POOL` ([CTR-UA-18](../contracts/accounts.md#CTR-UA-18)) is paired with the
  `UATransfer` of the same log batch and reported as the UA movement, never as a `UA_POOL` balance; balances feed
  `/v1/events` per canonical id; native ids keep today's form;
- post-quantum Zether: `MetaTransactionExecuted`, `UAMetaTransactionExecuted`, `Transfer` and `UATransfer` of a PQZ
  token normalized like any meta token's, beside the `Pqz*` events ([contracts/pq-zether.md](../contracts/pq-zether.md));
- planned asset suite: `OrderRecorded`, `OrderRevoked`, `AccountFrozen`, `AccountUnfrozen`, `ForcedTransfer`, `Paused`,
  `Unpaused`, `FeatureDisabled`, `RoleGranted`, `RoleRevoked`, `Attested`, `AttesterSet`, `GrantCreated`, `Released`, `Revoked`,
  `RevocationRenounced`, `MilestoneApproved`, `ExcessSwept`, `DistributionCreated`, `Claimed`, `Cancelled`, `Swept`,
  `OfferCreated`, `Exchanged`, `Closed`, `Rescued`; `TieredTokenDeployed` (flags 5–8 are fields of the token, [CTR-AS-17](../contracts/asset-suite.md#CTR-AS-17)).

## <a id="feeds"></a>3. Feeds

<a id="feeds"></a><a id="NODE-IDX-04"></a>**NODE-IDX-04** — **Change feeds** (a client's data platform may land them in its own
`raw` tables; that platform is outside the node): `GET /v1/jobs?cursor=` (job state
changes) and `GET /v1/events?cursor=` (`GET /v1/events?cursor=…`: index ranges, balances, DEX items). `seq` comes from the store's counter row,
filtered per namespace; every page carries `store_id`, `incarnation`, `restore_epoch`, `head_seq`; the client cursor
rule is the bus overlap rule ([cursors](#cursors)); `wait ≤ 25 s` long-poll for clients that want it (an ERP cron uses
`wait=0`, so no client worker is held). Cursor older than retention ⇒ `410 CURSOR_EXPIRED`. Results reach clients
only through the feeds: the node never calls a client and never dials a callback URL taken from an intent. A client
that polls every minute, and every ~10 s while it has live pushed jobs, sees job states ≤ ~10 s after the node while
jobs are live, ≤ 1 min otherwise ([INT-ERP-18](../integration.md#INT-ERP-18), [INT-ERP-20](../integration.md#INT-ERP-20)).

`GET /v1/jobs?cursor=901&limit=200&wait=0`:

```json
{"store_id": "32 hex", "incarnation": "32 hex", "restore_epoch": 0, "head_seq": 950, "next": 902,
 "items": [{"seq": 902, "uid": 17, "client_ref": "erp:1234", "origin": {"scope": "6f1c…:1", "producer": "…", "key": "0x8d…",
            "generation": 0}, "state": "signed", "tx_hash": "0x…", "outer_nonce": 42, "signer": "0x…", "error": null, "at": 1790000000123}]}
```

Each item is a **snapshot** of the job after that transition (state + journal fields: `queued`, `leased`, `signed`,
`broadcast`, `mined`, `reverted`, `consumed`, `dead`, `cancelled`), so a client that missed earlier items can still
reach the right state. `final` never appears here (finality comes from the events feed). Every item carries
`trace_id`; `mined`/`reverted` items add `gas_used`, `gas_price`, `cost_native`, `sponsor: {policy, account} | null`
and `sponsor_fallback: <policy name> | null` (`sponsor_fallback: <policy> | null`) ([sponsorship.md#feed](sponsorship.md#feed),
[NODE-OPS-11](ops.md#NODE-OPS-11)). Error values a client must recognise on `dead`/`reverted` items: `cancelled`,
decoded contract errors (`MetaTxBadNonce`, `MetaTxExpired`, …), `ATTEMPTS_EXHAUSTED` (`attempt_count` passed
`chain.max_attempts`, default 5), and a `reverted` after one billed retry (the chain charged the lane for a failure the
subject could make deterministic, e.g. Hedera `INSUFFICIENT_GAS`, Aptos out-of-gas, Solana CU exhaustion — the subject
must re-sign; [NODE-LANE-14](submit-lanes.md#NODE-LANE-14)).

## <a id="event-items"></a>4. Event items

<a id="event-items"></a><a id="NODE-IDX-05"></a>**NODE-IDX-05** — **Event feed items are the indexer's normalized
ranges, unchanged**: `kind = range` = `{chain_key, from_block, to_block, to_block_hash, events}`, one finalized block
range per chain, **always served even when empty** (`from_block = previous to_block + 1`: continuity is what a client
checks). Drift C = `kind = balances` items written right after their range, so a balance never runs ahead of the
events (a client's decoder can be reused as is, and a race between balance and range reads cannot happen). DEX mirror
items are `dex_order`, `dex_trade`, `dex_range` ([dex-venue.md#persistence](dex-venue.md#persistence)).

```json
{"seq": 77, "kind": "range", "chain_key": "evm:7622", "from_block": 41233001, "to_block": 41233040,
 "to_block_hash": "0x…",
 "events": [{"event": "PaymentSettled", "contract": "0xtoken…", "block_number": 41233017, "block_hash": "0x…",
             "tx_hash": "0x…", "log_index": 3, "from": "0xpayer…", "to": "0xpayee…", "amount": "100000000",
             "fee": "0", "fee_recipient": "0x0000…", "entry_ref": "0x8d…"},
            {"event": "MetaTransactionExecuted", "contract": "0xtoken…", "block_number": 41233017, "tx_hash": "0x…",
             "log_index": 4, "from": "0xpayer…", "relayer": "0xlane…", "batch": "7412…", "nonce": "0",
             "digest": "0x…", "fee_recipient": "0x0000…", "fee": "0"}]}
```

A non-EVM range looks the same: `{"seq": 77, "kind": "range", "chain_key": "sui:localnet", "from_block": 101,
"to_block": 140, "to_block_hash": "0x…64 hex", "events": [ … ]}`.

Serve-time filter per namespace (the stored item is chain-wide): drop `Transfer` not to one of the namespace's `watch`
pairs; drop events whose `contract` is outside the namespace token subset (empty = all dropped unless `all_tokens`,
[NODE-JOB-12](job-api.md#NODE-JOB-12)). **A range item is always served**, even with empty `events`.

Index-time: the indexer filters `Transfer` by the union of all watch lists; a watch added later is not retroactive
(clients push watch lists right after approving a receiving wallet).

`kind = balances` (drift C, EVM): written hourly right after a range, read at `height = chain_index.indexed_block`,
served filtered to the namespace's watch pairs:

```json
{"seq": 78, "kind": "balances", "chain_key": "evm:7622", "height": 140,
 "balances": [{"token": "0x…", "address": "0x…", "balance": "1000000"}]}
```

<a id="NODE-IDX-06"></a>**NODE-IDX-06** (owner, 2026-10-07) — **A repeated `entryRef` is flagged by the node and checked by
the client — both.** The first `PaymentSettled` per `(chain_key, token, entryRef)` is the payment; every later one is
an overpayment and a reconciliation exception, never a second payment
([CTR-MTX-10](../contracts/metatx.md#CTR-MTX-10)). The node keeps the first finalized `PaymentSettled` per
`(chain_key, token, entryRef)` in its store and marks every later `PaymentSettled` item on `/v1/events` with
`repeat_of` = the first event's `(tx_hash, log_index)` (`null` on the first). The client still detects repeats from
the events itself and books them; it never relies on the flag alone, because a node only knows the history it has
indexed (a new or restored node may start after the first payment). A repeat keeps payer, amount, fee and
transaction so that the business can decide a refund to the payer; a refund is a business decision and a new,
separate payment, never automatic. Status: SPECIFIED.

### <a id="cursors"></a>4.1 Cursors

<a id="cursors"></a>Both feeds:

- Rows with `seq > cursor` visible to the namespace, ordered by `seq`, ≤ `limit` (≤ 500) and ≤ 1 MiB; at least one
  item when one is due. `cursor = -1` returns no items and `next = head_seq`.
- `wait` (0–25 s): await a per-store `Notify` fired on feed inserts, re-query once; ≤ 4 waits per key.
- Client rule: `cursor = max(0, last − 200)`, apply idempotently (skip `seq ≤ applied seq` per job), persist `next` with
  `store_id`, `incarnation`, `restore_epoch` and the last applied `(seq, uid, state)`.
- **Continuity checks**: `store_id` or `restore_epoch` changed ⇒ halt; `head_seq < stored cursor` ⇒ halt;
  `incarnation` changed (a restart) ⇒ read `cursor = last_seq − 1, limit = 1` and compare with the stored
  `(seq, uid, state)`; different or missing (not `410`) ⇒ halt; equal ⇒ accept the new incarnation. Re-pushing to a
  recreated or restored store is an operator action ([NODE-ADM-07](admin-auth.md#NODE-ADM-07)).
- Retention: `job_event`/`feed_item` older than `feed_retention_secs` (7 d) are deleted; the same purge transaction
  raises `meta('<table>_floor')` to the highest purged `seq` (never lowered); `cursor < floor` ⇒ `410 CURSOR_EXPIRED`
  (an empty table with `head_seq > 0` cannot tell "expired" from "nothing new"). Recovery: jobs — `GET /v1/jobs/{uid}`
  for each non-terminal pushed job, then `cursor = -1`; events — reset to 0 (idempotent by block range: a client drops
  events at or below its indexed block when a range straddles it).

## 5. Drift and readiness

Drift A (inbound transfers that match no payment) and drift C (balances of watched receiving wallets at the indexed
height) are computed by the indexer from the watch lists and delivered as events; the client compares them with its
books ([INT-ERP-09](../integration.md#INT-ERP-09)). Non-EVM drift needs a family `balanceOf` and transfer events
(PLANNED per family). `/readyz` per chain: ≥ quorum RPCs answer within 3 s, indexer lag ≤ `max_index_lag`, finality
not violated ([ops.md#health](ops.md#health)).

## <a id="snapshots"></a>6. Snapshots

<a id="snapshots"></a>(PLANNED) Deterministic Merkle snapshot of a token at a final block, for distributions
([contracts/asset-suite.md#snapshot](../contracts/asset-suite.md#snapshot), format there). Input: `(chain_key,
recordToken, recordBlock, policy)` with `recordBlock` final under the chain's finality gate. Balances = replay of every
finalized `Transfer` of `recordToken` from its creation block (indexer watch list) to the end of `recordBlock`; must
equal `balanceOf(a)` at `recordBlock` for a sampled set (archive RPC quorum) or the build fails. Policy (canonical JSON,
`policyHash = keccak256` of its RFC 8785 bytes): excluded addresses and attribution of protocol clones; the builder
**must** classify every leaf that has code — every `AssetFactory` clone (known from its events, including
counterfactual grant addresses funded before `GrantCreated`, found with `predictGrant` of pending client grants) and the
token's own address are excluded or attributed — and any other contract leaf **fails the build** unless the policy
lists it. Tree: OZ `StandardMerkleTree` v1, leaf encoding `["uint256","address","uint256"]` = `(index, account,
amount)`, leaf = `keccak256(bytes.concat(keccak256(abi.encode(index, account, amount))))`, `sortLeaves = true`,
sorted-pair node hashing as `MerkleProof.verify`. Output: root, total, leafCount, leaves file (CSV + JSON), proofs. API (job-API conventions, namespace-scoped):
`POST /v1/snapshots {chain, token, block, policy}` → `{id}`; `GET /v1/snapshots/{id}` → `{state, root, total,
leaf_count, policy_hash}`; `GET /v1/snapshots/{id}/leaves`; `GET /v1/snapshots/{id}/proof?account=` (public data).
CLI `scaas-node snapshot verify <file>` recomputes a root from chain without trusting the store. The node is not
trusted for the root: the review window and independent recomputation are the control. Vectors
`test/vectors/merkle_dist_vectors.json` (Solidity, Rust node, client) include 1, 2, 3, 7 and 2¹⁰ + 1 leaves.

## <a id="limitations"></a>7. Limitations

<a id="limitations"></a><a id="NODE-IDX-07"></a>**NODE-IDX-07** (open; PLANNED) — **A second, independent event
source.** The event-set quorum bounds what one dishonest RPC provider can inject; it does not bound a compromised node,
which can lie on `/v1/events`. A second event source (another node or an independent indexer) and client-side
agreement before booking are PLANNED; signed feed pages make sense only with such a second verifier.
