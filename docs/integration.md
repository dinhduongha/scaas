# SCaaS Integration Guide — ERPs and applications

**Status:** normative, 2026-10-06. Companion of [`SCaaS.md`](SCaaS.md) (the system specification; its §0
precedence applies here). Status tags as in SCaaS.md: **BUILT**, **SPECIFIED** (link), **PLANNED**.

This guide describes integration under the **current model** (owner rulings 2026-10-06, NI R87–R111): the ERP or
application is a **client** of `scaas-node`. It keeps its own transactional outbox, **pushes** jobs to the node's job
API, and **polls** two feeds (`/v1/jobs`, `/v1/events`) to learn job states and finalized chain facts. The node never
calls the client. The node's store is the configuration authority.

> **Transition note.** The job API, feeds and admin API are **SPECIFIED**
> ([node independence](superpowers/specs/2026-10-06-node-independence-design.md) §5–§7) and not yet built. The node
> that runs today (**BUILT**) pulls work from the Odoo addons over `/json/2` (`relay_poll`/`relay_claim`/
> `relay_report`, `chain_event_ingest`). New integrations must target the push model; Odoo migrates chain by chain
> through the flag `blockchain.chain.node_transport ∈ pull|push` (R104). The public gateway `POST /v1/metatx` and
> `/v1/dex/*` are **BUILT** and unchanged.

**Contents:** 1 Model · 2 Onboarding · 3 Pushing jobs · 4 Feeds and reconciliation · 5 Payment references ·
6 Procure-to-Pay · 7 Fast path and batching · 8 Inbound payments and self-relay · 9 Sealed-bid tender ·
10 Accounts and identity · 11 Regulated tokens · 12 Asset suite · 13 Wallets and signers · 14 The app ·
15 Worked example: Odoo · 16 Failure handling and reconciliation runbook · 17 Checklist

---

## 1. Integration model

```
  Client (ERP / app)                                              scaas-node
  ┌─────────────────────────────┐                                ┌──────────────────────────────┐
  │ business tx:                │                                │ job API  (HMAC per key)      │
  │   document change           │   push cron  POST /v1/jobs ───►│   accept → store (job)       │
  │   + outbox row  (one COMMIT)│   cancel     POST …/cancel ───►│   lanes: lease → simulate →  │
  │                             │   PUT /v1/watch, /v1/tokens ──►│   journal → broadcast        │
  │ sync cron                   │◄── GET /v1/jobs?cursor=  ──────│   job_event feed             │
  │   apply job snapshots       │◄── GET /v1/events?cursor= ─────│   indexer → feed_item(range) │
  │   apply finalized ranges    │                                │   finality gate + RPC quorum │
  └─────────────────────────────┘                                └──────────────────────────────┘
        ▲ subject signs on device (passkey / seed vault / wallet); the client never holds subject keys
```

Responsibilities:

| Client | Node |
|---|---|
| Build typed data / `MetaOp` for the subject; choose `validUntil`; verify the signature shape | Recompute the digest from the payload (a differing client digest ⇒ `422 BAD_PAYLOAD`) |
| Record the outbox row in the business transaction | Accept idempotently; enforce namespace grants, registered tokens, normalization (R100) |
| Push, retry, cancel | Lease to a lane, simulate, journal before broadcast, replace, gap-fill, consumption checks |
| Apply job snapshots; mark business documents final **only** from finalized events | Index finalized ranges with RPC quorum; serve them per namespace |
| Keep payer/payee/party mapping and business data | Keep jobs ≤ 30 d after terminal, feeds ≤ 7 d |

Rules every client must follow:

1. **No socket inside a business transaction.** Network calls happen after commit (cron/worker).
2. **Nothing is "paid" before a finalized event.** HTTP 200, `tx_hash`, `signed`, `broadcast` or `mined` are progress,
   not results.
3. **Never sign for a subject** unless the subject explicitly entrusted a custodial/delegated wallet with limits
   (SCaaS.md §1.2).
4. **Apply feeds idempotently** and persist cursors together with the node's `store_id`, `incarnation`,
   `restore_epoch`.

---

## 2. Onboarding a client (SPECIFIED, NI §11.3)

| Step | Who | Command / route |
|---|---|---|
| 1 | Host operator | `scaas-node admin create alice --role admin --role key_custodian --config node.toml` (first admin) |
| 2 | Admin | Create namespace: `POST /v1/admin/namespaces {"name": "acme-erp", "chains": ["evm:100"], "allow_call": false, "max_live_jobs": 10000}` (`allow_call = true` only if the client needs `call` jobs: mandates, subject-account deploys, DEX settles) |
| 3 | Admin | Register chains/tokens on the node if not yet present (`POST /v1/admin/chains/{key}/tokens`); RPC URLs and lane keys are toml-only |
| 4 | key_custodian | `scaas-node key create --namespace acme-erp --scopes "submit read"` or `POST /v1/admin/keys` → `{"key_id": "k_3f9a0c1d2e4b5a6c", "secret": "<64 hex>", …}` shown **once** |
| 5 | Client admin | Store `key_id` + secret in the client's secret store (never in a business table) |
| 6 | Client | `GET /v1/info` → api version, `store_id`, `incarnation`, `restore_epoch`, `head_seq`s, granted chains with lanes, tokens, `fee_recipient`, profile, state |
| 7 | Client | `PUT /v1/tokens/{chain}` with the tokens it uses (intersected with the node registry; `missing` listed) and `PUT /v1/watch/{chain}` with its receiving wallets (drift detection) |

One namespace per client database is the default; several legal entities may share it, distinguished by
`origin.scope`.

### 2.1 Request signing (HMAC, R92)

```
X-Scaas-Key:       k_3f9a0c1d2e4b5a6c
X-Scaas-Timestamp: 1790000000                     # unix seconds; ±300 s accepted
X-Scaas-Nonce:     9b2cf0e1                       # [A-Za-z0-9_-]{1,64}, single use until ts + 300 s
X-Scaas-Signature: hex(HMAC-SHA256(secret, ts + "." + nonce + "." + METHOD + " " + path_with_query + "\n" + body))
```

```python
import hashlib, hmac, os, time, requests

def signed(method, url_path, body_bytes, key_id, secret_hex):
    ts, nonce = str(int(time.time())), os.urandom(8).hex()
    msg = f"{ts}.{nonce}.{method} {url_path}\n".encode() + body_bytes
    sig = hmac.new(bytes.fromhex(secret_hex), msg, hashlib.sha256).hexdigest()
    return {"X-Scaas-Key": key_id, "X-Scaas-Timestamp": ts, "X-Scaas-Nonce": nonce,
            "X-Scaas-Signature": sig, "Content-Type": "application/json"}

# requests.post(base + "/v1/jobs", data=body, headers=signed("POST", "/v1/jobs", body, kid, sec),
#               allow_redirects=False, timeout=(5, 30))
```

A shared KAT (`scaas-node/tests/api/hmac_kat.json`) pins the byte layout; clients must test against it. Unknown key
and bad signature both return `401 UNAUTHORIZED`. Machine keys never work on the admin listener (R109). Rotation:
`POST /v1/admin/keys/{id}/rotate` (generation + 1; the old secret dies immediately).

---

## 3. Pushing jobs (SPECIFIED, NI §5.2)

### 3.1 Request

`POST /v1/jobs` — up to 50 jobs, body ≤ 1 MiB, per-item results.

```json
{"jobs": [{
  "origin": {"scope": "6f1c…:1", "producer": "blockchain.payment.request", "key": "0x8d…", "generation": 0},
  "client_ref": "erp:1234",
  "chain_key": "evm:100",
  "kind": "metatx",
  "payload": {"token": "0x…", "signature": "0x…",
              "metatx": {"from": "0x…", "to": "0x…", "value": "100000000", "data": "0x…", "batch": "7412…",
                         "nonce": "0", "validUntil": "1790000300", "mode": 1, "relayer": "0x…", "fee": "0",
                         "feeRecipient": "0x0000000000000000000000000000000000000000"}},
  "bus": {"scope": "restricted", "private_window_secs": 120}}]}
```

| Field | Rule |
|---|---|
| `origin.scope` | Client-chosen, stable: e.g. `"<database uuid>:<legal entity id>"` |
| `origin.producer` | Business object type that produced the job (e.g. `blockchain.payment.request`, `purchase.tender`) |
| `origin.key` | Natural key of the business event (e.g. the payment `entryRef`, `invoice:42:attempt:1`) |
| `origin.generation` | `0` initially; `+1` on an operator requeue of a dead job |
| `client_ref` | Echoed in feeds; for the client's own lookup |
| `kind` | `metatx` (EVM meta-tx), `signed_op` (non-EVM `MetaOp` or Soroban auth payload), `call` (calldata to a contract, needs `allow_call`) |
| `payload.digest` / `op.digest` | Optional; if present must equal the node's digest |
| `bus.scope` | `restricted` (company lanes only; default), `open` (admitted peers after the window), `public` (also the open mesh; A2) |

Payload by kind:

| Kind | Payload |
|---|---|
| `metatx` | `{token, signature, metatx: {11 fields of MetaTransaction}}`; `uint256` as decimal strings; addresses lowercase |
| `signed_op` | `{op: {op_kind: "pay", payload: "0x<exact signed bytes>", signature, public_key, auth_kind: "wallet"|"passkey", extra: {…native params}}}`; `from`, lane, nonce, `valid_until`, relayer are decoded from `payload` |
| `call` | `{call: {target, calldata, validUntil}}` — e.g. `MandateWallet.payUnderMandate(...)`, `SubjectAccountFactory.deploy(...)`; the signature lives inside the calldata |

### 3.2 Accept checks (in order; no RPC)

1. Scope `submit`, namespace active, chain granted ⇒ `403 CHAIN_NOT_GRANTED`.
2. Payload decodes; node computes `digest` (per family) and `payload_hash` = SHA-256 of RFC 8785 (JCS) of the payload
   ⇒ `422 BAD_PAYLOAD`.
3. Token registered, active and in the namespace subset ⇒ `422 UNKNOWN_TOKEN`.
4. `kind = call` needs `allow_call` ⇒ `403 CALL_NOT_ALLOWED`.
5. `now < valid_until ≤ now + 3600` ⇒ `422 EXPIRED` / `VALID_TOO_LONG`.
6. Bound relayer must be one of the chain's lanes ⇒ `422 RELAYER_NOT_OURS` (else `lane_hint` pins the job).
7. Normalization of unbound `relayer`/`feeRecipient` (stored work only; `payload_hash` is over the client's payload).
8. Idempotency (one transaction): same key + same hash ⇒ `created: false` + current snapshot; tombstone ⇒
   `created: false, state: cancelled`; different hash ⇒ `409 IDEMPOTENCY_MISMATCH {uid}`; lower generation still live
   ⇒ `409 PREVIOUS_GENERATION_LIVE {uid}`; same digest live under another key ⇒ `409 DUPLICATE_DIGEST`; quota ⇒
   `429 QUOTA`.

Response `200`:

```json
{"results": [{"client_ref": "erp:1234", "uid": 17, "created": true, "state": "queued", "last_seq": 902},
             {"client_ref": "erp:1235", "error": "UNKNOWN_TOKEN", "detail": "0x… is not registered on evm:100"}]}
```

Paused chain: accepted and held `queued`. Halted chain: `409 CHAIN_HALTED`.

### 3.3 Client push algorithm

```
loop (cron, after each new outbox commit and every minute):
  rows = SELECT outbox rows WHERE state='queued' AND push_state='local' ... FOR UPDATE SKIP LOCKED LIMIT 50
  UPDATE rows SET push_attempted = true; COMMIT            # marker durable BEFORE any HTTP call
  results = POST /v1/jobs(rows)
  for each (row, r):
     accepted               → push_state='sent', node_uid=r.uid, apply r's snapshot (§4.3)
     BAD_PAYLOAD | UNKNOWN_TOKEN | EXPIRED | VALID_TOO_LONG | RELAYER_NOT_OURS | CALL_NOT_ALLOWED | CHAIN_NOT_GRANTED
                            → business job dead/failed with last_error (the node holds nothing)
     IDEMPOTENCY_MISMATCH | PREVIOUS_GENERATION_LIVE
                            → push_state='attention', node_uid from the 409 body, GET /v1/jobs/{uid}, apply it;
                              NEVER mark dead (the node holds a job under this key)
     DUPLICATE_DIGEST       → stay 'local', last_error (another key carries this intent)
     transport | 429 | 503  → stay 'local' (retry; idempotent)
  COMMIT
```

The `push_attempted` marker decides cancel semantics (§3.4): an unmarked row can be killed locally; a marked row may
exist on the node and must be cancelled there.

### 3.4 Cancel

`POST /v1/jobs/{uid}/cancel` or `POST /v1/jobs/cancel {"origin": {…}}`:

| Node state | Result |
|---|---|
| `queued`/`leased`, never published | `cancelled` (reported as `dead`, `error = "cancelled"`) |
| no job yet for the origin | tombstone written; a late push of that key returns `created: false, state: cancelled` |
| `queued` but published on the bus | `409 TOO_LATE {state, published: true}`; job held (never leased by us) but a peer may still land it |
| `signed` or later | `409 TOO_LATE {state}` |

Client handling: `cancelled` ⇒ local dead + side effects; `TOO_LATE` ⇒ treat as "already sent", keep the business
request open until final or expiry; transport error ⇒ `cancel_requested`, retried first on the next sync. A
subject can always invalidate its own pending intents with `cancelMetaNonce(batch)` (EVM, direct call) — the
authoritative cancel.

---

## 4. Feeds and reconciliation (SPECIFIED, NI §5.3, §6)

### 4.1 Jobs feed

`GET /v1/jobs?cursor=901&limit=200&wait=0`:

```json
{"store_id": "…32 hex", "incarnation": "…32 hex", "restore_epoch": 0, "head_seq": 950,
 "items": [{"seq": 902, "uid": 17, "client_ref": "erp:1234",
            "origin": {"scope": "6f1c…:1", "producer": "blockchain.payment.request", "key": "0x8d…", "generation": 0},
            "state": "signed", "tx_hash": "0x…", "outer_nonce": 42, "signer": "0x…", "error": null,
            "at": 1790000000123}],
 "next": 902}
```

Each item is a **snapshot** after one transition (`queued`, `leased`, `signed`, `broadcast`, `mined`, `reverted`,
`consumed`, `dead`, `cancelled`). `final` never appears here (finality comes from §4.2).

### 4.2 Events feed

`GET /v1/events?cursor=…`: items of kind `range` (one finalized block range per chain, always served even when empty,
`from_block = previous to_block + 1`), `balances` (hourly, drift C), `dex_order`/`dex_trade`/`dex_range` (DEX
mirrors).

```json
{"seq": 77, "kind": "range", "chain_key": "evm:100", "from_block": 41233001, "to_block": 41233040,
 "to_block_hash": "0x…",
 "events": [{"event": "PaymentSettled", "contract": "0xtoken…", "block_number": 41233017, "block_hash": "0x…",
             "tx_hash": "0x…", "log_index": 3, "from": "0xpayer…", "to": "0xpayee…", "amount": "100000000",
             "fee": "0", "fee_recipient": "0x0000…", "entry_ref": "0x8d…"},
            {"event": "MetaTransactionExecuted", "contract": "0xtoken…", "block_number": 41233017, "tx_hash": "0x…",
             "log_index": 4, "from": "0xpayer…", "relayer": "0xlane…", "batch": "7412…", "nonce": "0",
             "digest": "0x…", "fee_recipient": "0x0000…", "fee": "0"}]}
```

Per-namespace filtering at serve time: only contracts in the namespace token subset; `Transfer` only to watched
wallets.

### 4.3 Client rules

| Rule | Detail |
|---|---|
| Cursor | Request `cursor = max(0, last − 200)` (overlap), apply idempotently (skip `seq ≤ applied seq` per job), persist `next` with `store_id`, `incarnation`, `restore_epoch` and the last applied `(seq, uid, state)` |
| Continuity | `store_id` or `restore_epoch` changed ⇒ **halt** sync for this node (needs attention); `head_seq < stored cursor` ⇒ halt; `incarnation` changed ⇒ read `cursor = last_seq − 1, limit = 1` and compare with the stored item; differs ⇒ halt |
| Expired cursor | `410 CURSOR_EXPIRED` ⇒ jobs: `GET /v1/jobs/{uid}` for each non-terminal pushed job, then `cursor = -1`; events: restart at 0 (ranges are idempotent) |
| Adoption | An item whose `uid` is unknown locally is matched by `origin` (+ generation) — covers a rollback after the node accepted |
| State ladder | Map node → client states (`leased → nonce_leased`, `cancelled → dead`) and walk `queued → nonce_leased → signed → broadcast → mined` up to the target, applying side effects once; late `mined`/`reverted` after `final` or `consumed` are no-ops |
| Ranges | Reject a gap (`from_block > indexed + 1`) ⇒ halt events; straddle (`from_block ≤ indexed < to_block`) ⇒ drop events at or below `indexed`; dedup events by `(chain_key, tx_hash, log_index)` |
| Unknown contract | Event for a contract that is not a client token ⇒ drop and count, never fail the page |
| Finality | A job is **final** when a `MetaTransactionExecuted` with its digest arrives in a range (by any relayer: `landed_elsewhere = relayer ∉ our signers`) |
| Business booking | Only from `PaymentSettled` (or the family equivalent) in a range, matched on `(chain, contract, to, entryRef)`; isolate business hooks (savepoint) so a failing hook never blocks the cursor |
| Consumed | `consumed` keeps the business request pending; it becomes final via the event, or dead if no event arrives by `valid_until + grace + 1 h` (superseded) |
| Latency | Poll with `wait = 0` every minute, and every ~10 s while pushed jobs are live (≤ 25 s long-poll available for clients that can hold a connection) |

---

## 5. Payment references: `entryRef` (payId)

### 5.1 Generation (BUILT, R9)

```
entryRef = 32 bytes from a CSPRNG                     # carries no information; unlinkable by construction
batch    = keccak256("bamboo.pay.lane" ‖ entryRef)    # lane of this request ("scaas.pay.lane" in the next version)
nonce    = 0
```

- One `entryRef` per **payment request** (an invoice may have several requests over time; each request is payable at
  most once because its lane has nonce 0).
- The client stores `entryRef` with a UNIQUE constraint on the request, together with `chain`, `token`,
  `receiving_address`, `payer_address` (locked at start), `amount_base`, `issued_valid_until`.
- Do **not** derive `entryRef` from business identifiers (`keccak256(company ‖ move ‖ amount ‖ salt)` as in older
  drafts): a random value needs no salt management and cannot be brute-forced from known invoice numbers.
- Splitting: Zether `n_v = 64` removed the need to split large payments; for transparent tokens one payment per
  request. If a business case needs partial payments, issue one request (one `entryRef`) per instalment.

### 5.2 Two-way verification

**Client → chain (before signing and at push):**
1. Typed data built server-side from the request: `to = receiving_address`, `value = amount_base`, `data =
   pay(entryRef)`, `batch` as above, `validUntil = issued_valid_until` (server-chosen, e.g. now + 300 s).
2. After signing: recompute the digest; a 65-byte signature must recover `payer_address` (EOA); a contract wallet
   (ERC-1271) is accepted unverified and judged by the node's simulation.
3. The node recomputes the digest and simulates before broadcast.

**Chain → client (on each finalized range):**
1. Filter `PaymentSettled` by `contract == request.token` **and** `to == request.receiving_address` **and**
   `entry_ref == request.entryRef`.
2. `amount_settled = Σ amount` of matching events; `amount_settled ≥ amount_base` ⇒ request final; more than due ⇒
   final + needs attention (refund manually); less ⇒ partial.
3. Cross-check `MetaTransactionExecuted(digest)` to mark the outbox job final.
4. Drift checks: unmatched inbound `Transfer` to a watched wallet ⇒ drift A record; hourly `balances` vs ledger
   balance of the token's bank journal ⇒ drift C.

A third party paying 1 unit with someone else's `entryRef` cannot complete a request (sum must reach the amount); an
overpayment by a stranger is just money received.

---

## 6. Procure-to-Pay — seven steps

Buyer pays a supplier's invoice with a public payment token (META tier 2 wrapper of a stablecoin). Both companies may
use the same or different nodes.

| # | Step | System | Detail | Status |
|---|---|---|---|---|
| 1 | Bill approved | Buyer ERP | Vendor bill posted and approved (maker-checker for R3 amounts) | client |
| 2 | Payment request | Buyer ERP | `entryRef` random; request row (token, supplier's approved receiving wallet, amount in base units, payer wallet); typed data with `pay(entryRef)` | **BUILT** (Odoo, inbound direction); outbound treasury payouts **PLANNED** (HANDOFF #9) |
| 3 | Sign | Buyer signer | Human approver signs on device (passkey/seed), or the delegated/custodial path signs under `SigningPolicyService` limits (`validUntil − now ≤ 300 s`) or `MandateWallet.payUnderMandate` | **BUILT** (device, mandate); policy service **PLANNED** |
| 4 | Outbox + push | Buyer ERP → node | Outbox row in the same transaction as `request → pending`; push cron `POST /v1/jobs` (`kind = metatx`, or `call` for mandates) | outbox **BUILT**; push **SPECIFIED** |
| 5 | Submit | Node | Lease, simulate, journal, broadcast; `MODE_RESTRICT_RELAYER` pins the company lane; fee 0 | **BUILT** |
| 6 | Finalize | Node indexer | Range with `PaymentSettled(buyer → supplier, amount, entryRef)` after the finality gate + RPC quorum | **BUILT** |
| 7 | Reconcile both sides | Buyer and supplier ERPs | Buyer: job final, bill paid (outbound payment entry in the token's journal). Supplier: its node/feed (or a watch on its receiving wallet) delivers the same event; it matches the `entryRef` the buyer communicated with the remittance advice (or a `Transfer` to its watched wallet) and posts the receipt | buyer **SPECIFIED**; supplier matching by `entryRef` **BUILT** for requests it issued itself |

When the **supplier** issues the request (its portal/invoice shows a pay link), steps 2 and 7 are on the supplier's
side and the buyer only signs (step 3) — this is the BUILT portal flow (§15).

---

## 7. Fast path and batching

| Path | Use today | Status |
|---|---|---|
| `executeMetaTransaction` with `data = pay(entryRef)` | Every relayed payment; emits `PaymentSettled` | **BUILT** |
| `payWithFee(to, amount, feeMode, fee, feeRecipient, entryRef)` | Contract wallets and payers submitting themselves | **BUILT** |
| `mtxPay(...)` | Typed fast path (~4 k gas less) with its own typehash (SCaaS.md §5.8) | **PLANNED** |
| `batchMtxPay(Payment[])` | 10–50 payments of one token per transaction; 40–60 % gas saving | **PLANNED** |

Client contract for the future fast path: same `entryRef`, same lanes (a request lane can be consumed by either path,
never both), same event — so reconciliation code does not change. The node batches per `(chain_key, token)` at 50
items or 3 s; batching is invisible to the client except that several jobs share one `tx_hash`.

---

## 8. Inbound payments: gateway, sponsorship, payee self-relay

| Pattern | How the client integrates | Status |
|---|---|---|
| Enterprise inbound gateway | Partners/agents post signed EVM meta-txs to the company node: `POST /v1/metatx {chain, token, m, signature}` (gateway auth `bearer`/`hmac` for partners; `none` only on loopback behind a proxy). The client sees results on its events feed by `entryRef`/`to` | **BUILT** |
| Non-EVM inbound | The client builds the `MetaOp`, the payer signs, the client pushes `signed_op` jobs | **BUILT** (via Odoo outbox); job API **SPECIFIED** |
| Payee self-relay ("e-cheque") | Payer signs offline with fee 0 and relayer unbound or bound to the payee's address; the payee (or its node) submits; ERP books from `PaymentSettled` exactly as usual | contract **BUILT**; QR (EIP-681-style payload) tooling **PLANNED** |
| Gas sponsorship policy | Node policy rows: e.g. "to wallet W, value ≥ X ⇒ fee 0, gas to account Y"; the client books gas from the job's receipt data | **PLANNED** |
| Receiver pays fee | Two signatures (payer's `pay`, payee's fee authorization); booked as payment N and fee F | **PLANNED** |

Never accept raw subject-signed native transactions (Sui `txBytes`, TON BOC from the subject wallet, Stellar
envelopes) as the integration format: they order operations by the subject's account sequence (R30). Always use the
contract-level payload of the family (SCaaS.md §7).

---

## 9. Sealed-bid tender in procurement (PLANNED)

Contract: SCaaS.md §10 / §14.7. Client flow:

| # | Buyer ERP | Bidder | Chain |
|---|---|---|---|
| 1 | Create tender document; `documentRef = keccak256(canonical tender docs)`; `createTender(config)` via a `call` job from the buyer's account | — | `TenderCreated` |
| 2 | Publish tender id, deadlines, deposit token and amount | Generates `salt` (32 random bytes), computes `commitment = keccak256(abi.encode(tenderId, price, salt, bidder, chainId, tender))`, stores `(price, salt)` in its secret store | — |
| 3 | — | Signs the commit op (gasless meta-tx); deposit `minDeposit` pulled by the tender contract | `BidSubmitted` |
| 4 | Shows commitments count only | After `commitDeadline`: signs `revealBid(tenderId, price, salt)` | `BidRevealed` |
| 5 | After `revealDeadline`: `settleTender` (anyone after `awardDeadline`) | — | `TenderSettled(winner, price)` |
| 6 | On the finalized event: create the purchase order for the winner; record deposits | Losers sign `withdrawDeposit` (100 % back) | `DepositRefunded` / `DepositSlashed` |
| 7 | Bond release on contract signature / delivery | — | `BondReleased` / `BondClaimed` |

ERP constraints: the ERP never sees prices before reveal; the PO is created only from the finalized `TenderSettled`;
non-revealers are flagged from `DepositSlashed`.

---

## 10. Accounts, Universal Accounts and identity sync

### 10.1 Subject accounts (BUILT)

- **EVM `SubjectAccount`** (passkey + seed keys, guardian): address predicted by
  `SubjectAccountFactory.predict(firstKey, guardian)`; the client enqueues a `call` job `deploy(firstKey, guardian)`
  **before** the subject's first payment (deploy is permissionless and idempotent). Key changes go through
  `executeAsOwner` signed by an existing key (client builds `OwnerCall(bytes data,uint256 nonce,uint256
  validUntil)`).
- Non-EVM: open the subject's account object (`meta::open`/`open_passkey` on Sui/Aptos, `open`/`open_passkey` on
  Solana, `BindKey` on TON, custom account on Soroban).

### 10.2 Universal Account registration (BUILT on dev chains; production after audit)

1. Client derives the confidential key `x` on the device (seed path `m/254|12381/<coin>/<account>/7`), computes
   `encodedY`, `UA = keccak256(encodedY)`.
2. Reads `popChallenge(encodedY, account)` = `keccak256(abi.encodePacked(registry, encodedY, account))` where
   `account` is the subject's EOA or smart account that will call `register`.
3. Produces `schnorrPop` (Schnorr by `x` over the challenge, `zetherPop` in clientkeys) and `authPop` per scheme
   (multisig signatures, FROST/MuSig2 group Schnorr, BLS PoP, or ERC-1271 over the challenge).
4. The **subject's account** calls `register(encodedY, scheme, authData, abi.encode(schnorrPop, authPop), linkEVM)`
   (not relayable by a third party because the challenge binds `msg.sender`; a smart account may be relayed at its
   own layer).
5. On the finalized `AccountRegistered(ua, scheme, linkedEVM, authData)` event the client updates its party record:
   `ua`, linked address, scheme, `registered = true`.

Scheme choice: staff/outlets → `SMART_ACCOUNT_1271` (passkey account) or `SELF_SCHNORR`; boards and finance →
`ECDSA_MULTISIG`; agent clusters → `FROST_BN254`; never BLS on the same curve as the Zether key.

### 10.3 Identity sync rules

- The party ↔ address/UA mapping lives only in the client (erasable, SCaaS.md §11).
- Receiving wallets are approved with four-eyes and become usable after a cooling-off period (24 h in the Odoo
  example, R22); push them to the node watch list.
- One UA per (curve, network, account) — never per token. A new key is a new UA (no rotation).

---

## 11. Regulated-token compliance flow (PLANNED)

```
authority ruling ──► issuer legal/compliance verifies, computes courtRulingId = keccak256(canonical ruling id)
        ──► client creates an intervention request (freeze / unfreeze / force transfer / burn) with the ruling document
            stored off chain
        ──► quorum members sign the multisig transaction (≥ 3-of-5) on their devices
        ──► client pushes a `call` job from the quorum contract (namespace with allow_call)
        ──► finalized AccountFrozen / AccountUnfrozen / JudicialTransferExecuted / CourtOrderedBurn
        ──► client books the effect (e.g. reclassify the frozen balance; post the forced transfer) and links the
            ruling document to the event
```

Rules: never an EOA authority; the ruling id is mandatory; frozen accounts still receive; every intervention event is
reconciled to exactly one approved request (unmatched intervention events ⇒ incident). Securities: transfers call
`checkTransferCompliant`; the client keeps KYC/accreditation data off chain and only pushes attester flags to the
registry extension (SCaaS.md §14.5).

---

## 12. Asset-suite configuration

Creating a token is a subject-signed (or treasury-multisig) factory call pushed as a `call` job, or sent directly by
the creator's wallet.

| Template | Call | Client configuration |
|---|---|---|
| Loyalty points (tier 1) | `createMetaToken(1, address(0), abi.encode(name, symbol, decimals, initialSupply, minter), salt)` | `minter` = the issuer's mint contract or multisig; earn rules in the ERP trigger `mint` jobs; fee 0 |
| Internal 1:1 money (tier 2) | `createMetaToken(1, underlying, abi.encode(name, symbol, 0, 0, address(0)), salt)` | Journal per (company, token) for accounting; wrap/unwrap by holders |
| Confidential money | `createZetherToken(1, underlying, verifier, abi.encode(name, symbol, registry, shieldScale, maxDecryptableShielded, confidentialFee, auditorKey), salt)` | dev chains only until audit; curve decision; auditor key custody |
| Basket, vesting, controlled, NFT | — | **PLANNED** (SCaaS.md §4) |

After creation: read `predictAddress` before, verify `isDeployedHere`, `creatorOf`, `versionOf` after; register the
token on the node (`POST /v1/admin/chains/{key}/tokens`) and in the client (`PUT /v1/tokens/{chain}`), record the
EIP-712 domain from `eip712Domain()`.

---

## 13. Wallets and signers in the client (`clientkeys`, BUILT)

`clientkeys` is an ESM bundle (`@noble/curves`, `@noble/hashes`, `@scure/bip32`, `@scure/bip39`, all pinned) with
three entry points; load only what the chosen signer needs.

| Entry | Exports (main) | Use |
|---|---|---|
| `passkey-signer.js` | `passkeySupported`, `creationOptions` (PRF on), `requestOptions`, `publicKeyFromSpki`, `derToRS`, `encodeAssertion`, `hashTypedData`, `passkeySubjectKey`, `accountSignature`, `merkleBatch`, `checkOwnerCall`, `checkPayment` | Create a passkey (`navigator.credentials.create`), sign `challenge = digest`, encode for `SubjectAccount.isValidSignature` |
| `seed-signer.js` | `normalizeMnemonic`, `wordsToEntropy`, `seedFromEntropy`, `deriveKey`, `signDigest`, `NETWORKS`, `createVault`, `openVault`, `enablePrf`, `rewrapPin`, `SeedBackup`, `wipe` | 24-word vault: generate, back up (3-word challenge), unlock by PRF or PIN, derive per family, sign digests |
| `zether-keys.js` | `deriveConfKey`, `confPublic`, `zetherPop`, `sealConfKey`/`openConfKey`, `checkBalance`, balance cache helpers, `readBalance` | Confidential keys and balance cache; proofs via `zether-prover` WASM `zetherCall(cmd, json)` (`keygen`, `encrypt`, `decrypt`, `decryptPending`, `checkBalance`, `proveTransfer`, `proveBurn`, `verifyTransfer`, `verifyBurn`, `pop`, `fundCalldata`, `envelope`) |

Client UX rules:

1. Show the operation in human terms (amount, payee, token, chain, expiry) before invoking the authenticator.
2. Extension wallets: EIP-6963 discovery (fallback EIP-1193), `wallet_switchEthereumChain`/`wallet_addEthereumChain`,
   `eth_signTypedData_v4`; ask `eth_getCode` through the wallet to tell `eoa` from `contract`; user rejection (4001) is
   not an error.
3. Batch related operations under one passkey assertion (Merkle root).
4. Never send mnemonics, `x`, PRF outputs or PINs to any server; tokens and keys live in memory or the encrypted vault.
5. Non-EVM connectors (Wallet Standard for Sui/Aptos, Keplr/Leap `signArbitrary`, Freighter, TON Connect) are loaded
   lazily per chosen network. Solana, Soroban and Aptos seed signers in clientkeys are **PLANNED**.

---

## 14. The app (`scaas/app/`, PLANNED)

React + Vite console and dApp: wallets (passkey, seed vault, extension wallets, dev key), payments, DEX book, Zether,
contracts, node admin. Chain features work without login; node admin requires a built-in login (session token) or
OIDC (Authorization Code + PKCE S256, tokens in memory only); the UI hides actions the token's roles cannot perform
(the node enforces). Screens for gossip: Peers, Topics, Announces, Bans, Trusted list (A2 §13.2). ERPs may embed or
link the app for wallet setup instead of building their own signer UI.

---

## 15. Worked example: Odoo (one client among others)

The Odoo addons in the `bamboo-dms` repository are **one example** of a SCaaS client. Names are Odoo-specific;
another ERP implements the same contract with its own models.

### 15.1 Addons

| Addon | Depends | Role | Status |
|---|---|---|---|
| `dms_blockchain` | `base`, `mail` | Chains, tokens, metatx/signed-op envelopes, outbox `blockchain.relay.job`, chain events, payment requests, receiving/paying wallets (four-eyes), subject accounts, family address/digest libraries (`lib/eip712.py`, `lib/fam_*.py`, pure Python, KAT-locked) | **BUILT** |
| `dms_blockchain_payment` | `dms_blockchain`, `account_payment` | Payment provider `code = 'chain'`; `payment.transaction` ↔ request; auto-pay policies (`blockchain.autopay.policy`/`.run`) with custodial (`env:` dev-only adapter) and delegated (`MandateWallet`) modes | **BUILT** |
| `dms_blockchain_bridge` | `dms_blockchain_payment`, `dms_portal` (auto-install) | Portal facade on `dms.portal.api` (`dms_portal_chain_payment_options/start/submit/status`, subject-account register/add-key) + JS signers (EIP-6963, passkey, seed vault, family connectors) | **BUILT** |
| `dms_blockchain_dex` | `dms_blockchain` | DEX markets, read-only book/trade mirrors, DEX and relayer fee accounting | **BUILT** |

All service entry points are public model methods reachable by `call_kw` and `/json/2`, with private
implementations, and never accept `company_id` from the client (project rule).

### 15.2 Data model essentials

- `blockchain.relay.job` (outbox): `company_id`, `chain_id`, `job_kind ∈ {metatx, call, signed_op}`, `metatx_id` /
  `signed_op_id` / (`target_address`, `calldata_hex`, `call_valid_until_ts`), `payment_request_id`,
  `origin_producer`, `origin_key` (`UNIQUE(company_id, origin_producer, origin_key)`), `chain_state ∈ {queued,
  nonce_leased, signed, broadcast, mined, final, reverted, dead, consumed}`, `business_state ∈ {pending, success,
  failed}`, `signer_address`, `tx_hash`, `outer_nonce`, `attempt_count`, `last_error`, `landed_elsewhere`,
  `mesh_published_datetime`. Push model adds (SPECIFIED): `node_id`, `node_job_uid`, `push_state ∈ {local, sent,
  cancel_requested, attention}`, `push_attempted`, `push_generation`, `node_event_seq`.
- `blockchain.payment.request`: `request_uuid`, `company_id`, `chain_id`, `token_id`, `receiving_address`,
  `amount_base`, `amount_settled_base`, `entry_ref_hex` (32 random bytes, UNIQUE), `batch_hex`, `payer_address`,
  `issued_valid_until`, `expiry_datetime`, `request_state ∈ {open, partial, final, expired}`, `needs_attention`,
  `res_model`/`res_id`.
- `blockchain.chain.event`: `UNIQUE(chain_id, tx_hash, log_index)`; `event_name ∈ {MetaTransactionExecuted,
  PaymentSettled, Transfer}`; `relayer_address`.
- Push model (SPECIFIED): `blockchain.node` (url, `key_id`, secret in `ir.config_parameter`
  `dms_blockchain.node_secret.<id>`, `bound_db_uuid`, `bound_base_url`, cursors, `store_id`, `incarnation`,
  `restore_epoch`, `needs_attention`), `blockchain.node.route` (`UNIQUE(company_id, chain_id)` → node).
- Groups: `group_blockchain_viewer` ⊂ `operator` ⊂ `manager`; service groups `relay_worker`/`indexer` exist for the
  pull model and are deleted in P9.

### 15.3 Portal payment, end to end

```
portal user           Odoo                                   node                         chain
 connect wallet ───► dms_portal_chain_payment_start(order, from)
                     entitlement; order confirmed (state = 'sale');
                     token currency == order currency (no FX);
                     amount = posted invoices' residual, or order total − paid (advance);
                     request: entryRef random, lane = keccak("bamboo.pay.lane" ‖ entryRef), nonce 0,
                     issued_valid_until = now + validity
 ◄── typed data ──── {to: receiving wallet, value, data: pay(entryRef), mode: RESTRICT_RELAYER, relayer: company lane, fee 0}
 eth_signTypedData_v4 / passkey
 ── signature ─────► dms_portal_chain_payment_submit(reference, valid_until, signature, wallet_kind)
                     valid_until == issued_valid_until; digest rebuilt; 65-byte sig must recover payer;
                     metatx + relay.job (outbox) + tx pending   [COMMIT]
                     ── pull model today: node relay_poll/claim ── push model: cron POST /v1/jobs ──►
                                                                    simulate, journal, send ─────► PaymentSettled
                     ◄── relay_report / GET /v1/jobs (signed, broadcast, mined) ──
                     ◄── chain_event_ingest / GET /v1/events (finalized range) ──
                     request final when Σ PaymentSettled(token, to, entryRef) ≥ amount
                     → payment.transaction._set_done() → account_payment posts and reconciles
 poll status ──────► dms_portal_chain_payment_status(reference) → {tx_state, request_state, job_state, tx_hash}
```

Guarantees: amount set by the server; one payment per request (one lane, nonce 0); changing the payer wallet only
after the previous typed data expired (new request, new lane); relayer cannot redirect funds (digest covers `to`,
`value`, `data`); booking only from finalized events.

### 15.4 Push and sync crons (SPECIFIED, NI §10)

- `cron_node_push` → `model._cron_node_push()`: batches of 50 per transaction, `push_attempted` committed before HTTP,
  results applied as in §3.3; re-triggered after every new outbox job (`ir.cron._trigger()`).
- `cron_node_sync` → `model._cron_node_sync()`: every minute, plus `_trigger(now + 10 s)` while pushed jobs are live;
  order per node: retry `cancel_requested`, jobs feed, events feed (chains whose `event_node_id` is this node), watch
  and token sync when their hashes changed.
- Safety: `neutralize.sql` deletes node secrets and resets chains to `pull` on database copies; push/sync refuse when
  `database.uuid` or `web.base.url` differ from the node record's `bound_*`.
- Cutover per chain (`action_switch_to_push`): routes exist for every company with jobs or approved wallets; node
  reachable with `api ≥ 1`; Odoo tokens ⊆ node tokens; node `lane.journal_max` ≥ Odoo `max(outer_nonce)` per signer;
  DEX markets paused. Rollback = set the chain back to `pull`.

### 15.5 Auto-pay

`blockchain.autopay.policy` (payer, paying wallet, trigger `invoice_posted|invoice_due`, caps per payment/day/month,
four-eyes, kill switch) → cron `_cron_autopay` creates exactly one `blockchain.autopay.run` per (policy, invoice,
event) (UNIQUE) → same request + outbox path as manual payments. Custodial wallets sign through the custody adapter
(dev `env:` only; production KMS/HSM PLANNED); delegated wallets sign `PayUnderMandate` and push a `call` job to
`MandateWallet.payUnderMandate`. Kill: off-chain immediately, and for delegated wallets a `revokeWithSig` job.

---

## 16. Failure handling and reconciliation runbook

### 16.1 Situations

| Situation | What the client sees | Action |
|---|---|---|
| Node unreachable | Push/sync transport errors | Retry with backoff; jobs stay `local`/`sent`; signatures live until `validUntil` — expired requests are re-issued (new `entryRef` or same request after expiry per client policy) |
| Simulation revert (insufficient balance, expired, bad signature) | Snapshot `dead` with decoded `error` (`MetaTxBadNonce`, `MetaTxExpired`, …) | Request stays open; ask the payer to fund and re-sign |
| Lost race / paid elsewhere | `consumed` then a range with `MetaTransactionExecuted(digest)` | Mark final, `landed_elsewhere = true`; no business failure |
| Superseded intent | `consumed`, no event by `valid_until + grace + 1 h` | Mark dead; the subject spent that lane nonce on another intent — investigate if unexpected |
| Stuck transaction | `signed`/`broadcast` for a long time | Nothing to do client-side; the node replaces at ×1.25 up to its fee cap; operator may raise the cap |
| Reverted on chain | `reverted` (rare: state changed between simulation and inclusion) | Re-push with `generation + 1` after operator requeue if still wanted; the subject nonce was not consumed |
| Chain paused | Jobs accepted and held `queued`; events continue | None; resumes automatically |
| Chain halted | `409 CHAIN_HALTED`; no new ranges | Wait for the operator; do not re-route to another node for the same (company, chain) |
| `IDEMPOTENCY_MISMATCH` | 409 with `uid` | The business payload changed under the same key (e.g. module upgrade); fetch the node job, compare, decide manually; never mark dead |
| Range gap | `from_block > indexed + 1` | Halt event sync, needs attention; check the node's `event_node_id` routing and restore events from 0 |
| Store recreated or restored | `store_id`/`restore_epoch` change, `head_seq < cursor`, incarnation mismatch | Halt sync; operator verifies the node runbook was followed (`store restored` CLI), then acknowledges in the client; acknowledged re-push of non-terminal jobs (old outer txs may still be in a mempool: funds safe, gas may be lost) |
| Underpayment / overpayment | `partial` / `final` + needs attention | Partial: wait or re-request; overpayment: manual refund from the company wallet |
| Unknown inbound transfer to a watched wallet | Drift A record | Identify the payer off chain; book manually |
| Balance drift vs ledger | Drift C mismatch on two consecutive snapshots | Reconcile journal vs wallet (sweeps to cold wallets must be booked) |
| Business hook failure during ingest | Event and cursor committed; request needs attention | Fix the accounting condition (closed period, credit hold) and re-run the hook manually |

### 16.2 Daily reconciliation

1. Every non-terminal pushed job older than its `valid_until + 1 h` ⇒ `GET /v1/jobs/{uid}`; mismatch with the local
   state ⇒ apply the snapshot.
2. Every request `open/partial` past `expiry_datetime` with no live signature ⇒ expire and cancel the payment
   transaction.
3. For each (company, token): Σ finalized `PaymentSettled` into receiving wallets (feed) = Σ booked receipts; Σ wallet
   balances (latest `balances` item at the indexed height) = ledger balance of the token journal (± booked sweeps).
4. `needs_attention` queue reviewed by an operator; every item closed with a note.
5. Gas cost per finalized job allocated to its business document (PLANNED FinOps).

### 16.3 After a node restore (client side)

1. Sync halts automatically (continuity check).
2. Confirm with the node operator: restore time, `restore_epoch`, re-revoked keys.
3. Acknowledge the store change (Odoo: `action_acknowledge_store_change`, system group): cursors reset, non-terminal
   pushed jobs return to `local`.
4. Re-push; idempotency returns `created: false` for jobs the restored store still knows; new jobs are created for the
   rest; consumption checks on the node prevent double execution (the subject nonce is the final guard).

---

## 17. Integration checklist

- [ ] Outbox row written in the same transaction as the business change; no network call inside it.
- [ ] Typed data built server-side; amount and `validUntil` chosen by the server; `entryRef` random.
- [ ] Signature shape verified before push; never store subject secrets.
- [ ] HMAC client passes the shared KAT; clock synced (NTP).
- [ ] Idempotency tuple stable across retries; generation bumped only by operator requeue.
- [ ] `push_attempted` committed before HTTP; permanent vs transient errors distinguished; 409 never ⇒ dead.
- [ ] Both feeds polled with overlap; cursors persisted with `store_id`, `incarnation`, `restore_epoch`; continuity
      checks halt on mismatch.
- [ ] Business documents booked only from finalized events matched on (chain, contract, to, `entryRef`).
- [ ] Business hooks isolated so they never block the cursor.
- [ ] Watch list and token subset pushed after every wallet approval and token activation.
- [ ] Cancel semantics implemented (`TOO_LATE` = already sent; `cancelMetaNonce` for subject-side cancel).
- [ ] Database copies neutralized (secrets removed, pushing disabled).
- [ ] No personal data in any payload; party ↔ address mapping erasable on the client side.
