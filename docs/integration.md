# Integrating an ERP or back office with SCaaS

This guide is for teams connecting an ERP, accounting system or line-of-business application ("the client") to a
`scaas-node`. The client keeps its own transactional outbox, **pushes** jobs to the node's job API and **polls** two
feeds (`/v1/jobs`, `/v1/events`) to learn job states and finalized chain facts. The node never calls the client; the
node's store is the configuration authority ([NODE-STO-03](node/store.md#NODE-STO-03)). The node is independent of any
ERP ([ARCH-POS-05](architecture.md#ARCH-POS-05)); one worked ERP connector is shown at the end as an example.

Status tags: **BUILT**, **SPECIFIED**, **PLANNED**. The job API, the feeds and the admin API are **SPECIFIED**
([node/job-api](node/job-api.md), [node/indexer-feeds](node/indexer-feeds.md)); the node that runs today pulls work
from the example connector over its RPC (the legacy pull path, [NODE-JOB-10](node/job-api.md#NODE-JOB-10)). New
integrations target the push model. The public gateway `POST /v1/metatx` and `/v1/dex/*` are **BUILT**.

**TON is blocked on every push, mesh and gateway path** until the node enforces the forward-TON cap
([NET-TON-14](networks/ton.md#NET-TON-14)): an unbounded forward-TON floor drains a lane. Until then no job API, mesh
or gateway submission may reach a TON lane, and no TON chain is cut over to push. The legacy pull path is safe: it
builds `extra = 0` and no `forward_nanoton`.

## Integration model

<a id="model"></a>

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

| Client | Node |
|---|---|
| Build typed data / `MetaOp` for the subject; choose `validUntil` inside the lane horizon ([payment references](#payment-references)); verify the signature shape | Recompute the digest from the payload (a differing client digest ⇒ `422 BAD_PAYLOAD`); read every signed field from the payload, never from job JSON ([NODE-LANE-16](node/submit-lanes.md#NODE-LANE-16)) |
| Record the outbox row in the business transaction; keep it immutable ([outbox rules](#outbox)) | Accept idempotently; enforce namespace grants, registered tokens, normalization ([NODE-LANE-10](node/submit-lanes.md#NODE-LANE-10)), the `call` target table, value-out and deposit caps, the per-subject grief score |
| Push, retry, cancel | Lease to a lane, simulate, journal before broadcast, replace, gap-fill, consumption checks |
| Apply job snapshots; mark business documents final **only** from finalized events | Index finalized ranges with RPC quorum; serve them per namespace |
| Keep payer/payee/party mapping and business data | Keep jobs ≤ 30 d after terminal, feeds ≤ 7 d |

Rules every client follows:

1. **No socket inside a business transaction.** Network calls happen after commit (cron/worker).
2. **Nothing is "paid" before a finalized event.** HTTP 200, `tx_hash`, `signed`, `broadcast` or `mined` are progress,
   not results.
3. **Never sign for a subject** unless the subject explicitly entrusted a custodial/delegated wallet with limits
   ([custody](#custody)).
4. **Apply feeds idempotently** and persist cursors together with the node's `store_id`, `incarnation`,
   `restore_epoch`.

## Onboarding a client

<a id="onboarding"></a>

| Step | Who | Command / route |
|---|---|---|
| 1 | Host operator | `scaas-node admin create alice --role admin --role key_custodian --config node.toml` (first admin) |
| 2 | Admin | Create namespace: `POST /v1/admin/namespaces {"name": "acme-erp", "chains": ["evm:100"], "allow_call": false, "max_live_jobs": 10000}` (`allow_call = true` only if the client needs `call` jobs: mandates, subject-account deploys, DEX settles; even then only the selectors and targets of the [call table](#call-targets) run) |
| 3 | Admin | Register chains/tokens on the node if not yet present (`POST /v1/admin/chains/{key}/tokens`); RPC URLs and lane keys are toml-only |
| 4 | key_custodian | `scaas-node key create --namespace acme-erp --scopes "submit read"` or `POST /v1/admin/keys` → `{"key_id": "k_3f9a0c1d2e4b5a6c", "secret": "<64 hex>", …}` shown **once** |
| 5 | Client admin | Store `key_id` + secret in the client's secret store (never in a business table) |
| 6 | Client | `GET /v1/info` → api version, `store_id`, `incarnation`, `restore_epoch`, `head_seq`s, granted chains with lanes, tokens, `fee_recipient`, profile, state |
| 7 | Client | `PUT /v1/tokens/{chain}` with the tokens it uses (intersected with the node registry; `missing` listed) and `PUT /v1/watch/{chain}` with its receiving wallets (drift detection) |

One namespace per client database is the default; several legal entities may share it, distinguished by
`origin.scope` ([NODE-JOB-03](node/job-api.md#NODE-JOB-03)).

**API keys are for external server-side clients only** ([NODE-JOB-05](node/job-api.md#NODE-JOB-05),
[NODE-ADM-06](node/admin-auth.md#NODE-ADM-06)): the ERP backend or another service holds the key in its secret store.
Never embed one in a browser, mobile or desktop app or an extension — client apps sign user actions with `clientkeys`
and submit through the gateway ([inbound](#inbound), [clients/app](clients/app.md)), and read namespace data through
their own backend. API keys never reach the admin API; admin access is a built-in user or OIDC login, and config
automation (CI, Terraform, scripts) uses OIDC client credentials or the host CLI.

**Request signing (HMAC).**

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
and bad signature both return `401 UNAUTHORIZED`. API keys never work on the admin listener. Rotation:
`POST /v1/admin/keys/{id}/rotate` (generation + 1; the old secret dies immediately).

<a id="node-routing"></a><a id="INT-ERP-16"></a>**INT-ERP-16** — **One node per (company, chain).** A client routes each
`(company, chain)` to exactly one node; two nodes for one company only on **different chains**, enforced client-side
by a `UNIQUE(company_id, chain_id)` route table. The node has no company notion
([NODE-JOB-03](node/job-api.md#NODE-JOB-03)); it claims work by a CAS `queued → leased` inside its single owner
process ([NODE-JOB-06](node/job-api.md#NODE-JOB-06)). Why: one lane journal per signer is the double-spend guard.

## Pushing jobs

<a id="push"></a>

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
| `kind` | `metatx` (EVM meta-tx, incl. v1 envelopes of a `PqzToken`), `signed_op` (non-EVM `MetaOp` or Soroban auth payload), `call` (calldata to a contract, needs `allow_call` **and** a [call table](#call-targets) row); planned `ua_metatx` (UA; incl. v3 envelopes of a `PqzToken`) and `pqz_call` (direct PQZ calls, private chain) |
| `payload.digest` / `op.digest` | Optional; if present must equal the node's digest |
| `bus.scope` | `restricted` (company lanes only; default), `open` (admitted peers after the window), `public` (also the open mesh) — see [bus scope](#bus-scope) |

| Kind | Payload |
|---|---|
| `metatx` | `{token, signature, metatx: {11 fields of MetaTransaction}}`; `uint256` as decimal strings; addresses lowercase |
| `signed_op` | `{op: {op_kind: "pay", payload: "0x<exact signed bytes>", signature, public_key, auth_kind: "wallet"|"passkey", extra: {…native params}}}`; `from`, lane, nonce, `valid_until`, relayer are decoded from `payload` |
| `call` | `{call: {target, calldata, validUntil}}` — e.g. `MandateWallet.payUnderMandate(...)`, `SubjectAccountFactory.deploy(...)`; the signature lives inside the calldata; selector and target must match a call-table row; no native value |
| `ua_metatx` (SPECIFIED) | MetaToken v3 `UAMetaTransaction` with `from: bytes32` and its `auth`; same lifecycle as `metatx` |
| `pqz_call` (SPECIFIED; private chain only) | **Direct open calls only**: `{chain, contract, selector ∈ {pqzTransfer, pqzBurn, rollOver}, calldata}` to a configured PQZ token (direct `fund` pulls the caller's underlying and is never a node job) |
| PQZ envelopes (SPECIFIED) | **No new kind**: a `PqzToken` is an `IERC20MetaTx` token, so its envelope ops travel as ordinary `metatx` (v1 domain `("SCaaS PqzToken", "1", chainId, token)`) or `ua_metatx` (v3, `salt = chainUid`) jobs, `m.to = 0`, `m.value = 0`, `m.data` = the direct calldata of `pqzTransfer`/`pqzBurn`/`fund`/`rollOver` (opaque to the client); outer fee `NONE`/`FIXED` only; never batched, never on the mesh; 1 MiB job body on the `pqz` profile; a gasless exit is the envelope `pqzBurn` paying the underlying to `recipient` |

**Accept checks** (in order; no RPC):

1. Scope `submit`, namespace active, chain granted ⇒ `403 CHAIN_NOT_GRANTED`.
2. Payload decodes; node computes `digest` (per family) and `payload_hash` = SHA-256 of RFC 8785 (JCS) of the payload
   ⇒ `422 BAD_PAYLOAD`. Every field the signed payload carries (`contract`, `valid_until`, `from`, lane, nonce,
   relayer binding, value or forward floors) is taken from the payload; a job-JSON copy that differs ⇒
   `422 BAD_PAYLOAD`; unsigned fields may only narrow, never widen.
3. Token registered, active and in the namespace subset ⇒ `422 UNKNOWN_TOKEN`.
4. `kind = call` needs `allow_call` ⇒ `403 CALL_NOT_ALLOWED`, **and** its selector and target must match the call
   table ⇒ `403 CALL_TARGET_REFUSED` (re-checked at lease).
5. Native value the job makes the lane send beyond fees ≤ `chain.max_value_out` (TON 0.05 TON above the fixed attach,
   every other family 0) ⇒ `422 VALUE_OUT_TOO_HIGH` (also at lease, config is hot;
   [NODE-LANE-17](node/submit-lanes.md#NODE-LANE-17)). A lane-funded deposit a third party can reclaim (e.g. a Solana
   ATA of an unconfigured recipient) ⇒ `422 DEPOSIT_NOT_ALLOWED` (re-checked before signing;
   [NODE-LANE-18](node/submit-lanes.md#NODE-LANE-18)).
6. The payload's `from` is over the grief threshold (≥ 10 billed failures in 24 h, or cost ≥ `chain.grief_cost_cap`)
   ⇒ `429 SUBJECT_THROTTLED {retry_after}`; from 3 in 24 h it gets one live job per chain
   ([NODE-LANE-15](node/submit-lanes.md#NODE-LANE-15)).
7. `now < valid_until ≤ now + 3600` ⇒ `422 EXPIRED` / `VALID_TOO_LONG`.
8. Bound relayer must be one of the chain's lanes ⇒ `422 RELAYER_NOT_OURS` (else `lane_hint` pins the job).
9. Normalization of unbound `relayer`/`feeRecipient` (stored work only; `payload_hash` is over the client's payload);
   denylist (`403 SUBJECT_DENIED`); sponsorship match on job data ([node/sponsorship](node/sponsorship.md)): a matched
   job needs `valid_until ≥ now + min_valid_secs` (default 120) to be sponsored.
10. Idempotency (one transaction): same key + same hash ⇒ `created: false` + current snapshot; tombstone ⇒
   `created: false, state: cancelled`; different hash ⇒ `409 IDEMPOTENCY_MISMATCH {uid}`; lower generation still live
   ⇒ `409 PREVIOUS_GENERATION_LIVE {uid}`; same digest live under another key ⇒ `409 DUPLICATE_DIGEST`; the same `call`
   (target + calldata) live in this namespace ⇒ `409 DUPLICATE_CALL {uid}` (follow that job or cancel it; other
   namespaces are not blocked, [NODE-JOB-13](node/job-api.md#NODE-JOB-13)); quota ⇒ `429 QUOTA`; a matched sponsor
   policy reserves its day budget and takes its hour / payer-hour counts here (released if the job ends before
   broadcast) ⇒ `429 SPONSOR_BUDGET | SPONSOR_RATE | SPONSOR_TOO_SHORT {policy}`, or the job goes unsponsored when the
   policy says `on_exhausted = unsponsored`.

Response `200`:

```json
{"results": [{"client_ref": "erp:1234", "uid": 17, "created": true, "state": "queued", "last_seq": 902},
             {"client_ref": "erp:1235", "error": "UNKNOWN_TOKEN", "detail": "0x… is not registered on evm:100"}]}
```

Paused chain: accepted and held `queued`. Halted chain: `409 CHAIN_HALTED`.

**Client push algorithm:**

```
loop (cron, after each new outbox commit and every minute):
  rows = SELECT outbox rows WHERE state='queued' AND push_state='local' ... FOR UPDATE SKIP LOCKED LIMIT 50
  UPDATE rows SET push_attempted = true; COMMIT            # marker durable BEFORE any HTTP call
  results = POST /v1/jobs(rows)
  for each (row, r):
     accepted               → push_state='sent', node_uid=r.uid, apply r's snapshot (feeds, below)
     BAD_PAYLOAD | UNKNOWN_TOKEN | EXPIRED | VALID_TOO_LONG | RELAYER_NOT_OURS | CALL_NOT_ALLOWED | CHAIN_NOT_GRANTED
       | CALL_TARGET_REFUSED | VALUE_OUT_TOO_HIGH | DEPOSIT_NOT_ALLOWED | SUBJECT_DENIED | FEATURE_UNSUPPORTED
       | UA_NOT_REGISTERED | BAD_SIGNATURE
                            → business job dead/failed with last_error (the node holds nothing); fail dependants
     IDEMPOTENCY_MISMATCH | PREVIOUS_GENERATION_LIVE
                            → push_state='attention', node_uid from the 409 body, GET /v1/jobs/{uid}, apply it;
                              NEVER mark dead (the node holds a job under this key)
     DUPLICATE_DIGEST       → stay 'local', last_error (another key carries this intent)
     DUPLICATE_CALL         → stay 'local', last_error with the 409 body's uid (follow that job, or cancel and re-push)
     SUBJECT_THROTTLED      → stay 'local', retry after retry_after; flag the subject for attention (its intents keep failing)
     SPONSOR_BUDGET | SPONSOR_RATE | SPONSOR_TOO_SHORT, transport | 429 | 503
                            → stay 'local' (retry; idempotent)
  COMMIT
```

The `push_attempted` marker decides cancel semantics: an unmarked row can be killed locally; a marked row may exist on
the node and must be cancelled there. HTTP runs after the marker commits and holds no row lock except the batch's own
rows; other writers of those rows (cancel, dependency failure) lock with `FOR UPDATE` and wait at most one batch.

## Cancel

<a id="cancel"></a><a id="INT-ERP-17"></a>**INT-ERP-17** — **The client kills a job locally only if it was never pushed;
otherwise it cancels on the node, by uid or by origin.** `POST /v1/jobs/{uid}/cancel` or `POST /v1/jobs/cancel {origin}`
is a node CAS ([NODE-JOB-07](node/job-api.md#NODE-JOB-07)) that succeeds from `queued`/`leased` only if the job was
never published on the bus:

| Node state | Result |
|---|---|
| `queued`/`leased`, never published | `cancelled` (reported as `dead`, `error = "cancelled"`) |
| no job yet for the origin | tombstone written; a late push of that key returns `created: false, state: cancelled` |
| `queued` but published on the bus | `409 TOO_LATE {state, published: true}`; job held (never leased by us) but a peer may still land it |
| `signed` or later | `409 TOO_LATE {state}` |

Client handling: `cancelled` ⇒ local dead + side effects; `TOO_LATE` ⇒ treat as "already sent", keep the business
request open until final or expiry; transport error ⇒ `cancel_requested`, retried first on the next sync. A subject can
always invalidate its own pending intents with `cancelMetaNonce(batch)` (EVM, direct call) — the authoritative cancel.

## Outbox rules

<a id="outbox"></a><a id="INT-ERP-05"></a>**INT-ERP-05** — **Outbox `call` jobs are immutable and operators are
read-only.** A `call` job is a transaction a node lane signs as `msg.sender`; whoever can edit an outbox row can point it
anywhere. Every client's outbox therefore follows these rules (the node's half is the call table,
[NODE-JOB-01](node/job-api.md#NODE-JOB-01)):

| Rule | Detail |
|---|---|
| **Operators are read-only** | No role below the service itself may write outbox rows (ACL `1,0,0,0` for operators). Requeue of a `dead`/`reverted` job is one public method that checks the operator group explicitly and then writes internally; a viewer calling it over RPC fails |
| **Job fields are immutable after create** | company, chain, job kind, envelope link, `target_address`, `calldata_hex`, call validity, payment request, subject account, `origin_producer`, `origin_key` — `write` raises for every environment, privileged ones included; `prerequisite_job_id` may be set once, from empty, while the job is `queued`. State and progress fields (`chain_state`, `tx_hash`, `outer_nonce`, `last_error`, push fields) stay writable by the service |
| **A different call is a new job** | Never edit target, calldata, kind or payload of an existing row; create a new outbox row (new origin key or `generation + 1` after an operator requeue) |
| **No context-key switches** | Immutability is enforced in `write` itself, not bypassed by a client-settable flag (client context reaches the server on RPC) |
| **Signed envelopes are immutable too** | metatx / signed-op rows are frozen after signing |

Tests a client must carry: operator write on any job field ⇒ access error; privileged write of each immutable field ⇒
error; `prerequisite_job_id` set once from empty passes, a second change fails; operator requeue still works. A `call`
outside the table is `dead` with `CALL_TARGET_REFUSED` before simulation on the legacy pull path and
`403 CALL_TARGET_REFUSED` at accept on the push path. A job carries `job_kind` (`metatx` | `call` | `signed_op`),
`target_address`, `calldata_hex` and `payment_request_id`; the node uses `calldata` when present, and the request
becomes `final` only from its `PaymentSettled` — the node is never a "blind signer" of client calldata.

<a id="call-targets"></a>**Call targets.** `allow_call` on the namespace is necessary, not sufficient. The node runs a
`call` job only if its 4-byte selector is in this table **and** the target meets the row's rule; never when the target
is a registered token of the chain (any kind), the token factory, or a contract in which a lane key holds a role; `call`
jobs carry no native value.

| Selector | Target rule | Typical producer |
|---|---|---|
| `SubjectAccountFactory.deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)` | the chain's account factory (`chain_contract.kind = account_factory`) | subject-account onboarding ([accounts](#accounts)) |
| `SubjectAccount.executeAsOwner(bytes,uint256,uint256,bytes)` | an EIP-1167 clone of that factory's implementation (checked at lease) | subject-account key changes |
| `MandateWallet.payUnderMandate`, `revokeWithSig` (epoch-bound), `executeAsOwner`; `HederaMandateWallet.executeAsOwnerRaw` (ED25519 owners) | any address that is not a registered token (the target checks the delegate/owner signature) | delegated payments, auto-pay, kill switch ([auto-pay](#auto-pay)) |
| `OrderBookDex.settle` / `cancel` / `invalidateNonces` | the chain's DEX | DEX venue / DEX accounting |
| `UniversalAccountRegistry.register` (`UARegistry.register` once the UA registry lands) | `chain.ua_registry`, `~gateway` only | node gateway `POST /v1/ua/register` ([accounts](#accounts)) |

Anything else a client wants to call on chain (e.g. `createTender`, factory `createTiered`, regulated interventions)
needs a table row first (node release) or is sent by the subject's or treasury's own wallet.

## Feeds and reconciliation

<a id="reconciliation"></a>

**Jobs feed.** `GET /v1/jobs?cursor=901&limit=200&wait=0`:

```json
{"store_id": "…32 hex", "incarnation": "…32 hex", "restore_epoch": 0, "head_seq": 950,
 "items": [{"seq": 902, "uid": 17, "client_ref": "erp:1234",
            "origin": {"scope": "6f1c…:1", "producer": "blockchain.payment.request", "key": "0x8d…", "generation": 0},
            "state": "signed", "tx_hash": "0x…", "outer_nonce": 42, "signer": "0x…", "error": null,
            "at": 1790000000123}],
 "next": 902}
```

Each item is a **snapshot** after one transition (`queued`, `leased`, `signed`, `broadcast`, `mined`, `reverted`,
`consumed`, `dead`, `cancelled`). `final` never appears here (finality comes from the events feed). `mined`/`reverted`
items add `gas_used`, `gas_price`, `cost_native`, `sponsor: {policy, account} | null` and
`sponsor_fallback: <policy> | null` (a policy matched but was exhausted and the job was booked to the namespace). Error
values the client must recognise on `dead`/`reverted` items: `cancelled`, decoded contract errors (`MetaTxBadNonce`,
`MetaTxExpired`, …), `ATTEMPTS_EXHAUSTED` (`attempt_count` passed `chain.max_attempts`, default 5), and a `reverted`
after one billed retry (the chain charged the lane for a failure the subject could make deterministic, e.g. Hedera
`INSUFFICIENT_GAS`, Aptos out-of-gas, Solana CU exhaustion — the subject must re-sign;
[NODE-LANE-14](node/submit-lanes.md#NODE-LANE-14)).

**Events feed.** `GET /v1/events?cursor=…`: items of kind `range` (one finalized block range per chain, always served
even when empty, `from_block = previous to_block + 1`), `balances` (hourly, drift C), `dex_order`/`dex_trade`/`dex_range`
(DEX mirrors).

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

Per-namespace filtering at serve time: only contracts in the namespace token subset; `Transfer` only to watched wallets.

| Rule | Detail |
|---|---|
| Cursor | Request `cursor = max(0, last − 200)` (overlap), apply idempotently (skip `seq ≤ applied seq` per job), persist `next` with `store_id`, `incarnation`, `restore_epoch` and the last applied `(seq, uid, state)` |
| Continuity | `store_id` or `restore_epoch` changed ⇒ **halt** sync for this node (needs attention); `head_seq < stored cursor` ⇒ halt; `incarnation` changed ⇒ read `cursor = last_seq − 1, limit = 1` and compare with the stored item; differs ⇒ halt |
| Expired cursor | `410 CURSOR_EXPIRED` ⇒ jobs: `GET /v1/jobs/{uid}` for each non-terminal pushed job, then `cursor = -1`; events: restart at 0 (ranges are idempotent) |
| Adoption | An item whose `uid` is unknown locally is matched by `origin` (+ generation) — covers a rollback after the node accepted |
| State ladder | Map node → client states (`leased → nonce_leased`, `cancelled → dead`) and walk `queued → nonce_leased → signed → broadcast → mined` up to the target, applying side effects once; late `mined`/`reverted` after `final` or `consumed` are no-ops |
| Ranges | Reject a gap (`from_block > indexed + 1`) ⇒ halt events; straddle (`from_block ≤ indexed < to_block`) ⇒ drop events at or below `indexed`; dedup events by `(chain_key, tx_hash, log_index)` |
| Unknown contract | Event for a contract that is not a client token ⇒ drop and count, never fail the page |
| Finality | A job is **final** when a `MetaTransactionExecuted` with its digest arrives in a range (by any relayer: `landed_elsewhere = relayer ∉ our signers`). A range is served only after ≥ `quorum` independent RPC endpoints returned the same event set ([NODE-IDX-01](node/indexer-feeds.md#NODE-IDX-01)); a chain with `quorum = 1` is single-provider trust — confirm the chain's quorum with the node operator (gauge `scaas_finality_quorum{chain}`) before booking material amounts on it |
| Business booking | Only from `PaymentSettled` (or the family equivalent) in a range, matched on `(chain, contract, to, entryRef)`; isolate business hooks (savepoint) so a failing hook never blocks the cursor |
| Consumed | `consumed` keeps the business request pending; it becomes final via the event, or dead if no event arrives by `valid_until + grace + 1 h` (superseded) |
| Latency | Poll with `wait = 0` every minute, and every ~10 s while pushed jobs are live (≤ 25 s long-poll available for clients that can hold a connection) |

**Consumption and `landed_elsewhere`.** A job whose subject nonce was used by another digest or relayer is `consumed`
("nonce used elsewhere"); allowed from `nonce_leased`, `signed` and `broadcast`. Applying it records
`last_error = 'nonce consumed: <kind>'` and keeps the business state `pending`; it does not touch the envelope's state
and is not a failure state, so dependants are not failed. Expiry moves a `consumed` job to dead/failed when
`valid_until < now − _EXPIRY_GRACE − 3600` and no final event arrived (superseded). When the executed event arrives, the
job becomes `final` + `success` from any earlier state including `consumed`, with
`landed_elsewhere = True` unless the event's relayer (or, without one, the tx hash) matches the job's own signer. The
event's `relayer` is stored with the event when the family reports it. `landed_elsewhere` and the mesh-published time
are **server-only**: set explicitly on every create (never from a client default), stripped from client writes.

<a id="status-sync"></a><a id="INT-ERP-18"></a>**INT-ERP-18** — **Client push and sync cadence.** The outbox is
unchanged; two scheduled jobs, bodies in methods: **push** sends one batch (≤ 50) per transaction and is re-triggered
after the commit of every new job; **sync** runs every minute, plus 10 s after itself while any pushed job is live,
with `wait=0`. Push and sync fields on the outbox are server-only. Sync order per node: retry `cancel_requested`, jobs
feed, events feed (chains whose event node is this node), watch and token sync when their hashes changed. Why: a client
that cannot hold a long poll still sees status within seconds.

<a id="sync-latency"></a><a id="INT-ERP-20"></a>**INT-ERP-20** — *Open (default applied).* **Payment status latency is
≤ ~10 s while jobs are live and ≤ 1 min otherwise**, from the cadence of [INT-ERP-18](#INT-ERP-18). Owner confirmation
pending; the default stands.

<a id="store-change"></a><a id="INT-ERP-19"></a>**INT-ERP-19** — **The client halts sync on a store change.** A changed
`store_id` or `restore_epoch`, `head_seq < cursor`, or an `incarnation` change whose last item differs sets
`needs_attention` on the node record and stops both feeds; an operator acknowledges the store change (cursors reset,
non-terminal pushed jobs return to `local`). Node admin mutations are audited separately
([NODE-ADM-07](node/admin-auth.md#NODE-ADM-07)).

## Payment references

<a id="payment-references"></a>

**Generation (BUILT; [CTR-MTX-03](contracts/metatx.md#CTR-MTX-03)):**

```
entryRef = 32 bytes from a CSPRNG                     # carries no information; unlinkable by construction
batch    = keccak256("scaas.pay.lane" ‖ entryRef)     # lane of this request (v2 tokens: payLane(entryRef) on chain)
nonce    = 0
```

- One `entryRef` per **payment request** (an invoice may have several requests over time; each request is payable at
  most once because its lane has nonce 0).
- **Lane horizon** ([CTR-MTX-04](contracts/metatx.md#CTR-MTX-04)): pay-once holds only if every signature the client
  issues on a pay lane has `validUntil ≤ t_first_issue + 30 d`. Re-issuing terms on the same lane later than that, or
  signing an op with `valid_until > now + 30 d` on a pruning family (TON, Aptos, Solana, Sui), gives no pay-once
  guarantee — issue a new request (new `entryRef`, new lane) instead. Wallet connectors and `clientkeys` refuse such ops
  ([NET-ALL-01](networks/README.md#NET-ALL-01)).
- The client stores `entryRef` with a UNIQUE constraint on the request, together with `chain`, `token`,
  `receiving_address`, `payer_address` (locked at start), `amount_base`, `issued_valid_until`.
- Do **not** derive `entryRef` from business identifiers (`keccak256(company ‖ move ‖ amount ‖ salt)` as in older
  drafts): a random value needs no salt management and cannot be brute-forced from known invoice numbers.
- Splitting: Zether `n_v = 64` removed the need to split large payments; for transparent tokens one payment per
  request. If a business case needs partial payments, issue one request (one `entryRef`) per instalment.

**Client → chain (before signing and at push):**
1. Typed data built server-side from the request: `to = receiving_address`, `value = amount_base`,
   `data = pay(entryRef)`, `batch` as above, `validUntil = issued_valid_until` (server-chosen, e.g. now + 300 s).
2. After signing: recompute the digest; a 65-byte signature must recover `payer_address` (EOA); a contract wallet
   (ERC-1271) is accepted unverified and judged by the node's simulation ([INT-ERP-03](#INT-ERP-03)).
3. The node recomputes the digest and simulates before broadcast.

**Chain → client (on each finalized range):**
1. Filter `PaymentSettled` by `contract == request.token` **and** `to == request.receiving_address` **and**
   `entry_ref == request.entryRef`.
2. `amount_settled = Σ amount` of matching events; `amount_settled ≥ amount_base` ⇒ request final; more than due ⇒
   final + needs attention (refund manually); less ⇒ partial.
3. Cross-check `MetaTransactionExecuted(digest)` to mark the outbox job final.
4. Drift checks: unmatched inbound `Transfer` to a watched wallet ⇒ drift A record; hourly `balances` vs ledger balance
   of the token's bank journal ⇒ drift C ([accounting](#accounting)).

A third party paying 1 unit with someone else's `entryRef` cannot complete a request (sum must reach the amount); an
overpayment by a stranger is just money received. Reconciliation matches on (chain, token contract, receiving address,
`entryRef`) — never on the amount alone.

<a id="payment-terms"></a><a id="INT-ERP-06"></a>**INT-ERP-06** — **Self-service payment terms use fee `NONE` and
`MODE_RESTRICT_RELAYER` to the company relayer, `fee = 0`, and a server-chosen validity (default 300 s).** This trades
payer self-submission for front-run safety; payee self-relay stays available ([inbound](#inbound)). With bus scope
`open` the relayer is left unbound instead ([INT-ERP-15](#INT-ERP-15)).

<a id="currency"></a><a id="INT-ERP-07"></a>**INT-ERP-07** — **No FX: the token's currency equals the order currency.**
A rate quote would need a price source; only a token pegged to the document's currency is offered (the example
connector has no quote model).

<a id="payment-modes"></a><a id="INT-ERP-27"></a>**INT-ERP-27** — **The payment mode is configuration, not code.** A
deployment chooses per company and channel among: sponsored (company relayer, `MODE_FEE_NONE` +
`MODE_RESTRICT_RELAYER`, gas as OPEX); fee in token (`MODE_FEE_PERCENT`/`FIXED`, fee ≤ 1 % to `feeRecipient`); payee
self-relay ([inbound](#inbound)); receiver pays the fee; a node gas-sponsorship policy; the enterprise inbound gateway.

<a id="bus-scope"></a><a id="INT-ERP-15"></a>**INT-ERP-15** — **Bus scope is a per-tenant client setting delivered per
job.** `restricted` (default) keeps [INT-ERP-06](#INT-ERP-06): terms pin `MODE_RESTRICT_RELAYER` to the company relayer
and the job never leaves the company's lanes. `open`: terms are built with `relayer = 0`; the node publishes the job to
admitted peers after a private window (`bus.private_window_secs`, default 120 s) while it is still `queued`, so
`validUntil` must leave room for it (≥ the 300 s default). `public` also reaches the open mesh. The node publishes
([NODE-MESH-15](node/mesh.md#NODE-MESH-15)).

<a id="mesh-scope"></a>The setting is a required selection `blockchain_bus_scope ∈ {restricted, open, public}` (default
`restricted`) plus `blockchain_bus_private_window_secs`, editable by the client's blockchain managers; the payment start
leaves the relayer unbound only when the company's scope is `open`; delegated (mandate) payments are `call` jobs and stay
`restricted`.

## Wallets and custody

<a id="receiving-wallets"></a>

**Receiving wallets** are kept per (company, network, asset):

- **Address:** accept all-lowercase/all-uppercase, or mixed case with a **correct EIP-55 checksum**; a bad checksum is
  refused. Refuse `0x0`, `0x…dEaD`, the address of **the token itself** or of any registered token or contract. Other
  families use their own normalised form ([addresses](#addresses)).
- **Four-eyes:** proposed by someone holding wallet-admin rights for that company; approved by **a different person**
  with the same right (one seam decides the right; a treasury group, or the system group of the platform company).
- **Immutable once approved** (except the default flag and archiving); a change is a new wallet, the old one archived.
- **Default:** at most one default per company (partial unique index). Record rule: a company sees and edits only its
  own wallets.
- **Snapshot:** the payment request copies `receiving_address`, `chain_id`, `token_id`, `amount_base`, `payer_address`
  and the receiving wallet id (audit reference), and is write-locked thereafter. The payment provider no longer holds
  token or receiving address: only relayer, signature validity and journal; token and address come from the receiving
  wallet the payer picks. The payment options list only usable (chain, asset) pairs of the receiving company whose token
  currency equals the order currency.

<a id="INT-ERP-01"></a>**INT-ERP-01** — **A newly approved receiving wallet is usable only after a cooling-off of 24 h**
(`usable_from = approved + N hours`, default 24): new requests and the default flag wait for it. Push approved wallets to
the node watch list (`PUT /v1/watch/{chain}`).

<a id="payer-wallets"></a>**Paying wallets** have three modes:

| Mode | Who signs | From | Rule |
|---|---|---|---|
| `manual` (default) | the user, each time | their EOA/wallet | the existing flow |
| `custodial` | the platform through the custody adapter (`signer_ref`) | an EOA the adapter controls | `signer_ref` required; a wallet of a **non-company partner** (customer/outlet) also needs `license_ref` |
| `delegated` | a platform delegate key (through the adapter) **within on-chain limits** | the payer's `MandateWallet` | the payer keeps the owner key; limits enforced on chain ([CTR-ACC-07](contracts/accounts-mandates.md#CTR-ACC-07)) |

<a id="INT-ERP-02"></a>**INT-ERP-02** — **A `custodial` paying wallet of a non-company partner requires `license_ref`.**
Holding someone else's key for them is a regulated activity; the reference records the licence it runs under.

<a id="custody"></a>**Custody** is pluggable and chosen at deploy time; the ERP holds only a `signer_ref`, never key
material. The custody adapter is a registry by `signer_ref` scheme with the interface `address(ref)` and
`sign_digest(ref, digest32) -> 65 byte`; production schemes (KMS/HSM `broker:`) are PLANNED. A delegated or custodial
signature is issued only through a signing policy (`SigningPolicyService`, PLANNED) with `validUntil − now ≤ 300 s`.

<a id="INT-ERP-08"></a>**INT-ERP-08** — **The ERP-held `env:` custody is dev-only and signs through OpenSSL.** The `env:`
adapter registers only when a dev-custody flag is `1`, and signs only for wallets on a chain with `is_dev_chain = True`;
production custodial and delegated wallets need another scheme. ECDSA signing goes through the `cryptography` library
(OpenSSL; constant-time, random `k` rather than RFC 6979, low-s and `v` recomputed by `ecrecover` against the address),
never a pure-language `secp256k1.sign`. Node lane keys are separate ([NODE-LANE-20](node/submit-lanes.md#NODE-LANE-20)).

<a id="mandates"></a><a id="INT-ERP-04"></a>**INT-ERP-04** — **A `MandateWallet` is deployed outside the ERP**
(`forge create … --constructor-args <owner>`); the ERP only records its address. The ERP makes no deploy RPC and holds
no deploy key; a CREATE2 factory would force it to compute addresses. Contract rules:
[contracts/accounts-mandates](contracts/accounts-mandates.md).

<a id="auto-pay"></a>**Auto-pay.** A policy (payer, paying wallet, trigger `invoice_posted|invoice_due`, caps per
payment/day/month, four-eyes, kill switch) drives a scheduled job that finds the payer's `posted`, unpaid customer
invoices and creates exactly **one** run per (policy, invoice, event) (`UNIQUE`); each run creates the same request and
outbox job as a manual payment (a `chain` payment transaction over `invoice_ids`, `operation='offline'`). `custodial`
wallets sign `pay` through the custody adapter under `SigningPolicyService` (`validUntil ≤ 300 s`); `delegated` wallets
sign `PayUnderMandate` and push a `call` job to `MandateWallet.payUnderMandate`. A run ends `done` when the payment
transaction is done (the accounting module posts and reconciles) or `failed`. Kill: off-chain immediately, and for
delegated wallets a `revokeWithSig` job; the revoke digest is `RevokeMandate(address token,uint64 epoch,uint256
validUntil)` with the wallet's current `epoch[token]` ([CTR-ACC-07](contracts/accounts-mandates.md#CTR-ACC-07)).

## Families and addresses

<a id="addresses"></a><a id="INT-ERP-10"></a>**INT-ERP-10** — **The ERP is family-aware: chains carry a family,
addresses are stored in the family's normalised form, and non-EVM payments are signed ops.** The ERP verifies ed25519
itself; every other non-EVM check it cannot complete is left to the node's simulation.

- Chain: `family`, `network_key` (EVM/Hedera: chain id; Sui: `mainnet|testnet|devnet|localnet`; Stellar:
  `pubnet|testnet|standalone`; Cosmos: chain id; TON: `-239|-3|localnet`), `chain_key = family:network_key` (EVM:
  `evm:N`), `is_dev_chain`, `bech32_prefix`, `network_passphrase`; CAIP-2: `eip155:N`, `hedera:mainnet|testnet`,
  `sui:<net>`, `stellar:<pubnet|testnet>`, `cosmos:<chain-id>`, `ton:<-239|-3>`.
- `parse(family, value, chain)` returns the stored form: EVM EIP-55; Hedera EIP-55 **or** `0.0.N` (⇒ long-zero `0x000…N`), stored
  as `0x`; Sui `0x` + up to 64 hex, normalised to 64 lower-case; Stellar strkey `G…` (account) / `C…` (contract): base32,
  version byte, CRC16-XModem, `M…`/`S…` refused; Cosmos bech32 (BIP-173), HRP = the chain's `bech32_prefix`, 20 (account)
  or 32 bytes (contract); TON raw `wc:hex64` or user-friendly base64/base64url of 48 characters (tag, wc, hash,
  CRC16-XModem; the testnet flag must match the chain), stored raw `wc:hex64`; Aptos `0x` + 64 lower-case hex, short
  forms (`0x1`, `0xa`) padded (AIP-40); Solana base58 decoding to exactly 32 bytes, **never lower-cased**
  ([NET-ALL-16](networks/README.md#NET-ALL-16)).
- Database address checks (`CHECK ~ '^0x…'`) move to per-family validation in code; the column stays text; the old
  constraint is dropped on upgrade (verify in `pg_constraint` after the upgrade, `-u`).
- **Signed payload per family** next to the EVM envelope: `family`, `contract`, `from`, `payload` (the family's exact
  signed bytes), `signature`, `pubkey`, `auth_kind` (`wallet|passkey`), `digest`, validity, state; the outbox job has
  `kind = 'signed_op'`.
- Receiving and paying wallets exist per (company, network, asset) for every family.

<a id="families"></a>**Per-family ERP rules.** Each family library offers `build_terms(request, valid_until)` (no RPC:
the payment request alone fixes contract, network, `lane = batch_hex`, `pay_ref = entry_ref_hex`, nonce 0, relayer) and
`verify(request, payload, signature, public_key)` returning `True`, `False` or `None`:

<a id="INT-ERP-21"></a>**INT-ERP-21** — **ERP verifiers are three-valued and verify only with a key provably bound to the
payer** ([NET-ALL-14](networks/README.md#NET-ALL-14)): `False` for a wrong envelope or a bad signature; `True` only when
the public key derives the payer's address; `None` when the key cannot be tied to the payer without chain reads (rotated
keys, added keys, keyless or passkey accounts) — the job is then pushed with `signature_verified = False` and the node's
simulation decides. Sui verify follows the same rule as Aptos and Solana.

<a id="INT-ERP-03"></a>**INT-ERP-03** — **Contract wallets: the ERP defers to node simulation.** The browser reports the
`wallet_kind` (from `eth_getCode` through the wallet); for `contract` the ERP accepts the signature unverified and the
node's simulation arbitrates. A 23-byte `0xef0100…` code is an EIP-7702 delegated **EOA**
([CTR-UA-24](contracts/universal-account.md#CTR-UA-24)).

<a id="INT-ERP-13"></a>**INT-ERP-13** — **Hedera long-zero payers sign with their native ED25519 key.** A payer stored as
`0.0.N` (long-zero) takes the native-key path: the ERP issues the raw 32-byte digest, receives a **64-byte** signature
plus the public key, verifies ed25519 itself, and the key↔account binding is checked on chain (job with
`signature_verified = False`, since without RPC the ERP cannot know whether the key belongs to `0.0.N`).

<a id="INT-ERP-14"></a>**INT-ERP-14** — **The ERP verifies Stellar `G…` ed25519 through OpenSSL.** For `from` = `G…` the
check is real ed25519 over `sha256(payload)` with the master key from the strkey (64-byte hex signature), via the
`cryptography` library already required by custody, not a pure-language ed25519; for `C…` (custom account) `None`.

| Family | ERP specifics |
|---|---|
| Hedera | Chain `family = hedera`, `evm_chain_number` 295–298. An alias `0x…` payer uses the EVM path (EIP-712 + EIP-6963) unchanged. Tokens and receiving wallets entered as `0.0.N` are resolved through the mirror node (`/api/v1/{contracts|accounts}/0.0.N` ⇒ `evm_address`), because `0.0.N` → long-zero is right only for ED25519 accounts without alias, and a CREATE2 clone's `address(this)` is its EVM address (a long-zero entry would break `verifyingContract`). To check on testnet: `msg.sender` of an ECDSA account with alias is the alias `0x…`. The connector signs the raw `digest` with a page-provided ED25519 signer (`m/44'/3030'/0'/0'/i'` seed key); one key per family — a connector key that signs any 32 bytes is never shared with Stellar or a TON mandate delegate ([NODE-LANE-20](node/submit-lanes.md#NODE-LANE-20)) |
| Cosmos | `build_terms` builds the signed `payload` (contract = token address, `network` = `chain.network_key`); terms `{chain_id, signer, data_b64}`. `verify`: base64 64-byte signature + 33-byte pubkey, rebuild the ADR-036 doc, recover secp256k1 and compare; bind the address with `ripemd160` if `hashlib` has it, else `None`. Connector `cosmos.js`: `window.keplr || window.leap`, `enable(chainId)`, `getKey` ⇒ `{address, publicKey}`, `signArbitrary(chainId, signer, payloadString)` ⇒ `{signature, publicKey}`; no library |
| Soroban | `build_terms(request, valid_until)` ⇒ `payload` (XDR), `digest`, `contract` = token, `terms` = `{network_passphrase, contract, function: "pay", from, preimage_b64, nonce, expiration_ledger, …}`. The chain keeps an anchor timestamp updated on event ingest. Freighter: `@stellar/freighter-api` pinned and vendored in `static/lib/`, loaded lazily; `connect()` = `requestAccess` ⇒ `{address}`; `sign(terms)` ⇒ `signAuthEntry(preimage_b64, …)` |
| Sui | Token adds `sui_coin_type` (e.g. `0x2::sui::SUI`); `address` = the `Registry<T>` id; `chain.network_key` must equal the string given to `set_network`. A start checkpoint is taken at enable time (else the latest via the public RPC). A Sui receiving address is an object ⇒ checked as an `Account<T>`. `build_terms(req, valid_until)`: amount > u64::MAX refused; account = `derive(registry, payer)`; `MetaOp{pay, to=receiving, amount, pay_ref=entryRef, lane=batch, nonce=0, relayer=@0x0}` ⇒ `contract = account`, `terms = {message_b64, account, registry, network}`, `extra = {coin_type}`. `verify`: split the serialized signature; `blake2b256(flag ‖ pk)` must equal the payer; ed25519 / secp256k1 / secp256r1 checked with `cryptography`; passkeys check challenge + P-256, else `False`. Connector `connectors/sui.js`: pure Wallet Standard (`wallet-standard:register-wallet` / `wallet-standard:app-ready`), a wallet with `sui:signPersonalMessage`; `connect()` ⇒ `{address, publicKey}`; `sign(terms)` ⇒ `{signature (base64 serialized), publicKey}`; zkLogin/multisig accounts refused (key not 32/33 bytes, or flag ∉ 0/1/2/6) |
| Aptos | Chain `family = 'aptos'`, `network_key` = decimal chain id, `chain_key = aptos:<id>`, `caip2 = aptos:<id>`; adds the package address and a start block; root object id. `blockchain.token.address` = the FA metadata object; addresses normalised as for Sui (one shared normaliser). `build_terms(request, valid_until)`: amount > u64::MAX refused; `account = account_of(root, payer)`; `MetaOp{pay, …, lane=lane_batch(entryRef), nonce=0}` ⇒ `digest`, `contract = account`, `terms = {message, nonce, chain_id, account, asset, application}`, `extra = {asset}`. `verify(request, payload, signature, public_key)`: parse the blob strictly — `message` = digest and `application` = the portal origin, else `False`; bad ed25519 ⇒ `False`; pk proven when `sha3_256(pk‖0x00)` or `sha3_256(0x00‖0x20‖pk‖0x02)` = the payer ⇒ `True`; otherwise `None`. Any address receiving FA gets a primary store, so receiving wallets need no object check. Connector: Wallet Standard AIP-62 (`wallet-standard:register-wallet` / `wallet-standard:app-ready`, as `sui.js`), a wallet with `aptos:connect` + `aptos:signMessage`, network from `aptos:network` = `terms.chain_id`; `connect()` ⇒ `{address, publicKey}`, refusing non-ed25519-32-byte keys (keyless, MultiKey, secp256k1); `sign(terms)` ⇒ `signMessage({message, nonce, application: true, chainId: true})`, state `Approved`, `fullMessage` checked **before** returning `{signature: hex(sig64 ‖ utf8(fullMessage)), publicKey}`. Seed signer in `clientkeys`: `m/44'/637'/i'/0'/0'`. Tests: `node --test` with a fake wallet (line order, a second `message` line, wrong chain id, 33-byte key, refusal) |
| Solana | Chain `family='solana'`, `network_key` = genesis hash base58, `chain_key = solana:<genesis>`, CAIP-2 `solana:<first 32 chars of genesis>`; adds program id and config; `blockchain.token.address` = the mint, plus `solana_token_program` (`spl_token` | `token_2022`) to compute the deposit ATA. the Solana normaliser decodes base58 to exactly 32 bytes and returns standard base58. `build_terms(request, valid_until)`: amount > u64::MAX refused; `account = pda(["acct", owner])`; ⇒ `digest`, `contract = account`, `terms = {text, digest, network, account, asset, ocms_ok: true}`. PDAs in the ERP: sha256 + an "off-curve" check by ed25519 point decompression (~20 lines, RFC 8032 §5.1.3), cross-vectored with `Pubkey::find_program_address`. `verify(request, payload, signature, public_key)`: `kind 2` (passkey) ⇒ `None`; `kind 0/1`: message must equal `T`/OCMS else `False`; bad ed25519 ⇒ `False`; pk = payer ⇒ `True`. Connector: Wallet Standard (`wallet-standard:register-wallet` / `app-ready`, as `sui.js`), a wallet with `standard:connect` + `solana:signOffchainMessage` or `solana:signMessage`, `chains` containing `solana:<genesis32>`; `connect()` ⇒ `{address, publicKey}` (32 B); `sign(terms)` prefers `signOffchainMessage` (kind 1), else `signMessage(T)` (kind 0), and checks the returned `signedMessage` bytes before returning. Passkeys use the shared passkey signer (blob `kind 2`). Seed signer `m/44'/501'/i'/0'` signs `T`. Tests: `node --test` with a fake wallet (with/without OCMS, a wallet returning another message, wrong chain, key not 32 B, refusal) |
| TON | Chain: `ton_global_id` (default from `network_key`: -239/-3; required on localnet), app domain, manifest URL; token: jetton wallet code hash and depth. `build_terms`: `MetaOp` (lane = `batch_hex`, nonce 0, `pay_ref = entry_ref`), payload = BOC, digest = cell hash; connector terms `{schema, cell (base64 BOC), network, from, manifest_url}`. `verify`: wrong `domain` ⇒ False; **no `state_init` ⇒ None** (the declared key is not bound to the address); with it the hash must give the payer address. Cross vectors: `smartcontracts/ton/vectors/metaop.json`, checked by Python and Rust. TON Connect **embedded JS bridge** (`window[<jsBridgeKey>].tonconnect`): `connect(2, {manifestUrl, items:[{name:'ton_addr'}]})` ⇒ `{address, publicKey, walletStateInit}`; `send({method:'signData', params:[JSON]})`; no `@tonconnect/sdk`. Masterchain BFT: a committed block is final (`finality_mode = depth`, `depth = 0`/`1`). Normalised event `{event, contract=master, block_number=mc_seqno, block_hash=root_hash mc, tx_hash, log_index, from, to, amount, entry_ref, digest}`, addresses raw. `TradeSettled` is not ingested (as EVM) |

<a id="key-ops"></a>**Subject-account key operations (non-EVM).** The ERP library mirrors the on-chain key-op encoding:
op codes `ADD_KEY, REMOVE_KEY, ADD_ORIGIN, REMOVE_ORIGIN, SET_GUARDIAN, CANCEL_RECOVERY = range(6)`, domain
`KEYOP_DOMAIN = b'scaas.keyop.v1'` (callers pass `domain`), `keyop_bytes(network, account, op, …, valid_until)`,
`keyop_digest`, `personal_digest`, `parse_signature`, `address_of`, `verify_digest(…, rp_id_hash)` and `to_bytes`. The
passkey branch of `verify_digest` also refuses `b'"crossOrigin":true'` and `b'"topOrigin"'`; the vector generator
(`gen_vectors.py`) imports `keyop_bytes`; `signature_verified = False` for `None`. In a portal, a non-EVM signer pays with
the **owner key only**: the portal sends `signer.from` and has no chain reads, and a Sui `Account<T>` has no reverse
index from key to account, so the signer is `{family, account, owner, key_index}` with `key_index` 0.

## Accounting

<a id="accounting"></a><a id="INT-ERP-09"></a>**INT-ERP-09** — **One journal per (company, token); drift A and drift C.**
The token's journal is company-dependent: each company picks a bank journal per token, and payment transactions of the
chain provider post their payments to it. **Drift A** (unmatched inbound): `Transfer` events to watched receiving
wallets that belong to no transaction with a `PaymentSettled` become `unmatched_inbound` records for manual booking.
**Drift C** (balance): the node reads `balanceOf(receiving wallet)` hourly at a finalized height and serves `balances`
items; the client stores a balance snapshot and sets `drift_state = 'mismatch'` on two consecutive differences. A report
is compared only when its `height` equals the client's indexed cursor (else `stale`); the ledger side is the posted lines
of the token journal on the bank account plus every outstanding account the payment uses.

<a id="dex-accounting"></a><a id="INT-ERP-12"></a>**INT-ERP-12** — **The ERP mirrors DEX markets and books DEX fees.**
Market configuration lives in the node store ([NODE-DEX-14](node/dex-venue.md#NODE-DEX-14)); the ERP keeps read-only
mirrors of markets, orders and trades from the `dex_*` feed items and books: **DEX fees received** (the operator's fee
wallet) — debit the token journal's default account, credit the market's income account; **relayer fees paid** (payer =
an approved paying wallet of a company) — debit the market's relayer-expense account, credit that company's token journal
default account.

<a id="confidential-payments"></a><a id="INT-ERP-11"></a>**INT-ERP-11** — **Confidential payment requests are reconciled
from disclosed amounts, with an audit key per company.** The ERP issues confidential payment requests on Zether tokens,
reconciles from the amount the counterparty discloses (`ITransferDisclosure` opening) and holds the token's auditor key
per company. The token keeps ElGamal `acc/pending` balances with a decrypt bound of 2^40; design history:
[zether design](history/specs/2026-10-03-zether-design.md). Zether is **UNAUDITED — NOT FOR PRODUCTION FUNDS** and runs on dev chains
([contracts/zether](contracts/zether.md)).

## Procure-to-pay

<a id="procure-to-pay"></a>

A buyer pays a supplier's invoice with a public payment token (a META tier 2 wrapper of a stablecoin). Both companies may
use the same or different nodes.

| # | Step | System | Detail | Status |
|---|---|---|---|---|
| 1 | Bill approved | Buyer ERP | Vendor bill posted and approved (maker-checker for large amounts) | client |
| 2 | Payment request | Buyer ERP | `entryRef` random; request row (token, supplier's approved receiving wallet, amount in base units, payer wallet); typed data with `pay(entryRef)` | **BUILT** (example connector, inbound direction); outbound treasury payouts **PLANNED** |
| 3 | Sign | Buyer signer | Human approver signs on device (passkey/seed), or the delegated/custodial path signs under `SigningPolicyService` limits (`validUntil − now ≤ 300 s`) or `MandateWallet.payUnderMandate` | **BUILT** (device, mandate); policy service **PLANNED** |
| 4 | Outbox + push | Buyer ERP → node | Outbox row in the same transaction as `request → pending`; push `POST /v1/jobs` (`kind = metatx`, or `call` for mandates) | outbox **BUILT**; push **SPECIFIED** |
| 5 | Submit | Node | Lease, simulate, journal, broadcast; `MODE_RESTRICT_RELAYER` pins the company lane; fee 0 | **BUILT** |
| 6 | Finalize | Node indexer | Range with `PaymentSettled(buyer → supplier, amount, entryRef)` after the finality gate + RPC quorum | **BUILT** |
| 7 | Reconcile both sides | Buyer and supplier ERPs | Buyer: job final, bill paid (outbound payment entry in the token's journal). Supplier: its node/feed (or a watch on its receiving wallet) delivers the same event; it matches the `entryRef` the buyer communicated with the remittance advice (or a `Transfer` to its watched wallet) and posts the receipt | buyer **SPECIFIED**; supplier matching by `entryRef` **BUILT** for requests it issued itself |

When the **supplier** issues the request (its portal/invoice shows a pay link), steps 2 and 7 are on the supplier's side
and the buyer only signs (step 3) — the BUILT portal flow of the [example connector](#example-odoo-portal). Its
guarantees: (1) **no booking before finality** — done only from a finalized range, only when Σ `PaymentSettled` matching
(token, receiver, `entryRef`) ≥ the amount due; a range counts only after `quorum` RPCs agree, and `quorum = 1` is
single-provider trust; (2) **pay at most once per request** — every signature of a request shares the lane
`(from, batch)` with nonce 0, so the chain can execute only one; a different wallet (`from`) is another lane, so a new
`start` from a different wallet issues a new request, and every `validUntil ≤ first issue + H` (lane horizon, 30 d);
(3) **the server sets the amount** — `value` comes from the document; the client sends no amount; (4) **the relayer
never touches funds** — `to`, `value`, `data` are inside the digest; fee 0.

**Fast path and batching.**

| Path | Use today | Status |
|---|---|---|
| `executeMetaTransaction` with `data = pay(entryRef)` | Every relayed payment; emits `PaymentSettled` | **BUILT** |
| `payWithFee(to, amount, feeMode, fee, feeRecipient, entryRef)` | Contract wallets and payers submitting themselves | **BUILT** |
| v2 `mtxPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient, sig)` | Typed entry point over the SAME struct and typehash; lane `payLane(payId)` derived on chain, `nonce = 0`; same digest, so one signature works on either path ([CTR-MTX-10](contracts/metatx.md#CTR-MTX-10)) | **BUILT** (contracts); node use **SPECIFIED** |
| v2 `mtxBatch(MetaTransaction[], bytes[])` | Several intents of one token in one outer transaction, atomic (one failing item reverts all; the partial-success `batchMtxPay` and its second typehash were withdrawn, [CTR-MTX-11](contracts/metatx.md#CTR-MTX-11)) | **BUILT** (contracts); node batching **SPECIFIED** |

Client contract: same `entryRef`, same lanes (a request lane can be consumed by either path, never both), same
`PaymentSettled` — reconciliation code does not change; a second `PaymentSettled` for one `entryRef` (possible via
`payWithFee` or another lane) is a reconciliation exception, never a second payment. The node batches per
`(chain_key, token)` only items bound to its own lane, at 50 items or 3 s; batching is invisible to the client except
that several jobs share one `tx_hash`.

<a id="inbound"></a>**Inbound payments.**

| Pattern | How the client integrates | Status |
|---|---|---|
| Enterprise inbound gateway | Partners/agents post signed EVM meta-txs to the company node: `POST /v1/metatx {chain, token, m, signature}` (gateway auth `bearer`/`hmac` for partners; `none` only on loopback behind a proxy). The client sees results on its events feed by `entryRef`/`to` | **BUILT** |
| Door A intake rules | `value == 0` transfer/pay ⇒ `422 ZERO_VALUE`; the `~gateway` `min_fee` floor applies unless a sponsor policy matches (which also caps the spend); `profile = private` keeps fee 0, `profile = public` refuses fee-0 intents without a matching sponsor policy; per-`from` bucket (default 60 per hour); signature checked before simulation ([NODE-GW-01](node/gateway.md#NODE-GW-01)) | **SPECIFIED** |
| Gateway discovery and other families | `GET /v1/gateway` lists served chains (with `chain_uid` where a UA registry is configured), tokens, fee recipient and DEX policy; Hedera intents use `POST /v1/metatx` (64-byte HIP-632 signatures allowed); the six non-EVM families use `POST /v1/ops {chain, op}`; UA intents `POST /v1/ua-metatx`; errors follow the stable contract `{error, code, detail, revert_data?}` ([NODE-GW-06](node/gateway.md#NODE-GW-06)) | **SPECIFIED** |
| Non-EVM inbound | The client builds the `MetaOp`, the payer signs, the client pushes `signed_op` jobs | **BUILT** (via the example outbox); job API **SPECIFIED** |
| Payee self-relay ("e-cheque") | Payer signs offline with fee 0 and relayer unbound or bound to the payee's address; the payee (or its node) submits; the ERP books from `PaymentSettled` exactly as usual | contract **BUILT**; QR (EIP-681-style payload) tooling **PLANNED** |
| Gas sponsorship policy | Node policy rows: e.g. "to wallet W, value ≥ X ⇒ fee 0, gas to account Y"; the client books gas from the job's receipt data. A policy caps a tenant's own spend only with `on_exhausted = reject`; with `unsponsored` an exhausted policy books the job to the namespace and marks it `sponsor_fallback` (the admin must set `fallback_to_namespace`, audited) ([NODE-SPN-01](node/sponsorship.md#NODE-SPN-01)) | **SPECIFIED** |
| Receiver pays fee | Two signatures (payer's `pay`, payee's fee authorization); booked as payment N and fee F | **SPECIFIED** ([CTR-MTX-05](contracts/metatx.md#CTR-MTX-05); job field `receiver_fee`, event `ReceiverFeePaid`) |

Receiver pays, client side: the **payee ERP** sets `fee_paid_by_receiver` and `receiver_fee_amount` (base units) on the
request it issues; the payer's terms stay fee `NONE`; once the payer's address is known (portal: wallet connect), the
payee signs `ReceiverFee` over the `paymentDigest` (a `SubjectAccount` payee signs through `executeAsOwner` rules) and
books payment `N` received and fee `F` paid from `PaymentSettled` + `ReceiverFeePaid`. The **payer ERP** is unchanged
(pays `N`, books `N`). **E-cheque flow:** the payee's request names the relayer lane; the payer signs offline with that
relayer bound and hands the intent to the payee, which co-signs over the digest and pushes it to that node.

Never accept raw subject-signed native transactions (Sui `txBytes`, TON BOC from the subject wallet, Stellar envelopes)
as the integration format: they order operations by the subject's account sequence. Always use the contract-level
payload of the family ([NET-ALL-02](networks/README.md#NET-ALL-02)).

## Sealed-bid tender in procurement

<a id="tender"></a>

The contract is [contracts/tender](contracts/tender.md). The commit is the deposit token's own `pay` intent; reveal,
withdraw and settle need no signature and can be run by any keeper. **Open (call table):** the tender's `call` jobs
(`createTender`, `commitBid`, keeper `revealBid`/`withdrawDeposit`/`settleTender`, bond calls) are not yet rows of the
[call table](#call-targets), so the node refuses them (`CALL_TARGET_REFUSED`) until the rows are added (target rule:
the chain's `chain_contract.kind = tender`). Until then the buyer's and bidders' wallets send these calls themselves.

**Buyer (ERP):**

| # | Buyer ERP | Chain |
|---|---|---|
| 1 | Tender record linked to the RFQ; documents normalised (JCS), `documentRef` = salted commitment ([data protection](#data-protection)); deposit token, `minDeposit`, deadlines, public reserve, `minBidders`, bond policy, `slashSink`, allowlist root, `dqWindow`, `maxDisqualifications`, `forfeitClasses` | — |
| 2 | Chain check: refuses, or warns with a recorded reason, on a chain whose validators the buyer organization controls alone; then a `call` job `createTender(config)` from the buyer account (namespace with `allow_call`, [NODE-JOB-09](node/job-api.md#NODE-JOB-09)); stores `tenderId` from `TenderCreated` | `TenderCreated` |
| 3 | Publishes tender id, deadlines, deposit terms, eligibility proofs; may offer a sponsored portal path, never as the bidders' only path | — |
| 4 | Watches commits (count only); may cancel until `commitDeadline` (all deposits refund) | `BidCommitted`, `TenderCancelled` |
| 5 | Inside the award window: due diligence on the leader; if it fails, `disqualifyWinner(reasonRef, class)` with the reason document committed and retained for audit and dispute (leader only, only while a next valid bid exists) | `BidDisqualified` |
| 5b | Then `settleTender` (buyer early, or any keeper after the window) | `TenderSettled` |
| 6 | On the **finalized** `TenderSettled`: PO to the winner; non-revealers = committed set − revealed set (flagged from `DepositSlashed`); keeper jobs `withdrawDeposit` for every bid (refunds and forfeits) | `DepositRefunded`, `DepositSlashed` |
| 7 | Bond: `releaseBond` on contract signature/delivery, or `claimBond(reasonRef)` | `BondReleased`/`BondClaimed` |
| 8 | Supplier invoice paid with `mtxPay` and a **fresh random `entryRef`**; the link tender ↔ PO ↔ invoice ↔ `entryRef` stays off chain | `PaymentSettled` |

The payment `entryRef` is never derived from `tenderId`. The ERP never sees prices before reveal and creates the PO only
from the finalized `TenderSettled`.

**Bidder (ERP, portal or app):**

0. **Independent path (normative).** Before signing a deposit intent, the bidder's ERP/app checks that it can submit
   `commitBid` and `revealBid` on that chain **without the buyer**: its own node namespace or a neutral sponsor, never
   only the buyer's portal ([CTR-TND-04](contracts/tender.md#CTR-TND-04)).
1. Generate `salt`, compute `commitment = commitmentOf(…)` locally — `keccak256(abi.encode(BID_TAG, chainId, tender,
   tenderId, bidder, price, salt))` — and store `(tenderId, price, salt)` in the bidder's secret store **before**
   signing.
2. Build and sign the deposit intent ([CTR-TND-01](contracts/tender.md#CTR-TND-01)): `to = tender`,
   `value = minDeposit`, `data = pay(depositRef)`, `batch = payLane(depositRef)`, `nonce = 0`,
   `mode = MODE_RESTRICT_RELAYER`, `relayer = tender`, `fee = 0`, `feeRecipient = 0`, `validUntil ≤ now + 3600`.
3. Submit `commitBid` as a `call` job (own path, or the portal). Verify `BidCommitted` is final; if missing before
   `validUntil`/`commitDeadline − margin`, submit the same signed intent through the independent path.
4. After `commitDeadline`: submit `revealBid(tenderId, bidder, price, salt)` (no signature) through the independent path, or hand `(price, salt)` to the
   portal **and** verify `BidRevealed` before `revealDeadline − margin`, falling back to the independent path. Live-call
   dedupe is per namespace, so a portal copy never blocks the bidder's own path; on its own namespace
   `409 DUPLICATE_CALL {uid}` names its own live job.
5. After settlement: the refund arrives through any keeper's `withdrawDeposit(tenderId, bidder)`; the bidder's ERP books it from
   `DepositRefunded` (the outgoing deposit was booked from its own `PaymentSettled(entryRef = depositRef)`).

**Gas.** Bidder steps are relayed `call` jobs, so a bidder needs no native coin **if** its independent path pays gas (its
own node, or a neutral sponsor). A buyer may additionally sponsor its tender's `commitBid`/`revealBid`/`withdrawDeposit`/
`settleTender` (a sponsor policy matching `job_kind = call` to that tender); ERC-1271 bidders need the policy's
`max_cost_per_tx` sized for their verification cost ([contracts/tender](contracts/tender.md) gas table).

**Salt generation and backup.** A lost salt means a forfeited deposit. Either (a) 32 CSPRNG bytes, encrypted backup with
the bid record; or (b) derived from a high-entropy secret the bidder already backs up:
`salt = HKDF-SHA256(ikm = secret, info = "scaas.tender.salt" ‖ chainId ‖ tender ‖ tenderId)`, where the secret is never
the bid's own data. Either way the salt is unknown to anyone else until reveal, and in particular before
`commitDeadline`.

## Accounts, Universal Accounts and identity

<a id="accounts"></a>

**Subject accounts (BUILT).**

- **EVM `SubjectAccount`** (passkey + seed keys, guardian): address predicted by
  `SubjectAccountFactory.predict(firstKey, guardian)`; the client enqueues a `call` job `deploy(firstKey, guardian)`
  **before** the subject's first payment (deploy is permissionless and idempotent). Key changes go through
  `executeAsOwner` signed by an existing key (client builds `OwnerCall(bytes data,uint256 nonce,uint256 validUntil)`).
  Under Universal Accounts it is **option (b)**: the optional smart account for subjects who want recovery without moving
  funds or one address across key changes ([CTR-ACC-09](contracts/accounts-mandates.md#CTR-ACC-09)); its seed keys come
  from the role path `m/7622'/0'/<account>'/2'/<i>'`, never the EOA path
  ([CLI-SGN-30](clients/signers-clientkeys.md#CLI-SGN-30)).
- Non-EVM: open the subject's account object (`meta::open`/`open_passkey` on Sui/Aptos, `open`/`open_passkey` on
  Solana, custom account on Soroban). TON needs no open step and has no `BindKey` message: the first `SignedOp` carries
  the owner wallet's `stateInit` and the jetton wallet binds the key lazily.
- Every Aptos, Sui and Solana program is immutable at deploy, and Cosmos code is instantiated `--no-admin`
  ([NODE-STO-07](node/store.md#NODE-STO-07)): a contract fix is a new deployment with new package/program/account ids,
  and subjects move their balances by signing `pay` from the old account. Clients re-read chain profiles after such a
  redeploy.

**Universal Account registration (SPECIFIED; [contracts/universal-account](contracts/universal-account.md)).** It
replaces the Zether-only flow of the built `UniversalAccountRegistry` (`UA = keccak256(encodedY)`, PoP bound to
`msg.sender`, `AuthScheme`, `linkEVM`), which stays on dev chains until the new registry ships.

**Native accounts are never registered** ([CTR-UA-06](contracts/universal-account.md#CTR-UA-06)): an EVM EOA or contract
account (incl. `SubjectAccount`, Safe), Hedera native accounts (an `msig` member only on Hedera registries), Solana,
Stellar/Pi `G…`, Soroban `C…`, Aptos, Sui and Cosmos native accounts, TON wallets. They sign as today. Every **derived**
kind (passkey `webauthn-p256`, `p256`, `ed25519`, `bip340`, Schnorr/BLS, MuSig2/FROST, `msig`, ML-DSA/FN-DSA,
`zether-*`, `pqz-mlwe`) registers once on each chain where it is used:

1. The client derives the key for the kind on its own path (`m/7622'/0'/<account>'/<kindNo>'/<i>'`; Zether conf keys
   keep `m/254|12381/<coin>/<account>/7`; passkeys are one credential per `rpId`), builds the normalised `keyData`,
   computes `ua = keccak256(keccak256("scaas.ua.<kind>.v1") ‖ keyData)` and checks `ua >> 160 ≠ 0`.
2. It reads `popDigest(ua, authRef)` from the registry, or computes it —
   `keccak256(POP_TAG ‖ keccak256(chain_key) ‖ chainUid ‖ registry_id ‖ ua ‖ authRef)` binds chain (`chain_key` **and**
   `chain_uid`, the genesis hash: the chain id alone is not unique, [NET-ALL-22](networks/README.md#NET-ALL-22)),
   registry, UA and `authRef`, **not the caller** ([CTR-UA-07](contracts/universal-account.md#CTR-UA-07)). `chain_uid`
   comes from the chain profile (`GET /v1/gateway`) and must equal the registry's `chainUid()`; clientkeys refuses an
   EIP-712 domain whose `salt` differs from it. The client then signs `uaMessage(kind, POP_TAG, popDigest)` with the
   kind's signer (`UAKey.signUA("pop", …)`; MuSig2/FROST: a group signing session plus the KeyAgg hints or the DKG
   transcript). For a Zether kind with `authRef ≠ 0` the authority also signs `authPop` (purpose `authref`; a native
   authority signs the EIP-712 `UAAuth`). `authRef = 0` for every non-Zether kind.
3. **Anyone** submits `register(kind, keyData, pop, authRef, authPop)`: the subject self-paid, a relayer job, a sponsor,
   or the node gateway `POST /v1/ua/register {chain, kind, keyData, pop, authRef}` (gasless,
   [NODE-GW-03](node/gateway.md#NODE-GW-03)) — the only node path, since registry calls run only from `~gateway`.
   Front-running yields the identical record or a revert.
4. On the finalized `UARegistered` event the client reads `recordOf(ua)` — kind **and** `authRef` equal what it asked
   for — and only then marks the account usable on that chain.

Kind choice: staff/outlets with a phone → `webauthn-p256` UA (or `SubjectAccount` when they want recovery);
extension-wallet users → native EOA; boards and finance → `msig` over members' passkey UAs and/or EOAs (each member
confirms its listing off chain; membership is not consent); agent clusters and Schnorr MPC → `frost-*` (shown with its
attestation-only caveats); HSM keys → `p256`; confidential balances → `zether-*` with `authRef` one of the above; PQ
authority → `mldsa65`; PQZ on the private chain → `pqz-mlwe` with a PQ `authRef`. The registry refuses the same public
key under a second kind (`UAKeyInUse`) and a BLS `authRef` on the same curve as the Zether key.

**Identity sync rules.**

- The party ↔ address/UA mapping lives only in the client (erasable, [data protection](#data-protection)); a UA record
  holds kind, normalised id, key data and per-chain registrations.
- Normalised UA form everywhere: lower-case hex; a value whose top 96 bits are zero is the 20-byte native id. On non-EVM
  families a derived id is shown only as `urn:scaas:ua:v1:<kind>:<hex32>`, never as a native address
  ([CTR-UA-03](contracts/universal-account.md#CTR-UA-03)).
- Receiving wallets are approved with four-eyes and become usable after the cooling-off ([INT-ERP-01](#INT-ERP-01));
  push them to the node watch list.
- A UA is the same on every chain (chain-independent id) but registered per chain; never per token. No rotation inside a
  UA: a new key is a new UA plus a transfer ([CTR-UA-13](contracts/universal-account.md#CTR-UA-13)); a stable address
  across key changes is `SubjectAccount`.
- EVM balances of derived UAs exist only on MetaToken v3 clones (`bytes32` ledger, events `UATransfer`,
  `UAMetaTransactionExecuted`); v1/v2 tokens accept native ids only ([CTR-UA-14](contracts/universal-account.md#CTR-UA-14)).
- EIP-7702 delegated EOAs are native EOAs ([CTR-UA-24](contracts/universal-account.md#CTR-UA-24)): their key signs as an
  EOA everywhere; the UA registry and v3 also accept an ERC-1271 signature through the delegate. Never register them.
- Verifiable credentials stay optional ([CTR-UA-20](contracts/universal-account.md#CTR-UA-20)). A BBS presentation is
  never legal evidence: workflows with legal recourse require the account-bound KB-JWT with `nonce` = deal reference /
  `intent_id`.

## Regulated-token compliance

<a id="regulated-assets"></a>

```
authority order ──► issuer legal/compliance verifies; orderId = keccak256(normalised order id), document hash off chain
        ──► compliance contract (multisig) records the order {subject, beneficiary, maxAmount, freezeUntil}
        ──► issuer contract (multisig) freezes the subject, then force-transfers ≤ maxAmount to the beneficiary
            (members sign on their devices; the client pushes `call` jobs from a namespace with allow_call —
             once the issuer/compliance selectors are call-table rows; until then the multisig submits)
        ──► finalized freeze / order / forced-transfer / pause events
        ──► client books the effect (reclassify the frozen balance, post the forced transfer) and links the order
            document to the event
```

Rules ([CTR-AS-03](contracts/asset-suite.md#CTR-AS-03)): `issuer` and `compliance` are contracts, never EOAs; a forced
transfer needs a live order record and moves only from the frozen subject to the recorded beneficiary; there is no
court-ordered burn (a burn is a forced transfer to a beneficiary that burns or unwraps); frozen accounts still receive;
issuer-only freezes ≤ 30 days; pauses ≤ 7 days with a 7-day cooldown, and fee-less unwraps are never paused. Every
intervention event is reconciled to exactly one approved request (unmatched intervention events ⇒ incident).
Eligibility: the token pins a `ComplianceRegistry` and a `requiredFlags` mask; only receivers are checked; the client
keeps KYC/accreditation data off chain and only an attester pushes flags (no personal data on chain; optional VC
layer). An issuer wizard (templates, inputs, human-rate preview, mandatory disclosure) and a compliance console that
**builds** Safe transactions for orders, freezes, forced transfers, pauses and relaxations are client tooling; signing
stays with the multisig members.

**Asset-suite configuration.** Creating a token is a subject-signed (or treasury-multisig) factory call sent directly by
the creator's wallet; a `call` job to the factory is refused by the node. Templates are off-chain presets mapping to one
factory call plus optional action contracts ([CTR-AS-14](contracts/asset-suite.md#CTR-AS-14)).

| Template | Call | Client configuration | Status |
|---|---|---|---|
| Loyalty points (tier 1) | `createMetaToken(1, address(0), abi.encode(name, symbol, decimals, initialSupply, minter), salt)` or v2 `createTiered(META_NONE, …)` | `minter` = the issuer's mint contract or multisig; earn rules in the ERP trigger `mint` jobs; fee 0 | **BUILT** |
| Internal 1:1 money (tier 2) | `createMetaToken(1, underlying, abi.encode(name, symbol, 0, 0, address(0)), salt)` | Journal per (company, token) for accounting; wrap/unwrap by holders | **BUILT** |
| Wrapper with a rate, multi-underlying (tiers 2/3, v2) | `createTiered(kind, version, underlyings[], initData, salt)`, kind `META_SINGLE` or `META_MULTI` | rates fixed or adjustable (contract `rateAdmin`), guardian for multi | **BUILT** (contracts; client fields SPECIFIED) |
| Confidential money | `createZetherToken(1, underlying, verifier, abi.encode(name, symbol, registry, shieldScale, maxDecryptableShielded, confidentialFee, auditorKey), salt)` | dev chains only until audit; curve decision; auditor key custody | **BUILT** (dev chains) |
| Regulated tokens (kinds 5–7), vesting (`VestingGrant`), distributions, `ExchangeOffer` | `createTiered(META_*_REG, …)`; counterfactual clones via `predict*` | issuer/compliance contracts, `ComplianceRegistry`, `termsHash` disclosure | **SPECIFIED** |
| NFT kinds | — | — | **PLANNED** |

After creation: read `predictAddress` before, verify `isDeployedHere`, `creatorOf`, `versionOf` after (decoders know
kinds 0–7); register the token on the node (`POST /v1/admin/chains/{key}/tokens`) and in the client
(`PUT /v1/tokens/{chain}`), record the EIP-712 domain from `eip712Domain()`.

## Data protection

<a id="data-protection"></a>

Crypto-shredding covers the commitment formats, salt and key handling on the client, erasure and retention, and audit.
It removes the link to a person, not between addresses: the address graph stays public. Anchoring contracts and batch
scheduling are out of scope; only the commitment and leaf formats are fixed here.

| Data | On chain | Node | Client |
|---|---|---|---|
| Party identity, documents, contact data | never | never | yes (erasable) |
| Address ↔ party mapping | never | never | yes (erasable) |
| Salts, per-subject DEKs | never | never | yes (secret store) |
| Commitments, Merkle roots, `entryRef`, `depositRef`, digests | yes (permanent) | job payloads ≤ 30 d | yes |
| Addresses and transparent amounts | yes (permanent, value transfers) | job payloads ≤ 30 d, feeds 7 d | yes |
| Zether ciphertexts, auditor ciphertexts | yes (permanent) | job payloads ≤ 30 d | openings only when produced |
| Revealed tender prices | yes (permanent) | feeds 7 d | yes |

<a id="INT-ERP-22"></a>**INT-ERP-22** — **The client holds every salt and key; the chain holds only commitments; the node
holds neither salts nor personal data.** Node payloads are addresses, amounts, digests and commitments, retained for
`job_retention_secs`.

<a id="INT-ERP-23"></a>**INT-ERP-23** — **Commitment and Merkle formats:**

```
salt        = CSPRNG(32 bytes), one per record, never reused, never derived from the payload
payloadHash = SHA-256(JCS(payload))                          # RFC 8785, the same form as job payload hashing
commitment  = keccak256(abi.encode(REC_TAG, salt, payloadHash))
leaf        = keccak256(0x00 ‖ commitment)
node        = keccak256(0x01 ‖ min(a, b) ‖ max(a, b))        # sorted pairs; a custom verifier, not OZ MerkleProof
# replaces the earlier draft form commitment = keccak256(salt ‖ canonical(payload))
```

Only `commitment` goes on chain (or into a Merkle root).
Uses: `documentRef` (tender documents), `reasonRef` (cancel, bond claim), anchored records and batch roots. The payload is
never on chain; `payloadHash` alone is not published (a hash of a guessable payload is not a commitment).

<a id="INT-ERP-24"></a>**INT-ERP-24** — **Salts and anchored payloads are encrypted under a per-subject data key (DEK);
erasure destroys the DEK.** Hierarchy: KEK (KMS/HSM/Vault transit, or a key file/env secret outside the database) →
per-subject DEK (AES-256-GCM key, wrapped) → **salt and anchored payload** of each record encrypted with the DEK; the
subject is referenced as `subject_ref = HMAC(subject_key, party id)`; erasure logs are keyed by a separate `log_key`.

- **Tier A (KMS/secret store):** DEK destroyed in the KMS ⇒ salts and payloads unreadable everywhere, backups included,
  at once.
- **Tier B (no KMS):** wrapped DEK in the ERP database; erasure deletes it; complete when the last backup holding it
  expires (the deployment's backup retention, stated in its records of processing).
- **Not covered by the DEK (both tiers):** address ↔ party mappings (wallet approvals, payment requests) and ERP master
  data. They are deleted from the live database at once and leave backups at backup expiry, with itemized tombstones
  keyed by `subject_ref` replayed after any restore.
- **Multi-subject records:** the record's salt and payload are encrypted under a record key wrapped by each subject's
  DEK. Erasing one subject is refused (`legal_basis = other_subject`) while another subject's retention holds.
- **Never:** salts in the node store, on chain, in logs, in analytics exports, or derived from the payload or from a
  business id.

<a id="INT-ERP-25"></a>**INT-ERP-25** — **References carry no personal data and are not derived from business
identifiers.** `entryRef`/`payId`: 32 random bytes per payment request ([CTR-MTX-03](contracts/metatx.md#CTR-MTX-03));
never a hash of invoice numbers or parties; no salt needed; erasure = delete the request ↔ party link. `depositRef` is
derived from `(chainId, tender, tenderId, commitment)`: public data only. `documentRef`, `reasonRef`, bond/claim
references are salted commitments, so the documents and reasons they name are shreddable. `origin.key` and `client_ref`
sent to the node ([NODE-JOB-04](node/job-api.md#NODE-JOB-04)) are opaque (`entryRef`, record ids), never names. Bidder
identities are public at commit (addresses), prices at reveal, forever.

**Erasure and retention:**

```
erase_subject(party_id, reason) -> {ticket, erased: […], refused: [{model, id, legal_basis, retain_until}]}
requires role compliance_officer (client side)
1. ticket = random 16 bytes; append {ticket, HMAC(log_key, party_id), reason_code, scheduled_at} to the erasure log
2. for every record of the subject: retain_until > now ⇒ refused with its legal_basis; else delete
3. destroy the subject's DEK (tier A) or delete the wrapped DEK (tier B); delete address ↔ party mappings
4. node data needs no action: it holds no personal data and expires by job_retention_secs
```

Retention conflicts (accounting, anti-money-laundering, contract duties) refuse until `retain_until`, with the legal
basis returned; surplus personal data is still deleted; on-chain pseudonyms are handled by deleting the mapping. Zether:
erasure deletes the off-chain UA ↔ party mapping; the confidential amounts stay encrypted; disclosure proofs already
handed to a counterparty or auditor cannot be revoked (state this to data subjects).

<a id="INT-ERP-26"></a>**INT-ERP-26** — **Disclosure is opening a commitment.** An auditor verifies a commitment from
`(salt, payload)`, a batch member from the Merkle path; Zether amounts via `ITransferDisclosure.verifyTransferAmount`
(view, leaves no trace) or a counterparty's `attestTransferAmount`, which emits `AmountAttested(entryRef, amount, …)`.

| Question after erasing X | Answerable? |
|---|---|
| Retained record Y existed at time T | yes: `(salt_Y, payload_Y)` opens Y's commitment; Merkle path from leaf to the anchored root |
| Integrity of the remaining batch | yes: leaves are hashes of commitments, not personal data; the client keeps the leaf list after shredding X |
| What X contained / who X was about | no (by design) |
| Payment N from address A to B with `entryRef` E | yes from chain data; who A or B is: only while the mapping is retained |
| Zether amount of transfer E | yes with an opening (`ITransferDisclosure`: `SENDER_S`, `RECEIVER_X`, `AUDITOR`) via `verifyTransferAmount` (view, leaves no trace); identity only while the mapping is retained |
| Tender procedure fairness | yes: all events and reveals are public; `documentRef` opens only while its salt is retained |

Disclosure flow: the client hands the auditor `(salt, payload)` for the specific record, never the DEK. Transparent tokens:
amounts are public; reconciliation uses `entryRef`. Zether tokens: the receiver or sender produces an
`ITransferDisclosure` opening for the counterparty or an auditor; the token's auditor key reads every `C_aud` of that
token. The independent verifier CLI (PLANNED) gains `verify-commitment` and `verify-merkle`. Erasure of a salt makes its
commitment computationally unlinkable (2^256 preimage space); the on-chain value becomes random data.

## Failure handling and reconciliation runbook

<a id="runbook"></a>

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
| Chain halted for an upgradeable program | `409 CHAIN_HALTED`; operator reason `PROGRAM_UPGRADEABLE` (Aptos/Sui/Solana package or program still upgradeable, [NODE-STO-07](node/store.md#NODE-STO-07)) | Nothing to fix client-side; the operator redeploys immutable and the client updates the chain profile (new package/program and account ids) |
| `CALL_TARGET_REFUSED` | `403` per item (push) or `dead` with that error (pull) | Permanent: the call shape is not in the node's table. Do not retry; send the call from the subject's/treasury's wallet or ask for a table row |
| `VALUE_OUT_TOO_HIGH` | `422` per item | Permanent for this payload: the signed forward/value floor exceeds `chain.max_value_out` (TON); have the payer re-sign with a floor ≤ the cap |
| `DEPOSIT_NOT_ALLOWED` | `422` per item | The lane would fund a deposit a third party can reclaim (Solana: destination ATA missing for an unconfigured receiver); the receiver creates its ATA, or the operator configures the receiving wallet |
| `SUBJECT_THROTTLED` | `429 {retry_after}` | Retry after `retry_after`; the subject's intents keep failing after simulation (balance moved, nonce burnt, key changed) — investigate before re-pushing |
| `ATTEMPTS_EXHAUSTED` | Snapshot `dead`, `error = ATTEMPTS_EXHAUSTED` | Request stays open; re-sign if still wanted (new job); several in a row ⇒ check the chain's health with the operator |
| `IDEMPOTENCY_MISMATCH` | 409 with `uid` | The business payload changed under the same key (e.g. module upgrade); fetch the node job, compare, decide manually; never mark dead |
| Range gap | `from_block > indexed + 1` | Halt event sync, needs attention; check the node's event-node routing and restore events from 0 |
| Store recreated or restored | `store_id`/`restore_epoch` change, `head_seq < cursor`, incarnation mismatch | Halt sync; operator verifies the node runbook was followed (`store restored` CLI), then acknowledges in the client; acknowledged re-push of non-terminal jobs (old outer txs may still be in a mempool: funds safe, gas may be lost) |
| Underpayment / overpayment | `partial` / `final` + needs attention | Partial: wait or re-request; overpayment: manual refund from the company wallet |
| Unknown inbound transfer to a watched wallet | Drift A record | Identify the payer off chain; book manually |
| Balance drift vs ledger | Drift C mismatch on two consecutive snapshots | Reconcile journal vs wallet (sweeps to cold wallets must be booked) |
| Business hook failure during ingest | Event and cursor committed; request needs attention | Fix the accounting condition (closed period, credit hold) and re-run the hook manually |

**Daily reconciliation.**

1. Every non-terminal pushed job older than its `valid_until + 1 h` ⇒ `GET /v1/jobs/{uid}`; mismatch with the local state
   ⇒ apply the snapshot.
2. Every request `open/partial` past `expiry_datetime` with no live signature ⇒ expire and cancel the payment transaction.
3. For each (company, token): Σ finalized `PaymentSettled` into receiving wallets (feed) = Σ booked receipts; Σ wallet
   balances (latest `balances` item at the indexed height) = ledger balance of the token journal (± booked sweeps).
4. `needs_attention` queue reviewed by an operator; every item closed with a note.
5. Gas cost per finalized job allocated to its business document (PLANNED).

**After a node restore (client side).**

1. Sync halts automatically (continuity check, [INT-ERP-19](#INT-ERP-19)).
2. Confirm with the node operator: restore time, `restore_epoch`, re-revoked keys.
3. Acknowledge the store change (system role): cursors reset, non-terminal pushed jobs return to `local`.
4. Re-push; idempotency returns `created: false` for jobs the restored store still knows; new jobs are created for the
   rest; consumption checks on the node prevent double execution (the subject nonce is the final guard).

## Integration checklist

<a id="checklist"></a>

- [ ] Outbox row written in the same transaction as the business change; no network call inside it.
- [ ] Typed data built server-side; amount and `validUntil` chosen by the server; `entryRef` random.
- [ ] Signature shape verified before push; never store subject secrets.
- [ ] HMAC client passes the shared KAT; clock synced (NTP); the API key lives only in the server-side secret store
      (never in a browser, mobile or desktop app or extension).
- [ ] Idempotency tuple stable across retries; generation bumped only by operator requeue.
- [ ] Outbox rows immutable after create (kind, target, calldata, payload links, origin); operators read-only, requeue
      through one checked method; a different call is a new row.
- [ ] `call` jobs only for selectors/targets in the call table; everything else sent from the subject's or treasury's
      wallet.
- [ ] Every signature on a pay lane inside the 30-day lane horizon; new request (new `entryRef`) instead of re-issuing
      old terms.
- [ ] Error handling covers `CALL_TARGET_REFUSED`, `VALUE_OUT_TOO_HIGH`, `DEPOSIT_NOT_ALLOWED` (permanent),
      `SUBJECT_THROTTLED` (retry later), `ATTEMPTS_EXHAUSTED` (dead), `PROGRAM_UPGRADEABLE` halts.
- [ ] `push_attempted` committed before HTTP; permanent vs transient errors distinguished; 409 never ⇒ dead.
- [ ] Both feeds polled with overlap; cursors persisted with `store_id`, `incarnation`, `restore_epoch`; continuity checks
      halt on mismatch.
- [ ] Business documents booked only from finalized events matched on (chain, contract, to, `entryRef`).
- [ ] Business hooks isolated so they never block the cursor.
- [ ] Watch list and token subset pushed after every wallet approval and token activation.
- [ ] Cancel semantics implemented (`TOO_LATE` = already sent; `cancelMetaNonce` for subject-side cancel).
- [ ] Database copies neutralized (secrets removed, pushing disabled).
- [ ] No personal data in any payload; party ↔ address mapping erasable on the client side.

<!-- example:odoo -->
## Example: Odoo connector

<a id="example-odoo"></a>

The Odoo addons are **one example** of a SCaaS client; another ERP implements the same contract with its own models.
Names below are Odoo-specific. Every service entry point is a public model method (no `@api.private`, guarded by `check_service()`, writes under
`sudo()` only after that check) reachable by `call_kw` and `POST /json/2/<model>/<method>`, with private implementations, and never accepts `company_id` from the client. Scheduled-job bodies live in model methods
(the `ir.cron` eval context has no `fields`); secrets live in `ir.config_parameter`.

<a id="example-odoo-addons"></a>**Addons.**

| Addon | Depends | Auto-install | Role | Status |
|---|---|---|---|---|
| `dms_blockchain` | `base`, `mail` | `False` | Chains, RPC endpoints, tokens, metatx/signed-op envelopes, outbox `blockchain.relay.job`, chain events, payment requests, receiving/paying wallets (four-eyes), subject accounts, family address/digest libraries (`lib/eip712.py` — keccak-256 + EIP-712 + ecrecover in pure Python; `lib/fam_*.py`, KAT-locked) | **BUILT** |
| `dms_blockchain_payment` | `dms_blockchain`, `account_payment` | `False` | `payment.provider` `code='chain'` (`code = 'chain'`), `payment.method` `chain`; `payment.transaction` ↔ `blockchain.payment.request`, `_set_done`; auto-pay policies (`blockchain.autopay.policy`/`.run`) with custodial (`env:` dev-only adapter) and delegated (`MandateWallet`) modes | **BUILT** |
| `dms_blockchain_bridge` | `dms_blockchain_payment`, `dms_portal` | **`True`** | Portal facade on `dms.portal.api` (`dms_portal_chain_payment_options/start/submit/status`, subject-account register/add-key) + JS signers (EIP-6963, passkey, seed vault, family connectors) | **BUILT** |
| `dms_blockchain_dex` | `dms_blockchain` | `False` | DEX markets, read-only book/trade mirrors, DEX and relayer fee accounting | **BUILT** |

`bamboo_dms` and `dms_portal` depend on none of these; the bridge installs itself when both sides are present
(`auto_install: True` = `set(depends)`).

<a id="INT-ODOO-05"></a>**INT-ODOO-05** — **`dms_blockchain_payment` depends on `account_payment`** (formerly `payment`):
auto-pay reads invoices and hands reconciliation to `account_payment`; provider `chain` is not installable on a database
without accounting.

<a id="INT-ODOO-06"></a>**INT-ODOO-06** — **No `bamboo_idempotency` dependency; dedup by UNIQUE natural keys.** An
optional addon must install independently, and `bamboo_idempotency` adds a column to **every** table; it can be added
later as a dependency if needed.

<a id="INT-ODOO-07"></a>**INT-ODOO-07** — **The blockchain addons never depend on the DMS core; no accounting addon of
their own.** Three addons (`dms_blockchain`, `dms_blockchain_payment`, `dms_blockchain_bridge` for the portal), no
`dms_blockchain_account` and no `dms.payment.collection` (`depends ['dms_blockchain','dms']` was rejected); the bridge is
`depends ['dms_blockchain_payment','dms_portal']`; `account_payment` already creates `account.payment` when a transaction
is `done`. The DEX addon came later.

**Data model essentials.** Conventions: model prefix `blockchain.`; uint256 = `Char` + CHECK `'^(0|[1-9][0-9]{0,77})$'`
with suffix `_base`; addresses `Char` + CHECK `'^0x[0-9a-f]{40}$'` (stored lower-case; per-family checks for non-EVM);
hashes `_hash`; no `size=`; constraints are `models.Constraint` / `models.UniqueIndex` (`_sql_constraints` is ignored by
Odoo 19).

- `blockchain.chain` (`mail.thread`): `name`, `evm_chain_number` (unique), `caip2` (`eip155:<n>`), `native_currency`,
  `state` (`draft`/`active`/`paused`), `finality_mode` (`depth`/`tag`), `finality_depth`, `finality_quorum`,
  `indexed_block`, `public_rpc_url` (for `wallet_addEthereumChain`); activation refuses `rpc_urls < quorum`; seeds for
  100, 42220 and the private chain 7622 (formerly 9000).
- `blockchain.token` (`mail.thread`): `chain_id`, `address`, `name`, `symbol`, `decimals`, `domain_name` (default
  `SCaaS MetaToken`), `domain_version` (`1`), `currency_id`, `is_confidential`, `active`; `UNIQUE(chain_id, address)`.
- `blockchain.metatx` — signed envelope, immutable after signing: `company_id`, `chain_id`, `token_id`, `from_address`,
  `to_address`, `value_base`, `data_hex`, `batch_hex`, `nonce_base`, `valid_until_datetime`, `mode_flags`
  (`@api.constrains` against `MODE_KNOWN_MASK`), `relayer_address`, `fee_base`, `fee_recipient_address`, `digest_hash`
  (from `lib/eip712.py`), `signature_hex`, `signature_verified`, `metatx_state` (`signed`/`final`/`failed`/`expired`),
  `executed_tx_hash`; `UNIQUE(chain_id, digest_hash)`; `write` refuses signed fields (64-hex digests; validity < 2^31).
- `blockchain.relay.job` (outbox): `company_id`, `chain_id`, `job_kind ∈ {metatx, call, signed_op}`, `metatx_id` /
  `signed_op_id` / (`target_address`, `calldata_hex`, `call_valid_until_ts`), `payment_request_id`,
  `subject_account_id`, `prerequisite_job_id`, `origin_producer`, `origin_key`
  (`UNIQUE(company_id, origin_producer, origin_key)`), `chain_state ∈ {queued, nonce_leased, signed, broadcast, mined,
  final, reverted, dead, consumed}`, `business_state ∈ {pending, success, failed}`, `claimed_by`, `claimed_datetime`,
  `signer_address`, `tx_hash`, `outer_nonce`, `attempt_count`, `last_error`, `landed_elsewhere`,
  `mesh_published_datetime`; `state` moves only through the transition table, by `create`/`write` under `sudo` from the
  service (`blockchain_subject_account.py:493`). Push model adds: `node_id`, `node_job_uid`, `push_state ∈ {local, sent,
  cancel_requested, attention}`, `push_attempted`, `push_generation`, `node_event_seq`. Immutable after create and
  operator read-only ([INT-ERP-05](#INT-ERP-05)): `company_id`, `chain_id`, `job_kind`, `metatx_id`, `signed_op_id`,
  `target_address`, `calldata_hex`, `call_valid_until_ts`, `payment_request_id`, `subject_account_id`,
  `origin_producer`, `origin_key`; `prerequisite_job_id` set once from empty while `queued`. Group
  `group_blockchain_operator` gets ACL `1,0,0,0`; `action_requeue` checks
  `has_group('dms_blockchain.group_blockchain_operator')` then writes with `sudo()` (`blockchain_relay_job.py:249-262`);
  envelopes freeze via `_MUTABLE` (`blockchain_metatx.py:10,65`). The built ACL still gives operators write
  (`1,1,0,0`).
- `blockchain.payment.request`: `request_uuid`, `company_id`, `chain_id`, `token_id`, `receiving_address`,
  `relayer_address`, `amount_base`, `amount_settled_base` (Σ `PaymentSettled`), `entry_ref_hex` (32 random bytes,
  `UNIQUE(entry_ref_hex)`), `batch_hex` = `keccak256("scaas.pay.lane" ‖ entry_ref)`, `payer_address` (locked at `start`,
  so `(payer, batch)` is fixed), `issued_valid_until` (`submit` requires `valid_until` equal), `expiry_datetime`,
  `request_state ∈ {open, partial, final, expired}`, `needs_attention`, `res_model`/`res_id`, `metatx_ids`, `event_ids`.
  `_payment_gate()` counts an event only when `contract_address == token_id.address` and
  `to_address == receiving_address` (and `value_base` from the event); `int(amount_settled_base) >= int(amount_base)` ⇒
  `request_state='final'` + `_on_paid()`; more than due ⇒ `needs_attention = True`. An ingest batch still commits when
  a business hook fails (savepoint + log): a closed period or credit hold never blocks the cursor.
- `blockchain.chain.event`: `UNIQUE(chain_id, tx_hash, log_index)`; `event_name ∈ {MetaTransactionExecuted,
  PaymentSettled, Transfer}`; `relayer_address = fields.Char()` filled from the event's `relayer` (EVM:
  `indexer.rs` l.49). `_mark_executed(tx_hash, relayer=None)` on `blockchain.metatx` and `blockchain.signed.op` sets
  `final` + `success` (also from `consumed`) and `landed_elsewhere = True` for foreign relayers.
- Consumption in the pull model: `CHAIN_STATES += [('consumed', 'Consumed (nonce used elsewhere)')]`, allowed from
  `nonce_leased` (`TRANSITIONS`); `_apply_report('consumed')` keeps `business_state = 'pending'` and does not touch
  `metatx_state`/`op_state`; `consumed` is not in `FAILED_STATES` (`blockchain_subject_account.py`, `('dead',
  'reverted')`), so `_fail_dependents()` is not called; `_cron_expire` handles the superseded branch. Server-only fields:
  `create` always writes `landed_elsewhere = False` and `mesh_published_datetime = False` explicitly in `vals` (an explicit
  value beats a `default_*` context key; `super().create()` under `sudo()`), and `write` strips them unless
  `self.env.su`.
- Groups: `group_blockchain_viewer` (reads chains, tokens, events, requests, jobs of its company) ⊂ `operator` (+ reads
  metatx; reads jobs; requeues `dead`/`reverted` to `queued` via `action_requeue`) ⊂ `group_blockchain_manager` (CRUD
  chain, endpoint, token); service groups `group_blockchain_relay_worker` (`relay_poll/claim/report`, `node_config`) and
  `group_blockchain_indexer` (`chain_event_ingest`, `node_config`) exist for the pull model and are deleted when pull is
  removed.
- `relay_report(job, 'signed', tx_hash, n)` repeated with the same `(tx_hash, outer_nonce, signer_address)` succeeds
  unchanged ([NODE-LANE-02](node/submit-lanes.md#NODE-LANE-02)).

Pull-model transition table (legacy; `relay_report` unless noted):

| From | To | By |
|---|---|---|
| (create) | `queued` | Odoo, in the same transaction as `payment.transaction → pending` |
| `queued` | `nonce_leased` | `relay_claim` (CAS) |
| `nonce_leased` | `queued` (node restarted, unsigned) / `signed` / `dead` / `consumed` | `relay_report` |
| `signed` | `broadcast` / `mined` / `reverted` (receipt before `broadcast`) / `queued` (gap-filled at cold start) / `dead` / `consumed`; `signed` again with the same `(tx_hash, outer_nonce, signer)` = successful no-op, different values = error | `relay_report` |
| `broadcast` | `mined` / `reverted` / `broadcast` (replacement, new tx_hash) / `queued` (gap-filled) / `dead` / `consumed` | `relay_report` |
| `mined` | `reverted` | `relay_report` |
| `consumed` | `mined`/`reverted`/`consumed` = late no-op | `relay_report` (`LATE_NOOP`) |
| `queued`, `nonce_leased`, `signed`, `broadcast`, `mined`, `reverted`, `dead`, `consumed` | `final` + `success` | `chain_event_ingest` on `MetaTransactionExecuted(digest)` |
| `queued`, `nonce_leased`, `consumed` | `dead` | expiry cron (`valid_until` + 10 min, not final) |

Chain family selection `evm|hedera|sui|soroban|cosmos|ton` (Aptos and Solana added later); `evm_chain_number` only for
`evm|hedera`. No FX: a rate-quote model `blockchain.payment.quote` was rejected ([INT-ERP-07](#INT-ERP-07)).

**Payment provider.** `payment.provider`: `code` adds `chain`; fields `chain_token_id`, `chain_receiving_address`,
`chain_relayer_address`, `chain_validity_seconds` (default 300), state `disabled` by default, `payment.method` `chain`;
the provider needs `journal_id` (required by `account_payment` to create `account.payment`); when the transaction is
`done`, `sale` confirms the order and `account_payment` creates and reconciles the payment. `payment.transaction.chain_request_id`;
private `_chain_create_request()` converts `amount × 10^decimals` with `Decimal` and requires
`token.currency_id == tx.currency_id` ([INT-ERP-07](#INT-ERP-07)); `_chain_typed_data(from_address)`.
`blockchain.payment.request._on_paid()` override: finds the transaction; `done` already ⇒ nothing; `tx._set_done()` only
from `pending` (a `cancel`/`error` transaction gets a note for an operator, no automatic refund). Expiry cron: (a) jobs
`queued`/`nonce_leased` with `valid_until` + 10 minutes < now ⇒ `dead`, metatx ⇒ `expired`; (b) requests
`open` past `expiry_datetime` with no signature whose `valid_until` + 1 hour > now and no job in
`broadcast`/`mined` ⇒ `expired`, `_on_expired()` ⇒ `_set_canceled()`; a late payment turns `expired → final` and calls
`_set_done` with `needs_attention = True`.

<a id="example-odoo-portal"></a>**Portal payment, end to end.**

| Method | Rule |
|---|---|
| `dms_portal_chain_payment_start(order_id, from_address)` | entitlement (`dms_allowed_partner_ids`); order confirmed (`state == 'sale'`); `provider.chain_token_id.currency_id == order.currency_id`; amount = the `posted` invoices' (`invoice_ids`) `amount_residual`, or for an advance on `sale_order_ids` `amount_total − amount_paid`; reuses a `chain` transaction in `draft/pending` only for the same `from` (`payer_address`) after `issued_valid_until + 60 s`; sets `issued_valid_until = now + chain_validity_seconds`; returns `{reference, chain: {chainId, name, rpcUrl, nativeCurrency}, typed_data}` |
| `dms_portal_chain_payment_submit(reference, valid_until, signature)` | entitlement through the transaction; `valid_until == issued_valid_until` (the server picks validity: no clock skew, the client cannot extend it); the digest is rebuilt and a 65-byte signature must recover `payer_address` (`signature_verified = True`; `wallet_kind = contract` ⇒ `signature_verified = False`); creates `metatx` + `relay.job` + pending transaction in one commit |
| `dms_portal_chain_payment_status(reference)` | `{tx_state, request_state, job_state, tx_hash}` |
| `dms_portal_chain_payment_options(order_id)` | the usable (chain, asset) pairs of the receiving company whose token currency equals the order currency; `start(order_id, from_address, receiving_wallet_id=None)` |

```
portal user           Odoo                                   node                         chain
 connect wallet ───► dms_portal_chain_payment_start(order, from)
                     entitlement; order confirmed (state = 'sale');
                     token currency == order currency (no FX);
                     amount = posted invoices' residual, or order total − paid (advance);
                     request: entryRef random, lane = keccak("scaas.pay.lane" ‖ entryRef), nonce 0,
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

The pull-model sequence uses `relay_poll`, `relay_claim`, `eth_call`, `signTypedData`, `sendRawTransaction`,
`getLogs` and `chain_event_ingest`, with `RESTRICT_RELAYER`, `feeRecipient` 0, `validUntil`, `tx_hash` and
`amount_settled`; `_set_done` comes only from `chain_event_ingest` on finalized logs matching (token, receiver,
`entryRef`), with `quorum` RPCs agreeing (`quorum = 1` is single-provider trust). Lane horizon: every
`validUntil ≤ first issue + H` (`LANE_HORIZON_S`, 30 d); a different `from` is a different
`(from, batch)` lane, so `start` from another wallet creates a new request.

<a id="INT-ODOO-09"></a>**INT-ODOO-09** — **The portal pay button is plain JS calling the model facade**; no standard
payment-form integration (that needs its own JS payment form; website checkout does not use provider `chain` yet).

<a id="INT-ODOO-10"></a>**INT-ODOO-10** — **The portal pays confirmed orders only** (`state == 'sale'`): `sale._post_process`
would otherwise `action_confirm` a `draft/sent` quotation when the transaction is `done`, bypassing order approval and
`dms_check_credit`.

<a id="example-odoo-verify"></a><a id="INT-ODOO-08"></a>**INT-ODOO-08** — **Odoo verifies ECDSA signatures itself**
(keccak-256 + secp256k1 ecrecover in pure Python, 256-bit, no `pycryptodome`): immediate feedback and a third digest
implementation next to the contract and the node; narrowed by `wallet_kind` — a `contract` wallet's 65-byte or longer
signature is stored `signature_verified = False` and judged by simulation ([INT-ERP-03](#INT-ERP-03)).

<a id="example-odoo-platform-company"></a><a id="INT-ODOO-11"></a>**INT-ODOO-11** — **One receiving-company seam and one
"platform company".** The receiving company is `dms.portal.api._dms_chain_receiving_company(order)` (= `order.company_id`;
on the territory branch `res.company._dms_document_company()`); every lookup of provider, receiving wallet and staff note
goes through it (`_dms_chain_offered`, `_dms_chain_start`, `sale_order`, `payment_transaction`). One wallet-admin seam:
`res.users._blockchain_wallet_admin(company)` (`group_blockchain_treasury`, members with the company in
`user.company_ids`, or `base.group_system`). The former "Host" is the **"platform company"**: parameter
`dms_blockchain.platform_company_id` (the old `dms_blockchain.host_company_id`, defaulting to `base.main_company`, is read
once on upgrade; `host_company_id` stays read-only, `blockchain_receiving_wallet.py:9-10`), method
`_blockchain_platform_company()` (replacing `_blockchain_host_company()`); records with `company_id = False` belong to
it; `NONE` when unset. Receiving wallets: cooling-off parameter `dms_blockchain.receiving_wallet_cooling_hours`
(`usable_from = approved + N` hours, default 24); default wallet by a partial `UniqueIndex`; record rule per company,
`base.group_system` of the platform company sees all.

**Wallets and custody.** Paying wallets `manual`/`custodial`/`delegated` hold `signer_ref` and `license_ref`; the
custody adapter is `dms_blockchain/lib/custody.py` (`lib/custody.py:9-13,64-75`, schemes `env:` and `broker:`; the scheme
list is an `ir.model.fields` selection, secrets in `ir.config_parameter`); `env:` registers only with
`dms_blockchain.allow_dev_custody` = `1` and `is_dev_chain = True`, and signs through `cryptography`, not `secp256k1.py`.
Auto-pay: `blockchain.autopay.policy` → `_cron_autopay` → one `blockchain.autopay.run` per (policy, invoice, event);
`payment.transaction` provider `chain`, `invoice_ids`, `operation='offline'`; kill switch `revokeWithSig` job
(`eip712.revoke_mandate_digest`, `_enqueue_revoke`). The outbox generalisation added `job_kind`, `target_address`,
`calldata_hex`, `payment_request_id` to `blockchain.relay.job` and made `metatx_id` optional. Accounting:
`blockchain.token.journal_id` (company-dependent); drift A `blockchain.chain.event` with `event_name = 'Transfer'` ⇒
`unmatched_inbound`; drift C `blockchain.chain.balance_report(chain_key, height, [{token, address, balance}])` (pull) or
`balances` items (push) ⇒ `blockchain.balance.snapshot` with `drift_state = 'mismatch'`, compared only when `height` =
the indexed cursor (else `stale`; `payment` outstanding accounts included; `balanceOf` at the final block). Families:
`blockchain.chain.family` and `network_key`, `lib/addresses.py` `parse(family, value, chain) -> canonical`,
`blockchain.signed.op` next to `blockchain.metatx`, `kind = 'signed_op'`.

**Family libraries and connectors.** `dms_blockchain/lib/fam_<family>.py` + `models/blockchain_<family>.py` + connector
`dms_blockchain_bridge/static/src/js/connectors/<family>.js`: Hedera (`dms_blockchain/lib/fam_hedera.py`,
`models/blockchain_hedera.py`, `dms_blockchain_bridge/static/src/js/connectors/hedera.js`; `_issue` returns
`{family:'hedera', digest, typed_data, valid_until, …}` to connector `hedera`; `_accept_signature` takes the 64-byte
signature + public key and verifies with `cryptography`; `blockchain.chain.hedera_mirror_url`; resolution of
`blockchain.token` / `blockchain.receiving.wallet` through the mirror's `contracts` / `accounts`; signer
`window.dmsHederaSigner = {accountId, publicKey, signBytes(Uint8Array)}`; Rust config refuses a shared key in
`Config::validate`), Cosmos (`dms_blockchain/lib/fam_cosmos.py`, `fam_cosmos.build_terms`, `connectors/cosmos.js`),
Soroban (`fam_soroban.py`, `blockchain_soroban.py`, `connectors/soroban.js`, `blockchain.chain` `soroban_anchor_ts`
updated in `chain_event_ingest`; `fam_soroban.auth_nonce`, `fam_soroban.py:88-90`), Sui (`fam_sui.py`,
`blockchain_sui.py` = `models/blockchain_sui.py`, `connectors/sui.js`, `fam_sui.build_terms(req, valid_until)`, `fam_sui.verify`
(`address_of(flag, pk) == payer`), `blockchain.chain.sui_start_checkpoint`, `sui_coin_type`), Aptos
(`dms_blockchain/lib/fam_aptos.py`, `models/blockchain_aptos.py`, `dms_blockchain_bridge/static/src/js/connectors/aptos.js`,
`fam_aptos`, `aptos_package`, `blockchain.chain.aptos_start_block`, `aptos_root`; `blockchain_payment_request._issue`;
tests `TestAptosPayments.test_reissue_*`), Solana (`dms_blockchain/lib/fam_solana.py`, `models/blockchain_solana.py`,
`dms_blockchain_bridge/static/src/js/connectors/solana.js`, `fam_solana`, `_lane_address`, `solana_program_id`,
`solana_token_program`, `blockchain.chain.solana_start_slot`, `addresses.canonical('solana')`; `relay_report` path), TON (`fam_ton.py`,
`blockchain_ton.py`, `connectors/ton.js`, `ton_global_id`, `ton_app_domain`, `ton_manifest_url`,
`ton_wallet_code_hash`, `ton_wallet_code_depth`, `blockchain.token.address` = the jetton master, `batch_hex` lanes).
Contracts and adapters per family: `smartcontracts/move/aptos/` (package `scaas`), `scaas-node/src/adapters/aptos.rs`,
`scaas-node/tests/e2e_aptos.rs`; `smartcontracts/solana/` (program `scaas`), `scaas-node/src/adapters/solana.rs`,
`scaas-node/tests/e2e_solana.rs`. Test databases: `dms_test_chain_6` (Hedera), `dms_test_chain_8` (Soroban),
`dms_test_chain_10` (TON), `dms_test_chain_11` (Aptos, port 8931, gateway 32010–32019), `dms_test_chain_12` (Solana,
port 8932, ports 32020–32049); 118 addon tests, 4 of them Hedera (`test_fam_cosmos`, `test_fam_sui.py`); `lib/eip712.py`
and `blockchain_relay_job.py:137` are shared. Sui verifier tests (`test_fam_sui.py`): `test_added_key_signature_is_left_to_the_node` and
`test_recovered_key_signature_is_left_to_the_node` (⇒ `None`), `test_flipped_byte_from_added_key_is_refused` (`False`),
`test_own_key_still_verified`, `test_passkey_cross_origin_refused`, `test_keyop_bytes_match_move`,
`test_vectors_file_matches_move`, `test_signature_from_another_wallet_is_refused` (narrowed to "invalid under its own
key"); clientkeys mirrors them in `fam_sui.test.js`. Mandate payments through the connector
(`_enqueue_mandate_payment`) are EVM-only; for other families the contract exists and the connector path is a seam. Portal glue: `chain_pay.js` and `subject_signers.js` call
`window.dmsChainConnectors` and `dms_portal_chain_payment_options/start/submit`
(`test_options_carry_family_and_network`); the WalletConnect project id is `dms_blockchain.walletconnect_project_id` in
`ir.config_parameter`. `_hex32` normalises 32-byte values; `_apply_report` applies node reports.

**Backup-key switch.** Parameter `dms_blockchain.require_backup_key` (`'1'`/`'True'` = ON).
`blockchain.subject.account._dms_has_backup()` (private, `_dms_has_backup`; tested in `test_backup_policy.py`): distinct
active key rows, de-duplicated by `(public_x)` for passkeys and `evm_address` for seed keys; then ≥ 2, or 1 with
`guardian_address ∉ {ZERO_ADDRESS, account address, any key's evm_address}`. Known blind spots (accepted, the switch is
soft): `guardian_address` is the CREATE2 input, so a later `setGuardian` is not mirrored; removals done outside the portal
are not mirrored, and `key_state` has no "removed" state, so Odoo over-counts. `dms_portal_chain_payment_start` raises
`UserError("Add a backup key to your account first.")` when ON and the paying account has no backup; any future flow
paying **to** a subject account applies the same check. `subject_signers.js` with ON: after the first key the flow goes to
"add a backup" before the first payment; new seed keys use the role path and the key row stores the address in
`evm_address`. Non-EVM families: client enforcement only. Seed vault entries are stored under
`dms_chain_seed_vault:<subject>`.

<a id="example-odoo-subject-account"></a>**Subject accounts.**

<a id="INT-ODOO-01"></a>**INT-ODOO-01** — **The deploy job precedes payment through a prerequisite.** The `call` job that
deploys the account and the payment/owner-call job both sit in the outbox; the later job carries `prerequisite_job_id`,
and neither `relay_poll` nor the push batch hands it out until the earlier job is `mined/final`; when the earlier job
ends `dead/reverted`, the dependant goes `dead` too.

<a id="INT-ODOO-02"></a>**INT-ODOO-02** — **The `executeAsOwner` nonce is the count of the account's `mined/final`
owner-call jobs**; only one owner call is live at a time; `reverted` consumes no nonce (a failed receipt is not `mined`).

<a id="INT-ODOO-03"></a>**INT-ODOO-03** — **The first key registers in two steps with an HMAC challenge.**
`..._register_start` returns a challenge HMAC(`database.secret`; user, partner, chain, expiry) — nothing stored, TTL
600 s; the new key signs `keccak256("scaas-subject-register" ‖ challenge)`; the server checks the passkey with
`_clientDataOk` (origin `dms_blockchain_bridge.passkey_origin`, else `web.base.url`) or a seed key with `ecrecover`; the
caller must be a user entitled to act for that partner.

<a id="INT-ODOO-04"></a>**INT-ODOO-04** — **A deploy job is created only for the account of the paying partner itself**
(`res_model/res_id` of the request).

<a id="odoo-key-registration"></a><a id="INT-ODOO-14"></a>**INT-ODOO-14** — **Key registration is not the addon's job.**
The blockchain addon keeps generic subject accounts linked to partners; it knows nothing of outlets. Mapping outlets to
keys lives in a bridge, and the operator decides how keys are issued.

<a id="example-odoo-ua"></a><a id="INT-ODOO-13"></a>**INT-ODOO-13** — **Odoo stores UAs as addresses of a new kind and
never derives policy off chain.** Model `blockchain.ua`; partner links only in the client store.

| Where | Change |
|---|---|
| `dms_blockchain/models/` new `blockchain.ua` | `ua_id` (Char 66, indexed, normalised: lower-case, 20-byte form when the top 96 bits are zero, normalised in `create`/`write` and by `lib/addresses.canonical`), `kind`, `key_data`, `registration_ids`; `models.Constraint` unique `(ua_id)` |
| `blockchain.chain` config | `ua_registry_address`, `ua_registry_generation`, `ua_kinds_enabled` (read from chain) |
| `lib/addresses.py` (`canonical`) and `blockchain.address.mixin` | accept a 32-byte UA id as an address form on EVM (`0x` + 64 hex) alongside 20-byte addresses; never truncate |
| `blockchain.signed.op` | `auth_kind` gains `ua`; `from_address` holds the UA id |
| `blockchain.metatx`, `payment_request.payer_address`, `chain_event` from/to | accept UA ids; `blockchain.chain.event` maps `UATransfer` |
| `dms_portal_subject_account.py` | `register_start/register` gain the UA path (passkey ⇒ `webauthn-p256` UA) next to `SubjectAccount` |
| `lib/fam_*.py` `verify(...)` | `fam_evm.verify_ua(record, digest, auth)` using the shared Python kind library (same vectors) |
| `blockchain.subject.account.key` | `evm_address` keys created from now on come from the role path; existing dev keys get a migration note |
| Credentials (optional, relying-party side only) | `blockchain.ua.credential`: issuer, schema, `validUntil`, status URL, received VP / evidence as `ir.attachment` encrypted under the per-subject DEK ([INT-ERP-24](#INT-ERP-24)); `bundleHash` |
| Partner link | partner ↔ UA only in the client store (erasable) |

<a id="example-odoo-dex"></a>**DEX addon.** `blockchain.chain` (inherit): `dex_address`, `dex_indexed_block` (written by
the watcher only). `blockchain.dex.market`: `company_id` (operating company), `chain_id`, `base_token_id`,
`quote_token_id`, `fee_on`, `maker_fee_ppm`, `taker_fee_ppm` (CHECK 0..10000), `fee_recipient_address`,
`min_base_amount`, `income_account_id`, `relayer_expense_account_id`, `journal_id`, `active`. `blockchain.dex.order`:
`market_id`, `order_hash` (unique per chain), `maker_address`, `side`, amounts, `remaining_sell` (in `sellToken` units,
as `filled` on chain), `nonce`, `expiry_ts`, `flags`, `max_fee_ppm`, `signature_hex`, `order_json`, `seq`,
`order_state`. `blockchain.dex.trade`: `trade_ref` (unique), `market_id`, `maker_order_id`, `taker_order_id`,
`maker_fill_base`, `taker_fill_base`, expected/actual fees, `relay_job_id`, `trade_state`, `restored`, `tx_hash`,
`block_number`, `move_ids`. Fee postings use `income_account_id` and, for payers that are an approved
`blockchain.paying.wallet`, `relayer_expense_account_id` ([INT-ERP-12](#INT-ERP-12)).

<a id="INT-ODOO-12"></a>**INT-ODOO-12** — **A late `Matched` after a restore debits the Odoo-held book.** When
`dex_fill_ingest` flips a `failed` + `restored` trade to `settled` (`dex_trade.py:195-198`), the node subtracts that
amount from the book at the next sync; with the store-backed book ([NODE-DEX-14](node/dex-venue.md#NODE-DEX-14)) a late
`dex_trade` item in state settled subtracts it from `remaining`. Transitional: the Odoo-held book is BUILT.

**Tender.** Model `blockchain.tender` (config, state, `tender_id`, `chain_id`, links to RFQ/PO) and
`blockchain.tender.bid` (own bids: commitment, encrypted `(price, salt)`, state); `SERVER_ONLY` fields for chain state;
the PO is created from the finalized `TenderSettled`; all `dms_blockchain*` (example, not built).

**Crypto-shredding (not built).** `dms_blockchain` models `blockchain.shred.key` (`subject_ref = HMAC(subject_key,
res.partner id)`, `wrapped_dek`, `state`) and `blockchain.shred.record` (`model`, `res_id`, `ciphertext` of
`(salt, payload)`, `retain_until`, `legal_basis`), `SERVER_ONLY`; private `_shred_commit(record, payload)` and
`_shred_open(record)`; `log_key` and `subject_key` in `ir.config_parameter` (or the KMS).

**Bus scope.** `res.company.blockchain_bus_scope` (`restricted` default, `open`; `MODE_RESTRICT_RELAYER` vs
`relayer = 0`; the job stays `queued` during `blockchain_bus_private_window_secs`, default 120 s, with `validUntil` ≥ the
300 s default) is exposed in `res.config.settings` (related fields), editable by `group_blockchain_manager`;
`dms_blockchain_payment/models/payment_transaction.py` (l.47, `_chain_start`, also serving custodial auto-pay) sets
`relayer_address = None` instead of `provider.chain_relayer_address` when `company.blockchain_bus_scope == 'open'`;
`blockchain_autopay.py` delegated payments stay `call` jobs (l.267).

**Push and sync (SPECIFIED).** `blockchain.node` (`mail.thread`; url, `key_id`, secret in `ir.config_parameter`
`dms_blockchain.node_secret.<id>` written only by `base.group_system` (`secret_set` flag), `bound_db_uuid`,
`bound_base_url`, `jobs_cursor`, `jobs_last`, `events_cursor`, `store_id`, `incarnation`, `restore_epoch`,
`tokens_hash`, `watch_hash`, `last_sync_datetime`, `last_error`, `needs_attention`; `NODE_SERVER_ONLY`) and
`blockchain.node.route` (`company_id`, `chain_id`, `node_id`; `UNIQUE(company_id, chain_id)`,
[INT-ERP-16](#INT-ERP-16)). `url` must be `https` (`http` only with `dms_blockchain.allow_plain_node_url = '1'`).
`BigInteger` moves from `blockchain_relay_job.py:34-36` to `dms_blockchain/lib/fields.py`. `blockchain.chain` gains
`node_transport` (`pull` default | `push`, deleted with pull) and `event_node_id`; `action_reset_event_cursor(block)`
re-reads events; `action_acknowledge_store_change()` resets cursors after a store change (`store_id`, `restore_epoch`),
clears `needs_attention` and returns non-terminal pushed jobs to `push_state = 'local'`; a pushed job past `valid_until`
is cancelled by origin (`POST /v1/jobs/cancel {origin}`) before going `dead`; events dedupe by
`(chain_key, tx_hash, log_index)`. `blockchain.relay.job` gains server-only fields (`SERVER_ONLY` becomes a dict →
forced create value, so `push_state` is `'local'`, not `False`; `write` strips them unless `env.su`): `node_id`,
`node_job_uid`, `push_state` (`local` | `sent` | `cancel_requested` | `attention`), `push_attempted`,
`push_generation`, `node_event_seq`. `dms_blockchain/data/neutralize.sql` (as `addons/mail/data/neutralize.sql`) deletes
`ir_config_parameter` keys `dms_blockchain.node_secret.%`, sets every `blockchain_chain.node_transport = 'pull'` and
`needs_attention` on nodes; push/sync refuse when `database.uuid` or `web.base.url` differ from the node's `bound_*`.

- Client library `dms_blockchain/lib/node_client.py`: `requests`, `allow_redirects=False`, timeout `(5, 30)`, HMAC
  byte-identical to the node's `gwauth.rs` (shared KAT), response cap 4 MiB, error detail truncated to 300 characters;
  `blockchain.node._client()` builds it.
- Crons: `cron_node_push` → `model._cron_node_push()` and `cron_node_sync` → `model._cron_node_sync()`, re-triggered
  with `ir.cron._trigger()`; the server-only field list moves from `blockchain_relay_job.py:27-29, 79-86`; the two
  crons fit `max_cron_threads = 2`.
- Push `cron_node_push` → `_cron_node_push(batch=50, rounds=4)`: lock a batch (`SELECT … FOR UPDATE SKIP LOCKED`,
  re-checking `chain_state`), mark `push_attempted`, commit, `post_jobs` (results in `node_jobs`), apply results; domain
  `_poll_domain(chain) + [('push_state', '=', 'local')]` (reusing `_poll_domain` with the prerequisite extension,
  `blockchain_subject_account.py:451-455`), only routes with `tokens_hash` set. `_push_item()`: `origin = {scope:
  f'{dbuuid}:{company_id}', producer, key: origin_key, generation: push_generation}`, `client_ref = f'odoo:{id}'`,
  `payload = _payload()` minus `id`, `bus = {scope, private_window_secs}`. `_apply_push_result` follows the push
  algorithm above: accepted ⇒ `push_state='sent'`, `node_id`, `node_job_uid`, then `_apply_node_snapshot`; permanent
  errors ⇒ `dead`/`failed` with `last_error` and `_fail_dependents()`; `IDEMPOTENCY_MISMATCH`/`PREVIOUS_GENERATION_LIVE`
  ⇒ `push_state='attention'`, `needs_attention`, `GET /v1/jobs/{uid}`; `DUPLICATE_DIGEST`/`DUPLICATE_CALL`, `429`,
  `SPONSOR_*`, `503` ⇒ stay `local`. Other writers (`_node_cancel`, `_fail_dependents`) lock with `FOR UPDATE`.
- Sync `cron_node_sync` → `_cron_node_sync()` per `blockchain.node` with a secret and matching `bound_*`, each page in
  its own transaction, `wait=0`: (0) retry `cancel_requested`; (1) `GET /v1/jobs?cursor=max(0, jobs_cursor−200)`,
  continuity checks, each item in a savepoint through `_apply_node_event(node, item)` (a `UserError` ⇒
  `last_error = 'node event rejected: …'`), then `jobs_cursor = next`, `jobs_last`; (2) `GET /v1/events?cursor=…` for
  chains whose `event_node_id` is this node: `range` ⇒ `_ingest_range`, `balances` ⇒
  `blockchain.balance.snapshot._record` when `height == chain.indexed_block`, `dex_*` to the DEX addon,
  `from_block > indexed + 1` ⇒ `needs_attention`; (3) watch and token sync when hashes changed: `PUT /v1/watch/{chain}`
  with `_receiving_addresses()` (`blockchain_chain.py:215-219`), `PUT /v1/tokens/{chain}`; a `missing` token ⇒
  `needs_attention` "token active in Odoo but not registered on the node"; wallet approval triggers
  `cron_node_sync._trigger()`; (4) any non-terminal pushed job ⇒ `_trigger(now + 10 s)`.
- `_apply_node_event` finds the job by (`node_id`, `node_job_uid`) or adopts it by origin. `_apply_node_snapshot(snap)`
  maps `leased → nonce_leased`, `cancelled → dead` (error `cancelled`); a state in `FEED_LATE_NOOP`
  (`{'final': ALL, 'consumed': {'mined', 'reverted', 'consumed'}, 'dead': {...}}`) for the target is a no-op; otherwise
  it walks `queued → nonce_leased → signed → broadcast → mined` with `_apply_report(state, …, table=FEED_TRANSITIONS)`
  (the `signed` step writes `tx_hash`, `outer_nonce` and signer as `relay_report` did, `blockchain_relay_job.py:135-137`),
  then `reverted`/`consumed`/`dead` (`_apply_report` with `table=TRANSITIONS`; a failed `call` deploy fails dependants
  through `_fail_dependents`, `blockchain_subject_account.py:457-460`, `blockchain_relay_job.py:226-231`); `mined` of a
  `call` job releases dependants (RS4 ordering).
- `_ingest_range(chain, …)` = the body of `chain_event_ingest` (`blockchain_chain_event.py:84-103`) without
  `check_service`, with (a) the straddle rule — `from_block ≤ indexed < to_block` ⇒ drop events with
  `block_number ≤ indexed` and set `from_block := indexed + 1`; `to_block ≤ indexed` ⇒ skip; `from_block > indexed + 1`
  ⇒ halt — and (b) `_decode` per family (`:110-112`).
- Cancel: `blockchain.relay.job._node_cancel()` (used by `_cancel_unsent`, `blockchain_autopay.py:80-99`), after
  `SELECT … FOR UPDATE` on the job: `push_attempted` false ⇒ today's local `dead`; true ⇒ node cancel: `cancelled` ⇒
  `dead`; `TOO_LATE` (`published` or later) ⇒ "already sent", the request stays open until `final` or expiry; transport
  error ⇒ `push_state = 'cancel_requested'`. `action_requeue` (`blockchain_relay_job.py:249-261`) keeps its checks and adds
  `push_generation += 1`, `push_state = 'local'`, `push_attempted = False`, `node_job_uid = False`, `node_event_seq = 0`.
  `_cron_expire` (`:275-291`) adds `('push_attempted', '=', False)` to its first search; a pushed job's expiry is the
  node's; the `consumed` → superseded branch is unchanged.
- Transitional gates: `relay_poll` returns nothing for push chains (`if chain.node_transport == 'push': return []`, next
  to the paused-chain gate, l.110-111); `relay_claim` adds `AND push_attempted IS NOT TRUE` (l.130-132); `node_config`
  returns `'node_transport'` so the transitional node stops legacy ingest for `push` chains; `chain_event_ingest` refuses
  `push` chains and uses `_ingest_range` otherwise; `action_switch_to_push()` on `blockchain.chain` (manager group).
- ACL: `access_node_viewer` (`model_blockchain_node`, `group_blockchain_viewer`, `1,0,0,0`), `access_node_system`
  (`base.group_system`, `1,1,1,1`), `access_node_route_viewer`, `access_node_route_manager` (`model_blockchain_node_route`,
  `group_blockchain_manager`); only system users create/edit `blockchain.node` (dial target, key, SSRF); record rule
  `rule_node_route_company`: `[('company_id', 'in', company_ids)]`; `rule_relay_job_company` unchanged
  (`blockchain_security.xml:61`).

<a id="migration-from-pull"></a>**Migration from pull to push.**

| Node | Odoo | `node_transport` | Works? |
|---|---|---|---|
| old (pull only) | old | — | today |
| old | new | `pull` | yes: pull path unchanged |
| old | new | `push` | refused: `action_switch_to_push` requires `GET /v1/info` `api ≥ 1` |
| transitional (`[odoo]` present) | old | — | yes: legacy path; job API idle; store indexer runs |
| transitional | new | `pull` | yes |
| transitional | new | `push` | yes: store path for new jobs; legacy path drains in-flight Odoo jobs |
| final | new, all chains `push` | `push` | target |
| final | any chain `pull` | — | refused by the Odoo pre-migration; the final node refuses `[odoo]` ("removed by" the node release that deletes pull) |

Per-chain cutover (`action_switch_to_push`) preconditions: (1) every company with a non-terminal job **or an approved
receiving/paying wallet** on the chain has a route; `event_node_id` set; secrets set; `bound_*` match; (2) `GET /v1/info`:
`api ≥ 1`, chain granted, `state = active`; Odoo's active tokens ⊆ the node's tokens for the chain; every route's token
subset pushed (`tokens_hash` set); (3) **journal continuity**: for each lane the node reports, `journal_max ≥` Odoo's
`max(outer_nonce)` for that signer — the transitional node bumps `lane.journal_max` on every successful legacy `signed`
report and returns it in `node_config` ("as of the last read"); (4) DEX chain: every market paused, no `pending` trade;
(5) TON chains: the forward cap is deployed on the node ([NET-TON-14](networks/ton.md#NET-TON-14)); the node's
payload-sourced fields, cost metering, value-out and deposit caps are live before the first push cutover. Effects:
`node_transport = 'push'`; `relay_poll` serves nothing for the chain; queued jobs are pushed; legacy in-flight jobs keep
reporting through `relay_report` until terminal; the legacy indexer stops and the store indexer continues from
`node_config.indexed_block`. Rollback for a chain: `node_transport = 'pull'`; new jobs go back to the pull path; pushed
jobs stay with the node and keep syncing. Host bootstrap and the final removal of pull are node runbook steps
([node/runbooks](node/runbooks.md)).
<!-- /example -->
