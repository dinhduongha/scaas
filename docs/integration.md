# SCaaS Integration Guide — ERPs and applications

**Status:** normative, 2026-10-07. Companion of [`SCaaS.md`](SCaaS.md) (the system specification; its §0
precedence and component spec register apply here). Status tags as in SCaaS.md: **BUILT**, **SPECIFIED** (link), **PLANNED**.

This guide describes integration under the **current model** (owner rulings 2026-10-06 and 2026-10-07, NI rev 3.7
R87–R111, R320–R328, R340–R349; PD rev 1.1 CR-PD-1…6; TSS rev 1.3, UA rev 1.4, PQZ rev 1.4): the ERP or
application is a **client** of `scaas-node`. It keeps its own transactional outbox, **pushes** jobs to the node's job
API, and **polls** two feeds (`/v1/jobs`, `/v1/events`) to learn job states and finalized chain facts. The node never
calls the client. The node's store is the configuration authority.

> **Transition note.** The job API, feeds and admin API are **SPECIFIED**
> ([node independence](superpowers/specs/2026-10-06-node-independence-design.md) §5–§7) and not yet built. The node
> that runs today (**BUILT**) pulls work from the Odoo addons over `/json/2` (`relay_poll`/`relay_claim`/
> `relay_report`, `chain_event_ingest`). New integrations must target the push model; Odoo migrates chain by chain
> through the flag `blockchain.chain.node_transport ∈ pull|push` (R104). The public gateway `POST /v1/metatx` and
> `/v1/dex/*` are **BUILT** and unchanged.
>
> **TON is blocked on every non-Odoo path** until the node half of NET-TON-FIX1 lands (net-ton rev 1.1, review C1:
> an unbounded forward-TON floor drains a lane). Until then no job API, mesh or gateway submission may reach a TON
> lane, and no TON chain is cut over to push (§15.4). The built Odoo pull path is safe (it builds `extra = 0` and no
> `forward_nanoton`).

**Contents:** 1 Model · 2 Onboarding · 3 Pushing jobs (3.5 outbox rules, 3.6 `call` targets) · 4 Feeds and reconciliation · 5 Payment references ·
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
| Build typed data / `MetaOp` for the subject; choose `validUntil` inside the lane horizon (§5.1); verify the signature shape | Recompute the digest from the payload (a differing client digest ⇒ `422 BAD_PAYLOAD`); read every signed field from the payload, never from job JSON (R344) |
| Record the outbox row in the business transaction; keep it immutable (§3.5) | Accept idempotently; enforce namespace grants, registered tokens, normalization (R100), the `call` target table (§3.6), value-out and deposit caps, the per-subject grief score (R342, R345, R346) |
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
| 2 | Admin | Create namespace: `POST /v1/admin/namespaces {"name": "acme-erp", "chains": ["evm:100"], "allow_call": false, "max_live_jobs": 10000}` (`allow_call = true` only if the client needs `call` jobs: mandates, subject-account deploys, DEX settles; even then only the selectors and targets of §3.6 run) |
| 3 | Admin | Register chains/tokens on the node if not yet present (`POST /v1/admin/chains/{key}/tokens`); RPC URLs and lane keys are toml-only |
| 4 | key_custodian | `scaas-node key create --namespace acme-erp --scopes "submit read"` or `POST /v1/admin/keys` → `{"key_id": "k_3f9a0c1d2e4b5a6c", "secret": "<64 hex>", …}` shown **once** |
| 5 | Client admin | Store `key_id` + secret in the client's secret store (never in a business table) |
| 6 | Client | `GET /v1/info` → api version, `store_id`, `incarnation`, `restore_epoch`, `head_seq`s, granted chains with lanes, tokens, `fee_recipient`, profile, state |
| 7 | Client | `PUT /v1/tokens/{chain}` with the tokens it uses (intersected with the node registry; `missing` listed) and `PUT /v1/watch/{chain}` with its receiving wallets (drift detection) |

One namespace per client database is the default; several legal entities may share it, distinguished by
`origin.scope`.

**API keys are for external server-side clients only** (NI R92, R106, R109): the ERP backend or another service
holds the key in its secret store. Never embed one in a browser, mobile or desktop app or an extension — client apps
sign user actions with `clientkeys` and submit through the gateway (§8, §14), and read namespace data through their
own backend. API keys never reach the admin API; admin access is a built-in user or OIDC login, and config
automation (CI, Terraform, scripts) uses OIDC client credentials or the host CLI.

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
and bad signature both return `401 UNAUTHORIZED`. API keys never work on the admin listener (R109). Rotation:
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
| `kind` | `metatx` (EVM meta-tx, incl. v1 envelopes of a `PqzToken`), `signed_op` (non-EVM `MetaOp` or Soroban auth payload), `call` (calldata to a contract, needs `allow_call` **and** a §3.6 table row); planned `ua_metatx` (UA; incl. v3 envelopes of a `PqzToken`) and `pqz_call` (direct PQZ calls, private chain) |
| `payload.digest` / `op.digest` | Optional; if present must equal the node's digest |
| `bus.scope` | `restricted` (company lanes only; default), `open` (admitted peers after the window), `public` (also the open mesh; A2) |

Payload by kind:

| Kind | Payload |
|---|---|
| `metatx` | `{token, signature, metatx: {11 fields of MetaTransaction}}`; `uint256` as decimal strings; addresses lowercase |
| `signed_op` | `{op: {op_kind: "pay", payload: "0x<exact signed bytes>", signature, public_key, auth_kind: "wallet"|"passkey", extra: {…native params}}}`; `from`, lane, nonce, `valid_until`, relayer are decoded from `payload` |
| `call` | `{call: {target, calldata, validUntil}}` — e.g. `MandateWallet.payUnderMandate(...)`, `SubjectAccountFactory.deploy(...)`; the signature lives inside the calldata; selector and target must match a row of §3.6; no native value |
| `ua_metatx` (SPECIFIED, UA F5) | MetaToken v3 `UAMetaTransaction` with `from: bytes32` and its `auth`; same lifecycle as `metatx` (UA §11.2) |
| `pqz_call` (SPECIFIED, PQZ rev 1.4 §11.3; private chain only) | **Direct open calls only**: `{chain, contract, selector ∈ {pqzTransfer, pqzBurn, rollOver}, calldata}` to a configured PQZ token (direct `fund` pulls the caller's underlying and is never a node job) |
| PQZ envelopes (SPECIFIED, PQZ rev 1.4 R284, §11.4) | **No new kind**: a `PqzToken` is an `IERC20MetaTx` token, so its envelope ops travel as ordinary `metatx` (v1 domain `("SCaaS PqzToken", "1", chainId, token)`) or `ua_metatx` (v3, `salt = chainUid`) jobs, `m.to = 0`, `m.value = 0`, `m.data` = the direct calldata of `pqzTransfer`/`pqzBurn`/`fund`/`rollOver` (opaque to the client); outer fee `NONE`/`FIXED` only; never batched, never on the mesh; 1 MiB job body on the `pqz` profile; a gasless exit is the envelope `pqzBurn` paying the underlying to `recipient` |

### 3.2 Accept checks (in order; no RPC)

1. Scope `submit`, namespace active, chain granted ⇒ `403 CHAIN_NOT_GRANTED`.
2. Payload decodes; node computes `digest` (per family) and `payload_hash` = SHA-256 of RFC 8785 (JCS) of the payload
   ⇒ `422 BAD_PAYLOAD`. Every field the signed payload carries (`contract`, `valid_until`, `from`, lane, nonce,
   relayer binding, value or forward floors) is taken from the payload; a job-JSON copy that differs ⇒
   `422 BAD_PAYLOAD`; unsigned fields may only narrow, never widen (NI R344).
3. Token registered, active and in the namespace subset ⇒ `422 UNKNOWN_TOKEN`.
4. `kind = call` needs `allow_call` ⇒ `403 CALL_NOT_ALLOWED`, **and** its selector and target must match the call
   table (§3.6) ⇒ `403 CALL_TARGET_REFUSED` (re-checked at lease; PD CR-PD-1).
4a. Native value the job makes the lane send beyond fees ≤ `chain.max_value_out` (TON 0.05 TON above the fixed
   attach, every other family 0) ⇒ `422 VALUE_OUT_TOO_HIGH` (also at lease, config is hot; NI R345). A lane-funded
   deposit a third party can reclaim (e.g. a Solana ATA of an unconfigured recipient) ⇒ `422 DEPOSIT_NOT_ALLOWED`
   (re-checked before signing; NI R346).
4b. The payload's `from` is over the grief threshold (≥ 10 billed failures in 24 h, or cost ≥ `chain.grief_cost_cap`)
   ⇒ `429 SUBJECT_THROTTLED {retry_after}`; from 3 in 24 h it gets one live job per chain (NI R342).
5. `now < valid_until ≤ now + 3600` ⇒ `422 EXPIRED` / `VALID_TOO_LONG`.
6. Bound relayer must be one of the chain's lanes ⇒ `422 RELAYER_NOT_OURS` (else `lane_hint` pins the job).
7. Normalization of unbound `relayer`/`feeRecipient` (stored work only; `payload_hash` is over the client's payload);
   denylist (`403 SUBJECT_DENIED`); sponsorship match on job data (TSS §B1.3): a matched job needs
   `valid_until ≥ now + min_valid_secs` (default 120) to be sponsored.
8. Idempotency (one transaction): same key + same hash ⇒ `created: false` + current snapshot; tombstone ⇒
   `created: false, state: cancelled`; different hash ⇒ `409 IDEMPOTENCY_MISMATCH {uid}`; lower generation still live
   ⇒ `409 PREVIOUS_GENERATION_LIVE {uid}`; same digest live under another key ⇒ `409 DUPLICATE_DIGEST`; the same `call` (target + calldata) live in
   this namespace ⇒ `409 DUPLICATE_CALL {uid}` (follow that job or cancel it; other namespaces are not blocked, NI
   R325); quota ⇒ `429 QUOTA`; a matched sponsor policy reserves its day budget and takes its hour / payer-hour counts
   here (released if the job ends before broadcast) ⇒ `429 SPONSOR_BUDGET | SPONSOR_RATE | SPONSOR_TOO_SHORT
   {policy}`, or the job goes unsponsored when the policy says `on_exhausted = unsponsored` (NI rev 3.6 §5.2).

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
       | CALL_TARGET_REFUSED | VALUE_OUT_TOO_HIGH | DEPOSIT_NOT_ALLOWED
                            → business job dead/failed with last_error (the node holds nothing)
     IDEMPOTENCY_MISMATCH | PREVIOUS_GENERATION_LIVE
                            → push_state='attention', node_uid from the 409 body, GET /v1/jobs/{uid}, apply it;
                              NEVER mark dead (the node holds a job under this key)
     DUPLICATE_DIGEST       → stay 'local', last_error (another key carries this intent)
     DUPLICATE_CALL         → stay 'local', last_error with the 409 body's uid (follow that job, or cancel and re-push)
     SUBJECT_THROTTLED      → stay 'local', retry after retry_after; flag the subject for attention (its intents keep failing)
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

### 3.5 Outbox rules (PD rev 1.1 CR-PD-1 (a)(b); Odoo stream PAY-FIX1, SPECIFIED)

A `call` job is a transaction a node lane signs as `msg.sender`; whoever can edit an outbox row can point it anywhere.
Every client's outbox therefore follows these rules (the Odoo names are the reference implementation):

| Rule | Detail |
|---|---|
| **Operators are read-only** | No role below the service itself may write outbox rows. Odoo: `group_blockchain_operator` loses write on `blockchain.relay.job` (ACL `1,0,0,0`). Requeue of a `dead`/`reverted` job is one public method (`action_requeue`) that checks the operator group explicitly and then writes internally; a viewer calling it over RPC fails |
| **Job fields are immutable after create** | Odoo: `company_id`, `chain_id`, `job_kind`, `metatx_id`, `signed_op_id`, `target_address`, `calldata_hex`, `call_valid_until_ts`, `payment_request_id`, `subject_account_id`, `origin_producer`, `origin_key` — `write` raises for every environment, privileged ones included; `prerequisite_job_id` may be set once, from empty, while the job is `queued`. State and progress fields (`chain_state`, `tx_hash`, `outer_nonce`, `last_error`, push fields) stay writable by the service |
| **A different call is a new job** | Never edit target, calldata, kind or payload of an existing row; create a new outbox row (new origin key or `generation + 1` after an operator requeue) |
| **No context-key switches** | Immutability is enforced in `write` itself, not bypassed by a client-settable flag (client context reaches the server on RPC) |
| **Signed envelopes are immutable too** | `blockchain.metatx` / `signed_op` rows are frozen after signing (canon §C10.5) |

Tests a client must carry: operator write on any job field ⇒ access error; privileged write of each immutable field
⇒ error; `prerequisite_job_id` set once from empty passes, a second change fails; operator requeue still works.

### 3.6 `call` targets (PD CR-PD-1 (c); node stream PAY-FIX2, SPECIFIED)

`allow_call` on the namespace is necessary, not sufficient. The node runs a `call` job only if its 4-byte selector is
in this table **and** the target meets the row's rule; never when the target is a registered token of the chain (any
kind), the token factory, or a contract in which a lane key holds a role; `call` jobs carry no native value.

| Selector | Target rule | Typical producer |
|---|---|---|
| `SubjectAccountFactory.deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)` | the chain's account factory (`chain_contract.kind = account_factory`) | subject-account onboarding (§10.1) |
| `SubjectAccount.executeAsOwner(bytes,uint256,uint256,bytes)` | an EIP-1167 clone of that factory's implementation (checked at lease) | subject-account key changes |
| `MandateWallet.payUnderMandate`, `revokeWithSig` (epoch-bound, CR-ADW-1), `executeAsOwner`; `HederaMandateWallet.executeAsOwnerRaw` (ED25519 owners, CR-ADW-2) | any address that is not a registered token (the target checks the delegate/owner signature) | delegated payments, auto-pay, kill switch (§15.5) |
| `OrderBookDex.settle` / `cancel` / `invalidateNonces` | the chain's DEX | DEX venue / DEX accounting |
| `UniversalAccountRegistry.register` (`UARegistry.register` after UA F1) | `chain.ua_registry`, `~gateway` only | node gateway `POST /v1/ua/register` (§10.2) |

Refused ⇒ `403 CALL_TARGET_REFUSED` at accept (push model), `dead` with `CALL_TARGET_REFUSED` before simulation on the
legacy pull path. Anything else a client wants to call on chain (e.g. `createTender`, factory `createTiered`, regulated
interventions in §11–§12) needs a table row first (node release) or is sent by the subject's or treasury's own wallet;
SCaaS.md §6.10 is normative for the table until NI folds it.

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
`consumed`, `dead`, `cancelled`). `final` never appears here (finality comes from §4.2). `mined`/`reverted` items add
`gas_used`, `gas_price`, `cost_native`, `sponsor: {policy, account} | null` and `sponsor_fallback: <policy> | null`
(a policy matched but was exhausted and the job was booked to the namespace; TSS §B1.4). Error values the client
must recognise on `dead`/`reverted` items: `cancelled`, decoded contract errors (`MetaTxBadNonce`, `MetaTxExpired`, …),
`ATTEMPTS_EXHAUSTED` (`attempt_count` passed `chain.max_attempts`, default 5; NI R341), and a `reverted` after one
billed retry (the chain charged the lane for a failure the subject could make deterministic, e.g. Hedera
`INSUFFICIENT_GAS`, Aptos out-of-gas, Solana CU exhaustion — the subject must re-sign; NI R341).

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
| Finality | A job is **final** when a `MetaTransactionExecuted` with its digest arrives in a range (by any relayer: `landed_elsewhere = relayer ∉ our signers`). A range is served only after ≥ `quorum` independent RPC endpoints returned the same event set (CR-PD-2, CR-R3-2); a chain with `quorum = 1` is single-provider trust — confirm the chain's quorum with the node operator (gauge `scaas_finality_quorum{chain}`) before booking material amounts on it |
| Business booking | Only from `PaymentSettled` (or the family equivalent) in a range, matched on `(chain, contract, to, entryRef)`; isolate business hooks (savepoint) so a failing hook never blocks the cursor |
| Consumed | `consumed` keeps the business request pending; it becomes final via the event, or dead if no event arrives by `valid_until + grace + 1 h` (superseded) |
| Latency | Poll with `wait = 0` every minute, and every ~10 s while pushed jobs are live (≤ 25 s long-poll available for clients that can hold a connection) |

---

## 5. Payment references: `entryRef` (payId)

### 5.1 Generation (BUILT, R9)

```
entryRef = 32 bytes from a CSPRNG                     # carries no information; unlinkable by construction
batch    = keccak256("scaas.pay.lane" ‖ entryRef)     # lane of this request (v2 tokens: payLane(entryRef) on chain)
nonce    = 0
```

- One `entryRef` per **payment request** (an invoice may have several requests over time; each request is payable at
  most once because its lane has nonce 0).
- **Lane horizon** (protocol rule, PD CR-PD-4; SCaaS.md §5.5): pay-once holds only if every signature the client
  issues on a pay lane has `validUntil ≤ t_first_issue + 30 d`. Re-issuing terms on the same lane later than that, or
  signing an op with `valid_until > now + 30 d` on a pruning family (TON, Aptos, Solana, Sui), gives no pay-once
  guarantee — issue a new request (new `entryRef`, new lane) instead. Wallet connectors and `clientkeys` refuse such
  ops (RS11-24, RS12-24, RS7-11).
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
| v2 `mtxPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient, sig)` | Typed entry point over the SAME struct and typehash; lane `payLane(payId)` derived on chain, `nonce = 0`; same digest, so one signature works on either path ([TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §7) | **BUILT** (contracts); node use **SPECIFIED** (TW2 T7) |
| v2 `mtxBatch(MetaTransaction[], bytes[])` | Several intents of one token in one outer transaction, atomic (one failing item reverts all; R140 withdrew the partial-success `batchMtxPay` and its second typehash) | **BUILT** (contracts); node batching **SPECIFIED** (TW2 §7.5) |

Client contract: same `entryRef`, same lanes (a request lane can be consumed by either path, never both), same
`PaymentSettled` — so reconciliation code does not change; a second `PaymentSettled` for one `entryRef` (possible via
`payWithFee` or another lane) is a reconciliation exception, never a second payment (R139). The node batches per
`(chain_key, token)` only items bound to its own lane, at 50
items or 3 s; batching is invisible to the client except that several jobs share one `tx_hash`.

---

## 8. Inbound payments: gateway, sponsorship, payee self-relay

| Pattern | How the client integrates | Status |
|---|---|---|
| Enterprise inbound gateway | Partners/agents post signed EVM meta-txs to the company node: `POST /v1/metatx {chain, token, m, signature}` (gateway auth `bearer`/`hmac` for partners; `none` only on loopback behind a proxy). The client sees results on its events feed by `entryRef`/`to` | **BUILT** |
| Door A intake rules | `value == 0` transfer/pay ⇒ `422 ZERO_VALUE`; the `~gateway` `min_fee` floor applies unless a sponsor policy matches (which also caps the spend); `profile = private` keeps fee 0, `profile = public` refuses fee-0 intents without a matching sponsor policy; per-`from` bucket (default 60 per hour); signature checked before simulation (PD CR-PD-3, NI R343) | **SPECIFIED** (PAY-FIX4, NR3) |
| Gateway discovery and other families | `GET /v1/gateway` lists served chains (with `chain_uid` where a UA registry is configured), tokens, fee recipient and DEX policy; Hedera intents use `POST /v1/metatx` (64-byte HIP-632 signatures allowed); the six non-EVM families use `POST /v1/ops {chain, op}`; UA intents `POST /v1/ua-metatx`; errors follow the stable contract `{error, code, detail, revert_data?}` (NI §5.5, APP R178) | **SPECIFIED** (N1, N2, N4) |
| Non-EVM inbound | The client builds the `MetaOp`, the payer signs, the client pushes `signed_op` jobs | **BUILT** (via Odoo outbox); job API **SPECIFIED** |
| Payee self-relay ("e-cheque") | Payer signs offline with fee 0 and relayer unbound or bound to the payee's address; the payee (or its node) submits; ERP books from `PaymentSettled` exactly as usual | contract **BUILT**; QR (EIP-681-style payload) tooling **PLANNED** |
| Gas sponsorship policy | Node policy rows: e.g. "to wallet W, value ≥ X ⇒ fee 0, gas to account Y"; the client books gas from the job's receipt data. A policy caps a tenant's own spend only with `on_exhausted = reject`; with `unsponsored` an exhausted policy books the job to the namespace and marks it `sponsor_fallback` (the admin must set `fallback_to_namespace`, audited) | **SPECIFIED** ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) rev 1.3 §B1; cost fields on the jobs feed, §B1.4) |
| Receiver pays fee | Two signatures (payer's `pay`, payee's fee authorization); booked as payment N and fee F | **SPECIFIED** ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §B2; job field `receiver_fee`, event `ReceiverFeePaid`) |

Never accept raw subject-signed native transactions (Sui `txBytes`, TON BOC from the subject wallet, Stellar
envelopes) as the integration format: they order operations by the subject's account sequence (R30). Always use the
contract-level payload of the family (SCaaS.md §7).

---

## 9. Sealed-bid tender in procurement (SPECIFIED, [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §A)

Contract: SCaaS.md §10 / [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §A.3. Client flow
(summary of TSS §A.5, which is normative): the commit is the deposit token's own `pay` intent; reveal, withdraw and
settle need no signature and can be run by any keeper.

> **Open (call table).** The tender's `call` jobs (`createTender`, `commitBid`, keeper `revealBid`/`withdrawDeposit`/
> `settleTender`, bond calls) are not yet rows of the §3.6 table, so under CR-PD-1 the node refuses them
> (`CALL_TARGET_REFUSED`) until the rows are added (target rule: the chain's `chain_contract.kind = tender`). Until
> then the buyer's and bidders' wallets send these calls themselves (SCaaS.md §15.3).

| # | Buyer ERP | Bidder | Chain |
|---|---|---|---|
| 1 | Tender record; documents canonicalized, `documentRef` = salted commitment; config (deposit token, `minDeposit`, deadlines, public reserve, `minBidders`, bond policy, `slashSink`, allowlist root, `dqWindow`, `maxDisqualifications`, `forfeitClasses`); `createTender(config)` via a `call` job from the buyer's account | — | `TenderCreated` |
| 2 | Publish tender id, deadlines, deposit terms, eligibility proofs; a sponsored portal path may be offered, never as the bidders' only path | Generates `salt` (32 random bytes), computes `commitment = keccak256(abi.encode(BID_TAG, chainId, tender, tenderId, bidder, price, salt))`, stores `(price, salt)` in its secret store | — |
| 3 | Watches the commit count only; may cancel until `commitDeadline` (all deposits refund) | Signs one `pay` intent of `minDeposit` to the tender (`data = pay(depositRef)`, relayer bound to the tender); anyone submits `commitBid` | `BidCommitted` / `TenderCancelled` |
| 4 | — | After `commitDeadline`: `revealBid(tenderId, bidder, price, salt)` by the bidder or any keeper (no signature); the bidder's independent path is a namespace other than the portal's (live-call dedupe is per namespace, so a portal copy never blocks it; on its own namespace `409 DUPLICATE_CALL {uid}` names its own live job) | `BidRevealed` |
| 5 | Inside `dqWindow`: due diligence on the leader; if it fails, `disqualifyWinner(reasonRef, class)` (leader only, only while a next valid bid exists); then `settleTender` (buyer after reveals, anyone after the window) | — | `BidDisqualified`, `TenderSettled` |
| 6 | On the **finalized** `TenderSettled`: purchase order to the winner; keeper jobs `withdrawDeposit(tenderId, bidder)` for every bid | Refunds arrive without any signature | `DepositRefunded` / `DepositSlashed` |
| 7 | Bond: `releaseBond` on contract signature/delivery, or `claimBond(reasonRef)` | — | `BondReleased` / `BondClaimed` |
| 8 | Supplier invoice paid with a **fresh random `entryRef`** (§5.1), never derived from `tenderId` | — | `PaymentSettled` |

ERP constraints: the ERP never sees prices before reveal; the PO is created only from the finalized `TenderSettled`;
non-revealers are flagged from `DepositSlashed`; the bidder reconciles its deposit as a payment (`entryRef =
depositRef`).

---

## 10. Accounts, Universal Accounts and identity sync

### 10.1 Subject accounts (BUILT)

- **EVM `SubjectAccount`** (passkey + seed keys, guardian): address predicted by
  `SubjectAccountFactory.predict(firstKey, guardian)`; the client enqueues a `call` job `deploy(firstKey, guardian)`
  **before** the subject's first payment (deploy is permissionless and idempotent). Key changes go through
  `executeAsOwner` signed by an existing key (client builds `OwnerCall(bytes data,uint256 nonce,uint256
  validUntil)`). Under UA it is **option (b)**: the optional smart account for subjects who want recovery without
  moving funds or one address across key changes (UA R307); its seed keys come from the role path
  `m/7622'/0'/<account>'/2'/<i>'`, never the EOA path (UA R300, S4F R269).
- Non-EVM: open the subject's account object (`meta::open`/`open_passkey` on Sui/Aptos, `open`/`open_passkey` on
  Solana, custom account on Soroban). TON needs no open step and has no `BindKey` message: the first `SignedOp`
  carries the owner wallet's `stateInit` and the jetton wallet binds the key lazily (net-ton R10-5).
- Every non-EVM program is immutable at deploy (SCaaS.md §1.3): a contract fix is a new deployment with new
  package/program/account ids, and subjects move their balances by signing `pay` from the old account. Clients
  re-read chain profiles after such a redeploy (dev deployments are redeployed by stream R3-FIX15).

### 10.2 Universal Account registration (SPECIFIED, [UA](superpowers/specs/2026-10-06-universal-account-design.md) rev 1.4 §12.3)

Replaces the Zether-only flow of the built `UniversalAccountRegistry` (`UA = keccak256(encodedY)`, PoP bound to
`msg.sender`, `AuthScheme`, `linkEVM`), which stays on dev chains until UA stream F1 deletes it (UA R312).

**Native accounts are never registered** (UA R294): an EVM EOA or contract account (incl. `SubjectAccount`, Safe),
Hedera native accounts (an `msig` member only on Hedera registries, UA §4.2), Solana, Stellar/Pi `G…`, Soroban `C…`, Aptos, Sui and Cosmos native accounts, TON wallets.
They sign as today. Every **derived** kind (passkey `webauthn-p256`, `p256`, `ed25519`, `bip340`, Schnorr/BLS,
MuSig2/FROST, `msig`, ML-DSA/FN-DSA, `zether-*`, `pqz-mlwe`) registers once on each chain where it is used:

1. The client derives the key for the kind on its own path (`m/7622'/0'/<account>'/<kindNo>'/<i>'`; Zether conf keys
   keep `m/254|12381/<coin>/<account>/7`; passkeys are one credential per `rpId`), builds the canonical `keyData`,
   computes `ua = keccak256(keccak256("scaas.ua.<kind>.v1") ‖ keyData)` and checks `ua >> 160 ≠ 0`.
2. It reads `popDigest(ua, authRef)` from the registry, or computes it —
   `keccak256(POP_TAG ‖ keccak256(chain_key) ‖ chainUid ‖ registry_id ‖ ua ‖ authRef)` binds chain (`chain_key`
   **and** `chain_uid`, the genesis hash: the chain id alone is not unique, UA R330), registry, UA and
   `authRef`, **not the caller** (UA R295). `chain_uid` comes from the chain profile (`GET /v1/gateway`) and must
   equal the registry's `chainUid()`; clientkeys refuses an EIP-712 domain whose `salt` differs from it.
   The client then signs `uaMessage(kind, POP_TAG, popDigest)` with the kind's signer
   (`UAKey.signUA("pop", …)`; MuSig2/FROST: a group signing session plus the KeyAgg hints or the DKG transcript).
   For a Zether kind with `authRef ≠ 0` the authority also signs `authPop` (purpose `authref`; a native authority
   signs the EIP-712 `UAAuth`). `authRef = 0` for every non-Zether kind.
3. **Anyone** submits `register(kind, keyData, pop, authRef, authPop)`: the subject self-paid, or the node gateway
   `POST /v1/ua/register {chain, kind, keyData, pop, authRef}` (gasless; NI §5.5, R320) — the only node path, since
   registry calls run only from `~gateway` (§3.6).
   Front-running yields the identical record or a revert.
4. On the finalized `UARegistered` event the client reads `recordOf(ua)` — kind **and** `authRef` equal what it
   asked for — and only then marks the account usable on that chain.

Kind choice (UA §4.4): staff/outlets with a phone → `webauthn-p256` UA (or `SubjectAccount` when they want recovery);
extension-wallet users → native EOA; boards and finance → `msig` over members' passkey UAs and/or EOAs (each member
confirms its listing off chain; membership is not consent); agent clusters and Schnorr MPC → `frost-*` (shown with
its attestation-only caveats); HSM keys → `p256`; confidential balances → `zether-*` with `authRef` one of the above;
PQ authority → `mldsa65`; PQZ on the private chain → `pqz-mlwe` with a PQ `authRef`. The registry refuses the same
public key under a second kind (`UAKeyInUse`) and a BLS `authRef` on the same curve as the Zether key.

### 10.3 Identity sync rules

- The party ↔ address/UA mapping lives only in the client (erasable, SCaaS.md §11). In Odoo: `blockchain.ua`
  (kind, canonical id, key data, per-chain registrations), linked to partners only in the client store (UA R318).
- Canonical UA form everywhere: lower-case hex; a value whose top 96 bits are zero is the 20-byte native id. On
  non-EVM families a derived id is shown only as `urn:scaas:ua:v1:<kind>:<hex32>`, never as a native address (UA
  R291, R315).
- Receiving wallets are approved with four-eyes and become usable after a cooling-off period (24 h in the Odoo
  example, R22); push them to the node watch list.
- A UA is the same on every chain (chain-independent id) but registered per chain; never per token. No rotation
  inside a UA: a new key is a new UA plus a transfer (UA R302); a stable address across key changes is
  `SubjectAccount`.
- EVM balances of derived UAs exist only on MetaToken v3 clones (`bytes32` ledger, events `UATransfer`,
  `UAMetaTransactionExecuted`); v1/v2 tokens accept native ids only (UA R303, R308).
- EIP-7702 delegated EOAs are native EOAs (UA R331): their key signs as an EOA everywhere; the UA registry and v3
  also accept an ERC-1271 signature through the delegate. Never register them.
- Verifiable credentials stay optional (UA R310–R311). A BBS presentation is never legal evidence: workflows with legal
  recourse require the account-bound KB-JWT with `nonce` = deal reference / `intent_id` (UA §9.2, §9.7).

---

## 11. Regulated-token compliance flow (SPECIFIED, [AS](superpowers/specs/2026-10-06-asset-suite-design.md) §3)

```
authority order ──► issuer legal/compliance verifies; orderId = keccak256(canonical order id), document hash off chain
        ──► compliance contract (multisig) records the order {subject, beneficiary, maxAmount, freezeUntil}
        ──► issuer contract (multisig) freezes the subject, then force-transfers ≤ maxAmount to the beneficiary
            (members sign on their devices; the client pushes `call` jobs from a namespace with allow_call —
             once the issuer/compliance selectors are rows of the §3.6 table; until then the multisig submits)
        ──► finalized freeze / order / forced-transfer / pause events
        ──► client books the effect (reclassify the frozen balance, post the forced transfer) and links the order
            document to the event
```

Rules (AS R202–R206): `issuer` and `compliance` are contracts, never EOAs; a forced transfer needs a live order record
and moves only from the frozen subject to the recorded beneficiary; there is no court-ordered burn (a burn is a
forced transfer to a beneficiary that burns or unwraps); frozen accounts still receive; issuer-only freezes ≤ 30
days; pauses ≤ 7 days with a 7-day cooldown, and fee-less unwraps are never paused. Every intervention event is
reconciled to exactly one approved request (unmatched intervention events ⇒ incident). Eligibility: the token pins a
`ComplianceRegistry` and a `requiredFlags` mask; only receivers are checked; the client keeps KYC/accreditation data
off chain and only an attester pushes flags (no personal data on chain; optional VC layer, UA R310).

---

## 12. Asset-suite configuration

Creating a token is a subject-signed (or treasury-multisig) factory call sent directly by the creator's wallet; a
`call` job to the factory is refused by the node (the factory is excluded from the §3.6 table, CR-PD-1). Templates are off-chain presets mapping to one factory call plus optional action contracts
(AS R213).

| Template | Call | Client configuration | Status |
|---|---|---|---|
| Loyalty points (tier 1) | `createMetaToken(1, address(0), abi.encode(name, symbol, decimals, initialSupply, minter), salt)` or v2 `createTiered(META_NONE, …)` | `minter` = the issuer's mint contract or multisig; earn rules in the ERP trigger `mint` jobs; fee 0 | **BUILT** |
| Internal 1:1 money (tier 2) | `createMetaToken(1, underlying, abi.encode(name, symbol, 0, 0, address(0)), salt)` | Journal per (company, token) for accounting; wrap/unwrap by holders | **BUILT** |
| Wrapper with a rate, multi-underlying (tiers 2/3, v2) | `createTiered(kind, version, underlyings[], initData, salt)`, kind `META_SINGLE` or `META_MULTI` | rates fixed or adjustable (contract `rateAdmin`), guardian for multi; TW2 §4–§8 | **BUILT** (contracts; node/Odoo fields TW2 T7) |
| Confidential money | `createZetherToken(1, underlying, verifier, abi.encode(name, symbol, registry, shieldScale, maxDecryptableShielded, confidentialFee, auditorKey), salt)` | dev chains only until audit; curve decision; auditor key custody | **BUILT** (dev chains) |
| Regulated tokens (kinds 5–7), vesting (`VestingGrant`), distributions, `ExchangeOffer` | `createTiered(META_*_REG, …)`; counterfactual clones via `predict*` | issuer/compliance contracts, `ComplianceRegistry`, `termsHash` disclosure | **SPECIFIED** (AS) |
| NFT kinds | — | — | **PLANNED** |

After creation: read `predictAddress` before, verify `isDeployedHere`, `creatorOf`, `versionOf` after (decoders know
kinds 0–7); register the token on the node (`POST /v1/admin/chains/{key}/tokens`) and in the client
(`PUT /v1/tokens/{chain}`), record the EIP-712 domain from `eip712Domain()`.

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
   `eth_signTypedData_v4`; ask `eth_getCode` through the wallet to tell `eoa` from `contract` (a 23-byte `0xef0100…`
   designator is an EIP-7702 delegated **EOA**, UA R331); user rejection (4001) is
   not an error.
3. Batch related operations under one passkey assertion (Merkle root).
4. Never send mnemonics, `x`, PRF outputs or PINs to any server; tokens and keys live in memory or the encrypted vault.
5. Non-EVM connectors (Wallet Standard for Sui/Aptos, Keplr/Leap `signArbitrary`, Freighter, TON Connect) are loaded
   lazily per chosen network.
6. One key = one purpose: native keys keep their family paths (EVM `m/44'/60'/0'/0/i` is the EOA only); every UA
   kind and every account-role key comes from `m/7622'/0'/<account>'/<kindNo>'/<i>'` and signs only through
   `UAKey.signUA(purpose, digest)` — there is no raw "sign these 32 bytes" for a UA key (UA R298–R301). New
   `SubjectAccount` seed keys use the role path and are never equal to the subject's EOA (CR-ADW-3). A custody or
   connector key signs in one family only (NI R349).
7. **Pin the token client-side** (CR-ADW-4, ADW-FIX4): `checkPayment` takes `expectedToken` (and its decimals and
   symbol) from the signer's own chain profile (app/extension build or a user-pinned registry), never from the server
   response, and refuses `verifyingContract ≠ expectedToken`. A portal page served by the same server that serves the
   typed data cannot be defended this way (it ships the signer code) — stated out of scope.
8. **Lane horizon**: refuse to sign an op with `valid_until > now + 30 d` (§5.1).
9. **Sui and Solana wallet keys** (CR-WSF-1): the wallet must show a readable text the contract rebuilds from the
   `MetaOp` (`SCaaS <op>` / `Amount:` / `To:` / `Network:` / `Valid until:` / `Ref:` / `Digest:`), never a hex blob;
   offer the passkey first; accounts may set `POLICY_PASSKEY_FOR_VALUE` so value ops need a passkey (WSF-FIX1/2).
10. **Hedera ED25519 accounts** need a raw signer over the 32-byte EIP-712 digest (clientkeys seed
   `m/44'/3030'/0'/0'/i'`); HashPack/WalletConnect `hedera_signMessage` (HIP-820 prefix) cannot be verified on chain —
   use an ECDSA-alias account with those wallets (CR-WSF-2). An ED25519 `MandateWallet` owner pays through
   `executeAsOwnerRaw` (CR-ADW-2).
11. **Passkeys**: one `clientDataJSON` grammar on every family; assertions with `crossOrigin: true` or a `topOrigin`
   are refused (R3D CR-R3-1) — do not run the signer in a cross-origin iframe.

Specified next ([S4F](superpowers/specs/2026-10-06-signers-followups.md) rev 1.1, UA F3): vault v2 under a
non-extractable device key; scrypt `N = 2^17` for every new passphrase envelope (R259); Soroban, Aptos and Solana
seed and passkey signers built by clientkeys `fam/*` and one `wallets/*` connector implementation (R263–R267); role
keys for subject accounts (R269); the "backup key required" switch, default OFF, which never blocks an exit
(R250–R254); `ua.js` (`deriveUAKey`, `UAKey.signUA`, `uaOf`, `popDigest`) and MuSig2/FROST signing sessions.

---

## 14. The app (`scaas/app/`, SPECIFIED)

Design: [APP](superpowers/specs/2026-10-06-scaas-app-design.md) rev 1.2 (R150–R179).

React + Vite console and dApp over **all seven families** behind one adapter interface: EVM (Gnosis 100, Celo 42220,
the private chain 7622, anvil 31337), Hedera 295–298, Cosmos, Soroban (Stellar, Pi), Aptos, Sui, TON, Solana.
Wallets: the UA default (`webauthn-p256` UA registered gaslessly through `POST /v1/ua/register`), `SubjectAccount`
option (b), the seed vault in a key worker, extension wallets, dev key in dev builds only. Payments, wrap/unwrap,
token creation, DEX book, contracts. Zether screens run on dev chains 31337/1337 with a configured `ZetherToken`,
and on the private chain 7622 for configured **PQZ tokens** (PQZ §11.5; prover in the Zether worker). Chain id 7622
was formerly 9000; migration pending (stream CHAINID).

Submission: through a node gateway (`/v1/metatx` for EVM and Hedera, `/v1/ops` for the six non-EVM families,
`/v1/ua-metatx` for UA intents) or self-paid. The app holds **no API key**, no gateway secret and no RPC provider
key (R152; NI R109). Chain features work without login; node admin requires a built-in login (session token) or
OIDC (Authorization Code + PKCE S256, tokens in memory only); the UI hides actions the token's roles cannot perform
(the node enforces). Console screens include external-client API keys (managed by `key_custodian`), admin users,
audit, and gossip (Peers, Topics, Announces, Bans, Trusted list, A2 §13.2). ERPs may embed or link the app for
wallet setup instead of building their own signer UI.

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
  cancel_requested, attention}`, `push_attempted`, `push_generation`, `node_event_seq`. Immutable after create and
  operator read-only (SPECIFIED, PAY-FIX1, §3.5): `company_id`, `chain_id`, `job_kind`, `metatx_id`, `signed_op_id`,
  `target_address`, `calldata_hex`, `call_valid_until_ts`, `payment_request_id`, `subject_account_id`,
  `origin_producer`, `origin_key`; `prerequisite_job_id` set once from empty while `queued`. The built ACL still
  gives operators write (`1,1,0,0`).
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
  pull model and are deleted in P9. Operators read jobs and may requeue `dead`/`reverted` ones through
  `action_requeue` only (CR-PD-1).
- `relay_report(job, 'signed', tx_hash, n)` repeated with the same `(tx_hash, outer_nonce, signer_address)` succeeds
  unchanged (pull model, CR-PD-5, PAY-FIX5).

### 15.3 Portal payment, end to end

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
  DEX markets paused; for TON chains, NET-TON-FIX1 deployed on the node; NR1/NR2 (breaker cost metering, payload-
  sourced fields, value-out and deposit caps) landed before the first push cutover (NI §17: before P6). Rollback =
  set the chain back to `pull`.

### 15.5 Auto-pay

`blockchain.autopay.policy` (payer, paying wallet, trigger `invoice_posted|invoice_due`, caps per payment/day/month,
four-eyes, kill switch) → cron `_cron_autopay` creates exactly one `blockchain.autopay.run` per (policy, invoice,
event) (UNIQUE) → same request + outbox path as manual payments. Custodial wallets sign through the custody adapter
(dev `env:` only; production KMS/HSM PLANNED); delegated wallets sign `PayUnderMandate` and push a `call` job to
`MandateWallet.payUnderMandate`. Kill: off-chain immediately, and for delegated wallets a `revokeWithSig` job; the
revoke digest becomes `RevokeMandate(address token,uint64 epoch,uint256 validUntil)` with the wallet's current
`epoch[token]` (SPECIFIED, CR-ADW-1, ADW-FIX1: Odoo `eip712.revoke_mandate_digest` and `_enqueue_revoke` change with
the contract and the KAT).

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
| Chain halted for an upgradeable program | `409 CHAIN_HALTED`; operator reason `PROGRAM_UPGRADEABLE` (Aptos/Sui/Solana package or program still upgradeable, NI R348) | Nothing to fix client-side; the operator redeploys immutable (R3-FIX15) and the client updates the chain profile (new package/program and account ids) |
| `CALL_TARGET_REFUSED` | `403` per item (push) or `dead` with that error (pull) | Permanent: the call shape is not in the node's table (§3.6). Do not retry; send the call from the subject's/treasury's wallet or ask for a table row |
| `VALUE_OUT_TOO_HIGH` | `422` per item | Permanent for this payload: the signed forward/value floor exceeds `chain.max_value_out` (TON); have the payer re-sign with a floor ≤ the cap |
| `DEPOSIT_NOT_ALLOWED` | `422` per item | The lane would fund a deposit a third party can reclaim (Solana: destination ATA missing for an unconfigured receiver); the receiver creates its ATA, or the operator configures the receiving wallet |
| `SUBJECT_THROTTLED` | `429 {retry_after}` | Retry after `retry_after`; the subject's intents keep failing after simulation (balance moved, nonce burnt, key changed) — investigate before re-pushing |
| `ATTEMPTS_EXHAUSTED` | Snapshot `dead`, `error = ATTEMPTS_EXHAUSTED` | Request stays open; re-sign if still wanted (new job); several in a row ⇒ check the chain's health with the operator |
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
- [ ] HMAC client passes the shared KAT; clock synced (NTP); the API key lives only in the server-side secret store
      (never in a browser, mobile or desktop app or extension).
- [ ] Idempotency tuple stable across retries; generation bumped only by operator requeue.
- [ ] Outbox rows immutable after create (kind, target, calldata, payload links, origin); operators read-only, requeue
      through one checked method; a different call is a new row (§3.5).
- [ ] `call` jobs only for selectors/targets in §3.6; everything else sent from the subject's or treasury's wallet.
- [ ] Every signature on a pay lane inside the 30-day lane horizon; new request (new `entryRef`) instead of
      re-issuing old terms (§5.1).
- [ ] Error handling covers `CALL_TARGET_REFUSED`, `VALUE_OUT_TOO_HIGH`, `DEPOSIT_NOT_ALLOWED` (permanent),
      `SUBJECT_THROTTLED` (retry later), `ATTEMPTS_EXHAUSTED` (dead), `PROGRAM_UPGRADEABLE` halts (§16.1).
- [ ] `push_attempted` committed before HTTP; permanent vs transient errors distinguished; 409 never ⇒ dead.
- [ ] Both feeds polled with overlap; cursors persisted with `store_id`, `incarnation`, `restore_epoch`; continuity
      checks halt on mismatch.
- [ ] Business documents booked only from finalized events matched on (chain, contract, to, `entryRef`).
- [ ] Business hooks isolated so they never block the cursor.
- [ ] Watch list and token subset pushed after every wallet approval and token activation.
- [ ] Cancel semantics implemented (`TOO_LATE` = already sent; `cancelMetaNonce` for subject-side cancel).
- [ ] Database copies neutralized (secrets removed, pushing disabled).
- [ ] No personal data in any payload; party ↔ address mapping erasable on the client side.
