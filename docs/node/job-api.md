# Job API

The job API is how server-side clients (an ERP backend, a payment service, any other system that keeps a
transactional outbox) hand signed work to the node and learn what happened to it. It is served on `[api] bind`
(default `127.0.0.1:8548`). Status: **SPECIFIED**; the built path is the legacy pull adapter
([legacy pull](#legacy-pull)). The client side of every route is in [integration.md](../integration.md).

All bodies JSON, body cap 1 MiB, no cookies, no redirects, no CORS (a browser cannot call it cross-origin even with a
leaked key). Authentication [NODE-JOB-05](#NODE-JOB-05) on every route. Errors:
`{"error": "<CODE>", "detail": "<text ≤ 300 chars>", …}`, i.e. `{"error": "<CODE>", "detail": "<text ≤ 300 chars>"}`
plus code-specific fields (the gateway's contract is
`{error, code, detail, revert_data?}`, [NODE-GW-06](gateway.md#NODE-GW-06)).

## Namespaces

<a id="namespaces"></a><a id="NODE-JOB-03"></a>**NODE-JOB-03** — **Namespaces are the node's tenant unit**
(`[a-z0-9-]{3,40}`; names starting `~` are reserved: `~gateway`, `~mesh`, `~dex`, and `~lane` — a booking label only,
for gap-fillers of adopted nonces, never a job namespace). A namespace has granted chains and a token subset pushed by
the client ([NODE-JOB-12](#NODE-JOB-12)). The node has no notion of company or legal entity (owner: "the node doesn't know companies"): a client maps its own
tenants to a node endpoint + namespace credential. A namespace shared by several of a client's entities sees their
combined feed; the client routes by `origin`.

<a id="NODE-JOB-16"></a>**NODE-JOB-16** (open; default applied) — Several entities of one client may share one
namespace by using distinct `origin.scope` values; the default is one namespace per client database.

## Authentication

<a id="auth"></a><a id="NODE-JOB-05"></a>**NODE-JOB-05** — **Machine credentials are namespaced HMAC keys.** The
signing scheme is the gateway's `hmac` mode ([NODE-GW-02](gateway.md#NODE-GW-02)) plus header `X-Scaas-Key:
<key_id>`. Each key belongs to one namespace, scopes `submit` and/or `read`. Secret =
`HMAC-SHA256(master_key, "scaas-api-key/1" ‖ 0x00 ‖ key_id ‖ 0x00 ‖ u32be(generation))`; the store keeps **no
secret**. `master_key` is a `SecretSource` in toml (≥ 32 bytes). The scheme is fuzzed and binds method, path and body
and blocks replay; stealing the store yields no credential. Rotating `master_key` revokes every machine key at once; a
restore can resurrect a revoked key ([threat-model.md#node](threat-model.md#node) T19).

```
X-Scaas-Key: k_3f9a0c1d2e4b5a6c
X-Scaas-Timestamp: 1790000000                # unix seconds; ±300 s accepted
X-Scaas-Nonce: 9b2c…                         (1–64 [A-Za-z0-9_-], remembered until ts + 300 s)
X-Scaas-Signature: hex(HMAC-SHA256(secret, ts "." nonce "." METHOD " " path_with_query "\n" body))
```

Verification (`Auth::HmacKeys { keys, seen }`): look up `key_id` in the hot key snapshot (active, not expired,
namespace active), derive the secret, verify as the gateway check does, put `Caller { namespace, key_id, scopes }` in
the request extensions. Nonce cache keyed by `(key_id, nonce)`. Unknown key and bad signature both answer
`401 UNAUTHORIZED`. `MAX_INFLIGHT` (64) still bounds unauthenticated work. A shared KAT
(`scaas-node/tests/api/hmac_kat.json`) pins the byte layout; clients must test against it.

API keys are for **external server-side clients only** ([NODE-ADM-06](admin-auth.md#NODE-ADM-06)): never on admin
routes, never in a browser, mobile or desktop app or extension. Keys are created, rotated (`generation + 1`) and
revoked (hot, ≤ 2 s) by a `key_custodian` (`POST /v1/admin/keys`, `POST /v1/admin/keys/{id}/rotate`, CLI,
[admin-auth.md#cli](admin-auth.md#cli)); the secret (64 hex) is shown once.

## Journal and digests

<a id="journal"></a><a id="NODE-JOB-02"></a>**NODE-JOB-02** — **One journal, node-computed digests.** Every local
submission — job API, gateway door A, mesh scheduler, DEX settle — is a `job` row; mesh `intent` rows reference
`job_uid` instead of carrying their own lane, outer nonce and tx hash. `job.digest` is **derived by the node** from
the decoded payload with the mesh digest library ([mesh.md#intent-id](mesh.md#intent-id) per family; Soroban: SHA-256
of the `HashIdPreimage` the payload carries); a client `digest` that differs ⇒ `422 BAD_PAYLOAD`. A unique
live-digest index (`(chain_key, digest)` over live states; emulated on MySQL) makes G2
([README.md#invariants](README.md#invariants)) durable across namespaces and restarts. Two journals would mean two
`plan()` inputs and two outcome sinks; a client-supplied digest would let one tenant squat another's intent or bypass
G2.

## Idempotency

<a id="idempotency"></a><a id="NODE-JOB-04"></a>**NODE-JOB-04** — **Idempotency key** = `(namespace, origin.scope,
origin.producer, origin.key, origin.generation)`, plus `payload_hash` = SHA-256 of **RFC 8785 (JCS)** of the parsed
`payload`, **computed by the node** (shared KAT `jcs_kat.json`). Same key + same hash ⇒ `200` with the job's current
snapshot; different hash ⇒ `409 IDEMPOTENCY_MISMATCH` carrying the existing `uid`; lower generation live ⇒
`409 PREVIOUS_GENERATION_LIVE` with its `uid`. `generation` increments on operator requeue. A cancel by origin may
create a **tombstone** under the key ([NODE-JOB-07](#NODE-JOB-07), bounded by [NODE-JOB-11](#NODE-JOB-11)). A client
sends a stable `scope` (e.g. `"<database uuid>:<legal entity id>"`) matching its own unique outbox key. A mismatch
means "the node holds a job under this key", never "dead".

## Routes

<a id="routes"></a>

| Route | Scope | Purpose |
|---|---|---|
| `GET /v1/info` | read | api version, `store_id`, `incarnation`, `restore_epoch`, both `head_seq`s, granted chains with lanes, tokens, fee_recipient, profile, state, lane `journal_max` |
| `POST /v1/jobs` | submit | accept ≤ 50 jobs, per-item results |
| `GET /v1/jobs/{uid}` | read | one job snapshot (own namespace only, else 404) |
| `POST /v1/jobs/{uid}/cancel`, `POST /v1/jobs/cancel` (`{"origin": {…}, "chain_key", "valid_until"}`) | submit | [cancel](#cancel) |
| `GET /v1/jobs?cursor=&limit=&wait=` (`limit` ≤ 500) | read | jobs change feed ([indexer-feeds.md#feeds](indexer-feeds.md#feeds)) |
| `GET /v1/events?cursor=&limit=&wait=` | read | events feed ([indexer-feeds.md#event-items](indexer-feeds.md#event-items)) |
| `GET/PUT /v1/watch/{chain_key}` | read / submit | namespace's receiving wallets (full replace) |
| `GET/PUT /v1/tokens/{chain_key}` | read / submit | namespace's token subset (full replace; ∩ node registry incl. `chain_contract` rows; unknown ones listed in the response as `missing`) |
| planned: `POST /v1/snapshots {chain, token, block, policy}` → `{id}`; `GET /v1/snapshots/{id}` → `{state, root, total, leaf_count, policy_hash}`; `GET …/{id}/leaves`; `GET …/{id}/proof?account=` | submit / read | deterministic Merkle snapshot of a token at a final block ([indexer-feeds.md#snapshots](indexer-feeds.md#snapshots)), namespace-scoped |

### `POST /v1/jobs`

```json
{"jobs": [{
  "origin": {"scope": "6f1c…:1", "producer": "payment.request", "key": "0x8d…", "generation": 0},
  "client_ref": "erp:1234", "chain_key": "evm:7622", "kind": "metatx",
  "payload": {"token": "0x…", "digest": "0x…", "signature": "0x…",
              "metatx": {"from": "0x…", "to": "0x…", "value": "100", "data": "0x", "batch": "7", "nonce": "0",
                         "validUntil": "1790000300", "mode": 1, "relayer": "0x…", "fee": "0",
                         "feeRecipient": "0x0000000000000000000000000000000000000000"}},
  "bus": {"scope": "restricted", "private_window_secs": 120}}]}
```

| Field | Rule |
|---|---|
| `origin.scope` | Client-chosen, stable: e.g. `"<database uuid>:<legal entity id>"` |
| `origin.producer` | Business object type that produced the job (e.g. `payment.request`, `purchase.tender`) |
| `origin.key` | Natural key of the business event (e.g. the payment `entryRef`, `invoice:42:attempt:1`) |
| `origin.generation` | `0` initially; `+1` on an operator requeue of a dead job |
| `client_ref` | Echoed in feeds; for the client's own lookup |
| `kind` | below |
| `payload.digest` / `op.digest` | Optional; if present must equal the node's digest |
| `bus.scope` | `restricted` (own lanes only; default), `open` (admitted peers after the window), `public` (also the open mesh) ([NODE-MESH-15](mesh.md#NODE-MESH-15)) |

Payload by kind:

| Kind | Payload |
|---|---|
| `metatx` | `{token, signature, metatx: {11 fields of MetaTransaction}}`; `uint256` as decimal strings; addresses lowercase. May carry `receiver_fee: {fee, feeRecipient, validUntil, signature}` ([sponsorship.md#receiver-pays](sponsorship.md#receiver-pays)); incl. v1 envelopes of a `PqzToken` |
| `signed_op` | `{op: {op_kind: "pay", payload: "0x<exact signed bytes>", signature, public_key, auth_kind: "wallet"\|"passkey", extra: {…native params}}}`; `from`, lane, nonce, `valid_until`, relayer are decoded from `payload` (non-EVM `MetaOp` or Soroban auth payload) |
| `call` | `{call: {target, calldata, validUntil}}` — e.g. `MandateWallet.payUnderMandate(...)`, `SubjectAccountFactory.deploy(...)`; the signature lives inside the calldata; selector and target must match a row of the [call table](#call-table); no native value |
| `ua_metatx` (SPECIFIED; `kind = ua_metatx`) | MetaToken v3 `UAMetaTransaction` with `from: bytes32` and its `auth`: `{token, m: WireUAMetaTransaction, auth}`; same lifecycle as `metatx`; idempotency on `(chain, token, from, batch, nonce)`; digest = `uaDigest` (incl. v3 envelopes of a `PqzToken`) |
| `pqz_call` (SPECIFIED; private chain only) | **Direct open calls only**: `{chain, contract, selector ∈ {pqzTransfer, pqzBurn, rollOver}, calldata}` to a configured PQZ token (direct `fund` pulls the caller's underlying and is never a node job); stored like `call`: `digest` NULL, `call_hash` set |
| PQZ envelopes (SPECIFIED) | **No new kind** ([CTR-PQZ-15](../contracts/pq-zether.md#CTR-PQZ-15)): a `PqzToken` is an `IERC20MetaTx` token, so its envelope ops travel as ordinary `metatx` (v1 domain `("SCaaS PqzToken", "1", chainId, token)`) or `ua_metatx` (v3, `salt = chainUid`) jobs, `m.to = 0`, `m.value = 0`, `m.data` = the direct calldata of `pqzTransfer`/`pqzBurn`/`fund`/`rollOver` (opaque to the client); outer fee `NONE`/`FIXED` only; never batched, never on the mesh; 1 MiB job body on the `pqz` profile; a gasless exit is the envelope `pqzBurn` paying the underlying to `recipient` |

`payload` is exactly what every adapter `build` consumes today; `work_from_job` and the family adapters are
unchanged. A W3C `traceparent` header applies to every item of the batch ([NODE-OPS-09](ops.md#NODE-OPS-09)).

## Intake

<a id="intake"></a>Accept checks, in order (no RPC except a cached UA record read,
[gateway.md#ua-cache](gateway.md#ua-cache); simulation stays at lease time,
[NODE-LANE-23](submit-lanes.md#NODE-LANE-23)):

1. scope `submit`; namespace active; `chain_key` granted ⇒ else `403 CHAIN_NOT_GRANTED`.
2. payload decodes (`work_from_job` for EVM, family op parse otherwise); node computes `digest`
   ([NODE-JOB-02](#NODE-JOB-02)) and `payload_hash` (JCS, [NODE-JOB-04](#NODE-JOB-04)); client digest differs ⇒
   `422 BAD_PAYLOAD`. Every field the signed payload carries is taken from the payload; a job-JSON copy that differs ⇒
   `422 BAD_PAYLOAD`; unsigned fields may only narrow ([NODE-LANE-16](submit-lanes.md#NODE-LANE-16)).
3. token registered + active and in the namespace subset (empty = none unless `all_tokens`,
   [NODE-JOB-12](#NODE-JOB-12)) ⇒ `422 UNKNOWN_TOKEN` (the registered-token rule of
   [NODE-MESH-13](mesh.md#NODE-MESH-13) for every origin).
4. `kind = call` requires `allow_call` ⇒ `403 CALL_NOT_ALLOWED`, **and** its selector and target must match the
   [call table](#call-table) ⇒ `403 CALL_TARGET_REFUSED` (re-checked at lease).
   - 4a. Native value the job makes the lane send beyond fees ≤ `chain.max_value_out` (TON 0.05 TON above the fixed
     attach, every other family 0) ⇒ `422 VALUE_OUT_TOO_HIGH` (also at lease, config is hot;
     [NODE-LANE-17](submit-lanes.md#NODE-LANE-17)). A lane-funded deposit a third party can reclaim (e.g. a Solana
     ATA of an unconfigured recipient) ⇒ `422 DEPOSIT_NOT_ALLOWED` (re-checked before signing;
     [NODE-LANE-18](submit-lanes.md#NODE-LANE-18)).
   - 4b. The payload's `from` is over the grief threshold (≥ 10 billed failures in 24 h, or cost ≥
     `chain.grief_cost_cap`) ⇒ `429 SUBJECT_THROTTLED {retry_after}`; from 3 in 24 h it gets one live job per chain
     ([NODE-LANE-15](submit-lanes.md#NODE-LANE-15)).
5. `now < valid_until ≤ now + chain.max_valid_for_secs` (default: `now < valid_until ≤ now + 3600`) ⇒ `422 EXPIRED` / `VALID_TOO_LONG`.
6. relayer bound ⇒ a lane of this chain ⇒ `lane_hint`, else `422 RELAYER_NOT_OURS` ([NODE-JOB-08](#NODE-JOB-08)).
7. normalization (unbound `feeRecipient`/`relayer`) of the stored work ([NODE-LANE-10](submit-lanes.md#NODE-LANE-10));
   `payload_hash` is over the client's payload, so a retry hashes identically.
   - 7a. Kind rules: `receiver_fee` needs `token.features ∋ receiver_fee` (`422 FEATURE_UNSUPPORTED`), sets
     `valid_until = min(m.validUntil, receiver_fee.validUntil)` and `bus.scope = restricted`
     ([NODE-MESH-17](mesh.md#NODE-MESH-17)); `ua_metatx` needs `token.features ∋ ua` and a registered `from`
     (`422 UA_NOT_REGISTERED`, record cache); `call` and `pqz_call` compute `call_hash`.
   - 7b. Denylist: any listed party (`m.from`, `m.to`, op signer/payee, decoded `call` addresses) ⇒
     `403 SUBJECT_DENIED`, no order detail ([NODE-OPS-14](ops.md#NODE-OPS-14)).
   - 7c. Sponsorship match on job data only ([sponsorship.md#evaluation](sponsorship.md#evaluation)); on
     `~gateway`/`~mesh` a matched metatx/op needs a valid local payer signature (`422 BAD_SIGNATURE`; EIP-7702
     delegated payers per [gateway.md#eip-7702](gateway.md#eip-7702)); a matched job with `valid_until < now +
     p.min_valid_secs` is not sponsored (a sponsored job needs `valid_until ≥ now + min_valid_secs`) (`429 SPONSOR_TOO_SHORT` or unsponsored per `on_exhausted`).
8. In one transaction: **re-check steps 1, 3, 4 from store rows with locking reads** ([NODE-JOB-14](#NODE-JOB-14)),
   then `SELECT … FOR UPDATE` by the idempotency tuple (all generations) — existing same generation: same hash ⇒
   return it (`created: false`); tombstone ⇒ `created:false, state:cancelled`; different hash ⇒
   `409 IDEMPOTENCY_MISMATCH {uid}`; a higher generation present ⇒ `409 SUPERSEDED {uid}` (a stale push, e.g. after
   its own generation was purged); `valid_until` passed ⇒ `422 EXPIRED` again inside the transaction (a purged key is
   never re-accepted, [states](#states)); lower generation non-terminal ⇒ `409 PREVIOUS_GENERATION_LIVE {uid}`; then
   `INSERT`. A unique violation is classified **by constraint** (per backend: the constraint or index name, or on
   SQLite the column list, [store.md#backends](store.md#backends)): `job_live_digest` ⇒ `409 DUPLICATE_DIGEST`;
   `job_live_call` ⇒ `409 DUPLICATE_CALL {uid}` (the live job of this namespace, to follow or cancel);
   `job_origin` (lost race) ⇒ re-run the SELECT. Live count ≥ `max_live_jobs` (read under the lock) ⇒ `429 QUOTA`.
   A matched sponsor policy is admitted in this transaction (bucket locks, the day reservation **and** the
   day/hour/payer-hour `tx_count`, `sponsor_day`/`sponsor_hour` on the job); `429 SPONSOR_BUDGET | SPONSOR_RATE
   {policy}`, or unsponsored per `on_exhausted` with `job.sponsor_fallback = p.name` (client namespace: booked to the
   namespace, [NODE-SPN-01](sponsorship.md#NODE-SPN-01)). Deadlock/serialization failure ⇒ retry the transaction
   (≤ 3).

<a id="NODE-JOB-14"></a>**NODE-JOB-14** — **Intake authority is re-checked inside the insert transaction.** The
transaction that inserts a job (or a tombstone) re-reads, with locking reads (`FOR SHARE`; SQLite: inside
`BEGIN IMMEDIATE`), the namespace row (`state`, `allow_call`, `all_tokens`, quotas), the `namespace_chain` row, the
token's `namespace_token` row and the caller's `api_key` row, and refuses with the same codes as above. Every
admin/CLI change to a namespace, its grants, subset or keys also updates `namespace.updated_at`, so a concurrent change
commits first and is seen, or fails the accept with a serialization error that is retried. Pre-transaction checks stay
as fast rejects. (On PostgreSQL `REPEATABLE READ` the snapshot predates the wait on the fencing row, so plain reads
would miss a change committed meanwhile.)

Response `200` for a well-formed batch; each accepted item carries its **current snapshot**:

```json
{"results": [{"client_ref": "erp:1234", "uid": 17, "created": false, "state": "signed", "tx_hash": "0x…",
              "outer_nonce": 42, "signer": "0x…", "last_seq": 902},
             {"client_ref": "erp:1235", "error": "UNKNOWN_TOKEN", "detail": "0x… is not registered on evm:7622"}]}
```

A fresh accept answers `{"client_ref": "erp:1234", "uid": 17, "created": true, "state": "queued", "last_seq": 902}`.
Paused chain: accepted, waits `queued` ([NODE-STO-08](store.md#NODE-STO-08)). Halted: `409 CHAIN_HALTED`.

## Lease

<a id="lease"></a><a id="NODE-JOB-06"></a>**NODE-JOB-06** — **A claim is a CAS inside the one owner process**:
`queued → leased` inside the single owner of the store ([NODE-STO-04](store.md#NODE-STO-04)); no `SKIP LOCKED` is
needed ([store.md#durability](store.md#durability)). Each accepted job is owned by exactly one store; reassigning
needs a release protocol nobody needs yet. **Two nodes for one client entity** only on **different chains**: a
client routes each (entity, chain) to one node and takes events of a chain from one node. The same lane keys in two
stores is forbidden and detected heuristically on sequence families ([store.md#durability](store.md#durability)).

The lane scheduler leases queued rows of its chain with `hold = 0` and `lane_hint IS NULL OR = lane`, oldest first,
≤ 10 per round, skipping digests already in flight; after a restart, queued jobs are not leased for
`lease_hold_after_start_secs` (15 s), so queued cancels land first.

## Lane pinning

<a id="lane-pinning"></a><a id="NODE-JOB-08"></a>**NODE-JOB-08** — **Relayer-bound jobs are pinned to their lane**: a
meta-tx with `MODE_RESTRICT_RELAYER` (or a family op that binds the relayer) gets `lane_hint`; only that lane leases
it; a relayer that is none of the chain's lanes ⇒ `422 RELAYER_NOT_OURS`. Otherwise any lane could claim a bound job
and it would revert in simulation; with pinning a DEX chain may run several lanes.

## Token subsets

<a id="token-subsets"></a><a id="NODE-JOB-12"></a>**NODE-JOB-12** — **An empty namespace token subset means no
tokens.** `namespace.all_tokens` (default 0; `admin` only, audited) is the one way to serve every registered token of
the granted chains; `store init` creates the reserved `~gateway`, `~mesh`, `~dex` rows with it. A client pushes
`PUT /v1/tokens/{chain}` before its first job push on that chain (its push waits until the route's `tokens_hash`, the
hash of the last pushed subset, is set); until then its jobs get `422 UNKNOWN_TOKEN`.
("Empty ⇒ all" would give a new, copied or misconfigured namespace every token of its chains until the first sync.)

## Call jobs

<a id="call-jobs"></a><a id="NODE-JOB-09"></a>**NODE-JOB-09** — **`call` jobs are a namespace capability**
(`allow_call`, default `false`). **Precondition**: a target qualifies only if it enforces its own replay protection
(`MandateWallet` `refUsed[entryRef]`, idempotent account deploy, DEX fills consumed), because a `call` job has no node
digest and no subject nonce; after a restore a re-pushed `call` could otherwise execute twice. `allow_call` is
necessary but not sufficient: every `call` must also match the [call table](#call-table). The `~gateway` `call` jobs
are only the UA registration of [NODE-GW-03](gateway.md#NODE-GW-03). A `call` job makes our lane call a contract;
with several tenants this must be granted.

<a id="NODE-JOB-13"></a>**NODE-JOB-13** — **Live-call uniqueness is per namespace**: `job_live_call` =
`(namespace, chain_key, call_hash)` over live states (`call_hash = keccak256(target ‖ calldata)`). UA registrations
all live in `~gateway`, so they stay deduplicated node-wide. A duplicate across namespaces is left to the target's own
replay protection, which [NODE-JOB-09](#NODE-JOB-09) already requires of every `call` target. `job_live_digest` stays
global (a digest is the intent's identity; a call hash is not). An earlier key `(chain_key, call_hash)` let a tenant
with `allow_call` hold another tenant's retry at `409 DUPLICATE_CALL`. Two tenants may each queue the same call; the target
refuses the second.

<a id="NODE-JOB-15"></a>**NODE-JOB-15** (open; default applied) — The namespace created for an ERP client that
migrates from the legacy pull path gets `allow_call = true` (mandates and subject accounts need it).

## Call table

<a id="call-table"></a><a id="NODE-JOB-01"></a>**NODE-JOB-01** — **`call` jobs are limited to a selector/target
table.** A `call` job carries calldata the client built; a lane signs it as `msg.sender`. The node executes one only
if its 4-byte selector is in the table **and** the target meets the row's rule; **never** when the target is a
registered token of the chain (any kind) or the token factory; `call` jobs carry no native value. Lane keys never hold
a role on any contract ([NODE-GEN-01](README.md#NODE-GEN-01), owner 2026-10-07): a role-restricted call reaches its
target only through a Safe of the role holders (the `Safe.execTransaction` row, [NODE-JOB-19](#NODE-JOB-19)), and the
lane only relays an `execTransaction` the role holders already signed. Refusal: `403 CALL_TARGET_REFUSED` at accept (step 4), re-checked at lease; on the legacy
pull path `dead` with `CALL_TARGET_REFUSED` before simulation. A new call shape needs a table row (a node release).
Selector matching suffices outside the token/role set: a lane's authority is only `msg.sender` of the direct call,
never of calls the target makes. One operator session (or a stolen one) could otherwise turn a lane that holds fee
income into an arbitrary transaction. The client side keeps its outbox rows
immutable after creation ([INT-ERP-05](../integration.md#INT-ERP-05)).

<a id="NODE-JOB-19"></a>**NODE-JOB-19** — **Rows for permissionless and self-authenticating calls; role holders call
through their own contract.** Besides the account, mandate, DEX and UA rows, the table has rows only for
permissionless or self-authenticating selectors on registered targets: tender `commitBid` (carries the signed deposit
intent), `revealBid`, `withdrawDeposit`, `settleTender` (anyone after the award window); vesting `release` and
distribution `claim`, `claimMany`; `ExchangeOffer.exchange` legs. Every **role-restricted** call (`createTender`,
`cancelTender`, `disqualifyWinner`, bond release/claim, issuer and compliance interventions, `attest`, factory
`create*`) goes through the role holder's own contract — `SubjectAccount.executeAsOwner`, or `Safe.execTransaction` on
a registered role-holder contract — so a lane is never `msg.sender` of a privileged call. The factory stays excluded
(a lane would become token creator/admin).

| Selector | Target rule | Typical producer |
|---|---|---|
| `SubjectAccountFactory.deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)` | the chain's account factory (`chain_contract.kind = account_factory`) | client subject-account onboarding |
| `SubjectAccount.executeAsOwner(bytes,uint256,uint256,bytes)` | runtime code = EIP-1167 clone of that factory's `IMPLEMENTATION` (checked at lease, cached) | client subject accounts; role holders that are subject accounts |
| `MandateWallet.payUnderMandate`, `revokeWithSig` (epoch-bound, [CTR-ACC-07](../contracts/accounts-mandates.md#CTR-ACC-07)), `executeAsOwner`; `HederaMandateWallet.executeAsOwnerRaw` | any address that is not a registered token (self-authenticating: the target checks the delegate/owner signature) | client payment requests, auto-pay |
| `OrderBookDex.settle` / `cancel` / `invalidateNonces` | the chain's DEX (`chain_contract.kind = dex` or the chain's `dex` field) | DEX venue (`~dex`) |
| `UniversalAccountRegistry.register` (`UARegistry.register` once the UA registry is deployed) | `chain.ua_registry`, `~gateway` only ([NODE-GW-03](gateway.md#NODE-GW-03)) | node gateway |
| `SealedBidTender.commitBid`, `revealBid`, `withdrawDeposit`, `settleTender` | `chain_contract.kind = tender` | client tender flows ([contracts/tender.md](../contracts/tender.md)) |
| `VestingGrant.release`; `Distribution.claim`, `claimMany` | runtime code = EIP-1167 clone of the registered asset-suite implementation (codehash checked at lease, cached) | client asset-suite flows ([contracts/asset-suite.md](../contracts/asset-suite.md)) |
| `ExchangeOffer.exchange(MetaTransaction,bytes)` | EIP-1167 clone of the registered `ExchangeOffer` implementation (like `OrderBookDex.settle`: the leg carries the holder's own signature) | client corporate actions |
| `Safe.execTransaction` | a registered role-holder contract (`chain_contract.kind = role_holder`); the owners' signatures are inside the calldata | issuer / compliance / buyer role holders |

`pqz_call` jobs are not `call` jobs: their own selector list is in the kinds table above.

## Job states

<a id="states"></a>Node job states (store; one transaction = CAS + `job_event` INSERT + `job.last_seq` + fencing
check). The table mirrors the client-side transition table (`TRANSITIONS`) and late-no-op table (`LATE_NOOP`); both
sides read the vector file `scaas/scaas-node/tests/api/transitions.json` (clients keep a byte-identical copy; CI
`cmp`). Status: client-side state machine incl. `consumed` **BUILT**; node store state machine **SPECIFIED**.

```
            accept                lease (CAS, lane_hint)         journal (before send)
  (none) ─────────► queued ───────────────────────► leased ─────────────────────► signed ──► broadcast ──► mined
     │ cancel-by-     │  ▲  transient / restart       │                              │  ▲        │           │
     │ origin, no job │  └────────────────────────────┘                              │  └ replace┘           │ late receipt
     ▼                │ cancel (never published)                                     │                       ▼
  cancelled ◄─────────┤                                                              ├──► reverted ◄─────────┘
  (tombstone)         │ published + cancel ⇒ stays queued, hold = 1, 409 TOO_LATE    │
                      ├──► dead (expiry before submit, bad payload)                  ├──► dead (expired + gap-filled)
                      │                                                              │
                      └────────────── leased/signed/broadcast ──► consumed ◄─────────┘ (consumption classification)
```

| From | To | Who |
|---|---|---|
| — | `queued` | job API accept / gateway / mesh scheduler / DEX venue |
| — | `cancelled` (kind `tombstone`) | cancel by origin with no job ([NODE-JOB-07](#NODE-JOB-07); granted chain, capped TTL, quota, [NODE-JOB-11](#NODE-JOB-11)) |
| `queued` (`hold = 0`, past `lease_hold_after_start_secs` = 15 s) | `leased` (`lane_label`, `claim_block`, `attempt_count + 1` = `attempt_count+1`) | lane scheduler (replaces the legacy `relay_claim`) |
| `queued`, `leased` (never published) | `cancelled` | cancel |
| `queued` (published) | `queued` + `hold = 1` | cancel ⇒ `409 TOO_LATE, published: true` |
| `queued`, `leased` | `dead` | expiry before submit; `bad payload`; `attempt_count > chain.max_attempts` (default 5) ⇒ `ATTEMPTS_EXHAUSTED` ([NODE-LANE-14](submit-lanes.md#NODE-LANE-14)); at lease `SUBJECT_DENIED`, `SPONSOR_TX_CAP` (`SPONSOR_RATE` is an accept-time `429`, never a lease-time death) |
| `queued`, `leased` | `dead` (never published) or `hold = 1` (published) | deny entry added ([NODE-OPS-14](ops.md#NODE-OPS-14)) |
| `leased` | `queued` | transient simulate/fee/RPC error; restart before signing; in flight on another path; outcome **not included** (precheck/CheckTx/mempool reject, `BUSY`, dropped: nothing billed) |
| `broadcast` | `queued` once, then `reverted` | outcome **included and billed** ([NODE-LANE-14](submit-lanes.md#NODE-LANE-14)): at most one requeue per job, only where the family doc names the parameter the retry raises (gas or CU limit to its cap: Hedera, Aptos, Solana); otherwise, or the second time, `reverted` with the decoded reason (consumption checked first) |
| `leased` | `signed` (`outer_nonce`, `tx_hash`, signer; `lane.journal_max` bumped) | **journal, before send** |
| `leased`, `signed`, `broadcast` | `consumed` | consumption classification ([NODE-LANE-09](submit-lanes.md#NODE-LANE-09)) |
| `signed`, `broadcast` | `broadcast`, `mined`, `reverted`, `queued` (gap-filled at cold start), `dead` | submit / follow |
| `mined` | `reverted` | late receipt |
| `consumed` | (late `mined`/`reverted`/`consumed` = no-op, not stored) | `LATE_NOOP` |

A sponsored job that ends `dead`, `consumed` or `cancelled` before broadcast releases its reservation and its day, hour
and payer-hour `tx_count` (buckets of `sponsor_day`/`sponsor_hour`) in the terminal transaction; after broadcast it
books its measured cost and keeps its counts ([sponsorship.md#evaluation](sponsorship.md#evaluation)).

`final` is **not** a node job state: finality is a property of the event feed. A client marks its own job final when
a final `MetaTransactionExecuted(digest)` arrives on `/v1/events` (so a job is also final when someone else executed
it — `MODE_OPEN`, payee self-relay, a mesh peer). Node `cancelled` is reported to clients that have no such state as
`dead` with `error = 'cancelled'`. Terminal rows are purged only when `updated_at < now − job_retention_secs` (30 d)
**and** `valid_until < now − 86 400`: a purged origin key can never be re-accepted because its payload is expired.
Tombstones skip the 30 d ([NODE-JOB-11](#NODE-JOB-11)). `plan()` never aggregates over job rows (they are purgeable):
it reads `lane.journal_max`.

## Cancel

<a id="cancel"></a><a id="NODE-JOB-07"></a>**NODE-JOB-07** — **Cancel is a node CAS, by uid or by origin.**
`POST /v1/jobs/{uid}/cancel` or `POST /v1/jobs/cancel {origin}` succeeds from `queued`/`leased` only if the job was
**never published on the bus**; otherwise `409 TOO_LATE` with `state` and `published`. A published, still-queued job
is put on local hold (never leased by us) but reported `TOO_LATE` because peers may land it. Cancel by origin with no
job writes a `cancelled` tombstone (bounded, [NODE-JOB-11](#NODE-JOB-11)), so a late push of that key returns
`created:false, state:cancelled`. A client kills a job locally only if it never attempted the push. During a node
outage a kill waits for the node; the window is ≤ the job's `valid_until` (e.g. an auto-pay signing window of 300 s).

| Node state | Result |
|---|---|
| `queued`/`leased`, never published | `cancelled` (reported as `dead`, `error = "cancelled"`) |
| no job yet for the origin | tombstone written; a late push of that key returns `created: false, state: cancelled` |
| `queued` but published on the bus | `409 TOO_LATE {state, published: true}`; job held (never leased by us) but a peer may still land it |
| `signed` or later | `409 TOO_LATE {state}` |

A subject can always invalidate its own pending intents with `cancelMetaNonce(batch)` (EVM, direct call) — the
authoritative cancel.

<a id="NODE-JOB-11"></a>**NODE-JOB-11** — **Cancel-by-origin tombstones are bounded.** Body `{origin, chain_key,
valid_until}` (`valid_until` = the client job's); the chain must be granted (`403 CHAIN_NOT_GRANTED`); `valid_until ≤
now + chain.max_valid_for_secs` (`422 VALID_TOO_LONG`); `valid_until ≤ now` ⇒ `cancelled` with no row (such a key
can never pass intake step 5). A tombstone stores that `chain_key`/`valid_until`, counts toward
`namespace.max_tombstones` (default 1000, over ⇒ `429 QUOTA`) until purged, and is purged at `valid_until < now −
86 400` (no 30-day retention). Tombstone-creating cancels: 2 rps per key, burst 10. (A row per unknown origin with a
caller-chosen TTL and no quota would be ~1.7 M durable rows/day per key.)

<a id="NODE-JOB-17"></a>**NODE-JOB-17** (open; default applied) — A cancel of a published job reports "already sent"
and the client keeps its request open until final or expiry. (Client handling: `cancelled` ⇒ local dead + side
effects; `TOO_LATE` ⇒ already sent; transport error ⇒ `cancel_requested`, retried first on the next sync.)

<a id="NODE-JOB-18"></a>**NODE-JOB-18** (open; default applied) — Defaults: `max_tombstones = 1000`, tombstone
cancels 2 rps (burst 10).

## Errors and limits

<a id="errors"></a>

| HTTP | Code | When |
|---|---|---|
| 400 | `BAD_REQUEST` | malformed JSON, batch > 50, `limit`/`wait` out of range |
| 401 | `UNAUTHORIZED` | missing/unknown key, bad signature, stale timestamp, replayed nonce |
| 403 | `FORBIDDEN`, `CHAIN_NOT_GRANTED`, `CALL_NOT_ALLOWED`, `CALL_TARGET_REFUSED`, `SUBJECT_DENIED` | scope, grant, [NODE-JOB-09](#NODE-JOB-09), [call table](#call-table), denylist |
| 404 | `NOT_FOUND` | job of another namespace or unknown |
| 409 | `IDEMPOTENCY_MISMATCH`, `PREVIOUS_GENERATION_LIVE`, `SUPERSEDED` (all with `uid`), `DUPLICATE_DIGEST`, `DUPLICATE_CALL` (with `uid`), `TOO_LATE` (with `state`, `published`), `CHAIN_HALTED` | [intake](#intake), [cancel](#cancel) |
| 410 | `CURSOR_EXPIRED` | [indexer-feeds.md#cursors](indexer-feeds.md#cursors) |
| 413 | `TOO_LARGE` | body > 1 MiB |
| 422 | `BAD_PAYLOAD`, `UNKNOWN_CHAIN`, `UNKNOWN_TOKEN`, `EXPIRED`, `VALID_TOO_LONG`, `RELAYER_NOT_OURS`, `FEATURE_UNSUPPORTED`, `UA_NOT_REGISTERED`, `BAD_SIGNATURE`, `VALUE_OUT_TOO_HIGH`, `DEPOSIT_NOT_ALLOWED` | per item; `BAD_PAYLOAD` also when a job field differs from the signed payload |
| 429 | `RATE_LIMITED`, `QUOTA`, `SPONSOR_BUDGET`, `SPONSOR_RATE`, `SPONSOR_TOO_SHORT` (all three with `policy`), `SUBJECT_THROTTLED` (with `retry_after`) | per key: POST 20 rps (burst 40), GET 10 rps, tombstone-creating cancels 2 rps (burst 10); `Retry-After` |
| 503 | `NOT_READY`, `STORE_FULL`, `NOT_OWNER` | store not open; `max_rows`; fencing lost |

Terminal reasons that are not HTTP codes: job `dead` with `error = ATTEMPTS_EXHAUSTED` (`attempt_count >
chain.max_attempts`); chain `halted` with reason `PROGRAM_UPGRADEABLE` ([NODE-STO-07](store.md#NODE-STO-07)).

## Client conformance

<a id="client-tests"></a>What a client of this API must test (the reference client's suite runs against a fake node):

- Push: the outbox marker is committed before the HTTP call; a rollback after accept ⇒ the re-push applies the returned
  snapshot; feed items for an unknown uid are adopted by origin; permanent vs transient errors;
  `IDEMPOTENCY_MISMATCH`/`PREVIOUS_GENERATION_LIVE` ⇒ `attention`, never `dead`; a prerequisite job is not pushed
  until `mined`; paused chain; no route ⇒ creating the request raises; a copied database (bound values mismatch)
  refuses.
- Sync: the ladder from `queued` to every target state; `FEED_LATE_NOOP` (`final` absorbs a late `mined`); overlap
  no-op; poison item skipped; gap halts; straddle; unregistered contract dropped and counted; `balances` at the right
  height; `store_id`/`restore_epoch` change, `head_seq < cursor`, incarnation mismatch ⇒ halt; acknowledgement
  re-pushes.
- Cancel: never pushed ⇒ local; `cancelled`; `TOO_LATE` signed and published; transport error ⇒ `cancel_requested`
  retried first. Requeue bumps `generation`.
- Server-only node-sync fields on every client record (explicit values and default-context injection, as user and as
  superuser); transitional gates; cutover preconditions incl. tokens ⊆ node and journal continuity; the database
  neutralization effect; DEX mirror seq guard; the new UNIQUE constraints exist in the database catalog (checked with
  SQL, not trusted from code).

<!-- example:odoo -->
Reference client: `dms_blockchain/tests/test_node_client.py` (fake node via `_client()`), `push_attempted` false ⇒
local cancel, `bound_*` mismatch, `default_*` context, `action_switch_to_push` preconditions, `pg_constraint` check;
nightly `scripts/e2e_odoo_node.sh` (real Odoo test DB + node + anvil).
<!-- /example -->

## Legacy pull

<a id="legacy-pull"></a><a id="NODE-JOB-10"></a>**NODE-JOB-10** — **Per-chain pull/push flag, then one-step removal** (the decision on "flag or hard cut").
A client chain flag `node_transport ∈ pull|push` (default `pull`) selects the path. A transitional node runs both
paths in one process (legacy pull for `pull` chains, the store for `push` chains; same lane, same nonce counter, one
`lane.journal_max`). Legacy in-flight jobs drain on the legacy path; they are never imported into the store. After the
proof criterion ([runbooks.md#cutover](runbooks.md#cutover)) one release deletes the pull adapter, its config section,
the flag and the client's service methods; the final node refuses the legacy section ("removed"). A hard cut was
rejected: the in-flight journal lives in the client, so a hard cut means importing it (a one-off path that can
double-sign) or a stop-the-world drain (≥ one `valid_until` window per chain, payers re-sign), with no rollback.

Transitional (BUILT). The node pulls work from the client database over the client's JSON-RPC (`POST
/json/2/<model>/<method>`, `Authorization: Bearer <api key>`, database header), and reports outcomes back:

| Method | Caller key | In | Out / effect |
|---|---|---|---|
| `node_config` | relay worker or indexer | `evm_chain_number, relayer_address?` | chain params, finality, `indexed_block`, token `[{address, decimals}]`, `journal_max_nonce` and `inflight` (jobs `nonce_leased/signed/broadcast` of the relayer, with payload) for cold start |
| `relay_poll` | relay worker | `evm_chain_number, limit` | `queued` jobs with the full meta-tx (struct + signature + token) |
| `relay_claim` | relay worker | `job_ids, worker` | the ids claimed (CAS `UPDATE … WHERE chain_state='queued' RETURNING id`) |
| `relay_report` | relay worker | `job_id, chain_state, tx_hash?, outer_nonce?, error?` | transition per the client's allowed-transition table |
| `chain_event_ingest` | indexer | `evm_chain_number, from_block, to_block, to_block_hash, events[]` | record events + apply effects + advance the cursor, **one transaction** |

Each client method checks its service group explicitly and takes no tenant id from the caller. Further legacy methods:
`relay_stats` (readiness counts), `balance_report` (drift C), and the DEX book methods `dex_markets`,
`dex_book_load`, `dex_book_commit`, `dex_sync`, `dex_cursor`, `dex_fill_ingest`. Two service keys (relay worker,
indexer) with minimal scope; the indexer key can force bookings, so it is a separate user and is rotated.
The legacy pull rules: the signed report is idempotent ([NODE-LANE-02](submit-lanes.md#NODE-LANE-02)); `call` jobs
are checked against the [call table](#call-table) before simulation; a job the client moved to `dead` cannot be
journaled `signed` (the client refuses the transition), which acted as a client-side veto that the node CAS
([NODE-JOB-07](#NODE-JOB-07)) now replaces.

<!-- example:odoo -->
**Reference ERP client (Odoo) names.** The legacy pull path and the transitional node were built against one
reference ERP client, an Odoo addon (`dms_blockchain*`; DEX in `dms_blockchain_dex`). Its names, for readers of that
code (orientation only; line numbers as of 2026-10-07):

| Concept here | Reference client name |
|---|---|
| Legacy node client module (Rust) | `odoo.rs` (`odoo::Odoo`, `odoo::Job`, `odoo.rs:90-108`), config section `[odoo]`, marked with `// legacy(…)` comments until removal |
| Per-chain flag | `blockchain.chain.node_transport ∈ pull|push`; cutover `action_switch_to_push` sets `node_transport = 'push'`, rollback `node_transport = 'pull'` |
| Chain, its key and profile, DEX cursor, readiness counts | `blockchain.chain`, `blockchain.chain.chain_key`, `blockchain.chain.chain_profile`, `blockchain.chain.dex_indexed_block`, `blockchain.chain.relay_stats(chain_key)` |
| RPC endpoints (moved to `node.toml`) | `blockchain.rpc.endpoint` |
| Job (outbox row) and its payload builder | `blockchain.relay.job`, `blockchain.relay.job._payload` / `blockchain_relay_job._payload()` (`blockchain_relay_job.py:160-187`); allowed transitions `blockchain_relay_job.py:20-26`; idempotency `UNIQUE(company_id, origin_producer, origin_key)` (`blockchain_relay_job.py:99-101`); expiry cron `_cron_expire`; finality `_mark_final`; executed `_mark_executed`; dependents `_fail_dependents` / `_fail_dependents()` (`blockchain_subject_account.py`, `blockchain_subject_account.py:180-195`); autopay `blockchain_autopay.py:101-113`; durability around `blockchain_relay_job.py:121-138`; dependency field `prerequisite_job_id` |
| Locked `call` jobs (the client half of the call table) | group `group_blockchain_operator`; ACL `1,0,0,0`; `action_requeue` guarded by `has_group('dms_blockchain.group_blockchain_operator')` and `sudo()` (`blockchain_relay_job.py:249-262`); immutable fields `_MUTABLE` on `blockchain.metatx` (`blockchain_metatx.py:10,65`) |
| Legacy RPC methods | `relay_poll`, `relay_claim`, `relay_report(signed)` = `relay_report(job, 'signed', tx_hash, n)`, `chain_event_ingest` (`blockchain_chain_event.py:20-27`, `blockchain_chain_event.py:79`) |
| Digests the client stores | `blockchain.metatx.digest_hash`, `blockchain.signed.op.digest_hash` |
| Node record, route, attention state | `blockchain.node` (writable by `base.group_system` only), `blockchain.node.route` (`UNIQUE(company_id, chain_id)`), `blockchain.node.needs_attention` / `needs_attention`, acknowledgement `action_acknowledge_store_change`, event node `event_node_id`, crons `cron_node_push` / `cron_node_sync`, "never pushed" flag `push_attempted = False` |
| Copy protection | `neutralize.sql` deletes node secrets; push/sync compare `database.uuid` and `web.base.url` with the `bound_*` values stored when the secret was set |
| Secrets and server-only fields | node secrets in `ir.config_parameter`; `SERVER_ONLY` on every node-sync field; service users from `res.users.apikeys` |
| Bus scope per company | `res.company.blockchain_bus_scope` |
| Target acceptance policy (old design, now the node's `mesh_policy`) | `blockchain.target.policy`, `blockchain.target.policy.pool_visibility` |
| Old mesh client methods (superseded) | `mesh_config`, `mesh_publish_claim`, `mesh_report` |
| Payment request, settlement, tender | `blockchain.payment.request`, `blockchain.settlement`, `blockchain.tender`, `blockchain.tender.bid` |
| DEX mirrors | `blockchain.dex.order` / `blockchain.dex.order/trade` with server-only `node_seq`; `_apply_dex_order(item)`, `_apply_dex_trade(item)` (skip when `item.seq <= node_seq`), `_upsert`, `_create_from_node`, `_dex_ingest_range`, fee booking `_book_fees` with `move_ids`, errors as `UserError` (`dex_order.py:106-141`, `dex_order.py:151-152`, `dex_trade.py:58-76`, `dex_trade.py:195-198`, `dex_trade.py:203`, `dex_trade.py:207`) |
| Relayer address per chain | `chain_relayer_address` |
| Development custody | `dms_blockchain.allow_dev_custody` (`ir.config_parameter`), `is_dev_chain = True`, `signer_ref`; Python `cryptography` / `secp256k1.py` (`secp256k1.sign`, RFC 6979) |
| Roles | compliance officer `compliance_officer`; regulated templates `*_REG` |
| Client-side family libraries and vectors | `lib/eip712.py`, `lib/fam_*.py` (`lib/fam_cosmos.py`, `lib/fam_sui.py`, `lib/fam_aptos.py`, `lib/fam_ton.py`, `lib/fam_solana.py`; also cited as `fam_sui.py`, `fam_aptos.py`, `fam_ton.py`, `fam_solana.py`), `dms_blockchain/lib/addresses.py`, vectors `dms_blockchain/tests/data/mesh-envelope-v1.2.json` run by `dms_blockchain/tests/test_mesh_vectors.py`; test data under `dms_blockchain/tests/data/` |
| Idempotency scope the client sends | `scope = "<database.uuid>:<company_id>"` |
| Tender client | models `blockchain.tender` (`tender_id`, `chain_id`) and `blockchain.tender.bid` (encrypted `(price, salt)`, `SERVER_ONLY`); purchase order only from the finalized `TenderSettled`; reveal reminder at `commitDeadline` |
| Receiver-pays request fields | `fee_paid_by_receiver`, `receiver_fee_amount`, digest `paymentDigest` |
| DEX book location (old choice "Odoo hay SQLite": ERP or SQLite) | built in the ERP; target the node store; mirrors keyed by `order_hash`/`trade_ref`, market gains server-only `node_market_id` |
| Revert root cause on the client | `blockchain.transaction.revert_reason` |
| Other models | `blockchain.chain.event` (event rows), `blockchain.dex.market`, DEX order helper `dex_order.py:144-149` |
| Identity provider of the reference deployment | ABP AuthServer (`addons/bamboo_abp_auth`, role claim `role`) |
<!-- /example -->
