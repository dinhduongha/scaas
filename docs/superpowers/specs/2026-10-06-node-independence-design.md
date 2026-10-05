# Node independence — Odoo becomes a client of `bamboo-node` (design amendment)

Status: draft rev 1, 2026-10-06. Repo `custom-addons/bamboo-dms` at `main` 90a5b17 (mesh S0, S1a, S2 merged).
Rulings: **R87–R110** (§2), continuing the round-4 mesh spec (R70–R86).
Owner rulings folded in: "invert Odoo ↔ node" (2026-10-06) and "OIDC for the node admin API and the React app"
(2026-10-06, addition).

Amends:

| Short | File | How |
|---|---|---|
| PD | `docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` | R6, R16 superseded; R11, R20, R51, R53, R54, R56 amended (§2, §18.1) |
| R3D | `docs/superpowers/specs/2026-10-03-blockchain-round3-design.md` | R51, R53, R55, R56, R58 delivery paths amended (§9, §10) |
| MESH | `docs/superpowers/specs/2026-10-05-relayer-mesh-design.md` | sections listed in §13.1 superseded; streams in §13.2 changed |
| node | `bamboo-node/` | |

Contracts are cited in the **new layout** being introduced in parallel (`smartcontracts/evm/…`,
`smartcontracts/{move/aptos,move/sui,soroban,cosmos,ton,solana}/…`).

---

## 1. Scope and non-goals

### 1.1 Today (evidence)

The node is an Odoo worker. Every durable fact it relies on lives in Odoo and is read or written over `/json/2` (PD R6):

| Concern | Today | Evidence |
|---|---|---|
| Work source | `relay_poll` + `relay_claim` (CAS `FOR UPDATE SKIP LOCKED`) | `odoo.rs:190-201`; `blockchain_relay_job.py:105-138` |
| Journal before broadcast | `relay_report('signed')` must succeed before `send_raw` | `submit.rs:308-316`; `adapter.rs:419-423` |
| Outcomes | `relay_report` through `TRANSITIONS`/`LATE_NOOP` | `odoo.rs:203-206`; `blockchain_relay_job.py:20-26, 206-247` |
| Restart (`plan()`) | `node_config.inflight` + `journal_max_nonce` (SQL `max(outer_nonce)`) | `submit.rs:146-190`; `adapter.rs:232-248`; `blockchain_chain.py:189-196`; `nonce.rs:23-33` |
| Chain config | `node_config`: state (R53), finality, tokens, receiving wallets, indexed cursor | `blockchain_chain.py:163-197`; `indexer.rs:106-117`; `adapter.rs:445-458` |
| Gateway token list | `node_config` at start and every 30 s | `main.rs:131-167` |
| Indexing | `chain_event_ingest` holds the cursor (`indexed_block`) and applies effects | `blockchain_chain_event.py:78-103`; `odoo.rs:218-232` |
| Drift C | `balance_report` at `height == indexed_block` | `drift.rs:30-50`; `blockchain_chain.py:244-254` |
| Readiness / metrics | `relay_stats` | `admin.rs:125-153`; `blockchain_chain.py:223-242` |
| DEX book | `dex_markets`, `dex_book_load`, `dex_book_commit`, `dex_sync`, `dex_cursor`, `dex_fill_ingest` | `dex/venue.rs:3-6, 179-199, 403-421`; `dms_blockchain_dex/models/dex_order.py:65-104`; `dex_trade.py:106-155` |
| Config section | `[odoo] url, database, relay_api_key_env, indexer_api_key_env` (required) | `config.rs:11-19, 29-34`; `main.rs:103, 117, 131, 170, 188-191, 221-222` |
| Odoo veto | a job Odoo moved to `dead` cannot be journaled `signed` (transition refused), so the node never sends it | `blockchain_payment/models/blockchain_autopay.py:80-99` relies on it |

### 1.2 In scope

1. **Direction inversion** (R87). The node keeps all its state in its own SQLite store, exposes a job API and an
   event feed, and never opens a connection to Odoo. `odoo.rs`, the `[odoo]` section and every Odoo-specific path
   are deleted in one step after the push path is proven (R104).
2. **Odoo keeps its transactional outbox** (`blockchain.relay.job` written in the business transaction) and becomes a
   client: a push cron, a sync cron (job changes + chain events), cancel, requeue (R99–R101).
3. **Store** = mesh R71 SQLite, extended and always on: jobs, job events, chain index ranges, configuration, key
   metadata, audit log, DEX book (R88, R89, R105).
4. **Multi-tenancy without companies**: namespaces and per-namespace machine credentials (R90–R92).
5. **Admin API** for configuration, used by operators and the upcoming React+Vite app (`smartcontracts/app/`), with
   **OIDC** login (R106–R110).
6. **Migration**: per-chain feature flag, transitional binary that runs both paths, one-step removal (R104).
7. Every safety property already built is preserved (§9): R80/S2 consumption checks, the in-flight digest set,
   journal-before-broadcast, `plan()` restart, `consumed` semantics (S1a), no double broadcast, journaled nonces.

### 1.3 Non-goals

| Out | Why / where it goes |
|---|---|
| Node calling Odoo for anything (webhooks, callbacks) | R87: the node does not know Odoo exists. Latency is handled by long-poll + cron re-trigger (R101). |
| Two nodes owning jobs of one `(company, chain)` (HA failover) | R98. Failover = restore the store on another host. Follow-up §18.3. |
| Uploading lane keys, RPC URLs, the master key or OIDC issuers through the admin API | R95: secrets and dial targets stay in `node.toml`/keystores (PD R20 spirit). |
| Opaque-token introspection (RFC 7662), DPoP, mTLS-bound tokens | R107: JWT access tokens only; follow-up. |
| OIDC for machine clients on the job API | R109: machines keep HMAC keys; CI that needs *config* uses IdP client-credentials tokens on the admin API. |
| The React app itself | Requirements only (§7.7); built in its own plan. |
| Re-importing in-flight Odoo jobs into the store | R104: legacy in-flight jobs drain on the legacy path. |
| Odoo-side copies of node metrics | Prometheus on the node is the place (MESH §12 already). |

---

## 2. Rulings

Format of PD §13: **ruling — why — cost if wrong.**

| # | Ruling | Why | Cost if wrong |
|---|---|---|---|
| **R87** | (owner) **The node is independent of Odoo.** It never connects to Odoo; Odoo is one client among others. Supersedes **PD R6** (node → Odoo over `/json/2` only) and the MESH R71 clause "R6 unchanged: … Odoo stays control plane". The node's control plane is its own admin API (§7). | Owner. One product, many ERPs; the node becomes deployable without Odoo (MESH §3.3 "standalone" generalised to every node). | Odoo learns state by polling, not synchronously (R101 bounds it). |
| **R88** | **One store, always on**: the MESH R71 SQLite file (`rusqlite` bundled, WAL, `synchronous = FULL`) is opened by every node, not only with `[mesh]`. It holds jobs, job events, index ranges, config, key metadata, audit, DEX book, and the mesh tables. The process takes an exclusive `flock` on `<store>.lock` at open and `PRAGMA locking_mode = EXCLUSIVE`; a second process on the same store refuses to start. Supersedes **PD R16** entirely (gateway queue and DEX book in memory). | The journal must be local and synchronous to keep journal-before-broadcast without a network hop; one writer gives commit-ordered `seq` (MESH R71 argument). | A lost disk loses jobs; R110 makes recovery operator-confirmed. |
| **R89** | **One journal**: every local submission — job API, gateway door A, mesh scheduler, DEX settle — is a `job` row; mesh `intent` rows reference `job_uid` instead of carrying their own `lane_label/outer_nonce/tx_hash`. A partial UNIQUE index on `(chain_key, digest)` over live states makes G2 durable across namespaces and restarts. | Two journals (job + intent) mean two inputs to `plan()` and two outcome sinks (MESH §8.4, §8.6). One table, one CAS, one restart path. | Mesh intent states `submitting/broadcast/landed` become derived from the job (§13.1). |
| **R90** | **Namespaces**: the node's tenant unit is a `namespace` (string, `[a-z0-9-]{3,40}`; names starting `~` are reserved: `~gateway`, `~mesh`, `~dex`). A namespace is granted chains (and optionally a token subset). The node has no notion of company. Odoo maps companies to a node endpoint + namespace credential (`blockchain.node.route`). | Owner: "the node doesn't know companies". | A namespace shared by several companies sees their combined feed; Odoo routes by its own job ids. |
| **R91** | **Idempotency key** = `(namespace, origin.scope, origin.producer, origin.key, origin.generation)`, plus `payload_hash` = SHA-256 of the canonical job JSON. Same key + same hash ⇒ `200` with the existing job; same key + different hash ⇒ `409 IDEMPOTENCY_MISMATCH`. `generation` increments on operator requeue; a new generation is accepted only when every lower generation is terminal (`409 PREVIOUS_GENERATION_LIVE`). Odoo sends `scope = "<database.uuid>:<company_id>"` — the same tuple as `UNIQUE(company_id, origin_producer, origin_key)` (`blockchain_relay_job.py:99-101`). | Retries never duplicate (owner); `scope` lets several companies or databases share one namespace safely; `generation` replaces "reset the row to queued" (`action_requeue`, `blockchain_relay_job.py:249-261`), which has no meaning once the row lives on the node. | — |
| **R92** | **Machine credentials** = R54 `hmac`, unchanged signing string (`gwauth.rs:5-8`), plus header `X-Bamboo-Key: <key_id>`. Each key belongs to one namespace and has scopes `submit` (POST jobs, cancel, PUT watch) and/or `read` (GET jobs, events, info). Key secret = `HMAC-SHA256(master_key, "bamboo-api-key/1" ‖ 0x00 ‖ key_id ‖ 0x00 ‖ u32be(generation))`; the store keeps **no secret**, only key metadata. `master_key` is a `SecretSource` in `node.toml` (`[api] master_key`). Bearer is not offered on the job API. | R54 is implemented and fuzzed; HMAC binds method, path and body and blocks replay (nonce cache, `gwauth.rs:108-116`), so the job API is safe even behind a TLS-terminating proxy that logs headers. Derived secrets: stealing the store file yields no credential (§14 T5). | Rotating `master_key` revokes every machine key at once (disaster lever, documented). |
| **R93** | **Change feeds**: `GET /v1/jobs?cursor=` (job state changes) and `GET /v1/events?cursor=` (index ranges, balance snapshots, DEX items). `seq` = `INTEGER PRIMARY KEY AUTOINCREMENT` of the feed table, filtered per namespace; every page carries `store_id`; client rule = MESH §5.2 (`since = max(0, cursor − cursor_overlap)`, dedup, persist `next` with `store_id`). Long-poll `wait ≤ 25 s`. A cursor older than retention ⇒ `410 CURSOR_EXPIRED` (client resyncs by snapshot). | Same cursor discipline as the mesh bus (owner: "overlap like the mesh bus"); single writer makes overlap a belt, not a brace (MESH R71). | — |
| **R94** | **Event feed items are today's ingest arguments, unchanged**: `kind = range` carries exactly `{chain_key, from_block, to_block, to_block_hash, events}` as `chain_event_ingest` receives them (`blockchain_chain_event.py:79`), with the per-family event objects adapters already emit (§6). Drift C becomes `kind = balances` items written by the indexer right after the range they belong to, so `height == indexed_block` holds when Odoo applies them in order. | Odoo's decode/apply code (`_decode`, `_inbound_only`, `_apply`) is reused verbatim; the R56 race fix ("drift inside the indexer loop", `indexer.rs:81-82`) becomes an ordering property of the feed. | — |
| **R95** | **Config authority = the node store.** `node.toml` bootstraps: on start, entries absent from the store are imported, entries present are **not** overwritten (a differing toml value logs a warning and sets `bamboo_config_toml_drift`). Toml-only (never via API): lane keys/mnemonic, `rpc_urls`, `master_key`, OIDC issuers, listener binds, `admin_socket`. Hot-reloaded from the store (≤ 2 s): chain state, tokens, fee_recipient, breaker, policy, peers, namespaces, keys, watch lists, DEX markets. Restart-required (`pending_restart: true` in `GET /v1/admin/info`): lane index list, finality, family params. | Owner: "node.toml bootstraps; admin API mutations persist". Secrets and dial targets in toml keep R20 and remove the admin-API SSRF surface. Hot reload where the code already refreshes (tokens every 30 s, `main.rs:154-167`; MESH peers every 60 s). | Operators edit toml for keys and RPC, the app for the rest. |
| **R96** | **Finality, pause and the index cursor move to the node**: `blockchain.chain.finality_*`, `indexed_block` (as a source) and `state` stop being node inputs. Node chain `state ∈ active|paused|halted` keeps R53 semantics. Odoo keeps its own `state` as a **push gate** (a paused chain in Odoo pushes nothing new). | PD R11 already says finality is the node's decision; today the node reads it from Odoo (`indexer.rs:113`). | Two pause switches; the stricter wins. |
| **R97** | **Durability replaces SKIP LOCKED**: claim = CAS `UPDATE job SET state='leased' … WHERE uid=? AND state='queued'` inside the single process (R88). Two node processes never share a store. **Two nodes for one company** are allowed only on **different chains**: `UNIQUE(company_id, chain_id)` on `blockchain.node.route`, and exactly one event source node per chain (`blockchain.chain.event_node_id`). Same lane keys in two stores is forbidden and detected heuristically (§9.4). | Owner asked to choose. Each accepted job is owned by exactly one store; reassigning it needs a release protocol nobody needs yet. | No hot failover for one `(company, chain)` (§18.3). |
| **R98** | **Cancel is a node CAS.** `POST /v1/jobs/{uid}/cancel` succeeds only from `queued`/`leased` (never after `signed`, because `signed` is written before broadcast); `409 TOO_LATE` returns the current state. Odoo no longer moves a pushed job to `dead` by itself. | The Odoo veto of §1.1 disappears with the Odoo journal; the CAS on the node gives the same guarantee locally: the lane's `leased → signed` and the cancel `leased → cancelled` race in one SQLite transaction each, one wins. | A cancel during a node outage is deferred (`cancel_requested`, §10.5). |
| **R99** | **Bus scope arrives per job** (`bus.scope`, `bus.private_window_secs`), computed by Odoo from `res.company.blockchain_bus_scope` (MESH R73). The node publishes its own eligible jobs; `mesh_publish_claim` (MESH §10.5) is not built. Acceptance policy and peers are node store tables managed by the admin API; **MESH R79 is superseded** (policy is not Odoo-authoritative; no `blockchain.target.policy`/`blockchain.mesh.peer` Odoo models). | Owner: per-job field. The node owns the job, so it owns publication; policy is node behaviour. | Partners and policy are managed in the node app, not in Odoo. |
| **R100** | **R84 normalization applies to every origin**, including job API jobs. MESH §8.4's exception "Odoo builds fee=0, feeRecipient=0 itself" is dropped: the job API is multi-tenant and the node cannot assume a well-behaved client. Normalization touches only unbound fields, so the digest and every Odoo-built job are unchanged in effect. | A tenant (or a compromised Odoo) could otherwise route our relayer's fee elsewhere while we pay gas. | — |
| **R101** | **Odoo side**: outbox unchanged; `ir.cron` "push" and "sync", bodies in model methods (CLAUDE.md §5.4); push is re-triggered after commit of every new job (`ir.cron._trigger()`), sync re-triggers itself every 10 s while pushed jobs are live; feed reads use `wait`. Server-only fields follow the existing `SERVER_ONLY` mechanism (`blockchain_relay_job.py:27-29, 79-86`): never settable by `vals`, context or `default_*`. | Latency without a node→Odoo call; no context-key switches (project rule). | Job states reach Odoo ≤ ~10 s after the node (today: synchronous). Chain finality dominates payment latency anyway. |
| **R102** | **Relayer-bound jobs are pinned to their lane**: when a meta-tx has `MODE_RESTRICT_RELAYER` (or a family op binds the relayer), the node sets `lane_hint` = that lane and only that lane leases it; a relayer that is none of the chain's lanes ⇒ `422 RELAYER_NOT_OURS` at accept. | Today a multi-lane chain hands a bound job to any lane (RS5-11, `main.rs:181-186`), which then reverts in simulation. The store makes pinning one `WHERE` clause. | — |
| **R103** | **`call` jobs are a namespace capability** (`allow_call`, default `false` for new namespaces, `true` for the namespace created for Odoo at migration because mandates and subject accounts need it, `blockchain_autopay.py:101-113`, `blockchain_subject_account.py:180-195`). | A `call` job makes our lane call any contract with any calldata; with several tenants this must be granted, not implied. | Odoo namespaces need the flag set once. |
| **R104** | (decision on the owner's "flag or hard cut") **Per-chain feature flag, then one-step removal.** `blockchain.chain.node_transport ∈ pull|push` (default `pull`). A transitional node binary runs both paths in one process (legacy `[odoo]` pull for `pull` chains, store for `push` chains; same lane, same nonce counter). Legacy in-flight jobs drain on the legacy path. After the proof criterion (§11.4) stream **P9** deletes `odoo.rs`, `[odoo]`, the flag and the Odoo service methods in one release. **Hard cut rejected**: the journal of in-flight jobs is in Odoo; a hard cut means either importing it (a one-off path that can double-sign) or a stop-the-world drain (≥ one `valid_until` window per chain, payers re-sign), and it has no rollback. The flag allows testnet first and flipping a chain back to `pull` for new jobs. | Owner asked to decide and justify. | ~1 stream of transitional code (marked `// legacy(R104)`), deleted in P9. |
| **R105** | **DEX book moves to the store** (`dex_market`, `dex_order`, `dex_trade`); markets are admin-API config; settle/cancel/invalidate are `job` rows in namespace `~dex`; Odoo's `blockchain.dex.order/trade` become mirrors fed by `dex_*` feed items in the market's namespace, kept for accounting (`_book_fees`, `dex_trade.py:203`). A DEX chain cuts over with its markets paused. Supersedes RS5-2 (book persisted in Odoo) and the `dex_sync`/`restored` loop. | The venue is the book's only writer (`dex/venue.rs:1`); persisting it next to its settle jobs makes "matched but no job" impossible locally (the RS5-2 goal) without a network transaction. | DEX cutover needs a short market pause. |
| **R106** | (owner) **Node admin API = OAuth2 resource server** validating OIDC JWT access tokens: issuer discovery (`/.well-known/openid-configuration`, `issuer` must equal the configured value byte for byte), JWKS fetched over HTTPS, cached, refreshed on unknown `kid` (rate-limited); `iss` exact, `aud` contains the configured audience, `exp` required, `nbf`/`iat` with 60 s skew, `exp − iat ≤ max_token_lifetime_secs` (default 3600). Algorithms: allowlist per issuer from `RS256`, `ES256`, `EdDSA`, and the JWK must match (`kty`/`crv`); `none`, `HS*`, and header `jku`/`x5u`/`jwk`/`x5c` are rejected. Generic IdP: ABP AuthServer (`addons/bamboo_abp_auth`, role claim `role`) and Keycloak are configurations, not code. **Several issuers are allowed** (`[[api.oidc.issuers]]`), selected by exact `iss`; tokens from unconfigured issuers are rejected without any fetch. | Owner. Several issuers: IdP migration and a separate machine IdP need it, and selection by exact `iss` costs nothing. Verification uses `ring` (already in `Cargo.lock` via rustls, direct dep in MESH §3.4) — no JWT crate. | An IdP that only issues opaque tokens cannot be used (follow-up: introspection). |
| **R107** | **Roles**: `viewer` ⊂ `operator` ⊂ `admin`, plus `key_custodian` (separate, not implied by `admin`). Mapping from a configurable claim (`role_claim`, dotted path, string, array or space-separated `scope`) to node roles per issuer; unmapped values are ignored; no mapped role ⇒ `403`. Route table §7.3. | Minimal set that separates "look", "run", "configure", "mint machine credentials": an `admin` cannot mint a job key and a `key_custodian` cannot change fee routing (two-person rule for the money-relevant pair). | — |
| **R108** | **Break-glass = the admin router on a Unix socket** (`[api] admin_socket`, default `/run/bamboo/admin.sock`, mode `0600`, owner = node service user). Possession of the socket is the credential; no static admin token exists. The actor is recorded as `socket` + peer uid (`SO_PEERCRED`). Grants all four roles. Used to bootstrap before an IdP is configured and during IdP outages. Disabled by `admin_socket = ""`. | A static token is one more secret to leak and can be proxied by accident; a 0600 socket is reachable only from the host by the service user, cannot be exposed by a reverse proxy, and needs no rotation. | Remote break-glass needs SSH to the host. |
| **R109** | **Machine credentials never reach config routes**: HMAC keys are verified only by the job-API router on `[api] bind`; the admin router (on `[modules] admin_bind` and the socket) has no HMAC middleware at all. CI or automation that needs config uses an IdP client-credentials access token with a mapped role. | Structural separation instead of a per-route grant table nobody audits. | — |
| **R110** | **Audit and store loss**: every admin mutation appends `audit_log` (actor `iss`/`sub` or `socket:uid`, roles, route, target, before/after JSON, result) in the same SQLite transaction as the change. A `store_id` change seen by Odoo halts sync for that node (`needs_attention`); re-pushing non-terminal jobs to a recreated store is an operator action. | A recreated store has no journal; blind re-push can re-sign intents whose old outer txs are still in a mempool (G1 keeps funds safe, gas is lost). | One manual step after disk loss. |

---

## 3. Architecture after inversion

```
                 OIDC IdP (ABP / Keycloak / …)
                        │ access token (JWT)
 React+Vite app ────────┼──────────────► admin API  (admin_bind, CORS)      ┐
 operator shell ── unix socket (0600) ─► admin API  (break-glass, R108)     │
 Prometheus ────────────────────────────► /healthz /readyz /metrics         │  bamboo-node
                                                                            │   ├ store.sqlite (R88)
 Odoo  (outbox = blockchain.relay.job)                                      │   ├ submit / lane_runner
   cron push ── HMAC key ─► POST /v1/jobs, /cancel, PUT /v1/watch  (bind)   │   ├ indexer → feed
   cron sync ── HMAC key ─► GET /v1/jobs?cursor=  GET /v1/events?cursor=    │   ├ gateway (door A)
 third parties ────────────► gateway POST /v1/metatx  (R54, unchanged)     │   ├ mesh (MESH)
 mesh peers ── mTLS ───────► /v1/mesh/*  (MESH R72, unchanged)             ┘   └ dex venue
```

Listeners (all axum; the gateway and mesh ones exist or are specified already):

| Listener | Config | Auth | Routes |
|---|---|---|---|
| gateway | `[modules] gateway_bind` | R54 none/bearer/hmac (single secret, unchanged) | `/v1/metatx`, `/v1/intents/{id}`, `/v1/dex/*` |
| **job API** (new) | `[api] bind` (default `127.0.0.1:8547`) | R92 HMAC per key | `/v1/info`, `/v1/jobs*`, `/v1/events`, `/v1/watch/*` |
| admin | `[modules] admin_bind` (exists, `config.rs:51-52`) | open: `/healthz`, `/readyz`, `/metrics` (R51, unchanged); OIDC: `/v1/admin/*` | §7.3 |
| admin socket (new) | `[api] admin_socket` | file permission (R108) | same router as admin |
| mesh | `[mesh] bind` | mTLS (MESH §5.1) | `/v1/mesh/*` |

Non-loopback `[api] bind` or `admin_bind` with OIDC routes requires TLS in front (documented; `Config::validate`
refuses a non-loopback `admin_bind` when `[api.oidc]` has no issuer, exactly like `gateway_auth = none`,
`config.rs` `validate`).

---

## 4. Store schema additions

Same file, connection and pragmas as MESH §6; `meta.schema_version = '2'`. Migrations are forward-only `user_version`
steps run at open. `# ponytail: one connection + mutex (MESH §6); a writer thread if /metrics shows contention.`

```sql
-- tenants and credentials (R90, R92)
CREATE TABLE namespace (
  name          TEXT PRIMARY KEY CHECK (name GLOB '[a-z0-9~]*' AND length(name) BETWEEN 3 AND 40),
  state         TEXT NOT NULL CHECK (state IN ('active', 'suspended')),
  allow_call    INTEGER NOT NULL DEFAULT 0,                       -- R103
  max_live_jobs INTEGER NOT NULL DEFAULT 10000,
  created_at    INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE namespace_chain (namespace TEXT NOT NULL REFERENCES namespace(name),
  chain_key TEXT NOT NULL REFERENCES chain(chain_key), PRIMARY KEY (namespace, chain_key));
CREATE TABLE namespace_token (namespace TEXT NOT NULL, chain_key TEXT NOT NULL, token TEXT NOT NULL,
  PRIMARY KEY (namespace, chain_key, token));                     -- empty for a chain = every registered token
CREATE TABLE api_key (
  key_id      TEXT PRIMARY KEY CHECK (key_id GLOB 'k_[0-9a-f]*' AND length(key_id) = 18),
  namespace   TEXT NOT NULL REFERENCES namespace(name),
  scopes      TEXT NOT NULL CHECK (scopes IN ('submit', 'read', 'submit read')),
  generation  INTEGER NOT NULL DEFAULT 0,                         -- rotate = +1 (old secret dies)
  state       TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  label       TEXT, expires_at INTEGER, last_used_at INTEGER,
  created_by  TEXT NOT NULL, created_at INTEGER NOT NULL);       -- no secret column (R92)
CREATE TABLE watch (namespace TEXT NOT NULL, chain_key TEXT NOT NULL, token TEXT NOT NULL, address TEXT NOT NULL,
  PRIMARY KEY (namespace, chain_key, token, address));           -- receiving wallets (drift A/C, R56)

-- configuration (R95). One row per chain; secrets/dial targets are NOT here.
CREATE TABLE chain (
  chain_key TEXT PRIMARY KEY, family TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'paused', 'halted')),
  profile TEXT NOT NULL DEFAULT 'private' CHECK (profile IN ('public', 'private')),   -- MESH R76
  finality_mode TEXT NOT NULL, finality_depth INTEGER NOT NULL, finality_quorum INTEGER NOT NULL,
  fee_recipient TEXT, poll_ms INTEGER NOT NULL, stuck_after_secs INTEGER NOT NULL,
  max_gas_per_tx INTEGER NOT NULL, max_fee_cap_gwei INTEGER NOT NULL, max_index_lag INTEGER NOT NULL,
  breaker TEXT NOT NULL,                                          -- BreakerCfg as JSON (small metadata)
  dex TEXT, updated_at INTEGER NOT NULL);
CREATE TABLE token (chain_key TEXT NOT NULL REFERENCES chain(chain_key), address TEXT NOT NULL,
  decimals INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (chain_key, address));
CREATE TABLE lane (chain_key TEXT NOT NULL, label TEXT NOT NULL, account_index INTEGER NOT NULL,
  journal_floor INTEGER,                                          -- R104 legacy import: Odoo max(outer_nonce)
  PRIMARY KEY (chain_key, label));

-- jobs (R89, R91)
CREATE TABLE job (
  uid             INTEGER PRIMARY KEY AUTOINCREMENT,
  namespace       TEXT NOT NULL REFERENCES namespace(name),
  origin_scope    TEXT NOT NULL, origin_producer TEXT NOT NULL, origin_key TEXT NOT NULL,
  generation      INTEGER NOT NULL DEFAULT 0,
  client_ref      TEXT,                                           -- echoed, e.g. 'odoo:<relay.job id>'
  chain_key       TEXT NOT NULL,
  kind            TEXT NOT NULL CHECK (kind IN ('metatx', 'call', 'signed_op')),
  digest          BLOB CHECK (digest IS NULL OR length(digest) = 32),
  payload         BLOB NOT NULL,                                  -- today's relay_poll payload minus `id`
  payload_hash    BLOB NOT NULL,
  valid_until     INTEGER NOT NULL,
  lane_hint       TEXT,                                           -- R102
  bus_scope       TEXT NOT NULL DEFAULT 'restricted' CHECK (bus_scope IN ('restricted', 'open')),   -- R99
  private_window_secs INTEGER NOT NULL DEFAULT 120,
  state           TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'signed', 'broadcast', 'mined',
                                                 'reverted', 'dead', 'consumed', 'cancelled')),
  lane_label      TEXT, outer_nonce INTEGER, tx_hash TEXT, claim_block INTEGER,
  attempt_count   INTEGER NOT NULL DEFAULT 0, last_error TEXT,
  created_at      INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  UNIQUE (namespace, origin_scope, origin_producer, origin_key, generation));
CREATE INDEX job_sched   ON job (chain_key, state, uid) WHERE state IN ('queued', 'leased', 'signed', 'broadcast');
CREATE INDEX job_journal ON job (chain_key, lane_label, outer_nonce) WHERE outer_nonce IS NOT NULL;
CREATE UNIQUE INDEX job_live_digest ON job (chain_key, digest)
  WHERE digest IS NOT NULL AND state IN ('queued', 'leased', 'signed', 'broadcast');            -- durable G2

CREATE TABLE job_event (                                          -- the jobs feed (R93)
  seq INTEGER PRIMARY KEY AUTOINCREMENT, job_uid INTEGER NOT NULL REFERENCES job(uid),
  namespace TEXT NOT NULL, state TEXT NOT NULL, tx_hash TEXT, outer_nonce INTEGER, signer TEXT, error TEXT,
  at INTEGER NOT NULL);
CREATE INDEX job_event_ns ON job_event (namespace, seq);

-- index + events feed (R93, R94)
CREATE TABLE chain_index (chain_key TEXT PRIMARY KEY, indexed_block INTEGER NOT NULL, indexed_hash TEXT);
CREATE TABLE feed_item (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, chain_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('range', 'balances', 'dex_range', 'dex_order', 'dex_trade')),
  namespace TEXT,                                                 -- NULL = chain-wide (filtered at serve time)
  from_block INTEGER, to_block INTEGER, body BLOB NOT NULL, at INTEGER NOT NULL);
CREATE INDEX feed_chain ON feed_item (chain_key, seq);

-- admin (R110)
CREATE TABLE audit_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('oidc', 'socket', 'bootstrap')),
  iss TEXT, sub TEXT, roles TEXT NOT NULL, method TEXT NOT NULL, route TEXT NOT NULL, target TEXT,
  before TEXT, after TEXT, result INTEGER NOT NULL, request_id TEXT NOT NULL);
```

Mesh tables (MESH §6) change as R89 says: `intent.source` gains `'job'` and loses `'outbox'`; `odoo_job_id` →
`job_uid INTEGER REFERENCES job(uid)`; `lane_label`, `outer_nonce`, `tx_hash` are dropped (read from the job). DEX
tables: §12.

**Job state machine** (node, CAS `UPDATE … WHERE uid = ? AND state = ?` + one `job_event` INSERT in the same
transaction). It mirrors Odoo's `TRANSITIONS`/`LATE_NOOP` (`blockchain_relay_job.py:20-26`) so Odoo can apply every
event; both sides read the same vector file `bamboo-node/tests/api/transitions.json` (copied into
`dms_blockchain/tests/data/`, CI `cmp`).

| From | To | Who |
|---|---|---|
| — | `queued` | job API accept / gateway / mesh scheduler / DEX venue |
| `queued` | `leased` (`lane_label`, `claim_block`, `attempt_count+1`) | lane scheduler (replaces `relay_claim`) |
| `queued`, `leased` | `cancelled` | `POST …/cancel` (R98) |
| `queued`, `leased` | `dead` | expiry before submit; `bad payload` |
| `leased` | `queued` | transient (simulate/fee/RPC), restart before signing, in flight on another path |
| `leased` | `signed` (`outer_nonce`, `tx_hash`, signer) | **journal, before send** |
| `leased`, `signed`, `broadcast` | `consumed` | R80 classification |
| `signed`, `broadcast` | `broadcast`, `mined`, `reverted`, `queued`, `dead` | submit/follow, exactly as `TRANSITIONS` |
| `mined` | `reverted` | (reorg/late receipt, as today) |
| `consumed` | (`mined`/`reverted`/`consumed` = no-op, not stored) | `LATE_NOOP` |

`final` is never a node job state (it comes from indexed events, as today). `cancelled` is sent to Odoo as `dead`
with `error = 'cancelled'`. Terminal job rows are deleted by the janitor only when
`updated_at < now − job_retention_secs` (30 d) **and** `valid_until < now − 86 400`: a purged origin key can then never
be re-accepted because its payload is expired (`EXPIRED` at accept).

---

## 5. Job API (machine clients)

All bodies JSON, `Content-Type: application/json`, body cap 1 MiB, no cookies, no redirects, no CORS (machine
clients only). Auth R92 on every route. Errors: `{"error": "<CODE>", "detail": "<text ≤ 300 chars>"}`.

### 5.1 Authentication

```
X-Bamboo-Key: k_3f9a0c1d2e4b5a6c
X-Bamboo-Timestamp: 1790000000
X-Bamboo-Nonce: 9b2c…                         (1–64 [A-Za-z0-9_-], remembered until ts + 300 s)
X-Bamboo-Signature: hex(HMAC-SHA256(secret, ts "." nonce "." METHOD " " path?query "\n" body))
```

`gwauth.rs` gains `Auth::HmacKeys { keys: Arc<KeyTable>, seen }`: look up `key_id` in the hot-reloaded key snapshot
(active, not expired, namespace active), derive the secret (R92), verify exactly as `check()` does today
(`gwauth.rs:74-117`), then put `Caller { namespace, key_id, scopes }` in the request extensions. The nonce cache is
keyed by `(key_id, nonce)`. Unknown key and bad signature both answer `401 UNAUTHORIZED` (no oracle).
`MAX_INFLIGHT` (64) still bounds unauthenticated work (`gwauth.rs:25-26`).

### 5.2 Routes

| Route | Scope | Purpose |
|---|---|---|
| `GET /v1/info` | read | api version, `store_id`, granted chains with lanes, tokens, fee_recipient, profile, state, lane `journal_max` |
| `POST /v1/jobs` | submit | accept ≤ 50 jobs, per-item results |
| `GET /v1/jobs/{uid}` | read | one job snapshot (own namespace only, else 404) |
| `POST /v1/jobs/{uid}/cancel` | submit | R98 |
| `GET /v1/jobs?cursor=&limit=&wait=` | read | jobs change feed |
| `GET /v1/events?cursor=&limit=&wait=` | read | events feed |
| `GET /v1/watch/{chain_key}` / `PUT /v1/watch/{chain_key}` | read / submit | namespace's receiving wallets (full replace) |

`GET /v1/info`:

```json
{"api": 1, "node_id": "bamboo-node", "store_id": "32 hex",
 "chains": [{"chain_key": "evm:9000", "family": "evm", "state": "active", "profile": "private",
             "fee_recipient": "0x…", "allow_call": true,
             "tokens": [{"address": "0x…", "decimals": 6}],
             "lanes": [{"label": "0x…", "journal_max": 41}]}]}
```

`POST /v1/jobs`:

```json
{"jobs": [{
  "origin": {"scope": "6f1c…:1", "producer": "blockchain.payment.request", "key": "0x8d…", "generation": 0},
  "client_ref": "odoo:1234",
  "chain_key": "evm:9000",
  "kind": "metatx",
  "payload": {"token": "0x…", "digest": "0x…", "signature": "0x…",
              "metatx": {"from": "0x…", "to": "0x…", "value": "100", "data": "0x", "batch": "7", "nonce": "0",
                         "validUntil": "1790000300", "mode": 1, "relayer": "0x…", "fee": "0",
                         "feeRecipient": "0x0000000000000000000000000000000000000000"}},
  "bus": {"scope": "restricted", "private_window_secs": 120}}]}
```

`payload` is **exactly** today's `_payload()` (`blockchain_relay_job.py:160-187`) without `id`, for all three kinds
(`metatx`, `call`, `signed_op`), so `odoo::Job` (`odoo.rs:90-108`) moves to `job.rs` with `id` = node `uid`, and
`work_from_job` / every adapter `build(&Job, …)` are unchanged.

Accept checks, in order (no RPC; simulation stays at lease time):

1. key scope `submit`; namespace active; `chain_key` granted ⇒ else `403 CHAIN_NOT_GRANTED`.
2. payload decodes (`work_from_job` for EVM, family op parse otherwise) ⇒ `422 BAD_PAYLOAD`.
3. token registered + active on the chain and allowed for the namespace ⇒ `422 UNKNOWN_TOKEN` (MESH R86 holds for
   every origin).
4. `kind = call` requires `allow_call` ⇒ `403 CALL_NOT_ALLOWED` (R103).
5. `now < valid_until ≤ now + max_valid_for_secs` ⇒ `422 EXPIRED` / `VALID_TOO_LONG`.
6. relayer bound ⇒ a lane of this chain ⇒ `lane_hint`, else `422 RELAYER_NOT_OURS` (R102).
7. R100 normalization of the payload (unbound `feeRecipient`/`relayer`); `payload_hash` is over the **client's**
   canonical JSON, so a retry hashes identically.
8. `INSERT` (idempotency, R91): conflict on the UNIQUE tuple ⇒ same hash: existing row (`created: false`); different
   hash ⇒ `409 IDEMPOTENCY_MISMATCH`; lower generation live ⇒ `409 PREVIOUS_GENERATION_LIVE`; `job_live_digest`
   conflict ⇒ `409 DUPLICATE_DIGEST` (another namespace or path holds the intent live); live count ≥
   `max_live_jobs` ⇒ `429 QUOTA`.

Response `200` (always, for a well-formed batch):

```json
{"results": [{"client_ref": "odoo:1234", "uid": 17, "state": "queued", "created": true},
             {"client_ref": "odoo:1235", "error": "UNKNOWN_TOKEN", "detail": "0x… is not registered on evm:9000"}]}
```

Paused chain: jobs are accepted and wait `queued` (R53: "nothing new is submitted"); halted: `409 CHAIN_HALTED`.

`GET /v1/jobs?cursor=901&limit=200&wait=20`:

```json
{"store_id": "32 hex",
 "items": [{"seq": 902, "uid": 17, "client_ref": "odoo:1234",
            "origin": {"scope": "6f1c…:1", "producer": "blockchain.payment.request", "key": "0x8d…", "generation": 0},
            "state": "signed", "tx_hash": "0x…", "outer_nonce": 42, "signer": "0x…", "error": null,
            "at": 1790000000123}],
 "next": 902}
```

### 5.3 Cursor semantics (both feeds)

- Rows with `seq > cursor` visible to the caller's namespace, ordered by `seq`, ≤ `limit` (≤ 500) and ≤ 1 MiB; at
  least one item when one is due.
- `wait` (0–25 s): if nothing is due, the handler awaits a per-store `tokio::sync::Notify` fired on every feed insert,
  then re-queries once. ≤ 4 concurrent waits per key (`429` above).
- Client rule (MESH §5.2): request `cursor = max(0, last − cursor_overlap)` (200), apply idempotently, persist `next`
  with `store_id`. A different `store_id` ⇒ R110 (jobs) / reset to 0 (events, idempotent by block range).
- Retention: `job_event` and `feed_item` rows older than `feed_retention_secs` (7 d) are deleted; a cursor below the
  oldest retained `seq − 1` ⇒ `410 CURSOR_EXPIRED`. Recovery: jobs — `GET /v1/jobs/{uid}` for each non-terminal pushed
  job, then `cursor = ` the `next` of a `limit=1` read from 0 (the server returns the head when asked with
  `cursor=-1`); events — re-sync from Odoo's own `indexed_block` (the straddle rule, §10.4, makes it safe).

### 5.4 Errors and limits

| HTTP | Code | When |
|---|---|---|
| 400 | `BAD_REQUEST` | malformed JSON, batch > 50, `limit`/`wait` out of range |
| 401 | `UNAUTHORIZED` | missing/unknown key, bad signature, stale timestamp, replayed nonce |
| 403 | `FORBIDDEN`, `CHAIN_NOT_GRANTED`, `CALL_NOT_ALLOWED` | scope, grant, R103 |
| 404 | `NOT_FOUND` | job of another namespace or unknown |
| 409 | `IDEMPOTENCY_MISMATCH`, `PREVIOUS_GENERATION_LIVE`, `DUPLICATE_DIGEST`, `TOO_LATE`, `CHAIN_HALTED` | §5.2 |
| 410 | `CURSOR_EXPIRED` | §5.3 |
| 413 | `TOO_LARGE` | body > 1 MiB |
| 422 | `BAD_PAYLOAD`, `UNKNOWN_CHAIN`, `UNKNOWN_TOKEN`, `EXPIRED`, `VALID_TOO_LONG`, `RELAYER_NOT_OURS` | per item (in `results`) |
| 429 | `RATE_LIMITED`, `QUOTA` | token bucket per key: POST 20 rps (burst 40), GET 10 rps; `Retry-After` |
| 503 | `NOT_READY`, `STORE_FULL` | store not open; `max_rows` reached (nothing evicted) |

---

## 6. Event feed format per family

`kind = range` body (R94) — identical to the `chain_event_ingest` arguments:

```json
{"seq": 77, "kind": "range", "chain_key": "sui:localnet", "from_block": 101, "to_block": 140,
 "to_block_hash": "0x…64 hex", "events": [ … ]}
```

Every adapter already emits the same normalized event object (`adapter.rs:104-107`); the feed changes nothing in it:

| Family | Height = | `tx_hash` | Events emitted | Family-specific keys | Evidence |
|---|---|---|---|---|---|
| EVM | block | `0x`+64 | `PaymentSettled`, `MetaTransactionExecuted`, `Transfer` (only to watched wallets, drift A) | `relayer`, `batch`, `nonce`, `fee_recipient` | `indexer.rs:21-59, 69-77` |
| Hedera | block (JSON-RPC relay) | `0x`+64 | as EVM, via `index_runner` | as EVM | `adapters/hedera.rs:14-15` |
| Cosmos | block height | `0x`+64 | `PaymentSettled`, `MetaTransactionExecuted` | addresses bech32 | `adapters/cosmos.rs:278-290` |
| Sui | checkpoint | `0x`+64 | same two | `entry_ref`, `digest` from Move events | `adapters/sui.rs:364-393` |
| Aptos | block | `0x`+64 | same two | | `adapters/aptos.rs:352-380` |
| TON | masterchain seqno | `0x`+64 | same two | raw `0:…` addresses | `adapters/ton.rs:1022-1024, 1263-1272` |
| Solana | slot | `0x`+128 (first signature, `blockchain_chain_event.py:20-27`) | same two (`emit_cpi!`) | base58 addresses | `adapters/solana.rs:543-566` |
| Soroban | ledger | `0x`+64 | same two | `G…`/`C…` strkeys | `adapters/soroban.rs:191-198` |

Common keys: `event`, `contract`, `block_number`, `block_hash`, `tx_hash`, `log_index`, `from`, `to`, `amount`, `fee`,
`fee_recipient` (when the family has relayer fees), `entry_ref` (`PaymentSettled`), `digest`
(`MetaTransactionExecuted`). Addresses are canonical per family (R61); Odoo validates them in `_decode`
(`blockchain_chain_event.py:106-137`).

Serve-time filter per namespace (the stored item is chain-wide): drop `Transfer` events not to one of the namespace's
`watch` pairs; drop events whose `contract` is outside the namespace's token subset. **A range item is always
served**, even when its filtered `events` is empty — continuity of `from_block = indexed + 1` is what Odoo checks.

Index-time: the indexer filters `Transfer` by the union of all namespaces' watch lists (as today by Odoo's
receiving wallets, `indexer.rs:61-77`); a watch added later is not retroactive (same as today). The indexer writes the
`range` item and advances `chain_index` in one transaction; no token registered ⇒ the cursor holds (review M1,
`adapter.rs:450-453`).

`kind = balances` (drift C, EVM today; `drift.rs:30-50`): written by the indexer loop every hour right after a range,
read at `height = chain_index.indexed_block`:

```json
{"seq": 78, "kind": "balances", "chain_key": "evm:9000", "height": 140,
 "balances": [{"token": "0x…", "address": "0x…", "balance": "1000000"}]}
```

Served filtered to the namespace's watch pairs. `dex_*` kinds: §12.

---

## 7. Admin API and OIDC

### 7.1 Token validation (R106)

`node.toml`:

```toml
[api]
bind = "127.0.0.1:8547"                       # job API (R92)
master_key = { env = "BAMBOO_API_MASTER_KEY" } # ≥ 32 bytes; SecretSource like [keys]
admin_socket = "/run/bamboo/admin.sock"       # R108; "" disables
admin_cors_origins = ["https://app.example.com"]

[api.oidc]
clock_skew_secs = 60
max_token_lifetime_secs = 3600
jwks_refresh_secs = 600
jwks_max_stale_secs = 86400

[[api.oidc.issuers]]
issuer = "https://auth.example.com"           # exact; https only (http only for a loopback host, tests)
audience = "bamboo-node-admin"                # the node API resource, not the app's client id
client_ids = ["bamboo-node-app"]              # optional: `azp`/`client_id` must be one of these when present
algs = ["RS256", "ES256", "EdDSA"]
role_claim = "role"                           # ABP: "role"; Keycloak: "realm_access.roles"; scopes: "scope"
roles = { "BlockchainViewer" = "viewer", "BlockchainOperator" = "operator",
          "BlockchainAdmin" = "admin", "BlockchainKeyCustodian" = "key_custodian" }
# jwks_uri = "https://…"                      # optional override; otherwise from discovery
```

Validation of `Authorization: Bearer <jwt>` (`src/oidc.rs`, new; ~250 lines with `ring`, `base64`, `serde_json`):

1. Three base64url segments, header ≤ 2 KiB, token ≤ 8 KiB. Header `alg` ∈ the issuer's `algs`; header contains none
   of `jku`, `x5u`, `jwk`, `x5c`, `crit` ⇒ else `401`.
2. Payload decoded **unverified only to read `iss`**; `iss` must equal a configured `issuer` byte for byte, else
   `401` with no network activity.
3. Key: JWKS cache entry by `kid` (absent `kid` ⇒ the single key of matching `kty`, else reject). Unknown `kid` ⇒ one
   refetch, at most once per 60 s per issuer (a stream of random `kid`s cannot make us hammer the IdP). The JWK must
   fit the alg: `RS256` ⇒ `kty = RSA`, n ≥ 2048 bits (`ring` `RSA_PKCS1_2048_8192_SHA256` with
   `RsaPublicKeyComponents`); `ES256` ⇒ `kty = EC, crv = P-256` (`ECDSA_P256_SHA256_FIXED`, point `04‖x‖y`);
   `EdDSA` ⇒ `kty = OKP, crv = Ed25519`. A JWK with `use` ≠ `sig` is ignored.
4. Signature over `header.payload`.
5. Claims: `exp` required and `> now − skew`; `nbf`, `iat` (when present) `≤ now + skew`; `exp − iat ≤
   max_token_lifetime_secs` when `iat` is present; `aud` (string or array) contains `audience`; `azp`/`client_id`, when
   present and `client_ids` set, is listed; `sub` non-empty.
6. Roles = `roles[v]` for each value `v` found at `role_claim` (string, array of strings, or space-separated for
   `scope`). Empty ⇒ `403 NO_ROLE`.

Discovery: at start and every `jwks_refresh_secs`, `GET {issuer}/.well-known/openid-configuration` (HTTPS, no
redirects, 5 s timeout, 64 KiB cap); its `issuer` must equal the configured one (OIDC Discovery §4.3); `jwks_uri` must
be `https` and on the issuer's host unless `jwks_uri` is configured explicitly. JWKS fetch failures keep the last good
set for `jwks_max_stale_secs`, then the issuer fails closed. Removed keys disappear on the next successful refresh
(rotation). Metric `bamboo_oidc_jwks_refresh_total{issuer,result}`.

`# ponytail: hand-rolled JWS verify over ring (3 algs); a JWT crate if a fourth alg or JWE is ever needed.`

### 7.2 Break-glass (R108)

`tokio::net::UnixListener` at `admin_socket` (axum 0.8 serves Unix listeners), created with umask so the file is
`0600`; refuse to start if the parent directory is world-writable. Caller = `socket:<uid>` from `SO_PEERCRED`
(`UnixStream::peer_cred`), roles = all four. Bootstrap:

```bash
curl --unix-socket /run/bamboo/admin.sock -X POST localhost/v1/admin/namespaces -d '{"name":"odoo-prod", …}'
curl --unix-socket /run/bamboo/admin.sock -X POST localhost/v1/admin/keys -d '{"namespace":"odoo-prod","scopes":"submit read"}'
```

Every socket call is audited with `actor_kind = 'socket'` and counted in `bamboo_admin_break_glass_total`; operators
alert on it when an IdP is configured.

### 7.3 Routes and authorization (R107)

| Route | Role | Hot / restart |
|---|---|---|
| `GET /v1/admin/info` (version, store_id, node_id, `pending_restart`, toml drift) | viewer | — |
| `GET /v1/admin/chains`, `GET /v1/admin/chains/{key}` (rpc URLs shown as host only) | viewer | — |
| `PATCH /v1/admin/chains/{key}` — `poll_ms`, `stuck_after_secs`, `max_gas_per_tx`, `max_fee_cap_gwei`, `max_index_lag`, `breaker`, `profile` | admin | hot |
| `PATCH /v1/admin/chains/{key}` — `finality_*`, `index_from` (only while `chain_index` is empty) | admin | restart |
| `PUT /v1/admin/chains/{key}/state` (`active`/`paused`/`halted`) | operator | hot |
| `PUT /v1/admin/chains/{key}/fee_recipient` | admin | hot (audit + metric `bamboo_fee_recipient_changed_total`) |
| `POST /v1/admin/chains/{key}/breaker/reset` | operator | hot |
| `GET/POST/DELETE /v1/admin/chains/{key}/tokens` | viewer / admin / admin | hot |
| `GET /v1/admin/chains/{key}/lanes` (address, balance, breaker, journal_max) | viewer | — |
| `PUT /v1/admin/chains/{key}/lanes` (account indexes) | admin | restart |
| `GET/POST/PATCH /v1/admin/namespaces[/{name}]` (grants, token subset, `allow_call`, quota, state) | viewer / admin | hot |
| `GET /v1/admin/keys` (metadata only) | viewer | — |
| `POST /v1/admin/keys`, `POST /v1/admin/keys/{id}/rotate`, `DELETE /v1/admin/keys/{id}` | key_custodian | hot |
| `GET/POST/PATCH/DELETE /v1/admin/mesh/peers` | viewer / admin | hot |
| `PUT /v1/admin/mesh/peers/{id}/state` (suspend/activate) | operator | hot |
| `GET/POST/PATCH/DELETE /v1/admin/mesh/policy` | viewer / admin | hot |
| `GET/POST/PATCH /v1/admin/dex/markets`, `PUT …/{id}/state` | viewer / admin / operator | hot |
| `GET /v1/admin/jobs?namespace=&state=&chain=` (no payload, no counterparties) | viewer | — |
| `POST /v1/admin/jobs/{uid}/cancel` | operator | — |
| `GET /v1/admin/audit?since=` | viewer | — |

`POST /v1/admin/keys` returns `{"key_id", "secret": "<64 hex>", "namespace", "scopes"}` **once**; the secret is
re-derivable only with `master_key`, so it is never shown again. Validation on writes reuses the Odoo rules being
superseded: token/peer/policy constraints of MESH §10.2 (R86 `submit` only on registered contracts, `pool_visibility`
vs profile R76, peer `url` = `https://host[:port]` without userinfo/path/query/fragment, pin = 64 lowercase hex).

### 7.4 CORS (admin listener only)

`tower-http` (in `Cargo.lock`) as a direct dep with feature `cors`: allow origins = `admin_cors_origins` exactly
(no `*`, no reflection), methods `GET, POST, PATCH, PUT, DELETE`, headers `Authorization, Content-Type`,
`allow_credentials = false`, `max_age = 600`. `/healthz`, `/readyz`, `/metrics` are not CORS-enabled. No cookies are
ever set or read (CSRF has no surface).

### 7.5 Audit (R110)

The mutation handler runs `before = SELECT …`, the change, `after = SELECT …`, and the `audit_log` INSERT in one
transaction; a failed write is audited with `result = <http status>` in its own transaction. JSON before/after hold
config rows only (the store holds no secret). `request_id` is echoed as `X-Request-Id`. No purge in v1
(`# ponytail: audit kept forever; add a retention knob when it grows`).

### 7.6 Errors

`401 UNAUTHORIZED` (no/invalid token, unknown issuer, bad signature, expired, wrong aud) — body never says which;
`403 NO_ROLE`/`FORBIDDEN`; `404`; `409 CONFLICT` (constraint, e.g. `submit` on `*`); `422 INVALID` with field; `429`
(10 rps per `sub`); `503 IDP_UNAVAILABLE` (issuer failed closed).

### 7.7 React+Vite app (`smartcontracts/app/`) requirements

- Public OIDC client: Authorization Code + PKCE `S256`, no client secret, exact redirect URIs, `state` + `nonce`.
- Tokens in memory only (e.g. `oidc-client-ts` with an in-memory store; never `localStorage`/`sessionStorage`).
- Renewal: refresh-token rotation when the IdP issues refresh tokens to public clients; otherwise silent renew with
  `prompt=none`; on failure, interactive login. Logout via `end_session_endpoint` and dropping in-memory tokens.
- Requests to the node admin API with `Authorization: Bearer`, no cookies; audience = the node's `audience`
  (requested via `resource`/`audience`/scope as the IdP requires).
- Chain-only features (wallet, payments, DEX via the gateway) work without login; OIDC gates only node admin screens.
- UI hides actions the token's roles cannot perform (convenience; the node enforces).

---

## 8. Configuration authority and bootstrap (R95)

Start sequence (`main.rs`): load toml → open store (migrate, lock) → **import**: for each `[[chains]]` without a
`chain` row, insert chain + tokens + lanes from toml; same for `[[mesh.peers]]`, `[[mesh.policy]]`, `[[namespaces]]`
(new, optional bootstrap list) → build runtime from the store. Toml values that differ from existing rows set
`toml_drift` (listed in `GET /v1/admin/info`). `rpc_urls`, keys, `params`, `coin_type` are always read from toml.

Runtime snapshot: a `tokio::sync::watch::Sender<Arc<ConfigSnapshot>>` (no new crate) re-built from the
store after every admin commit (and every 30 s as a guard); consumers that refresh today read it instead of Odoo:
gateway tokens (`main.rs:131-167`), EVM/Hedera/TON/Solana token filters (`adapters/evm.rs:31`, `hedera.rs:14-15`,
`ton.rs:940`), the indexer token list and finality (`indexer.rs:106-117`, `adapter.rs:445-450`), drift pairs
(`drift.rs:31-33`), breaker config, chain state (R53), mesh peers/policy.

---

## 9. Submit and index paths: what changes, what is preserved

### 9.1 Code changes (node)

| Today | After |
|---|---|
| `odoo::Odoo` passed to `Submitter`, `lane_runner`, `index_runner`, `indexer::run`, `drift::step`, `admin::refresh_loop`, `Venue` (`main.rs:103-228`) | `Store` handle (+ `ConfigSnapshot` receiver). `odoo.rs` kept only for `// legacy(R104)` until P9. |
| `Submitter::poll_outbox`: `relay_poll` → skip in-flight digest → `relay_claim` (`submit.rs:540-568`) | `poll_store`: `SELECT uid, payload … FROM job WHERE chain_key=? AND state='queued' AND (lane_hint IS NULL OR lane_hint=?) ORDER BY uid LIMIT 10` → skip in-flight digest (N2 unchanged) → CAS `queued→leased`. Same loop shape. |
| `report(id, state, …)` → `relay_report` (`submit.rs:244-261`, `adapter.rs:151-159`) | `store.transition(uid, from, to, fields)` — synchronous local write + `job_event`. Returns `false` on CAS miss or I/O error exactly where `report()` returned `false`. |
| Journal `signed` over HTTP before `send_raw` (`submit.rs:308-316`; `adapter.rs:419-423`) | `transition(leased→signed, lane, outer_nonce, tx_hash)` before `send_raw`; failure ⇒ `retry` queue / `queued`, unchanged rule (review I5). |
| `Submitter::start` / `recover_lane` read `node_config.inflight` + `journal_max_nonce` (`submit.rs:146-190`, `adapter.rs:232-248`) | Same code over `store.inflight(chain, lane)` = rows `leased/signed/broadcast` with `lane_label = lane` (mirror of `_inflight`, `blockchain_relay_job.py:189-204`) and `journal_max = max(lane.journal_floor, max(job.outer_nonce))`. During R104 transition: union with legacy `node_config` (MESH §8.6 already specifies the union). |
| Gateway: `Work` on an in-memory `mpsc` channel to lane 0 (`main.rs:139-153`, `gateway.rs:129-137`) | Gateway INSERTs a job in `~gateway` (origin key = `intent_id`) and fires the chain's `Notify`; `GET /v1/intents/{id}` reads it (MESH §5.2). R16 closed for door A. |
| `index_step`/`indexer::step` call `ingest` and read the cursor from Odoo (`adapter.rs:443-458`, `indexer.rs:106-118`) | Cursor from `chain_index`; one transaction writes `feed_item(range)` + advances `chain_index`. |
| Drift reads `node_config.indexed_block` and posts `balance_report` (`drift.rs:30-50`) | Reads `chain_index` and appends `feed_item(balances)` inside the indexer loop (ordering = R94). |
| `/readyz` uses `relay_stats` (`admin.rs:125-153`) | Readiness = store open + RPC final head + lag from `chain_index`; `bamboo_relay_jobs{chain,state}` from `SELECT state, count(*) FROM job GROUP BY …`; `attention`/`drift_alerts` leave the node (they are Odoo business facts). |

### 9.2 Safety properties — where each now lives

| Property | Mechanism after inversion |
|---|---|
| Journal before broadcast (review F5/I5) | `leased→signed` committed with `synchronous = FULL` before `send_raw`; a crash after commit is recovered by `plan()` as a journaled nonce; a failed commit never sends. Strictly stronger than an HTTP round trip that may time out after Odoo committed. |
| `plan()` restart (R18, `nonce.rs:23-33`) | Inputs from the store: `leased` ⇒ requeue; `signed/broadcast` with `n < pending` ⇒ track; else gap-fill + requeue; `journal_max` includes `journal_floor` (legacy import) so a nonce journaled only in Odoo before cutover is still never reused. |
| In-flight digest set (G2, `submit.rs:63-90`) | Unchanged in memory (all lanes, gateway, mesh, non-EVM runners) **plus** durable `job_live_digest` partial UNIQUE index (R89): two live jobs for one digest cannot exist in the store at all. |
| R80/S2 consumption checks | Unchanged code (`submit.rs` `track()`, `refused`, `classify`; `adapter.rs:263-341, 396-410` `op_consumed`); only the sink changes from `relay_report` to `transition`. |
| `consumed` semantics (S1a) | Node table §4 mirrors `TRANSITIONS`/`LATE_NOOP`; shared vector file; Odoo keeps `_cron_expire` superseded rule and `_mark_final` from events (`blockchain_relay_job.py:263-291`). |
| No double broadcast | G2 + G3 as MESH §8.7; the cancel/lease race is a CAS (R98). |
| Journaled nonces (G4) | `job.outer_nonce` + `lane.journal_floor`; `intent` no longer journals (R89). |
| R53 pause, R55 breaker | Node chain state + breaker block `poll_store` (as they block `poll_outbox` today, `submit.rs:574-583`); Odoo state blocks push. |
| R84/R100 normalization | At accept for job API, at gateway and mesh work builders as today. |

### 9.3 Durability vs `SKIP LOCKED` (R97)

`relay_claim` needed `FOR UPDATE SKIP LOCKED` because several node processes (or lanes) competed over one Postgres
table (`blockchain_relay_job.py:121-138`). After inversion, one process owns one store (flock + exclusive locking
mode, R88); lanes of that process compete through one SQLite connection, and the CAS `UPDATE … WHERE state='queued'`
returns 0 rows to the loser. Odoo never claims: it only pushes (idempotent) and applies (ordered, idempotent). Two
node processes cannot open one store; scaling out is by chain (R97).

### 9.4 Same lane keys in two stores (forbidden, detected)

At lane start: if `journal_max` is known and `nonce_at(latest) > journal_max + 1 + tracked`, the lane's nonce was used
by a transaction this store never journaled ⇒ the lane does not lease, `/readyz` reason `lane <label> used outside
this store`, metric `bamboo_lane_foreign_nonce_total`. Heuristic (a manual wallet send also trips it), which is the
right default: someone else is using our hot key.

---

## 10. Odoo side

### 10.1 New models (`dms_blockchain`)

```python
class BlockchainNode(models.Model):
    _name = 'blockchain.node'
    _description = 'Relay node endpoint (Odoo is its client)'
    _inherit = ['mail.thread']

    name = fields.Char(required=True, tracking=True)
    url = fields.Char(required=True, tracking=True, groups='base.group_system',
                      help='https://host[:port] of the node job API. No path, query, userinfo.')
    key_id = fields.Char(required=True, tracking=True, groups='base.group_system')
    namespace = fields.Char(required=True, readonly=True, help='Shown by GET /v1/info; informational.')
    # Server-only (SERVER_ONLY pattern): written by the sync cron under sudo only.
    store_id = fields.Char(readonly=True, copy=False)
    jobs_cursor = fields.Integer(readonly=True, copy=False)     # int8 like BigInteger in relay_job
    events_cursor = fields.Integer(readonly=True, copy=False)
    last_sync_datetime = fields.Datetime(readonly=True, copy=False)
    last_error = fields.Char(readonly=True, copy=False)
    needs_attention = fields.Boolean(readonly=True, copy=False, index=True)

    _key_id_format = models.Constraint("CHECK(key_id ~ '^k_[0-9a-f]{16}$')", 'Key id is k_ + 16 hex.')

class BlockchainNodeRoute(models.Model):
    _name = 'blockchain.node.route'
    _description = 'Which node relays which company on which chain'
    company_id = fields.Many2one('res.company', required=True, index=True)
    chain_id = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='cascade')
    node_id = fields.Many2one('blockchain.node', required=True, index=True, ondelete='restrict')
    _company_chain_uniq = models.Constraint('UNIQUE(company_id, chain_id)', 'One node per company and chain (R97).')
```

Secret: `ir.config_parameter` key `dms_blockchain.node_secret.<id>` (CLAUDE.md §5.5: secret outside the record),
written by a `base.group_system`-only wizard; the record shows `secret_set` (computed). `url` constraint: scheme
`https`, or `http` only for `localhost`/`127.0.0.1`/`::1` or when `dms_blockchain.allow_plain_node_url = '1'` (dev);
no userinfo, path, query, fragment.

`blockchain.chain` gains `node_transport = Selection([('pull','Odoo outbox pulled by node (legacy)'),
('push','Odoo pushes to node')], default='pull', required=True, tracking=True)` (R104, deleted in P9) and
`event_node_id = Many2one('blockchain.node')` (R97: the one source of this chain's events).

`blockchain.relay.job` gains (all server-only; `SERVER_ONLY` becomes a dict field → create value so `push_state`
is forced to `'local'`, not `False`; `write` strips them unless `env.su`, `blockchain_relay_job.py:79-86`):

```python
node_id = fields.Many2one('blockchain.node', readonly=True, index=True, copy=False)
node_job_uid = BigInteger(readonly=True, copy=False, index=True)
push_state = fields.Selection([('local', 'Not sent'), ('sent', 'Accepted by node'),
                               ('cancel_requested', 'Cancel pending')], default='local', readonly=True,
                              required=True, index=True, copy=False)
push_generation = fields.Integer(readonly=True, copy=False)
node_event_seq = BigInteger(readonly=True, copy=False)
_node_uid_uniq = models.Constraint('UNIQUE(node_id, node_job_uid)', 'One Odoo job per node job.')
```

### 10.2 Client library

`dms_blockchain/lib/node_client.py`: `requests` (Odoo dependency), `allow_redirects=False`, timeout `(5, 30)`,
HMAC signing byte-identical to `gwauth.rs` (one KAT vector shared with the node tests), response capped at 4 MiB,
error detail truncated to 300 chars and stored as plain text. `blockchain.node._client()` is the seam tests replace.

### 10.3 Push (cron `cron_node_push`, `model._cron_node_push()`)

```python
@api.model
def _cron_node_push(self, limit=200):
    for chain in Chain.search([('node_transport', '=', 'push'), ('state', '=', 'active')]):   # R53 + R96 gate
        jobs = self._lock_skip_locked(self._push_domain(chain), limit)   # FOR UPDATE SKIP LOCKED: two cron
        for route, batch in groupby(jobs, key=_route_of):                # workers never push the same row
            results = route.node_id._client().post_jobs([j._push_item() for j in batch[:50]])
            for job, r in zip(batch, results): job._apply_push_result(route.node_id, r)
```

- `_push_domain(chain) = self._poll_domain(chain) + [('push_state', '=', 'local')]` — reuses `_poll_domain`
  including the RS4-6 prerequisite extension (`blockchain_subject_account.py:451-455`) and `queued` state; a job is
  pushed only after its prerequisite is `mined`/`final`.
- `_push_item()`: `origin = {scope: f'{dbuuid}:{company_id}', producer, key: origin_key, generation:
  push_generation}`, `client_ref = f'odoo:{id}'`, `payload = _payload()` minus `id`, `bus = {scope:
  company.blockchain_bus_scope, private_window_secs}` (MESH §10.4, built in stream S1b′).
- `_apply_push_result`: accepted (`created` true or false) ⇒ `push_state='sent'`, `node_id`, `node_job_uid`; permanent
  item error (`BAD_PAYLOAD`, `UNKNOWN_TOKEN`, `EXPIRED`, `VALID_TOO_LONG`, `RELAYER_NOT_OURS`,
  `IDEMPOTENCY_MISMATCH`, `CALL_NOT_ALLOWED`, `CHAIN_NOT_GRANTED`) ⇒ `dead`/`failed` with `last_error` (as `bad
  payload` today, `submit.rs:563-565`) and `_fail_dependents()`; `DUPLICATE_DIGEST` ⇒ stays `local`, `last_error`
  ("live on another path"); transport/`429`/`503` ⇒ stays `local`, `last_error`. No route ⇒ `last_error`, stays
  `local`.
- Latency: `blockchain.relay.job.create` (and `action_requeue`) call `env.ref('dms_blockchain.cron_node_push')
  ._trigger()` when the chain is `push` (R101).
- HTTP inside the cron transaction is safe: the node never calls Odoo, so no lock cycle (the R6 deadlock argument does
  not apply). If the cron transaction rolls back after the node accepted, the next run gets `created: false` and the
  same `uid`.

### 10.4 Sync (cron `cron_node_sync`, `model._cron_node_sync()`)

Per `blockchain.node` with a secret, each page in its own transaction:

1. `GET /v1/jobs?cursor=max(0, jobs_cursor−200)&wait=10`. `store_id` ≠ stored ⇒ first sync stores it; later a
   change ⇒ `needs_attention`, stop (R110). Each item in a savepoint: `_apply_node_event(node, item)`; a `UserError`
   rolls back the savepoint, writes `last_error = 'node event rejected: …'` on the job (under sudo), logs, continues —
   a poison item never blocks the feed. Then `jobs_cursor = next`.
2. `GET /v1/events?cursor=…` for chains whose `event_node_id` is this node: `range` ⇒ `_ingest_range(chain, …)`,
   `balances` ⇒ `blockchain.balance.snapshot._record` when `height == chain.indexed_block` (else log `stale` and skip),
   `dex_*` ⇒ §12. A range **gap** (`from_block > indexed + 1`) is a continuity violation, not poison: rollback the page,
   `needs_attention`, stop this node's event sync.
3. Watch sync: for each `(node, chain)` routed, `PUT /v1/watch/{chain_key}` with `chain._receiving_addresses()`
   (`blockchain_chain.py:215-219`) when its hash differs from the last pushed one (stored per route).
4. Retry `cancel_requested` jobs (§10.5).
5. If any pushed job of this node is non-terminal, `_trigger(now + 10 s)`.

`_apply_node_event(node, item)`:

```python
job = Job.search([('node_id', '=', node.id), ('node_job_uid', '=', item['uid'])], limit=1)
if not job or item['seq'] <= job.node_event_seq: return            # idempotent under overlap
state = {'leased': 'nonce_leased', 'cancelled': 'dead'}.get(item['state'], item['state'])
if state == 'nonce_leased' and job.chain_state == 'queued':        # what relay_claim wrote (l.135-137)
    job.write({'chain_state': 'nonce_leased', 'claimed_by': item['signer'] or node.name,
               'claimed_datetime': ts(item['at']), 'attempt_count': job.attempt_count + 1})
elif state == 'dead' and job.chain_state in ('queued', 'nonce_leased'):     # node expiry / cancel / bad payload
    job.write({...dead/failed..., 'last_error': item['error']}); job._fail_dependents()
else:
    job._apply_report(state, item['tx_hash'], item['outer_nonce'], item['signer'], item['error'])
job.node_event_seq = item['seq']
```

`_apply_report` is unchanged (`blockchain_relay_job.py:206-247`), so `consumed`, `LATE_NOOP`, `mined` of `call` jobs,
`dead` side effects and the RS4-6 `_fail_dependents` override (`blockchain_subject_account.py:457-460`) all keep
working.

`_ingest_range(chain, from_block, to_block, to_block_hash, events)` = the body of `chain_event_ingest`
(`blockchain_chain_event.py:84-103`) without `check_service`, with one generalisation for overlap and for the R104
transition: when `from_block ≤ indexed < to_block`, events with `block_number ≤ indexed` are dropped and
`from_block := indexed + 1`; `to_block ≤ indexed` stays a no-op; `from_block > indexed + 1` raises (gap).

### 10.5 Cancel, requeue, expiry

- `blockchain.relay.job._node_cancel()` (used by `_cancel_unsent`, `blockchain_autopay.py:80-99`): `push_state ==
  'local'` ⇒ today's local `dead`; `sent` ⇒ `POST /v1/jobs/{uid}/cancel`: `cancelled` ⇒ local `dead` + existing
  side effects; `TOO_LATE` ⇒ treated like `signed` today (chatter "already sent"); transport error ⇒ `push_state =
  'cancel_requested'`, request/tx **not** expired yet; the sync cron retries and finishes the side effects when the
  node answers (or when the feed brings a terminal state).
- `action_requeue` (`blockchain_relay_job.py:249-261`): unchanged checks; additionally `push_generation += 1`,
  `push_state = 'local'`, `node_job_uid = False`, `node_event_seq = 0` (sudo) — R91.
- `_cron_expire` (`blockchain_relay_job.py:275-291`): the first search adds `('push_state', '=', 'local')`; a pushed
  job's expiry is the node's (`dead` arrives on the feed). The `consumed` → superseded branch is unchanged.

### 10.6 Transitional gates (deleted in P9)

- `relay_poll`: `if chain.node_transport == 'push': return []` before `_poll_domain` (next to the R53 gate, l.110-111).
- `relay_claim`: SQL adds `AND push_state = 'local'` (l.130-132).
- `node_config` returns `'node_transport'`, so the transitional node stops legacy ingest for `push` chains.
- `chain_event_ingest`: refuses `push` chains (`UserError`), and uses `_ingest_range` otherwise.
- `action_switch_to_push()` on `blockchain.chain` (group manager): preconditions §11.2.

### 10.7 Deleted in P9

Public methods `relay_poll`, `relay_claim`, `relay_report`, `node_config` (+ `_node_config`, `_inflight`, the
`journal_max_nonce` SQL), `chain_event_ingest`, `relay_stats`, `balance_report`; DEX `dex_markets`,
`dex_book_load`, `dex_book_commit`, `dex_sync`, `dex_cursor`, `dex_fill_ingest`; groups `group_blockchain_relay_worker`
and `group_blockchain_indexer` and their service users' API keys (post-migration script removes the users' keys and
archives the users); `check_service` roles map entries (`blockchain_chain.py:13-25`); `node_transport`;
`dms_blockchain_dex/models/relay_job.py` write hook (`:10-16`). `blockchain.chain.finality_*` become informational
(help text: "configured on the node") and are removed from the form in P9.

### 10.8 ACL and record rules

```
access_node_viewer,node viewer,model_blockchain_node,group_blockchain_viewer,1,0,0,0
access_node_manager,node manager,model_blockchain_node,group_blockchain_manager,1,1,1,0
access_node_route_viewer,node route viewer,model_blockchain_node_route,group_blockchain_viewer,1,0,0,0
access_node_route_manager,node route manager,model_blockchain_node_route,group_blockchain_manager,1,1,1,1
```

`url` and `key_id` carry `groups='base.group_system'` (editing the dial target is a system right: SSRF, §14 T1).
Rule `rule_node_route_company`: `[('company_id', 'in', company_ids)]`. `blockchain.node` has no company (platform,
like `blockchain.chain`). `rule_relay_job_company` (`blockchain_security.xml:61`) already covers the new job fields.
No new ACL for service users (there are none after P9).

---

## 11. Migration

### 11.1 Version matrix

| Node | Odoo | Chain flag | Works? |
|---|---|---|---|
| old (pull only) | old | — | today |
| old | new (P5) | `pull` | yes: pull path unchanged |
| old | new | `push` | refused: `action_switch_to_push` requires `GET /v1/info` `api ≥ 1` |
| transitional (P1–P4, `[odoo]` present) | old | — | yes: legacy path; job API idle |
| transitional | new | `pull` | yes |
| transitional | new | `push` | yes: store path for new jobs; legacy path drains in-flight Odoo jobs |
| final (P9, no `[odoo]`) | new, all chains `push` | `push` | target |
| final | any chain `pull` | — | refused by P9's Odoo upgrade precondition (§11.4); the final node also refuses to start with an `[odoo]` section ("removed by R104; delete the section") |

### 11.2 Per-chain cutover (`action_switch_to_push`)

Preconditions (checked, each with a clear `UserError`):

1. Every company with a non-terminal job on the chain has a `blockchain.node.route`; `event_node_id` set; secrets set.
2. `GET /v1/info` of each routed node: `api ≥ 1`, the chain is granted, `state = active`.
3. **Journal floor**: for each lane label the node reports, `journal_max ≥` Odoo's `max(outer_nonce)` for that signer
   (the transitional node imports `lane.journal_floor` from every legacy `node_config` it reads, R104). Refuse
   otherwise — this is what makes the nonce history continuous across the switch.
4. DEX chain: every market paused, no `pending` trade (§12.4).

Effects: `node_transport = 'push'`. From the next poll, `relay_poll` serves nothing for the chain; queued jobs are
pushed; legacy in-flight jobs (`nonce_leased`/`signed`/`broadcast`, `push_state = 'local'`) keep reporting through
`relay_report` until terminal; a legacy job the old path requeues (`queued`) is pushed like any other. Both indexers
may run briefly; `FOR UPDATE` on the chain row (`blockchain_chain_event.py:86-88`) plus the straddle rule make the
overlap harmless. The node's store indexer cursor was bootstrapped from the legacy `node_config.indexed_block` at
store creation.

Rollback for a chain: `node_transport = 'pull'` (manager). New jobs go back to the pull path; already pushed jobs stay
with the node and keep syncing (the sync cron does not depend on the flag).

### 11.3 Bootstrap of the Odoo namespace (once)

Via the admin socket or an `admin` OIDC session: create namespace `odoo-<db>` with `allow_call = true`, grant its
chains; `key_custodian` creates one key with scopes `submit read`; a system user enters `key_id` + secret in Odoo.

### 11.4 Proof criterion and one-step removal (P9)

All chains `push` for ≥ 14 days; zero Odoo jobs with `push_state = 'local'` in `nonce_leased/signed/broadcast`; no
`needs_attention` in that window; e2e §16.4 green on the release candidate. Then one node release (P9) and one Odoo
upgrade (P9) delete everything listed in §9.1 "legacy" and §10.7. The Odoo upgrade's pre-migration aborts when any
chain is still `pull`.

---

## 12. DEX (R105)

### 12.1 Node

```sql
CREATE TABLE dex_market (id INTEGER PRIMARY KEY, chain_key TEXT NOT NULL, namespace TEXT NOT NULL,
  base TEXT NOT NULL, quote TEXT NOT NULL, fee_ppm INTEGER NOT NULL, fee_recipient TEXT,
  state TEXT NOT NULL CHECK (state IN ('active', 'paused')), body TEXT NOT NULL);   -- MarketCfg (dex.rs:187)
CREATE TABLE dex_order (order_hash BLOB PRIMARY KEY, market_id INTEGER NOT NULL, seq INTEGER NOT NULL,
  state TEXT NOT NULL, remaining TEXT NOT NULL, row TEXT NOT NULL);              -- Row (dex.rs:229)
CREATE TABLE dex_trade (tag BLOB PRIMARY KEY, market_id INTEGER NOT NULL, maker BLOB NOT NULL, taker BLOB NOT NULL,
  maker_fill TEXT NOT NULL, taker_fill TEXT NOT NULL, job_uid INTEGER REFERENCES job(uid),
  state TEXT NOT NULL CHECK (state IN ('pending', 'settled', 'failed')), restored INTEGER NOT NULL DEFAULT 0);
CREATE TABLE dex_cursor (chain_key TEXT PRIMARY KEY, indexed_block INTEGER NOT NULL);           -- RS5-8 stays separate
```

- `Venue::start` loads markets from the snapshot and the book from `dex_order` (replaces `dex_markets` +
  `dex_book_load`, `dex/venue.rs:179-199`); the on-chain market cross-check stays.
- A book change = one SQLite transaction (orders upsert + trades + settle `job` INSERT in `~dex` with origin key
  `keccak(calldata)` as today `dex_order.py:151-152` + `feed_item(dex_order/dex_trade)` rows in the market's namespace)
  — replaces `dex_book_commit` (`dex/venue.rs:403-421`). The "reload the book on commit timeout" path (review D20)
  disappears: a local commit either happened or not.
- Settle job ends `dead`/`reverted` ⇒ the venue marks the trades `failed`, restores fills to the book in the same
  transaction (replaces `dex_sync` + `restored` + the Odoo write hook). The DEX watcher writes `dex_range` items
  (today's `dex_fill_ingest` arguments) and advances `dex_cursor`.

### 12.2 Odoo (`dms_blockchain_dex`)

`blockchain.dex.order`/`trade` become mirrors: `_apply_dex_order(item)` / `_apply_dex_trade(item)` upsert by
`order_hash`/`trade_ref` (the decode code of `_upsert` and `_create_from_node`, `dex_order.py:106-141`,
`dex_trade.py:58-76`, reused); `_dex_ingest_range` = `dex_fill_ingest` body with the straddle rule, and `_book_fees`
unchanged. `blockchain.dex.market` keeps the accounting fields (company, accounts, journal) and gains
`node_market_id` (server-only); market trading parameters are edited in the node app. The Odoo `_cron_expire` for
orders (`dex_order.py:144-149`) is removed (the node expires and mirrors).

### 12.3 Gateway

`/v1/dex/*` routes unchanged (`gateway.rs:179-188`).

### 12.4 Cutover

Pause every market of the chain (Odoo flag today, node state after), wait for `pending` trades to settle or fail on
the legacy path, flip the chain (§11.2), the transitional node imports open orders once via legacy `dex_book_load`
into `dex_order`, resume markets in the node. Downtime = settlement of the last pending batch.

---

## 13. Interplay with the mesh spec

### 13.1 MESH sections superseded or amended

| MESH section | Status | Replacement |
|---|---|---|
| §1.1 item 3 ("authoritative in Odoo … delivered to the node") | superseded | R99: node store, admin API |
| §1.1 item 7 (per-company scope via Odoo outbox publication) | amended | setting in Odoo, delivered per job (R99); publication by the node |
| §2 **R71** clauses "R6 unchanged … Odoo stays control plane" and "(the DEX book stays as is)"; "When `[mesh]` is on" | superseded | R87, R88 (store always on), R105 |
| §2 **R73** last sentence (published after the window by Odoo `mesh_publish_claim`) | amended | the node publishes `bus_scope = open` jobs whose `created_at + private_window_secs ≤ now` and still `queued` |
| §2 **R74** "the origin keeps processing them through the Odoo outbox" | amended | "through its job store" |
| §2 **R79** | **superseded entirely** | R95, R99 |
| §2 **R83** "one fake Odoo" | superseded | fake job-API client (§16.4) |
| §2 **R86** "Odoo `node_config.tokens` … Odoo forbids `submit` on `*`" | amended | node `token` table; admin API validation |
| §3.1 shapes table ("no `[odoo]`", "indexer is refused without `[odoo]`") | superseded | every shape is Odoo-free; `indexer` writes the feed |
| §3.2 "`[odoo]` becomes optional" and every "standalone only" annotation | superseded | toml bootstraps every node (R95) |
| **§3.3 Standalone mode** | **superseded entirely** | there is only one mode |
| §5.3 `NOT_READY` reason "`[odoo]` present and `mesh_config` never fetched" | superseded | `NOT_READY` = store not open |
| §6 `intent.source 'outbox'`, `odoo_job_id`, journal columns, rows "Odoo-path outcome sink" | amended | R89 (§4) |
| §8.1 row `outbox` and the DUPLICATE flip paragraph | amended | `source = 'job'`, `job_uid` |
| §8.3 "try_send Work … to the chain's lane channel" | amended | INSERT job in `~mesh` (R89); `lane_runner` reads the store |
| §8.4 `Origin::Odoo`, "Odoo path avoids churn" bullet, outcome sink `relay_report`, R84 Odoo exception | amended | `Origin::Job(uid)` for all; skip-before-lease in `poll_store`; `transition`; R100 |
| §8.6 `journal_max = max(Odoo journal_max_nonce, …)`, "store rows of its lane (same rules as Odoo …)" | amended | §9.2 (store + `journal_floor`) |
| §8.7 G2 "Odoo `relay_claim` admit one Work per path" | amended | store CAS + `job_live_digest` |
| **§10 Odoo side** — §10.1, §10.2, §10.5, §10.6 | **superseded** | `profile` on node `chain`; policy/peers in node store; node-internal publication; no Odoo mesh models |
| §10.3 (S1a, done) | kept | — |
| §10.4 company setting | kept (built in S1b′), delivery per job | R99 |
| §12 "`/readyz` … `mesh_config` was never fetched"; "Odoo `relay_stats` already counts jobs" | amended | store counts |
| §13.3 fake Odoo; §13.4 mesh-model Odoo tests | amended | fake client; Odoo keeps S1a tests + §16.3 |
| §15.4 row "Node → Odoo channel … R6" | superseded | R87 |

### 13.2 Mesh streams

| Stream | State | Change |
|---|---|---|
| S0, S1a, S2 | merged | none (their `relay_report` calls move to `transition` in P3) |
| S3 envelope/digest/hubsig/vectors | unchanged | can run any time (pure library) |
| **S4** store and configuration | **replaced by P1** | P1 builds the store with the mesh tables (R89 shape) and the `[api]`/bootstrap config; the `[odoo]`-optional/standalone work and `odoo.rs` `mesh_config`/`mesh_publish_claim` are dropped |
| **S1b** Odoo chain profile, policy, peers, company scope, publication | **replaced by S1b′** | Odoo part shrinks to the company setting (MESH §10.4) and `bus` in `_push_item()`; profile/policy/peers move to P2b admin API |
| S5 mTLS transport and bus API | changed | peer table and refresh from the store snapshot, not Odoo/toml |
| S6 pipeline integration | changed (S6′) | scheduler INSERTs jobs; the "outbox publisher calling `mesh_publish_claim`" becomes a node-internal publisher over `job` rows with `bus_scope = open`; no Odoo-path sink |
| S7 multi-node e2e | changed (S7′) | no fake Odoo; jobs enter through the job API |
| S8 spec corrections | extended (S8′) | adds §18.1 |

---

## 14. Security

| # | Threat | Mitigation |
|---|---|---|
| T1 | **SSRF from Odoo** (a user sets `blockchain.node.url` to an internal service and reads responses) | `url`/`key_id` editable by `base.group_system` only; https (http only loopback or dev param); no userinfo/path/query; `allow_redirects=False`; response size cap; error detail truncated, stored as text, never rendered as HTML |
| T2 | **SSRF from the node** (admin points it at internal hosts) | dial targets in toml only (`rpc_urls`, issuers) (R95); mesh peer URL validated `https://host[:port]`; JWKS: issuer allowlist, https, `jwks_uri` on the issuer host unless configured, no redirects, 64 KiB cap, 5 s timeout; unknown `iss` never triggers a fetch |
| T3 | **Machine credential leak** (Odoo DB dump, logs) | secret in `ir.config_parameter` (system only), never in the record; HMAC sends no secret on the wire; scopes + namespace bound; key expiry; rotate = `generation + 1`; revoke hot (≤ 2 s) |
| T4 | **Replay** (HMAC request, admin token) | HMAC: ±300 s + nonce cache per key (`gwauth.rs:84-116`); job POST idempotent anyway (R91); feeds read-only. OIDC: short TTL (`max_token_lifetime_secs`), `aud` bound to the node API, bearer over TLS only, no cookies |
| T5 | **Store file stolen / backup leak** | no secrets in the store (R92 derivation; OIDC needs none); contains payloads (payer, payee, amounts) — file mode 0600, backups encrypted by the operator (doc) |
| T6 | **Compromised Odoo** | bounded to its namespace: granted chains, registered tokens, `allow_call` (R103), quota, rate limits, R55 breaker, R100 normalization; cannot read other namespaces, cannot reach config (R109), cannot cancel others' jobs (404). `call` jobs remain as powerful as today for that namespace (no worse than today). |
| T7 | **Compromised node** | holds lane keys (gas only, MESH T14) and can lie on the feeds: fake `range` events would book payments in Odoo. Same trust as today's indexer key (both keys lived in one node process, `main.rs:103, 117`). Follow-up: a second independent event source with Odoo-side agreement (§18.3). |
| T8 | **Cross-tenant leakage** | job and job_event rows namespace-filtered in SQL; events filtered by grant/token subset/watch; contract tests per route with two namespaces; public chains' events are public anyway; private chains granted explicitly |
| T9 | **Stolen OIDC access token** | ≤ 1 h lifetime, `aud`-bound, per-`sub` rate limit, audit with `sub`; the app keeps tokens in memory; revocation = IdP-side (follow-up: introspection for instant revoke) |
| T10 | **Alg confusion / key confusion** | per-issuer alg allowlist; JWK `kty`/`crv` must match `alg`; RSA ≥ 2048; `none`/`HS*` impossible (no symmetric path exists); `jku/x5u/jwk/x5c/crit` rejected |
| T11 | **Clock skew** | 60 s skew on `exp/nbf/iat`; HMAC 300 s; NTP required (doc) |
| T12 | **CSRF** | bearer header only, no cookies, CORS exact origins without credentials |
| T13 | **Admin misuse** (fee redirection, adding attacker tokens) | role split (R107): `fee_recipient` and tokens = `admin`, keys = `key_custodian`; audit before/after; `bamboo_fee_recipient_changed_total`, `bamboo_admin_mutations_total` alerts; admin bind loopback/VPN by default |
| T14 | **Break-glass abuse** | Unix socket 0600, host-local, actor uid audited, metric; disable with `admin_socket = ""` |
| T15 | **DoS on the job API / feeds** | per-key buckets, ≤ 4 long-polls per key, body/page caps, `MAX_INFLIGHT` before auth, `max_rows`/`STORE_FULL`, quota per namespace |
| T16 | **Client context forging server-only fields in Odoo** | `SERVER_ONLY` create override + `write` strip unless `env.su` for every new field; no context key consulted (project rule) |
| T17 | **Two processes on one store / one key set** | flock + exclusive locking (R88); §9.4 heuristic for keys |

---

## 15. Observability

Node `/metrics` additions (R51 renderer, `admin.rs:72`):

| Metric | Type | Labels |
|---|---|---|
| `bamboo_relay_jobs` | gauge | `chain`, `namespace`, `state` (now from the store) |
| `bamboo_job_api_requests_total` | counter | `route`, `code`, `namespace` |
| `bamboo_job_accept_total` | counter | `chain`, `namespace`, `result` (`created`, `existing`, `<CODE>`) |
| `bamboo_feed_client_cursor` | gauge | `namespace`, `feed` (last cursor a client asked for) |
| `bamboo_feed_last_poll_seconds` | gauge | `namespace`, `feed` |
| `bamboo_feed_head` | gauge | `feed` |
| `bamboo_index_cursor` | gauge | `chain` |
| `bamboo_admin_mutations_total` | counter | `route`, `actor_kind`, `result` |
| `bamboo_admin_break_glass_total` | counter | — |
| `bamboo_oidc_rejections_total` | counter | `issuer`, `reason` (`expired`, `aud`, `iss`, `sig`, `alg`, `role`) — low cardinality, no `sub` |
| `bamboo_oidc_jwks_refresh_total` | counter | `issuer`, `result` |
| `bamboo_fee_recipient_changed_total` | counter | `chain` |
| `bamboo_lane_foreign_nonce_total` | counter | `chain`, `lane` |
| `bamboo_config_toml_drift` | gauge | — |

`/readyz` reasons: store not open; chain final head missing; index lag > `max_index_lag`; a lane used outside the
store; an issuer failed closed (only when OIDC is configured). Logs: no payloads, no tokens, no HMAC headers;
`tracing` fields `uid`, `namespace`, `chain`, `state`, `code`, `sub` (admin only).

Odoo: `blockchain.node` form shows cursors, last sync, last error, `needs_attention`; a list filter "needs
attention"; the existing operator views of jobs show `push_state` and `node_job_uid`.

---

## 16. Test plan

Heavy runs one at a time (owner rule, OOM cap).

### 16.1 Unit (`cargo test`, no network)

- `store.rs`: migration v1→v2 on a temp file; flock refuses a second open; job state machine = `transitions.json`
  (every allowed and refused edge; `LATE_NOOP`); `job_event` written in the same transaction (kill between ⇒ neither);
  `job_live_digest` (second live insert fails; after terminal succeeds); idempotency (same hash, different hash,
  generation rules); purge never deletes an unexpired origin; lease vs cancel race (two threads, one winner).
- `jobs_api.rs`: every accept check and error code; batch partial results; namespace isolation (namespace B gets 404 on
  A's uid, never sees A's events); `wait` wakes on insert and times out; `410` below retention; `store_id` in pages.
- `gwauth.rs`: `HmacKeys` with two keys; revoked/expired/rotated key; nonce scoped per key; the shared KAT vector.
- `oidc.rs`: RS256 (fixture RSA PKCS#8 signed with `ring::RsaKeyPair`), ES256 and EdDSA (keys generated with `ring`);
  wrong `iss`, wrong `aud`, expired, `nbf` future, lifetime too long, `alg = none`, `HS256`, `alg`/`kty` mismatch,
  `jku` header, unknown `kid` ⇒ one refetch then reject, refetch rate limit, JWKS rotation (old key removed ⇒ old
  token rejected, new accepted), stale-JWKS fail-closed after `jwks_max_stale_secs`, role mapping for `role`
  (ABP string and array), `realm_access.roles`, `scope`.
- `admin.rs`: route × role matrix (each route with each role: allowed/403); CORS preflight from allowed and other
  origins; audit row with before/after and `sub`; break-glass socket peer uid recorded; HMAC key on the admin listener
  ⇒ 401.
- `submit.rs`/`adapter.rs`: existing S2 tests rewritten against a temp store instead of `fake_odoo`
  (`adapter.rs` tests `Fake`); `plan()` with `journal_floor`; `lane_hint` routing; §9.4 heuristic.
- `config.rs`: bootstrap import, toml drift, toml-only fields refused by the API, `[odoo]` accepted (transitional) /
  refused (P9).

### 16.2 Contract tests (node ↔ Odoo)

`bamboo-node/tests/api/`: `job_request.json`, `job_result.json`, `jobs_page.json`, `events_page.json` (one `range`
per family from the adapters' existing unit fixtures, plus `balances`), `transitions.json`, `hmac_kat.json`. Rust
tests serialize/deserialize them; copies under `dms_blockchain/tests/data/` are loaded by the Odoo tests; CI `cmp`
step as for the mesh vectors.

### 16.3 Odoo (`dms_blockchain/tests/test_node_client.py`, fake node via the `_client()` seam)

Push: idempotent re-push after rollback; permanent vs transient item errors; prerequisite (RS4-6) not pushed until
`mined`; paused chain pushes nothing; `_trigger` on create. Sync: every node state mapped through `_apply_node_event`
incl. `leased`, `cancelled`, `consumed`, `LATE_NOOP`; overlap re-delivery is a no-op; poison item skipped and cursor
advances; range gap stops and flags `needs_attention`; straddling range drops already-indexed events; `balances`
recorded at the right height; `store_id` change halts. Cancel: `cancelled`, `TOO_LATE`, transport error ⇒
`cancel_requested` then completion. Requeue bumps generation. Server-only fields: `create`/`write` with explicit
values and with `default_push_state` in context, as user and as sudo (only the service path sets them). Transitional
gates: `relay_poll` empty and `relay_claim` refuses for `push`; `action_switch_to_push` preconditions incl. the journal
floor. URL constraint. DEX mirrors (P7). Gate also: `pg_constraint` shows `UNIQUE(company_id, chain_id)` and
`UNIQUE(node_id, node_job_uid)` (CLAUDE.md §5.2).

### 16.4 e2e

- `tests/e2e_push.rs` (`--ignored`, anvil + forge, no Odoo): a Rust fake client pushes jobs through the HMAC API and
  follows both feeds to `mined` and a `range` with `MetaTransactionExecuted`; restart the node between `signed` and
  `broadcast` (journal from the store, no second outer tx at a new nonce); consumption by a second EOA ⇒ `consumed`;
  cancel/lease race; two namespaces isolation; gateway door A durable across restart; transitional run with a fake
  Odoo on the legacy path for one chain and the store path for another, same lane (shared nonce counter, `plan()`
  union).
- `tests/e2e_oidc.rs`: an in-test axum mock issuer (discovery + JWKS + token minting with EdDSA and RS256 fixture)
  ⇒ admin flows per role, key rotation at the issuer mid-run, issuer down ⇒ cached keys ⇒ fail closed after max stale.
- `scripts/e2e_odoo_node.sh` (manual / nightly, heavy): real Odoo test DB + node + anvil: portal payment → outbox →
  push → mined → final → payment request `final`; flip one chain `pull → push` with an in-flight legacy job.

---

## 17. Work breakdown

Ordered streams for **one agent at a time**. "Gate" = the stream's heavy command; run it alone.

**P1 — Store v2 and configuration** (replaces MESH S4)
- Files: `bamboo-node/Cargo.toml` (`rusqlite` bundled), `src/store.rs` (schema §4 incl. mesh tables in R89 shape,
  flock, migrations, CAS helpers, janitor), `src/config.rs` (`[api]`, bootstrap lists, `[odoo]` kept as
  `Option` + `// legacy(R104)`), `src/main.rs` (open store, bootstrap import, snapshot `watch`), `node.example.toml`.
- Gate: `cargo test` (first bundled-SQLite build). Done: reopen keeps `seq`/`store_id`; second process refused;
  bootstrap/drift tests green.

**P2 — Job API and machine keys**
- Files: `src/gwauth.rs` (`HmacKeys`), `src/jobs_api.rs` (§5), `src/job.rs` (`Job` moved from `odoo.rs`), `src/main.rs`
  (listener), `tests/api/*.json`.
- Gate: `cargo test`. Done: §16.1 job API + HMAC tests; contract JSON stable.

**P2b — Admin API, OIDC, break-glass, audit, CORS**
- Files: `src/oidc.rs`, `src/admin.rs` (router split: open health/metrics, OIDC `/v1/admin/*`), `src/admin_api.rs`
  (routes §7.3, validation, audit), `src/main.rs` (Unix socket), `Cargo.toml` (`ring` direct as MESH §3.4,
  `tower-http` `cors`).
- Gate: `cargo test` then `cargo test --test e2e_oidc -- --ignored`. Done: role matrix and JWKS rotation green.

**P3 — Submit and lanes from the store** (the safety-critical stream)
- Files: `src/submit.rs` (`poll_store`, `transition`, `start` from store ∪ legacy, `lane_hint`), `src/adapter.rs`
  (`lane_runner`/`step_once`/`follow`/`recover_lane` on the store), `src/nonce.rs` (floor), `src/gateway.rs` (job
  INSERT in `~gateway`, `GET /v1/intents/{id}`), `src/odoo.rs` (legacy: `journal_floor` import, `node_transport`),
  `src/metatx.rs` (R100 at accept).
- Gate: `cargo test` then `cargo test --test e2e -- --ignored` and `tests/e2e_push.rs` job cases. Done: no test
  reports `dead`/`reverted` for a consumed job; restart tests show no double broadcast; R18 tests unchanged.

**P4 — Indexer and events feed**
- Files: `src/indexer.rs`, `src/adapter.rs` (`index_step`), `src/drift.rs` (balances items), `src/jobs_api.rs`
  (`/v1/events`, `/v1/watch`), legacy ingest gated by `node_transport`.
- Gate: `cargo test` then the family e2e that exercise indexing (`e2e.rs` + one non-EVM, e.g. `e2e_cosmos.rs`, run
  alone). Done: feed ranges contiguous, balances follow their range.

**P5 — Odoo client** (`dms_blockchain`, `dms_blockchain_payment`)
- Files: `models/blockchain_node.py` (new), `models/blockchain_relay_job.py` (fields, push/sync/apply/cancel,
  transitional gates), `models/blockchain_chain.py` (`node_transport`, `event_node_id`, `action_switch_to_push`),
  `models/blockchain_chain_event.py` (`_ingest_range`), `lib/node_client.py`, `data/ir_cron.xml` (two crons, one-line
  bodies), `security/…`, `views/…`, `blockchain_payment/models/blockchain_autopay.py` (`_node_cancel`),
  `tests/test_node_client.py`, `tests/data/*.json`, manifest version.
- Gate: Odoo test run of `dms_blockchain`, `dms_blockchain_payment`. Done: §16.3 green; existing blockchain suites
  green; `pg_constraint` check.

**P6 — e2e push + first cutover rehearsal**
- Files: `tests/e2e_push.rs` (all §16.4 cases incl. transitional), `scripts/e2e_odoo_node.sh`, `bamboo-node/README.md`
  (job API, admin, OIDC, migration runbook).
- Gate: `cargo build --release` then `cargo test --test e2e_push -- --ignored`; then the script (alone).
- Done: green twice; runbook reviewed by the owner. **Owner cutover per chain (testnet first) starts here.**

**P7 — DEX on the store** (R105)
- Files: `src/dex/venue.rs`, `src/dex.rs` (rows), `src/store.rs` (DEX tables), `src/admin_api.rs` (markets),
  `dms_blockchain_dex/models/*` (mirrors, `_dex_ingest_range`), tests.
- Gate: `cargo test` + DEX e2e in `e2e.rs` (alone), then Odoo `dms_blockchain_dex` tests. Done: book survives restart
  without Odoo; failed settle restores locally; Odoo mirrors and books fees.

**S1b′ — Odoo company bus scope** (MESH §10.4 only) + `bus` in `_push_item()`.
- Gate: Odoo tests `dms_blockchain`, `dms_blockchain_payment`.

**S5 — mTLS bus** (MESH, peer table from the store snapshot). **S6′ — mesh pipeline on jobs** (R89). **S7′ — mesh
e2e without fake Odoo.** As MESH §14 with §13.2 changes.

**P9 — Removal** (R104), only after §11.4.
- Node: delete `src/odoo.rs`, `// legacy(R104)` blocks, `OdooCfg`, `fake_odoo` test helpers; `[odoo]` in toml ⇒
  start error. Odoo: §10.7 deletions, post-migration removing service users' keys, pre-migration abort if a chain is
  `pull`.
- Gate: `cargo test` + `e2e_push`; Odoo suites. Done: `grep -r json/2 bamboo-node/src` is empty.

**S8′ — Spec corrections** (text only, §18.1), after owner approval.

Order: **S3 (any time) → P1 → P2 → P2b → P3 → P4 → P5 → P6 → [owner cutover] → P7 → S1b′ → S5 → S6′ → S7′ → P9
→ S8′.** P9 is gated by the calendar criterion of §11.4, not by the mesh; if the proof window ends first, run P9
before S5 so the mesh never wires to legacy code.

---

## 18. Open follow-ups

### 18.1 Doc corrections required by R87–R110 (listed, not made)

| File | Where | Edit |
|---|---|---|
| PD | §13 R6 | mark superseded by R87: "Odoo calls the node job API; the node never calls Odoo". |
| PD | §13 R16, §3.4 l.287 | superseded by R88 (store-backed gateway queue and DEX book). |
| PD | R11 | finality config lives in the node store (R96). |
| PD | R20 | add: RPC URLs and OIDC issuers are toml-only (R95). |
| R3D | R51 | `relay_stats` → store counts; Odoo-only gauges (`attention`, `drift_alerts`) leave node metrics. |
| R3D | R53 | two gates: node chain state + Odoo push gate (R96). |
| R3D | R54 | job API extends it with key ids (R92). |
| R3D | R56 | drift C via `balances` feed items (R94); receiving wallets via `PUT /v1/watch`. |
| MESH | sections of §13.1 | as listed. |
| `blockchain_security.xml` l.35 comment, canon §C14.1 "two service keys" | | replaced by per-namespace key scopes (`submit`/`read`). |
| `bamboo-node/README.md` | operating invariants | job API, admin/OIDC, break-glass, migration runbook (done in P6). |
| `odoo.rs:1` module doc ("đường duy nhất vào Odoo (R6)") | | deleted with the file in P9. |

### 18.2 Interpretations to confirm with the owner

1. `admin` does not imply `key_custodian` (R107). If one person must do both, give the IdP user both roles.
2. Odoo's namespace gets `allow_call = true` at migration (R103).
3. A paused node chain accepts jobs and holds them (R53 reading of "nothing new is submitted").
4. Several companies may share one namespace via `origin.scope` (R90/R91); the default deployment uses one namespace
   per Odoo database.
5. Payment status latency up to ~10 s after the node's state change (R101).

### 18.3 Deferred

- HA: two nodes for one `(company, chain)` with an explicit job-release protocol (R97).
- A second, independent event source and Odoo-side agreement before booking (T7).
- OIDC token introspection / revocation, DPoP or mTLS-bound tokens (R106, T9).
- Admin-API management of RPC URLs with a dial allowlist (R95).
- Audit retention and export.
- Per-key IP allowlists.
- Signed feed pages (useful only with a second verifier; T7).
