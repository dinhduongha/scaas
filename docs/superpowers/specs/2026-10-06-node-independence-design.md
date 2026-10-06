# Node independence — Odoo becomes a client of `scaas-node` (design amendment)

Status: draft rev 3.4, 2026-10-06. Rev 3.4 consolidates every node addition the other component specs assigned to NI
(APP §9.6, OPS rev 1.2, TSS rev 1.2, F current rev, AS rev 1.1, TW2 rev 1.2; spec D assigns none): **NI is the single
normative place for node routes, tables and config**; the source specs keep the reasons. Table and source list: §20.
Earlier: review 1 (§19.1), admin-auth rulings and the rename (§19.2), P1 code corrections and mesh peer URLs (§19.3).
Node P1 is built (`scaas` `main`); the blockchain stack lives in repo `scaas` (`smartcontracts`, `docs`, `app`, node).
**Naming (owner, approved rename):** the node is `scaas-node` (crate, binary, directory `scaas/scaas-node/` — today
still `scaas/scaas-node/` until the rename stream lands; file:line citations refer to the current files); env vars
`SCAAS_*`; metrics `scaas_*` (incl. the R51 ones); HTTP headers `X-Scaas-*` (R54); signer/domain tags
`scaas.*`/`scaas-*`. Odoo addon and repo names
(`dms_blockchain*`, `bamboo-dms`, `bamboo_abp_auth`) are unchanged.
Rulings: **R87–R111** (§2; R111 = Amendment A1, end of file), continuing the round-4 mesh spec (R70–R86); rev 3.4
adds **R320–R321**.
Owner rulings folded in: "invert Odoo ↔ node", "OIDC for the node admin API and the React app", "SQLite/PostgreSQL/
MySQL storage backends, storage only", "node admin auth as simple as possible: built-in users, API keys, optional OIDC;
roles kept", "mesh peer URLs are editable through the admin API, admin role only, audited, with an SSRF guard" (all
2026-10-06).

Amends:

| Short | File | How |
|---|---|---|
| PD | `scaas/docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` | R6, R16 superseded; R11, R20, R51, R53, R54, R56 amended (§2, §18.1) |
| R3D | `scaas/docs/superpowers/specs/2026-10-03-blockchain-round3-design.md` | R51, R53, R55, R56, R58 delivery paths amended (§9, §10) |
| MESH | `scaas/docs/superpowers/specs/2026-10-05-relayer-mesh-design.md` | sections listed in §13.1 superseded; streams in §13.2 changed; envelope id is now `scaas-intent/1.2` (`1.3` adds the UA body, F R316) |
| node | `scaas/scaas-node/` | file:line citations `submit.rs:…` etc. are under `src/` |
| Odoo | `bamboo-dms/dms_blockchain*/` | unchanged location |

Contracts are cited in the new layout (`scaas/smartcontracts/evm/…`,
`scaas/smartcontracts/{move/aptos,move/sui,soroban,cosmos,ton,solana}/…`).

---

## 1. Scope and non-goals

### 1.1 Today (evidence)

The node is an Odoo worker. Every durable fact it relies on lives in Odoo and is read or written over `/json/2` (PD R6):

| Concern | Today | Evidence |
|---|---|---|
| Work source | `relay_poll` + `relay_claim` (CAS `FOR UPDATE SKIP LOCKED`) | `odoo.rs:190-201`; `blockchain_relay_job.py:105-138` |
| Journal before broadcast | `relay_report('signed')` must succeed before `send_raw`; failure ⇒ `retry` queue | `submit.rs:308-316`; `adapter.rs:419-423` |
| Outcomes | `relay_report` through `TRANSITIONS`/`LATE_NOOP` | `odoo.rs:203-206`; `blockchain_relay_job.py:20-26, 206-247` |
| Restart (`plan()`) | `node_config.inflight` + `journal_max_nonce` (SQL `max(outer_nonce)`, `int8`) | `submit.rs:146-190`; `adapter.rs:232-248`; `blockchain_chain.py:189-196`; `blockchain_relay_job.py:34-36, 70`; `nonce.rs:23-33` |
| Chain config | `node_config`: state (R53), finality, tokens, receiving wallets, indexed cursor | `blockchain_chain.py:163-197`; `indexer.rs:106-117`; `adapter.rs:445-458` |
| Gateway token list | `node_config` at start and every 30 s | `main.rs:131-167` |
| Gateway door A | **not journaled** (`job_id: None`) and **no digest** (`MetaRef::of(…, None)`) ⇒ outside G2 | `gateway.rs:139-150`; `submit.rs:309` |
| Bound relayer | `poll_outbox` claims any queued job for any lane; nothing routes a relayer-bound job to its lane (the DEX single-lane `bail!` is the workaround) | `submit.rs:540-568`; `main.rs:181-186` |
| Indexing | `chain_event_ingest` holds the cursor (`indexed_block`) and applies effects | `blockchain_chain_event.py:78-103`; `odoo.rs:218-232` |
| Drift C | `balance_report` at `height == indexed_block` | `drift.rs:30-50`; `blockchain_chain.py:244-254` |
| Readiness / metrics | `relay_stats` | `admin.rs:125-153`; `blockchain_chain.py:223-242` |
| DEX book | `dex_markets`, `dex_book_load`, `dex_book_commit`, `dex_sync`, `dex_cursor`, `dex_fill_ingest` | `dex/venue.rs:3-6, 179-199, 403-421`; `dex_order.py:65-104`; `dex_trade.py:106-155` |
| Config section | `[odoo] url, database, relay_api_key_env, indexer_api_key_env` (required) | `config.rs:11-19, 29-34`; `main.rs:103, 117, 131, 170, 188-191, 221-222` |
| Odoo veto | a job Odoo moved to `dead` cannot be journaled `signed` (transition refused), so the node never sends it | `blockchain_autopay.py:80-99` relies on it |

### 1.2 In scope

1. **Direction inversion** (R87). The node keeps all its state in its own store, exposes a job API and an event feed,
   and never opens a connection to Odoo. `odoo.rs`, the `[odoo]` section and every Odoo-specific path are deleted in
   one step after the push path is proven (R104).
2. **Odoo keeps its transactional outbox** (`blockchain.relay.job` written in the business transaction) and becomes a
   client: a push cron, a sync cron (job changes + chain events), cancel, requeue (R99–R101).
3. **Store** = mesh R71 store, extended, always on, on SQLite/PostgreSQL/MySQL (R111): jobs, job events, chain index
   ranges, configuration, key metadata, audit log, DEX book (R88, R89, R105).
4. **Multi-tenancy without companies**: namespaces and per-namespace machine credentials (R90–R92).
5. **Admin API** for configuration, used by operators and the React+Vite app (`scaas/app/`), authenticated by
   built-in users or optional OIDC, with roles (R106–R110). API keys are for external clients only (R92).
6. **Migration**: per-chain feature flag, transitional binary that runs both paths, one-step removal (R104).
7. Every safety property already built is preserved (§9): R80/S2 consumption checks, the in-flight digest set,
   journal-before-broadcast, `plan()` restart, `consumed` semantics (S1a), no double broadcast, journaled nonces.
   Two gaps of today close: gateway work becomes journaled and digest-guarded (§1.1), bound jobs go to their lane.
8. **Rev 3.4 additions** (§20): gateway capability, CORS, error contract, `/v1/ops`, UA routes and app serving (APP);
   denylist, FinOps, restore and integrity tooling (OPS); sponsorship, receiver-pays, chain contracts (TSS); UA jobs
   and records (F); planned AS7, TW2 T7 and N3 work.

### 1.3 Non-goals

| Out | Why / where it goes |
|---|---|
| Node calling Odoo for anything (webhooks, callbacks) | R87. Latency: cron re-trigger (R101). |
| Two nodes owning jobs of one `(company, chain)`, or HA on a shared database | R97, R111. Failover = restore the store on another host. §18.3. |
| Uploading lane keys, RPC URLs, database URLs, the master key or OIDC issuers through the admin API | R95: secrets and dial targets stay in `node.toml`/keystores (PD R20 spirit). The one exception is `mesh_peer.url` (owner, 2026-10-06; R95, §7.3). |
| Opaque-token introspection (RFC 7662), DPoP, mTLS-bound tokens | R106: JWT access tokens only; follow-up. |
| Admin credentials (sessions, OIDC) on the job API; API keys on admin routes; API keys in client-side apps | R109: external clients keep HMAC API keys server-side; config automation uses OIDC client credentials or the host CLI. |
| The React app itself | Requirements only (§7.7); built in its own plan. |
| Re-importing in-flight Odoo jobs into the store | R104: legacy in-flight jobs drain on the legacy path. |
| Odoo-side copies of node metrics | Prometheus on the node (MESH §12 already). |

---

## 2. Rulings

Format of PD §13: **ruling — why — cost if wrong.**

| # | Ruling | Why | Cost if wrong |
|---|---|---|---|
| **R87** | (owner) **The node is independent of Odoo.** It never connects to Odoo; Odoo is one client among others. Supersedes **PD R6** and the MESH R71 clause "R6 unchanged: … Odoo stays control plane". The node's control plane is its own admin API (§7). | Owner. One product, many ERPs; every node is "standalone" (MESH §3.3 generalised). | Odoo learns state by polling (R101 bounds it). |
| **R88** | **One store, always on**, opened by every node (not only with `[mesh]`); backend per R111. It holds jobs, job events, index ranges, config, key metadata, audit, DEX book and the mesh tables. **One owner process per store**, enforced by a backend-native owner lock **and a fencing epoch** checked in every journal transaction (R111). Supersedes **PD R16** entirely (gateway queue and DEX book in memory). | The journal must be local to keep journal-before-broadcast without an Odoo hop; one writer gives commit-ordered `seq` (MESH R71 argument). | A lost store loses jobs; R110 makes recovery operator-confirmed. |
| **R89** | **One journal, node-computed digests**: every local submission — job API, gateway door A, mesh scheduler, DEX settle — is a `job` row; mesh `intent` rows reference `job_uid` instead of carrying `lane_label/outer_nonce/tx_hash`. `job.digest` is **derived by the node** from the decoded payload with the S3 library (MESH §4.4 per family; Soroban: SHA-256 of the `HashIdPreimage` the payload carries); a client `digest` that differs ⇒ `422 BAD_PAYLOAD`. A unique live-digest index (`(chain_key, digest)` over live states; emulated on MySQL, R111) makes G2 durable across namespaces and restarts. | Two journals mean two `plan()` inputs and two outcome sinks (MESH §8.4, §8.6). A client-supplied digest (today `submit.rs:93-96`) would let one tenant squat another's intent or bypass G2 on a multi-tenant API (review H7). | Mesh intent states `submitting/broadcast/landed` become derived from the job (§13.1). S3 must precede P2. |
| **R90** | **Namespaces**: the node's tenant unit (`[a-z0-9-]{3,40}`; names starting `~` reserved: `~gateway`, `~mesh`, `~dex`, and `~lane` — a booking label only, for gap-fillers of adopted nonces, never a job namespace, OPS §8.1). Granted chains; token subset pushed by the client (R95). No notion of company. Odoo maps companies to a node endpoint + namespace credential (`blockchain.node.route`). | Owner: "the node doesn't know companies". | A namespace shared by several companies sees their combined feed; Odoo routes by origin. |
| **R91** | **Idempotency key** = `(namespace, origin.scope, origin.producer, origin.key, origin.generation)`, plus `payload_hash` = SHA-256 of **RFC 8785 (JCS)** of the parsed `payload`, **computed by the node** (shared KAT). Same key + same hash ⇒ `200` with the job's current snapshot; different hash ⇒ `409 IDEMPOTENCY_MISMATCH` carrying the existing `uid`; lower generation live ⇒ `409 PREVIOUS_GENERATION_LIVE` with its `uid`. `generation` increments on operator requeue. A cancel by origin may create a **tombstone** under the key (R98). Odoo sends `scope = "<database.uuid>:<company_id>"`, matching `UNIQUE(company_id, origin_producer, origin_key)` (`blockchain_relay_job.py:99-101`). | Retries never duplicate (owner). JCS makes the hash independent of key order and whitespace. A mismatch means "the node holds a job under this key", never "dead" (review H8). | A module upgrade that changes `_payload()` values flags `needs_attention` on re-push; nothing is lost. |
| **R92** | **Machine credentials** = R54 `hmac` (signing string `gwauth.rs:5-8`) + header `X-Scaas-Key: <key_id>`. Each key belongs to one namespace, scopes `submit` and/or `read`. Secret = `HMAC-SHA256(master_key, "scaas-api-key/1" ‖ 0x00 ‖ key_id ‖ 0x00 ‖ u32be(generation))`; the store keeps **no secret**. `master_key` is a `SecretSource` in toml. | R54 is implemented and fuzzed; HMAC binds method, path and body and blocks replay (`gwauth.rs:108-116`). Stealing the store yields no credential. | Rotating `master_key` revokes every machine key at once. A restore can resurrect a revoked key (§14 T19). |
| **R93** | **Change feeds**: `GET /v1/jobs?cursor=` (job state changes) and `GET /v1/events?cursor=` (index ranges, balances, DEX items). `seq` from the store's counter row (R111), filtered per namespace; every page carries `store_id`, `incarnation`, `restore_epoch`, `head_seq`; client rule = MESH §5.2 overlap; `wait ≤ 25 s` long-poll for clients that want it (Odoo uses `wait=0`, R101). Cursor older than retention ⇒ `410 CURSOR_EXPIRED`. | Same cursor discipline as the mesh bus; head/incarnation make a rewound store detectable (review H2). | — |
| **R94** | **Event feed items are today's ingest arguments, unchanged**: `kind = range` = `{chain_key, from_block, to_block, to_block_hash, events}` as `chain_event_ingest` receives them (`blockchain_chain_event.py:79`). Drift C = `kind = balances` items written right after their range. | Odoo's decode/apply code is reused; the R56 race fix (`indexer.rs:81-82`) becomes a feed ordering property. | — |
| **R95** | **Config authority = the node store.** `node.toml` bootstraps: entries absent from the store are imported; present ones are not overwritten (drift warning + gauge). Toml-only: lane keys/mnemonic, `rpc_urls`, `[store] url`, `master_key`, OIDC issuers, binds (incl. `metrics_bind`), CORS origin lists, `[app]`, `[log]`, `[api.admin_auth]` modes and session parameters. Hot (≤ 2 s): chain state, tokens (incl. `active`, `features`), fee_recipient, breaker, `max_valid_for_secs`, policy, peers, namespaces, keys, watch lists, namespace token subsets, DEX markets, deny list, sponsor policies, chain contracts. Restart: lane index list, finality, family params, `ua_registry`. **Token subsets per namespace are client state** (`PUT /v1/tokens/{chain}`), intersected with the node registry. **Exception (owner, 2026-10-06): `mesh_peer.url`** (mesh dial targets) **is editable through the admin API**: `admin` role only, audited (R110), behind the SSRF guard of §7.3. | Owner: "toml bootstraps; admin API mutations persist". Secrets and dial targets in toml keep R20 and remove admin-API SSRF; partners change often enough that peer URLs are managed in the app, so the one admin-editable dial target carries its own guard. Client-pushed token subsets keep Odoo's and the node's token lists in agreement (review H9). | Operators edit toml for keys, RPC, DB; the app for the rest. |
| **R96** | **Finality, pause and the index cursor move to the node**: Odoo's `finality_*`, `indexed_block` (as a source) and `state` stop being node inputs. Node chain `state ∈ active|paused|halted` keeps R53. Odoo keeps its `state` as a **push gate**. | PD R11 says finality is the node's decision; today the node reads it from Odoo (`indexer.rs:113`). | Two pause switches; the stricter wins. |
| **R97** | **Durability replaces SKIP LOCKED**: claim = CAS `queued → leased` inside the single owner process (R88). **Two nodes for one company** only on **different chains**: `UNIQUE(company_id, chain_id)` on `blockchain.node.route`, one event source node per chain. Same lane keys in two stores is forbidden and detected heuristically on sequence families (§9.4). | Each accepted job is owned by exactly one store; reassigning needs a release protocol nobody needs yet. | No hot failover for one `(company, chain)` (§18.3). |
| **R98** | **Cancel is a node CAS, by uid or by origin.** `POST /v1/jobs/{uid}/cancel` or `POST /v1/jobs/cancel {origin}` succeeds from `queued`/`leased` only if the job was **never published on the bus**; otherwise `409 TOO_LATE` with `state` and `published`. A published, still-queued job is put on local hold (never leased by us) but reported `TOO_LATE` because peers may land it. Cancel by origin with no job writes a `cancelled` tombstone, so a late push of that key returns `created:false, state:cancelled`. Odoo kills a job locally only if `push_attempted` is false (C1). | The Odoo veto (§1.1) disappears with the Odoo journal; the node CAS gives the same guarantee for our lanes (one SQLite/DB transaction each, one winner). Publication hands the intent to peers (MESH R74). | During a node outage a kill switch waits for the node; the window is ≤ the job's `valid_until` (autopay: `MAX_SIGNING_WINDOW = 300 s`, `blockchain_autopay.py:12`); `lease_hold_after_start_secs` (15 s) lets queued cancels land first after a restart. |
| **R99** | **Bus scope arrives per job** (`bus.scope`, `bus.private_window_secs`), computed by Odoo from `res.company.blockchain_bus_scope` (MESH R73). The node publishes its own eligible jobs (sets `published_at`); `mesh_publish_claim` (MESH §10.5) is not built. Policy and peers are node store tables (admin API); **MESH R79 is superseded**. | Owner: per-job field. The node owns the job, so it owns publication. | Partners and policy are managed in the node app, not in Odoo. |
| **R100** | **R84 normalization applies to every origin**, including job-API jobs (MESH §8.4's Odoo exception dropped). | The job API is multi-tenant; normalization touches only unbound fields, so Odoo-built jobs are unchanged in effect. | — |
| **R101** | **Odoo side**: outbox unchanged; `ir.cron` "push" and "sync", bodies in model methods (CLAUDE.md §5.4). Push: one batch (≤ 50) per transaction, re-triggered after commit of every new job (`ir.cron._trigger()`). Sync: fixed 1-minute interval **plus** `_trigger(now + 10 s)` while pushed jobs are live; feed reads use `wait=0` (no cron thread is held). Server-only fields on every new field of `blockchain.relay.job` **and** `blockchain.node` follow `SERVER_ONLY` (`blockchain_relay_job.py:27-29, 79-86`). | Latency without a node→Odoo call; no context-key switches (project rule); default `max_cron_threads = 2` must not be starved (review M3). | Job states reach Odoo ≤ ~10 s after the node while jobs are live, ≤ 1 min otherwise. |
| **R102** | **Relayer-bound jobs are pinned to their lane**: a meta-tx with `MODE_RESTRICT_RELAYER` (or a family op that binds the relayer) gets `lane_hint`; only that lane leases it; a relayer that is none of the chain's lanes ⇒ `422 RELAYER_NOT_OURS`. | Today any lane claims any job (`submit.rs:540-568`); a bound job claimed by the wrong lane reverts in simulation; the DEX avoids it only by refusing multiple lanes (`main.rs:181-186`). | — |
| **R103** | **`call` jobs are a namespace capability** (`allow_call`, default `false`; `true` for the Odoo namespace created at migration: mandates and subject accounts need it, `blockchain_autopay.py:101-113`, `blockchain_subject_account.py:180-195`). **Precondition** (OPS §11.2): a target qualifies only if it enforces its own replay protection (`MandateWallet` `refUsed[entryRef]`, idempotent account deploy, DEX fills consumed), because a `call` job has no node digest and no subject nonce. `~gateway` `call` jobs: R320. | A `call` job makes our lane call any contract; with several tenants this must be granted. After a restore a re-pushed `call` could otherwise execute twice. | — |
| **R104** | (decision on "flag or hard cut") **Per-chain feature flag, then one-step removal.** `blockchain.chain.node_transport ∈ pull|push` (default `pull`). A transitional node runs both paths in one process (legacy pull for `pull` chains, store for `push` chains; same lane, same nonce counter, one `lane.journal_max`). Legacy in-flight jobs drain on the legacy path. After §11.4, stream **P9** deletes `odoo.rs`, `[odoo]`, the flag and the Odoo service methods in one release. **Hard cut rejected**: the in-flight journal is in Odoo; a hard cut means importing it (a one-off path that can double-sign) or a stop-the-world drain (≥ one `valid_until` window per chain, payers re-sign), with no rollback. | Owner asked to decide and justify. | ~1 stream of transitional code (`// legacy(R104)`), deleted in P9. |
| **R105** | **DEX book moves to the store** (`dex_market`, `dex_order`, `dex_trade`); markets are admin config; settle/cancel/invalidate are `job` rows in `~dex`; Odoo's `blockchain.dex.order/trade` become seq-guarded mirrors fed by `dex_*` items, kept for accounting (`_book_fees`, `dex_trade.py:203`). A DEX chain cuts over with its markets paused. Supersedes RS5-2 and the `dex_sync`/`restored` loop. | The venue is the book's only writer (`dex/venue.rs:1`); persisting it next to its settle jobs makes "matched but no job" impossible locally (the RS5-2 goal). | DEX cutover needs a short market pause. |
| **R106** | (owner, rev 3.1) **Admin authentication = two modes** (`[api.admin_auth] modes`, default `["builtin"]`): (1) **built-in users** in the store (`admin_user`: name + Argon2id PHC hash + roles), login issues a short-lived node-signed session token (§7.2); (2) **OIDC** (optional, below). The token prefix selects the verifier (`scaas_s1.` session, otherwise a JWT when `oidc` is on). **"API key" means only the R92 credentials of external clients** (Odoo and other ERPs/services): namespace-scoped, `submit`/`read` on the job and event API, never admin, and **server-side only** (never in browser/mobile/desktop apps or extensions, §7.1). Config automation: OIDC client credentials or the host CLI (R109). | Owner: "as simple as possible"; a node works with no IdP. | Built-in mode makes the node a password store (Argon2id, lockout, §14 T21). |
| **R106a** | **OIDC mode** validates JWT access tokens (§7.1): discovery with exact `issuer`, JWKS cached by `(iss, kid)` with rotation, `iss` exact, `aud` contains the node audience, `exp` and `iat` required, 60 s skew, lifetime cap; algs RS256/ES256/EdDSA per issuer, JWK `kty/crv/alg` must match; `none`, `HS*`, `jku/x5u/jwk/x5c/crit` rejected; no redirects. Generic IdP (ABP AuthServer `addons/bamboo_abp_auth`, role claim `role`; Keycloak; others). **Several issuers allowed**, selected by exact `iss`; unknown `iss` never causes a fetch. | Owner. Several issuers cover IdP migration and a separate machine IdP at no cost. Verification on `ring` (in `Cargo.lock`, direct dep per MESH §3.4); no JWT crate. | An IdP that only issues opaque tokens cannot be used (follow-up). |
| **R107** | (owner, kept) **Roles**: `viewer` ⊂ `operator` ⊂ `admin`, plus `key_custodian` (not implied by `admin`). **Every admin credential carries roles**: built-in users store them; OIDC maps a configurable claim per issuer (scope-based mapping only for machine tokens: `sub == client_id`/`azp`, or `machine_only`). Creating, rotating and revoking **external-client API keys** (R92) and managing built-in admin users needs `key_custodian` (admin API, app or host CLI); a caller can only grant user roles it holds itself (no escalation: creating an `admin` user needs `admin` + `key_custodian`). Route table §7.3. | Separates look / run / configure / mint credentials; scopes are client permissions, not user roles (review M11). | One person doing everything holds all four roles. |
| **R108** | (owner, rev 3) **Bootstrap and break-glass = the host CLI**, which writes credential rows straight into the store: `scaas-node admin create <name> --role … --config node.toml` (password from stdin), `admin passwd`, `admin disable`, `key create|rotate|revoke` (external-client API key, R92; the secret is printed once). The CLI may run while the node runs: it touches only `admin_user`, `api_key`, `namespace` and `audit_log` (actor `cli:<uid>`), never jobs, so it needs no owner lock or fencing. **The Unix-socket break-glass of rev 2 is removed.** | Host access (to `node.toml` and the store) is already the root of trust; one CLI is simpler than a second listener. | Recovery when every admin is locked out needs shell access to the host. |
| **R109** | **API keys never reach admin routes, nor client-side apps; admin credentials never reach the job API**: HMAC API keys are verified only on the job-API listener; the admin router accepts only built-in session tokens and (when enabled) OIDC tokens. **Config automation (CI, Terraform, scripts) has exactly two paths**: an IdP service account using OIDC client credentials whose token carries `operator`/`admin` (audited by `iss`/`sub`), or the host CLI (R108) on nodes without an IdP — never a built-in user's password and never an API key. **API keys are server-side only**: never embedded in browser, mobile or desktop apps or extensions; client apps sign user actions with `clientkeys` through the gateway and read namespace data through their own backend (§7.1). | Structural separation instead of a grant table. | — |
| **R110** | **Audit and store loss**: every admin mutation appends a hash-chained `audit_log` row (actor `user:<name>`, `oidc:<iss>|<sub>` or `cli:<uid>`, roles, route, target, before/after, result) in the same transaction as the change. Odoo halts sync for a node (`needs_attention`) when `store_id` or `restore_epoch` changes, when `head_seq < cursor`, or when after an `incarnation` change the item at its cursor differs from the one it applied (§5.3). Re-pushing to a recreated or restored store is an operator action (`action_acknowledge_store_change`). | A recreated or rewound store has no record of signed jobs; blind re-push can re-sign intents whose old outer txs are still in a mempool (G1 keeps funds safe, gas is lost). | One manual step after disk loss or restore. |
| **R111** | (owner, Amendment A1) **SQLite, PostgreSQL or MySQL, storage only** — corrected by review H4/H5/H6/M10; normative text at the end of this file. | Owner. | — |
| **R320** | (rev 3.4) **Gateway `call` jobs exist only for UA registration.** `POST /v1/ua/register` (N4, §5.5) is the one gateway route that creates a `call` job in `~gateway`: target = the chain's `chain.ua_registry`, function `register`, calldata built by the node from the checked body. It is a gateway capability, not an `allow_call` grant; R103 is unchanged for namespaces. `job_live_call` (§4) dedupes retries. | APP §9.6.3 ("gateway capability, not a namespace grant") contradicts R103 as written; restricting the target and function keeps R103's reason. | Sponsored registration spam: per-chain quota (F §17 Q8) and TSS sponsor budgets. |
| **R321** | (rev 3.4, planned TW2 T7) **A batch is several jobs journaled together.** `mtxBatch` groups `metatx` jobs of one `(chain_key, token)` whose relayer is bound to the submitting lane (TW2 §7.5). One `leased → signed` transaction journals every item with the same `lane_label`, `outer_nonce`, `tx_hash` and bumps `lane.journal_max` once; each item keeps its own digest (G2), state and `job_event`. A failing batch is re-simulated and resubmitted without the failing item (`dead` with its decoded reason). Measured cost is split evenly over the items (remainder to the lowest `uid`), so `usage_day` sums to the fee paid. **Never batched**: unwrap ops (TW2 §7.6), `receiver_fee` jobs (TSS §B2.5), `call` jobs, sponsored jobs (their cap is per tx, TSS R190). Flush: 50 items or 3 s (SCaaS §5.8). | One journal transaction per outer tx keeps journal-before-broadcast and `plan()` unchanged. | Batched jobs wait ≤ 3 s. |

---

## 3. Architecture after inversion

```
                 OIDC IdP (optional: ABP / Keycloak / …)
                        │ access token (JWT)
 React+Vite app ────────┼─ login / session / JWT ─► admin API (admin_bind, CORS) ┐
   (node-served: same origin, [app] files + CSP on admin_bind, APP §13.2)   │
 host shell ──── scaas-node admin|key|store|lane|index|report … (CLIs)      │
 Prometheus ────────────► /healthz /readyz /metrics (metrics_bind, OPS R230)│  scaas-node
                                                                            │   ├ store (R88/R111)
 Odoo  (outbox = blockchain.relay.job)                                      │   ├ submit / lane_runner
   cron push ── HMAC key ─► POST /v1/jobs, cancel, PUT watch/tokens (bind)  │   ├ indexer → feed
   cron sync ── HMAC key ─► GET /v1/jobs?cursor=  GET /v1/events?cursor=    │   ├ gateway (door A)
 wallets, apps, third parties ─► gateway /v1/gateway /v1/metatx /v1/ops     │   ├ mesh (MESH)
                                  /v1/ua-* /v1/dex/*  (R54, CORS, §5.5)     │   └ dex venue
 mesh peers ── mTLS ───────► /v1/mesh/*  (MESH R72, unchanged)             ┘
```

| Listener | Config | Auth | Routes |
|---|---|---|---|
| gateway | `[modules] gateway_bind` | R54 none/bearer/hmac (single secret, unchanged) | §5.5: `/v1/gateway`, `/v1/metatx`, `/v1/ops`, `/v1/ua-metatx`, `/v1/ua/register`, `/v1/intents/{id}`, `/v1/dex/*` |
| **job API** (new) | `[api] bind` (default `127.0.0.1:8548`; `127.0.0.1:8547` is the gateway default, `127.0.0.1:9108` the admin default) | R92 HMAC per key | `/v1/info`, `/v1/jobs*`, `/v1/events`, `/v1/watch/*`, `/v1/tokens/*`; planned AS7 `/v1/snapshots*` |
| admin | `[modules] admin_bind` (`config.rs:51-52`) | open: `/healthz`, `/readyz`, `/metrics` (R51), `/v1/admin/login`, `/v1/admin/auth-modes`, app files (`[app]`); R106 credentials: other `/v1/admin/*` | §7.3 |
| metrics (opt.) | `[modules] metrics_bind` (default `""` = served on `admin_bind`) | none | only `/metrics`, `/readyz`, `/healthz` (OPS R230) |
| mesh | `[mesh] bind` | mTLS (MESH §5.1) | `/v1/mesh/*` |

Non-loopback `[api] bind` or `admin_bind` requires TLS in front (doc); `Config::validate` refuses `modes = []`, an
`oidc` mode without an issuer, two enabled listeners on one port (same host, or either on the wildcard address),
`[app] enabled` without `dir/index.html`, and more than the OPS R244 caps (16 chains, 8 lanes per chain, 32 namespaces,
64 tokens per chain, 256 watched wrapper legs; admin routes answer `422 LIMIT`). `gwauth.rs:23` `MAX_BODY` (64 KiB)
becomes a per-listener parameter: gateway 64 KiB, job API 1 MiB.

**Toml sections added in rev 3.4** (toml-only, R95, except the bootstrap list, which R95 imports into the store):

| Key | Meaning | Source |
|---|---|---|
| `[modules] gateway_cors_origins = []` | exact origins (no `*`, no reflection); `GET, POST`; header `Content-Type`; no credentials; `max_age = 600` | APP §9.6.1 |
| `[modules] metrics_bind = ""` | separate monitoring listener, above | OPS R230 |
| `[app] enabled = false, dir, config, extra_connect_src = []` | serve the built app on the admin listener only (APP R160); `config` served as `/config.json`, validated at start; a changed file sets `pending_restart` | APP §13.2 |
| `[log] format = "text" \| "json"` | JSON lines in production; fields and redaction OPS §7 | OPS R237 |
| `[[sponsorship.policies]]` | bootstrap rows of `sponsor_policy` (import if absent, R95) | TSS §B1.5 |

---

## 4. Store schema additions

Logical schema below in SQLite dialect; the **normative per-backend DDL** (types, collations, live-digest emulation,
counter row) is in A1 §A1.3 and a DDL-equivalence test keeps them aligned. Migrations: `sqlx::migrate!`, one
directory per backend, `meta.schema_version = '2'`. Every key/hash/address column compares **byte-exact** on every
backend (A1). Nonces are `BIGINT` (i64); adapters refuse values > `i64::MAX` (every family fits: EVM nonce,
Cosmos/Aptos sequence, Stellar `ledger << 32`, TON u32).

```sql
-- tenants and credentials (R90, R92)
CREATE TABLE namespace (
  name          TEXT PRIMARY KEY,                                 -- [a-z0-9-]{3,40} or reserved '~…' (checked in code)
  state         TEXT NOT NULL CHECK (state IN ('active', 'suspended')),
  allow_call    INTEGER NOT NULL DEFAULT 0,                       -- R103
  max_live_jobs INTEGER NOT NULL DEFAULT 10000,
  created_at    INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE namespace_chain (namespace TEXT NOT NULL, chain_key TEXT NOT NULL, PRIMARY KEY (namespace, chain_key));
CREATE TABLE namespace_token (namespace TEXT NOT NULL, chain_key TEXT NOT NULL, token TEXT NOT NULL,
  PRIMARY KEY (namespace, chain_key, token));                     -- client-pushed (R95); empty = none yet ⇒ all
CREATE TABLE api_key (
  key_id      TEXT PRIMARY KEY,                                   -- 'k_' + 16 hex
  namespace   TEXT NOT NULL,
  scopes      TEXT NOT NULL CHECK (scopes IN ('submit', 'read', 'submit read')),
  generation  INTEGER NOT NULL DEFAULT 0,                         -- rotate = +1 (old secret dies)
  state       TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
  label TEXT, expires_at INTEGER, last_used_at INTEGER,           -- last_used_at flushed from memory every 60 s
  created_by  TEXT NOT NULL, created_at INTEGER NOT NULL);        -- no secret column (R92)
CREATE TABLE watch (namespace TEXT NOT NULL, chain_key TEXT NOT NULL, token TEXT NOT NULL, address TEXT NOT NULL,
  PRIMARY KEY (namespace, chain_key, token, address));            -- receiving wallets (drift A/C, R56)

-- configuration (R95); secrets and dial targets are NOT here (exception: mesh_peer.url, R95, §7.3)
CREATE TABLE chain (
  chain_key TEXT PRIMARY KEY, family TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('active', 'paused', 'halted')),
  profile TEXT NOT NULL DEFAULT 'private' CHECK (profile IN ('public', 'private')),   -- MESH R76
  finality_mode TEXT NOT NULL, finality_depth INTEGER NOT NULL, finality_quorum INTEGER NOT NULL,
  fee_recipient TEXT, poll_ms INTEGER NOT NULL, stuck_after_secs INTEGER NOT NULL,
  max_gas_per_tx INTEGER NOT NULL, max_fee_cap_gwei INTEGER NOT NULL, max_index_lag INTEGER NOT NULL,
  breaker TEXT NOT NULL,                                          -- BreakerCfg as JSON text (small metadata)
  dex TEXT, updated_at INTEGER NOT NULL);
CREATE TABLE token (chain_key TEXT NOT NULL, address TEXT NOT NULL, decimals INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (chain_key, address));
CREATE TABLE lane (chain_key TEXT NOT NULL, label TEXT NOT NULL, account_index INTEGER NOT NULL,
  journal_max BIGINT,                                             -- monotonic: max(journal_max, n) in the SAME
  PRIMARY KEY (chain_key, label));                                -- transaction as leased→signed (and legacy signed)

-- jobs (R89, R91)
CREATE TABLE job (
  uid             BIGINT PRIMARY KEY,                             -- from counter row 'job' (A1)
  namespace       TEXT NOT NULL,
  origin_scope    TEXT NOT NULL, origin_producer TEXT NOT NULL, origin_key TEXT NOT NULL,
  generation      INTEGER NOT NULL DEFAULT 0,
  client_ref      TEXT,                                           -- echoed, e.g. 'odoo:<relay.job id>'
  chain_key       TEXT NOT NULL,
  kind            TEXT NOT NULL CHECK (kind IN ('metatx', 'call', 'signed_op', 'tombstone')),
  digest          BLOB,                                           -- node-computed (R89); NULL for call/tombstone
  payload         BLOB,                                           -- NULL only for kind = 'tombstone'
  payload_hash    BLOB,                                           -- JCS SHA-256 (R91); NULL only for tombstone
  -- CHECK ((digest IS NULL) = (kind IN ('call', 'tombstone'))): job_live_digest skips NULL, so a digest-bearing
  -- kind without its digest would bypass durable G2. CHECK ((payload_hash IS NULL) = (kind = 'tombstone')).
  valid_until     BIGINT NOT NULL,
  lane_hint       TEXT,                                           -- R102
  bus_scope       TEXT NOT NULL DEFAULT 'restricted' CHECK (bus_scope IN ('restricted', 'open')),
  private_window_secs INTEGER NOT NULL DEFAULT 120,
  published_at    BIGINT,                                         -- set when offered on the bus (R98, R99)
  hold            INTEGER NOT NULL DEFAULT 0,                     -- 1 = never lease (cancelled after publication)
  state           TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'signed', 'broadcast', 'mined',
                                                 'reverted', 'dead', 'consumed', 'cancelled')),
  lane_label      TEXT, outer_nonce BIGINT, tx_hash TEXT, claim_block BIGINT,
  attempt_count   INTEGER NOT NULL DEFAULT 0, last_error TEXT, last_seq BIGINT,
  created_at      BIGINT NOT NULL, updated_at BIGINT NOT NULL,
  CONSTRAINT job_origin UNIQUE (namespace, origin_scope, origin_producer, origin_key, generation));
CREATE INDEX job_sched   ON job (chain_key, state, uid);
CREATE INDEX job_journal ON job (chain_key, lane_label, outer_nonce);
CREATE UNIQUE INDEX job_live_digest ON job (chain_key, digest)
  WHERE digest IS NOT NULL AND state IN ('queued', 'leased', 'signed', 'broadcast');   -- durable G2 (A1: MySQL emulation)

CREATE TABLE job_event (                                          -- the jobs feed (R93)
  seq BIGINT PRIMARY KEY, job_uid BIGINT NOT NULL, namespace TEXT NOT NULL,
  state TEXT NOT NULL, tx_hash TEXT, outer_nonce BIGINT, signer TEXT, error TEXT, at BIGINT NOT NULL);
CREATE INDEX job_event_ns ON job_event (namespace, seq);

-- index + events feed (R93, R94)
CREATE TABLE chain_index (chain_key TEXT PRIMARY KEY, indexed_block BIGINT NOT NULL, indexed_hash TEXT);
CREATE TABLE feed_item (
  seq BIGINT PRIMARY KEY, chain_key TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('range', 'balances', 'dex_range', 'dex_order', 'dex_trade')),
  namespace TEXT,                                                 -- NULL = chain-wide (filtered at serve time)
  from_block BIGINT, to_block BIGINT, body BLOB NOT NULL, at BIGINT NOT NULL);
CREATE INDEX feed_chain ON feed_item (chain_key, seq);

-- store identity and ownership (R88, R93, R110, R111)
CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);   -- schema_version, store_id, restore_epoch
CREATE TABLE store_owner (id INTEGER PRIMARY KEY CHECK (id = 1), epoch BIGINT NOT NULL,
  incarnation TEXT NOT NULL, owner TEXT NOT NULL, since BIGINT NOT NULL);
CREATE TABLE seq_counter (name TEXT PRIMARY KEY, value BIGINT NOT NULL);   -- 'job', 'job_event', 'feed_item', 'audit'

-- admin credentials (R106, R107); roles = space-separated subset of 'viewer operator admin key_custodian'
CREATE TABLE admin_user (
  name TEXT PRIMARY KEY,                                          -- [a-z0-9._-]{3,64}
  password_hash TEXT NOT NULL,                                    -- Argon2id PHC string ($argon2id$v=19$m=19456,t=2,p=1$…)
  roles TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
  session_epoch INTEGER NOT NULL DEFAULT 0,                       -- +1 on logout-all, password change, disable, role change
  failed_logins INTEGER NOT NULL DEFAULT 0, locked_until BIGINT,
  created_by TEXT NOT NULL, created_at BIGINT NOT NULL, last_login_at BIGINT);

-- admin audit (R110)
CREATE TABLE audit_log (seq BIGINT PRIMARY KEY, at BIGINT NOT NULL,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('user', 'oidc', 'cli', 'bootstrap')),
  iss TEXT, sub TEXT, roles TEXT NOT NULL, method TEXT NOT NULL, route TEXT NOT NULL, target TEXT,
  before TEXT, after TEXT, result INTEGER NOT NULL, request_id TEXT NOT NULL,
  prev_hash BLOB NOT NULL, row_hash BLOB NOT NULL);               -- row_hash = sha256(prev_hash ‖ canonical row)
```

**Rev 3.4 additions** (§20). Each implementing stream (§17) ships one numbered migration per backend directory
(`schema_version` + 1); counter rows `deny_subject`, `sponsor_policy` join `seq_counter`.

```sql
-- chain, token, job columns
ALTER TABLE chain ADD COLUMN max_valid_for_secs INTEGER NOT NULL DEFAULT 3600;  -- §5.2 step 5, /v1/gateway, mesh accept
ALTER TABLE chain ADD COLUMN ua_registry TEXT;  ALTER TABLE chain ADD COLUMN ua_registry_gen INTEGER;  -- F §11.2; NULL = no UA routes
ALTER TABLE token ADD COLUMN kind TEXT NOT NULL DEFAULT 'meta' CHECK (kind IN ('meta', 'zether', 'meta_none',
  'meta_single', 'meta_multi', 'meta_none_reg', 'meta_single_reg', 'meta_multi_reg'));  -- versionOf().kind 0–7 (TW2 §14, AS §9.1)
ALTER TABLE token ADD COLUMN features TEXT NOT NULL DEFAULT '';  -- space-separated: 'receiver_fee' (TSS §B2.5), 'ua' (v3: registry() ≠ 0, F)
ALTER TABLE job ADD COLUMN trace_id TEXT;                -- 32 hex from W3C traceparent, else generated (OPS R236)
ALTER TABLE job ADD COLUMN call_hash BLOB;               -- kind = call: keccak256(target ‖ calldata); set by code on every new call job
ALTER TABLE job ADD COLUMN sponsor_policy_id BIGINT;  ALTER TABLE job ADD COLUMN sponsor_reserved TEXT;
ALTER TABLE job ADD COLUMN sponsor_day TEXT;  -- TSS §B1.2: NULL policy = booked to the namespace; reserved amount, 'd:YYYY-MM-DD'
ALTER TABLE job ADD COLUMN gas_used BIGINT;  ALTER TABLE job ADD COLUMN gas_price TEXT;
ALTER TABLE job ADD COLUMN cost_native TEXT;  -- every job at mined/reverted (OPS R238; per family TSS §B1.2), smallest native unit
CREATE UNIQUE INDEX job_live_call ON job (chain_key, call_hash)
  WHERE call_hash IS NOT NULL AND state IN ('queued', 'leased', 'signed', 'broadcast');   -- ⇒ 409 DUPLICATE_CALL
-- job.kind gains 'ua_metatx' (F §11.2; digest-bearing: digest = uaDigest): CHECK rebuilt by the F5 migration
-- planned AS7: token.reg_cache TEXT (controls, roles, compliance registry; AS §9.1) and the snapshot builder's table

-- subject denylist (OPS R246, §4.5)
CREATE TABLE deny_subject (id BIGINT PRIMARY KEY, chain_key TEXT NOT NULL,      -- a chain key or '*'
  address TEXT NOT NULL, order_ref TEXT NOT NULL, document_hash BLOB NOT NULL,  -- canonical address; SHA-256 of the order
  state TEXT NOT NULL CHECK (state IN ('active', 'lifted')), valid_until BIGINT, -- NULL = until lifted
  created_by TEXT NOT NULL, created_at BIGINT NOT NULL, lifted_by TEXT, lifted_at BIGINT, lift_ref TEXT);
CREATE INDEX deny_subject_addr ON deny_subject (address, chain_key);            -- lifted/expired rows kept 400 d

-- integrity and FinOps (OPS R233, R241, §8.2)
CREATE TABLE breaker_latch (chain_key TEXT NOT NULL, breaker TEXT NOT NULL, opened_at BIGINT NOT NULL,
  reason TEXT NOT NULL, PRIMARY KEY (chain_key, breaker));                      -- re-read at start; cleared only by breaker/reset
CREATE TABLE lane_adopted (chain_key TEXT NOT NULL, lane_label TEXT NOT NULL, nonce BIGINT NOT NULL,
  tx_hash TEXT, adopted_at BIGINT NOT NULL, PRIMARY KEY (chain_key, lane_label, nonce));   -- deleted once latest passes
CREATE TABLE usage_day (day TEXT NOT NULL, chain_key TEXT NOT NULL,            -- 'YYYY-MM-DD' UTC; purged after 400 d
  namespace TEXT NOT NULL, token TEXT NOT NULL,          -- namespace incl. '~gateway' '~mesh' '~dex' '~lane'; token = contract, call target or ''
  sponsor_policy TEXT NOT NULL DEFAULT '',               -- policy name, '' = none
  jobs_mined BIGINT NOT NULL DEFAULT 0, jobs_reverted BIGINT NOT NULL DEFAULT 0, jobs_consumed BIGINT NOT NULL DEFAULT 0,
  jobs_expired BIGINT NOT NULL DEFAULT 0, gas_used BIGINT NOT NULL DEFAULT 0,
  cost_native TEXT NOT NULL DEFAULT '0', fee_earned TEXT NOT NULL DEFAULT '0',   -- decimal, summed in code
  PRIMARY KEY (day, chain_key, namespace, token, sponsor_policy));       -- upserted in the terminal-transition transaction

-- gas sponsorship (TSS §B1.2) and registered non-token contracts (TSS §A.6)
CREATE TABLE sponsor_policy (id BIGINT PRIMARY KEY, name TEXT NOT NULL UNIQUE,  -- [a-z0-9._-]{3,64}
  state TEXT NOT NULL CHECK (state IN ('active', 'paused')), priority INTEGER NOT NULL DEFAULT 100,
  namespace TEXT NOT NULL, chain_key TEXT NOT NULL,      -- namespace, '~gateway', '~mesh' or '*'
  job_kind TEXT NOT NULL CHECK (job_kind IN ('metatx', 'signed_op', 'call', '*')),
  contract TEXT NOT NULL, selector TEXT NOT NULL,        -- canonical or '*'; EVM '0x'+8 hex | '0x' | '*', non-EVM 'pay' | '*'
  receiver TEXT, min_value TEXT NOT NULL DEFAULT '0',    -- uint256 decimal, token base units
  account TEXT NOT NULL,                                 -- opaque booking label, no personal data
  max_cost_per_tx TEXT NOT NULL, budget_per_day TEXT NOT NULL,   -- smallest native unit
  max_tx_per_hour INTEGER NOT NULL, max_tx_per_payer_hour INTEGER NOT NULL,
  on_exhausted TEXT NOT NULL CHECK (on_exhausted IN ('reject', 'unsponsored')),
  valid_from BIGINT, valid_to BIGINT, created_by TEXT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL);
CREATE INDEX sponsor_policy_match ON sponsor_policy (chain_key, state, priority, id);
CREATE TABLE sponsor_usage (policy_id BIGINT NOT NULL,
  bucket TEXT NOT NULL,                                  -- 'd:2026-10-06' | 'h:2026-10-06T14' | 'p:<payer>:2026-10-06T14'
  tx_count BIGINT NOT NULL DEFAULT 0, cost_spent TEXT NOT NULL DEFAULT '0', cost_reserved TEXT NOT NULL DEFAULT '0',
  PRIMARY KEY (policy_id, bucket));                      -- hour/payer buckets pruned after 48 h, day buckets after 400 d
CREATE TABLE chain_contract (chain_key TEXT NOT NULL, address TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('tender', 'sponsorship_pool')), PRIMARY KEY (chain_key, address));
```

Per-backend notes (A1.3 unchanged): new address/name/bucket columns are byte-exact keys (MySQL lengths: addresses,
`contract`, `receiver`, `token` 128; `name`, `sponsor_policy` 64; `bucket` 160; `day` 10; `breaker` 40; `order_ref`,
`lift_ref` 256); `call_hash`, `document_hash` = `BLOB`/`bytea`/`BINARY(32)`; amounts are decimal text, never ordered or
aggregated in SQL; MySQL emulates `job_live_call` as `job_live_digest` (generated `live_call_hash` + `UNIQUE (chain_key,
live_call_hash)`); SQLite's column list `job.chain_key, job.call_hash` maps to `DUPLICATE_CALL` (classifier test).
Upserts of `usage_day`/`sponsor_usage` lock their rows (`INSERT … ON CONFLICT DO NOTHING`, `SELECT … FOR UPDATE`;
SQLite: the single writer); restart recomputes `sponsor_usage.cost_reserved` from live jobs (TSS §B1.3).

`restore_epoch` (in `meta`) is incremented by the CLI `scaas-node store restored --config node.toml`, mandatory after
any restore (runbook); the same audited transaction **sets every chain `paused`** and runs the retention purge
(OPS R240), so nothing is leased before clients reconcile. `incarnation` is a random 16-byte hex written at every open.

Mesh tables (MESH §6) change as R89 says: `intent.source` gains `'job'` and loses `'outbox'`; `odoo_job_id` →
`job_uid`; `lane_label`, `outer_nonce`, `tx_hash` dropped (read from the job). DEX tables: §12.

**Job state machine** (node; one transaction = CAS + `job_event` INSERT + `job.last_seq` + fencing check). It mirrors
Odoo's `TRANSITIONS`/`LATE_NOOP` (`blockchain_relay_job.py:20-26`); both sides read the vector file
`scaas/scaas-node/tests/api/transitions.json` (copied to `dms_blockchain/tests/data/`, CI `cmp`).

| From | To | Who |
|---|---|---|
| — | `queued` | job API accept / gateway / mesh scheduler / DEX venue |
| — | `cancelled` (kind `tombstone`) | cancel by origin with no job (R98) |
| `queued` (`hold = 0`, past `lease_hold_after_start_secs`) | `leased` (`lane_label`, `claim_block`, `attempt_count+1`) | lane scheduler (replaces `relay_claim`) |
| `queued`, `leased` (never published) | `cancelled` | cancel (R98) |
| `queued` (published) | `queued` + `hold = 1` | cancel ⇒ `409 TOO_LATE, published: true` |
| `queued`, `leased` | `dead` | expiry before submit; `bad payload`; at lease `SUBJECT_DENIED` (OPS §4.5), `SPONSOR_TX_CAP`/`SPONSOR_RATE` (TSS §B1.3) |
| `queued`, `leased` | `dead` (never published) or `hold = 1` (published) | deny entry added (OPS §4.5) |
| `leased` | `queued` | transient (simulate/fee/RPC), restart before signing, in flight on another path |
| `leased` | `signed` (`outer_nonce`, `tx_hash`, signer; `lane.journal_max` bumped) | **journal, before send** |
| `leased`, `signed`, `broadcast` | `consumed` | R80 classification |
| `signed`, `broadcast` | `broadcast`, `mined`, `reverted`, `queued`, `dead` | submit/follow, exactly as `TRANSITIONS` |
| `mined` | `reverted` | late receipt, as today |
| `consumed` | (`mined`/`reverted`/`consumed` = no-op, not stored) | `LATE_NOOP` |

`final` is never a node job state. `cancelled` is sent to Odoo as `dead` with `error = 'cancelled'`. Terminal rows are
purged only when `updated_at < now − job_retention_secs` (30 d) **and** `valid_until < now − 86 400`: a purged origin
key can never be re-accepted because its payload is expired. `plan()` never aggregates over job rows (they are
purgeable): it reads `lane.journal_max`.

---

## 5. Job API (machine clients)

All bodies JSON, body cap 1 MiB, no cookies, no redirects, no CORS. Auth R92 on every route. Errors:
`{"error": "<CODE>", "detail": "<text ≤ 300 chars>", …}`.

### 5.1 Authentication

```
X-Scaas-Key: k_3f9a0c1d2e4b5a6c
X-Scaas-Timestamp: 1790000000
X-Scaas-Nonce: 9b2c…                         (1–64 [A-Za-z0-9_-], remembered until ts + 300 s)
X-Scaas-Signature: hex(HMAC-SHA256(secret, ts "." nonce "." METHOD " " path?query "\n" body))
```

`gwauth.rs` gains `Auth::HmacKeys { keys, seen }`: look up `key_id` in the hot key snapshot (active, not expired,
namespace active), derive the secret (R92), verify as `check()` does (`gwauth.rs:74-117`), put
`Caller { namespace, key_id, scopes }` in the request extensions. Nonce cache keyed by `(key_id, nonce)`. Unknown key
and bad signature both answer `401 UNAUTHORIZED`. `MAX_INFLIGHT` (64) still bounds unauthenticated work.

### 5.2 Routes

| Route | Scope | Purpose |
|---|---|---|
| `GET /v1/info` | read | api version, `store_id`, `incarnation`, `restore_epoch`, both `head_seq`s, granted chains with lanes, tokens, fee_recipient, profile, state, lane `journal_max` |
| `POST /v1/jobs` | submit | accept ≤ 50 jobs, per-item results |
| `GET /v1/jobs/{uid}` | read | one job snapshot (own namespace only, else 404) |
| `POST /v1/jobs/{uid}/cancel`, `POST /v1/jobs/cancel` (`{"origin": {…}}`) | submit | R98 |
| `GET /v1/jobs?cursor=&limit=&wait=` | read | jobs change feed |
| `GET /v1/events?cursor=&limit=&wait=` | read | events feed |
| `GET/PUT /v1/watch/{chain_key}` | read / submit | namespace's receiving wallets (full replace) |
| `GET/PUT /v1/tokens/{chain_key}` | read / submit | namespace's token subset (full replace; ∩ node registry incl. `chain_contract` rows, TSS §A.6; unknown ones listed in the response as `missing`) |
| planned AS7: `POST /v1/snapshots {chain, token, block, policy}` → `{id}`; `GET /v1/snapshots/{id}` → `{state, root, total, leaf_count, policy_hash}`; `GET …/{id}/leaves`; `GET …/{id}/proof?account=` | submit / read | deterministic Merkle snapshot of a token at a final block (AS §5.4), namespace-scoped |

`POST /v1/jobs`:

```json
{"jobs": [{
  "origin": {"scope": "6f1c…:1", "producer": "blockchain.payment.request", "key": "0x8d…", "generation": 0},
  "client_ref": "odoo:1234", "chain_key": "evm:9000", "kind": "metatx",
  "payload": {"token": "0x…", "digest": "0x…", "signature": "0x…",
              "metatx": {"from": "0x…", "to": "0x…", "value": "100", "data": "0x", "batch": "7", "nonce": "0",
                         "validUntil": "1790000300", "mode": 1, "relayer": "0x…", "fee": "0",
                         "feeRecipient": "0x0000000000000000000000000000000000000000"}},
  "bus": {"scope": "restricted", "private_window_secs": 120}}]}
```

`payload` is **exactly** today's `_payload()` (`blockchain_relay_job.py:160-187`) without `id`, so `odoo::Job`
(`odoo.rs:90-108`) moves to `job.rs` with `id` = `uid`, and `work_from_job` / every adapter `build(&Job, …)` are
unchanged. `payload.digest` / `op.digest` are optional; when present they must equal the node's digest. Rev 3.4:
`kind = metatx` may carry `receiver_fee: {fee, feeRecipient, validUntil, signature}` (TSS §B2.5); `kind = ua_metatx`
carries `{token, m: WireUAMetaTransaction, auth}` with 32-byte `from`, idempotency on `(chain, token, from, batch,
nonce)` (F §11.2); a W3C `traceparent` header applies to every item of the batch (OPS R236).

Accept checks, in order (no RPC except a cached UA record read, §9.1; simulation stays at lease time):

1. scope `submit`; namespace active; `chain_key` granted ⇒ else `403 CHAIN_NOT_GRANTED`.
2. payload decodes (`work_from_job` for EVM, family op parse otherwise); node computes `digest` (R89) and
   `payload_hash` (JCS, R91); client digest differs ⇒ `422 BAD_PAYLOAD`.
3. token registered + active and in the namespace subset ⇒ `422 UNKNOWN_TOKEN` (MESH R86 for every origin).
4. `kind = call` requires `allow_call` ⇒ `403 CALL_NOT_ALLOWED`.
5. `now < valid_until ≤ now + chain.max_valid_for_secs` ⇒ `422 EXPIRED` / `VALID_TOO_LONG`.
6. relayer bound ⇒ a lane of this chain ⇒ `lane_hint`, else `422 RELAYER_NOT_OURS` (R102).
7. R100 normalization (unbound `feeRecipient`/`relayer`) of the stored work; `payload_hash` is over the client's
   payload, so a retry hashes identically.
   - 7a. Kind rules: `receiver_fee` needs `token.features ∋ receiver_fee` (`422 FEATURE_UNSUPPORTED`), sets
     `valid_until = min(m.validUntil, receiver_fee.validUntil)` and `bus.scope = restricted` (TSS §B2.5);
     `ua_metatx` needs `token.features ∋ ua` and a registered `from` (`422 UA_NOT_REGISTERED`, record cache §9.1);
     `call` computes `call_hash`.
   - 7b. Denylist: any listed party (OPS §4.5: `m.from`, `m.to`, op signer/payee, decoded `call` addresses) ⇒
     `403 SUBJECT_DENIED`, no order detail.
   - 7c. Sponsorship match on job data only (TSS §B1.3); on `~gateway`/`~mesh` a matched metatx/op needs a valid
     local payer signature (`422 BAD_SIGNATURE`).
8. In one transaction: `SELECT … FOR UPDATE` by the idempotency tuple (all generations) — existing same generation:
   same hash ⇒ return it (`created: false`); tombstone ⇒ `created:false, state:cancelled`; different hash ⇒
   `409 IDEMPOTENCY_MISMATCH {uid}`; a higher generation present ⇒ `409 SUPERSEDED {uid}` (a stale push, e.g.
   after its own generation was purged); `valid_until` passed ⇒ `422 EXPIRED` again inside the transaction (a purged
   key is never re-accepted, §4); lower generation non-terminal ⇒ `409 PREVIOUS_GENERATION_LIVE {uid}`; then
   `INSERT`. A unique violation is classified **by constraint** (per backend, A1.3: the constraint or index name, or
   on SQLite the column list): `job_live_digest` ⇒
   `409 DUPLICATE_DIGEST`; `job_live_call` ⇒ `409 DUPLICATE_CALL`; `job_origin` (lost race) ⇒ re-run the SELECT.
   Live count ≥ `max_live_jobs` ⇒ `429 QUOTA`. A matched sponsor policy is admitted in this transaction (bucket
   locks, reservation; `429 SPONSOR_BUDGET {policy}` or unsponsored per `on_exhausted`). Deadlock/serialization
   failure ⇒ retry the transaction (≤ 3).

Response `200` for a well-formed batch; each accepted item carries its **current snapshot** (C1):

```json
{"results": [{"client_ref": "odoo:1234", "uid": 17, "created": false, "state": "signed", "tx_hash": "0x…",
              "outer_nonce": 42, "signer": "0x…", "last_seq": 902},
             {"client_ref": "odoo:1235", "error": "UNKNOWN_TOKEN", "detail": "0x… is not registered on evm:9000"}]}
```

Paused chain: accepted, waits `queued` (R53). Halted: `409 CHAIN_HALTED`.

`GET /v1/jobs?cursor=901&limit=200`:

```json
{"store_id": "32 hex", "incarnation": "32 hex", "restore_epoch": 0, "head_seq": 950, "next": 902,
 "items": [{"seq": 902, "uid": 17, "client_ref": "odoo:1234", "origin": {"scope": "6f1c…:1", "producer": "…", "key": "0x8d…",
            "generation": 0}, "state": "signed", "tx_hash": "0x…", "outer_nonce": 42, "signer": "0x…", "error": null, "at": 1790000000123}]}
```

Each item is a **snapshot** of the job after that transition (state + journal fields), so a client that missed
earlier items can still reach the right state (§10.4). Rev 3.4: every item carries `trace_id`; `mined`/`reverted`
items add `gas_used`, `gas_price`, `cost_native` and `sponsor: {policy, account} | null` (TSS §B1.4, OPS R238).

### 5.3 Cursor semantics (both feeds)

- Rows with `seq > cursor` visible to the namespace, ordered by `seq`, ≤ `limit` (≤ 500) and ≤ 1 MiB; at least one
  item when one is due. `cursor = -1` returns no items and `next = head_seq`.
- `wait` (0–25 s): await a per-store `Notify` fired on feed inserts, re-query once; ≤ 4 waits per key.
- Client rule (MESH §5.2): `cursor = max(0, last − 200)`, apply idempotently, persist `next` with `store_id`,
  `incarnation`, `restore_epoch` and the last applied `(seq, uid, state)`.
- **Continuity checks (R110)**: `store_id` or `restore_epoch` changed ⇒ halt; `head_seq < stored cursor` ⇒ halt;
  `incarnation` changed (a restart) ⇒ read `cursor = last_seq − 1, limit = 1` and compare with the stored
  `(seq, uid, state)`; different or missing (not `410`) ⇒ halt; equal ⇒ accept the new incarnation.
- Retention: `job_event`/`feed_item` older than `feed_retention_secs` (7 d) are deleted; the same purge transaction
  raises `meta('<table>_floor')` to the highest purged `seq` (never lowered); `cursor < floor` ⇒ `410 CURSOR_EXPIRED`
  (an empty table with `head_seq > 0` cannot tell "expired" from "nothing new"). Recovery: jobs — `GET /v1/jobs/{uid}` for each non-terminal pushed job,
  then `cursor = -1`; events — reset to 0 (idempotent by block range, §10.4 straddle rule).

### 5.4 Errors and limits

| HTTP | Code | When |
|---|---|---|
| 400 | `BAD_REQUEST` | malformed JSON, batch > 50, `limit`/`wait` out of range |
| 401 | `UNAUTHORIZED` | missing/unknown key, bad signature, stale timestamp, replayed nonce |
| 403 | `FORBIDDEN`, `CHAIN_NOT_GRANTED`, `CALL_NOT_ALLOWED`, `SUBJECT_DENIED` | scope, grant, R103, OPS §4.5 |
| 404 | `NOT_FOUND` | job of another namespace or unknown |
| 409 | `IDEMPOTENCY_MISMATCH`, `PREVIOUS_GENERATION_LIVE`, `SUPERSEDED` (all with `uid`), `DUPLICATE_DIGEST`, `DUPLICATE_CALL`, `TOO_LATE` (with `state`, `published`), `CHAIN_HALTED` | §5.2 |
| 410 | `CURSOR_EXPIRED` | §5.3 |
| 413 | `TOO_LARGE` | body > 1 MiB |
| 422 | `BAD_PAYLOAD`, `UNKNOWN_CHAIN`, `UNKNOWN_TOKEN`, `EXPIRED`, `VALID_TOO_LONG`, `RELAYER_NOT_OURS`, `FEATURE_UNSUPPORTED`, `UA_NOT_REGISTERED`, `BAD_SIGNATURE` | per item |
| 429 | `RATE_LIMITED`, `QUOTA`, `SPONSOR_BUDGET` | per key: POST 20 rps (burst 40), GET 10 rps; `Retry-After` |
| 503 | `NOT_READY`, `STORE_FULL`, `NOT_OWNER` | store not open; `max_rows`; fencing lost (A1) |

### 5.5 Gateway (door A) routes (APP §9.6: N1, N2, N4)

Every gateway route keeps R54 auth, the 64 KiB cap, `gateway_cors_origins` (§3) and the **stable error contract**
(APP R178): `{"error": "<CODE>", "code": "<CODE>", "detail": "<≤ 300 chars>", "revert_data": "0x…"?}` (`error` keeps
the code for old clients). Codes: `UNKNOWN_CHAIN`, `TOKEN_NOT_SERVED`, `BREAKER_OPEN`, `SUBMIT_BUSY`, `EXPIRED`,
`BAD_SIGNATURE`, `BAD_PAYLOAD`, `RELAYER_NOT_OURS`, `SIMULATION_REVERT` (raw revert data), `RPC_UNAVAILABLE`,
`QUOTA`, `SUBJECT_DENIED`, `SPONSOR_BUDGET`, the UA and managed-market codes below. Unlike the job API, gateway doors
simulate before INSERT (as today); an accepted item is a `~gateway` job (origin key = node digest = `intent_id`,
§9.1, rules 3, 6 and 7a–7c of §5.2 apply) answered `202 {"status": "queued", "intent_id"}`.

| Route | Stream | Body / answer | Accept checks, in order |
|---|---|---|---|
| `GET /v1/gateway` | N1 | `{"api": 1, "chains": [{chain, chain_key, family, routes, tokens, fee_recipient, breaker_open, max_valid_for_secs, dex?: {address, relayer, markets: [{id, min_base_amount}], relayer_fee_policy: {modes, max_ppm}, max_open_per_maker, min_ttl_secs, max_ttl_secs}}]}`; `chain` numeric for EVM/Hedera, `chain_key` always; `routes` ⊆ `metatx, ops, ua-metatx, ua-register, dex` | — |
| `POST /v1/metatx {chain, token, m, signature}` | today; Hedera N2 | as today; on Hedera chains (295–298) `sig_bytes` may be 64 bytes (HIP-632 ED25519), elsewhere 65–2048 | as today |
| `POST /v1/ops {chain, op}` | N2 (after P3) | `op` = the job API `signed_op` payload without `id` | chain served (`UNKNOWN_CHAIN`); `op.family` = the chain's (`BAD_PAYLOAD`); decode + node digest, client digest equal (`BAD_PAYLOAD`); token/asset registered (`TOKEN_NOT_SERVED`); expiry (`EXPIRED`); family signature verify where the node has one (`BAD_SIGNATURE`; L9 `None` goes on to simulation); bound relayer is a lane (`RELAYER_NOT_OURS`); simulation (`SIMULATION_REVERT`); INSERT `signed_op`. Soroban never published on the mesh (R77); TON `attach_nanoton` is the node's |
| `POST /v1/ua-metatx {chain, token, m: WireUAMetaTransaction, auth}` | N4 (after F1/F2, with F5) | `ua_metatx` job | token `features ∋ ua`; `from >> 160 ≠ 0` ⇒ registry record (§9.1 cache, `UA_NOT_REGISTERED`); cheap kinds verified locally (F R317); node computes `uaDigest` |
| `POST /v1/ua/register {chain, kind, keyData, pop, authRef}` | N4 | `call` job to `chain.ua_registry` (R320) | id recomputed, `>> 160 ≠ 0`; not registered (`UA_ALREADY_REGISTERED`, `UA_KEY_IN_USE`); PoP verified for cheap kinds; per-chain registration quota (F §17 Q8) |
| `GET /v1/intents/{id}` | today | the `~gateway` job | — |
| `POST /v1/dex/orders`, `…/cancel`, `…/cancel-all`; `GET /v1/dex/{markets,depth,trades,ticker,orders}` | today (§12.3); N3 non-EVM books planned (after P7/G3) | unchanged | planned AS7 managed markets (AS §8.2): `NOT_ELIGIBLE {reason}`, `UNBOUND_FORBIDDEN`, `FEE_FORBIDDEN`, `PAUSED`, `ATTESTATION_SHORTER`; mesh `route_order` ⇒ `MANAGED_LOCAL` |

N2 depends on P3: before it the gateway's in-memory `mpsc` feeds only the EVM submitter.

---

## 6. Event feed format per family

`kind = range` body (R94), identical to the `chain_event_ingest` arguments:

```json
{"seq": 77, "kind": "range", "chain_key": "sui:localnet", "from_block": 101, "to_block": 140,
 "to_block_hash": "0x…64 hex", "events": [ … ]}
```

Adapters already emit one normalized event object (`adapter.rs:104-107`); the feed changes nothing in it:

| Family | Height = | `tx_hash` | Events | Family-specific keys | Evidence |
|---|---|---|---|---|---|
| EVM | block | `0x`+64 | `PaymentSettled`, `MetaTransactionExecuted`, `Transfer` (watched wallets only, drift A) | `relayer`, `batch`, `nonce`, `fee_recipient` | `indexer.rs:21-59, 69-77` |
| Hedera | block (JSON-RPC relay) | `0x`+64 | as EVM, via `index_runner` | as EVM | `adapters/hedera.rs:14-15` |
| Cosmos | block height | `0x`+64 | `PaymentSettled`, `MetaTransactionExecuted` | bech32 addresses | `adapters/cosmos.rs:278-290` |
| Sui | checkpoint | `0x`+64 | same two | `entry_ref`, `digest` from Move events | `adapters/sui.rs:364-393` |
| Aptos | block | `0x`+64 | same two | | `adapters/aptos.rs:352-380` |
| TON | masterchain seqno | `0x`+64 | same two | raw `0:…` addresses | `adapters/ton.rs:1022-1024, 1263-1272` |
| Solana | slot | `0x`+128 (first signature, `blockchain_chain_event.py:20-27`) | same two (`emit_cpi!`) | base58 (case-sensitive) | `adapters/solana.rs:543-566` |
| Soroban | ledger | `0x`+64 | same two | `G…`/`C…` strkeys (case-sensitive) | `adapters/soroban.rs:191-198` |

Common keys: `event`, `contract`, `block_number`, `block_hash`, `tx_hash`, `log_index`, `from`, `to`, `amount`, `fee`,
`fee_recipient` (families with relayer fees), `entry_ref` (`PaymentSettled`), `digest` (`MetaTransactionExecuted`).
Addresses canonical per family (R61); Odoo validates them in `_decode` (`blockchain_chain_event.py:106-137`).

**Events added in rev 3.4** (same object, same filters): TW2 T7 `Wrapped`, `Unwrapped`, `ReserveAdded`,
`RateChangeProposed`, `RateChanged`, `RateChangeCancelled`, `RateAdminRenounced`, `WrapDisabled`, `GuardianRenounced`,
`MinterRenounced`, `MetaNonceCancelled`, factory `TieredTokenDeployed` (kinds 0–7), `ImplementationRegistered`,
`ImplementationDeprecated` (TW2 §10.2, OPS §4.3); TSS `ReceiverFeePaid` and the tender events of `chain_contract`
rows (TSS §A.6, §B2.5); F5 `UATransfer`, `UAMetaTransactionExecuted`, `UARegistered` (with key data), balances per
32-byte id (F §11.2); planned AS7 `OrderRecorded`, `OrderRevoked`, `AccountFrozen`, `AccountUnfrozen`,
`ForcedTransfer`, `Paused`, `Unpaused`, `ControlsDisabled`, `RoleRenounced`, `Attested`, `AttesterSet`,
`GrantCreated`, `Released`, `Revoked`, `RevocationRenounced`, `MilestoneApproved`, `ExcessSwept`,
`DistributionCreated`, `Claimed`, `Cancelled`, `Swept`, `OfferCreated`, `Exchanged`, `Closed`, `Rescued` (AS §9.1).
Decoders for a new kind ship before the first such token is created (AS R200).

Serve-time filter per namespace (stored item is chain-wide): drop `Transfer` not to one of the namespace's `watch`
pairs; drop events whose `contract` is outside the namespace token subset. **A range item is always served**, even
with empty `events` — continuity of `from_block = indexed + 1` is what Odoo checks.

Index-time: the indexer filters `Transfer` by the union of all watch lists (as today, `indexer.rs:61-77`); a watch
added later is not retroactive (Odoo pushes watch lists right after approval, §10.4). The indexer writes the `range`
item and advances `chain_index` in one transaction; no token registered ⇒ the cursor holds (`adapter.rs:450-453`).

`kind = balances` (drift C, EVM; `drift.rs:30-50`): written hourly right after a range, read at
`height = chain_index.indexed_block`, served filtered to the namespace's watch pairs:

```json
{"seq": 78, "kind": "balances", "chain_key": "evm:9000", "height": 140,
 "balances": [{"token": "0x…", "address": "0x…", "balance": "1000000"}]}
```

`dex_*` kinds: §12.

---

## 7. Admin API and authentication

### 7.1 Credentials and token validation (R106, R106a)

```toml
[api]
bind = "127.0.0.1:8548"                       # job API (R92); never the port of gateway_bind / admin_bind
master_key = { env = "SCAAS_API_MASTER_KEY" } # ≥ 32 bytes; SecretSource like [keys]; also keys session tokens
admin_cors_origins = ["https://app.example.com"]
lease_hold_after_start_secs = 15              # R98

[api.admin_auth]
modes = ["builtin"]                           # builtin and/or oidc; [] refused
session_ttl_secs = 900                        # built-in session token lifetime
session_max_age_secs = 43200                  # refresh allowed until login + this
login_max_failures = 10                       # then locked for login_lock_secs
login_lock_secs = 900

[api.oidc]                                    # only read when "oidc" ∈ modes
clock_skew_secs = 60
max_token_lifetime_secs = 3600
jwks_refresh_secs = 600
jwks_max_stale_secs = 86400

[[api.oidc.issuers]]
issuer = "https://auth.example.com"           # exact; https only (http only for a loopback host, tests)
audience = "scaas-node-admin"                 # the node API resource; must NOT be one of client_ids
client_ids = ["scaas-node-app"]               # optional: `azp`/`client_id` must be listed when present
algs = ["RS256", "ES256", "EdDSA"]
require_typ_at_jwt = false                    # true ⇒ header typ must be "at+jwt" (RFC 9068)
machine_only = false                          # true ⇒ every token of this issuer is a machine token
role_claim = "role"                           # ABP: "role"; Keycloak: "realm_access.roles"; machines: "scope"
roles = { "BlockchainViewer" = "viewer", "BlockchainOperator" = "operator",
          "BlockchainAdmin" = "admin", "BlockchainKeyCustodian" = "key_custodian" }
# jwks_uri = "https://…"                      # optional override; otherwise from discovery
```

`Authorization: Bearer <token>` on `/v1/admin/*` (except `login`) is dispatched by prefix, each verifier only when its
mode is enabled:

| Prefix | Verifier | Caller |
|---|---|---|
| `scaas_s1.` | built-in session (§7.2) | `user:<name>`, roles of the user row |
| three base64url segments | OIDC (below) | `oidc:<iss>|<sub>`, mapped roles |

Anything else ⇒ `401`. API keys (R92) are never looked at here (R109).

**Config automation** (R109, rev 3.2): OIDC client credentials (an IdP service account whose token carries
`operator`/`admin` via `role_claim`, or `scope` on a `machine_only` issuer; audited by `iss`/`sub`) or the host CLI
(R108); never admin API keys or a built-in user's password. **Client API keys are server-side only** (hard rule): never
in a browser, mobile or desktop app or extension; client apps sign user actions with `clientkeys` through the gateway
(§5.5), use built-in/OIDC login for admin screens, and read namespace data through their own backend. The job API sends
no CORS headers (§5), so a browser cannot call it cross-origin even with a leaked key.

**OIDC (R106a).** `Config::validate` refuses `audience ∈ client_ids` (an ID token of the app would otherwise be accepted as an access
token) and `role_claim = "scope"` unless `machine_only = true` or the mapping is marked `scope_for_machines = true`.

Validation of `Authorization: Bearer <jwt>` (`src/oidc.rs`, new; `ring`, `base64`, `serde_json`):

1. Three base64url segments; header ≤ 2 KiB, token ≤ 8 KiB. Header `alg` ∈ the issuer's `algs`; no `jku`, `x5u`,
   `jwk`, `x5c`, `crit`; `typ = at+jwt` when required.
2. Payload decoded **unverified only to read `iss`**; `iss` must equal a configured `issuer` byte for byte, else `401`
   with no network activity.
3. Key from the cache keyed by **`(iss, kid)`** (absent `kid` ⇒ the single key of matching `kty`, else reject). Unknown
   `kid` ⇒ one refetch, at most once per 60 s per issuer. The JWK must fit the alg: `RS256` ⇒ `kty = RSA`, n ≥ 2048
   (`RSA_PKCS1_2048_8192_SHA256`); `ES256` ⇒ `kty = EC, crv = P-256` (`ECDSA_P256_SHA256_FIXED`); `EdDSA` ⇒
   `kty = OKP, crv = Ed25519`. A JWK with `use` ≠ `sig` is ignored; a JWK `alg`, when present, must equal the header
   `alg`.
4. Signature over `header.payload`.
5. Claims: `exp` and `iat` required; `exp > now − skew`; `nbf`, `iat` ≤ `now + skew`; `exp − iat ≤
   max_token_lifetime_secs`; `aud` (string or array) contains `audience`; `azp`/`client_id`, when present and
   `client_ids` set, is listed; `sub` non-empty.
6. Roles = `roles[v]` for each value at `role_claim` (string, array, or space-separated for `scope` — the latter only
   for machine tokens: `machine_only`, or `sub` equals `azp`/`client_id`). Empty ⇒ `403 NO_ROLE`.

Discovery and JWKS clients: `reqwest` with `redirect::Policy::none()`, HTTPS, 5 s timeout, 64 KiB cap. At start and
every `jwks_refresh_secs`, `GET {issuer}/.well-known/openid-configuration`; its `issuer` must equal the configured one;
`jwks_uri` must be `https` with **exactly** the issuer's scheme, host and port unless configured explicitly. Failures
keep the last good set for `jwks_max_stale_secs`, then the issuer fails closed. Removed keys disappear on the next
successful refresh. `# ponytail: hand-rolled JWS verify over ring (3 algs); a JWT crate if a fourth alg or JWE is needed.`

### 7.2 Built-in users and the CLI (R106, R108)

- **Password hashing**: Argon2id (`argon2` crate, RustCrypto — the one new dependency of this section), PHC string,
  parameters m = 19 MiB, t = 2, p = 1 (OWASP minimum), stored per row so they can be raised later; verification is
  run in `spawn_blocking`. Passwords ≥ 12 characters, ≤ 256 bytes.
- **Login**: `POST /v1/admin/login {"name", "password"}` (no auth, rate-limited 5/min per name and 20/min per source
  address). Disabled user, unknown user and wrong password all answer `401` after a full Argon2 verification (a dummy
  hash for unknown names: no timing oracle). `login_max_failures` consecutive failures ⇒ `locked_until = now +
  login_lock_secs`. Success resets the counter and returns `{"token", "expires_at", "roles"}`.
- **Session token**: `scaas_s1.` ‖ base64url(JSON `{sub: name, ep: session_epoch, roles, iat, exp, auth_time}`) ‖ `.` ‖
  base64url(HMAC-SHA256(K, payload)), K = HMAC-SHA256(`master_key`, `"scaas-admin-session/1"`). Valid iff MAC ok,
  `exp > now`, the user is active and `ep == session_epoch` and `roles` equal the row's (one indexed read per request).
  `POST /v1/admin/session/refresh` returns a new token while `now < auth_time + session_max_age_secs`.
  `POST /v1/admin/logout` increments `session_epoch` (logs out every session of that user — simple and sufficient).
- **External-client API keys** (R92) are managed by `key_custodian` users through `/v1/admin/keys` (§7.3), the app,
  or the CLI; the secret is shown once; rotate = `generation + 1`; revoke is hot. They authenticate nothing here.
- **CLI (R108)**, run on the host as the service user, writes the store directly (credential tables + audit only):

```bash
scaas-node admin create alice --role admin --role key_custodian --config node.toml   # password from stdin, twice
scaas-node admin passwd alice --config node.toml
scaas-node admin disable alice --config node.toml
scaas-node key create --namespace odoo-prod --scopes "submit read" --config node.toml  # API key for Odoo (R92)
scaas-node key rotate k_3f9a0c1d2e4b5a6c --config node.toml
scaas-node key revoke k_3f9a0c1d2e4b5a6c --config node.toml
```

  Every CLI action is audited (`actor_kind = 'cli'`, uid) and counted in `scaas_admin_cli_total`.
- **Maintenance CLIs** (rev 3.4; node stopped, owner lock taken, epoch + 1, audited — R108's lock-free rule covers
  only the credential CLIs above); read-only ones take no lock:

```bash
scaas-node store init|restored --config node.toml       # restored: restore_epoch + 1, every chain paused, purge (OPS R240)
scaas-node lane accept-nonce --chain <key> --lane <label> [--confirm <n>] --config node.toml     # OPS R241
scaas-node index reset --chain <key> --to <block> --confirm <block> --config node.toml          # OPS R242 (c)
scaas-node addresses [--chain <key> --labels] --config node.toml                               # read-only
scaas-node report usage --from <day> --to <day> [--prices prices.csv] [--format csv|json]      # read-only, OPS §8.3
scaas-node snapshot verify <file>                       # planned AS7: recompute a root from chain, store not trusted
```

  `accept-nonce` (behaviour OPS R241): max `pending` over every endpoint, refuses unless `pending − 1 >
  lane.journal_max`, lists `[journal_max + 1, pending)` with digest match, needs `--confirm = pending − 1`, then sets
  `lane.journal_max` and writes `lane_adopted`; adopted nonces are tracked like journaled ones.

### 7.3 Routes and authorization (R107)

| Route | Role | Hot / restart |
|---|---|---|
| `GET /v1/admin/info` (version, store_id, incarnation, owner epoch, `pending_restart`, toml drift) | viewer | — |
| `GET /v1/admin/chains[/{key}]` (rpc URLs shown as host only) | viewer | — |
| `PATCH /v1/admin/chains/{key}` — `poll_ms`, `stuck_after_secs`, `max_gas_per_tx`, `max_fee_cap_gwei`, `max_index_lag`, `max_valid_for_secs`, `breaker` (JSON merge patch, RFC 7396: absent keys kept), `profile` | admin | hot |
| `PATCH /v1/admin/chains/{key}` — `finality_*`, `index_from` (only while `chain_index` is empty), `ua_registry`, `ua_registry_gen` | admin | restart |
| `PUT /v1/admin/chains/{key}/state` `{"state": "active\|paused\|halted", "reason"}` (reason audited) | operator | hot |
| `PUT /v1/admin/chains/{key}/fee_recipient` | admin | hot (metric `scaas_fee_recipient_changed_total`) |
| `POST /v1/admin/chains/{key}/breaker/reset` `{"lane": "<label>\|*", "breaker": "<name>\|*"}`; also clears `breaker_latch` | operator | hot |
| `GET/POST/DELETE /v1/admin/chains/{key}/tokens` (`POST` sets `decimals`, `kind`, `features`; `DELETE` also stops indexing, so runbooks pause instead, OPS RB-12) | viewer / admin / admin | hot |
| `PATCH /v1/admin/chains/{key}/tokens/{address}` `{active: bool}` — `false` refuses intake on every door, keeps indexing | admin | hot |
| `GET/POST/DELETE /v1/admin/chains/{key}/contracts` (`chain_contract`, TSS §A.6) | viewer / admin / admin | hot |
| `GET /v1/admin/chains/{key}/watch` (leg backing ratios, last watched events; OP3) | viewer | — |
| `GET /v1/admin/chains/{key}/lanes` (address, balance, breaker, journal_max) | viewer | — |
| `PUT /v1/admin/chains/{key}/lanes` (account indexes) — `409 LANE_BUSY` while a removed lane has `leased/signed/broadcast` rows | admin | restart |
| `GET/POST/PATCH /v1/admin/namespaces[/{name}]` (grants, `allow_call`, quota, state) | viewer / admin | hot |
| `GET /v1/admin/auth-modes` (no auth: `{"builtin": bool, "oidc": [{issuer, client_id, audience}]}`) | — | — |
| `POST /v1/admin/login` (no auth), `POST /v1/admin/session/refresh`, `POST /v1/admin/logout` | — / any role | — |
| `GET /v1/admin/me` (caller, roles, expiry) | any role | — |
| `GET /v1/admin/users` (metadata only) | viewer | — |
| `POST/PATCH/DELETE /v1/admin/users[/{name}]` (create, roles, disable, reset password) — roles granted ⊆ caller's | key_custodian | hot |
| `POST /v1/admin/users/{self}/password` (own password; bumps `session_epoch`) | any role | hot |
| `GET /v1/admin/keys` (external-client API keys, metadata only) | viewer | — |
| `POST /v1/admin/keys`, `POST …/{id}/rotate`, `DELETE …/{id}` | key_custodian | hot |
| `GET/POST/PATCH/DELETE /v1/admin/mesh/peers`; `PUT …/{id}/state` | viewer / admin; operator | hot |
| `GET/POST/PATCH/DELETE /v1/admin/mesh/policy` | viewer / admin | hot |
| `GET/POST/PATCH /v1/admin/dex/markets`, `PUT …/{id}/state` | viewer / admin / operator | hot |
| `GET /v1/admin/jobs?namespace=&state=&chain=` (no payload, no counterparties) | viewer | — |
| `POST /v1/admin/jobs/{uid}/cancel` | operator | — |
| `GET /v1/admin/audit?since=` (with chain head) | viewer | — |
| `GET /v1/admin/deny[?address=]`; `POST /v1/admin/deny {chain_key, address, order_ref, document_sha256, valid_until?}`; `POST …/deny/{id}/lift {lift_ref}` (OPS §4.5) | operator; admin; admin | hot |
| `GET /v1/admin/sponsorship/policies[/{id}]`; `POST`, `PATCH …/{id}`, `DELETE …/{id}` (`409 POLICY_BUSY` while live jobs reference it); `PUT …/{id}/state` | viewer; admin; operator | hot |
| `GET /v1/admin/sponsorship/usage?policy=&since=&bucket=day\|hour` (TSS §B1.5) | viewer | — |
| `GET /v1/admin/usage?from=&to=&chain=&namespace=` (`usage_day` rows, no conversion, OPS §8.3) | viewer | — |

`POST /v1/admin/keys` returns `{"key_id", "secret": "<64 hex>", "namespace", "scopes"}` **once**. Write validation
reuses the rules being superseded: MESH §10.2 (R86 `submit` only on registered contracts, `pool_visibility` vs profile
R76, pin = 64 lowercase hex). Policy `contract` and token addresses are stored in the family's canonical form
(`addresses.canonical`, KAT `tests/api/addresses.json`); policy selectors in lowercase hex. Sponsor policies follow
TSS §B1.5 (`contract = '*'` ⇒ `min_value = '0'`; `call` ⇒ no `receiver`; `~gateway`/`~mesh` need a concrete
`contract` and `min_value > 0` or a `receiver`; a `PATCH` never changes live reservations). Deny rows mirror to the
log with the address as `***` (OPS R237).

**Mesh peer URL (owner ruling 2026-10-06, R95 exception).** `mesh_peer.url` is a dial target that the admin API may
create and change (`POST`/`PATCH /v1/admin/mesh/peers`): **`admin` role only** (never `operator`), every change audited
with before/after (R110), and an **SSRF guard** applied at write and again at every dial (DNS rebinding):
- scheme `https://` or `quic://` only; `host[:port]`, no userinfo, path, query or fragment; no redirects followed;
- the literal address, or every address the host resolves to, is refused when it is loopback (`127.0.0.0/8`, `::1`),
  unspecified, link-local (`169.254.0.0/16`, `fe80::/10`), a cloud metadata endpoint (`169.254.169.254`,
  `fd00:ec2::254`, `100.100.100.200`, and the rest of `169.254.0.0/16`), multicast or broadcast — always, even with
  `allow_private`;
- private ranges (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`) only when the admin explicitly allows them
  **for that peer** (`mesh_peer.allow_private`, default 0, itself an audited admin change).
P2 adds the column and the write-time check on the bootstrap routes; P2b serves the full `mesh/peers` route with the
dial-time check. Toml `[[mesh.peers]]` stays `https://` only until then.

### 7.4 CORS (admin listener only)

`tower-http` (in `Cargo.lock`) direct dep, feature `cors`: exact `admin_cors_origins` (no `*`, no reflection), methods
`GET, POST, PATCH, PUT, DELETE`, headers `Authorization, Content-Type`, `allow_credentials = false`, `max_age = 600`.
Health/metrics are not CORS-enabled. No cookies are ever set or read.

### 7.5 Audit (R110)

Mutation handler: `before = SELECT …`, the change, `after = SELECT …`, `audit_log` INSERT with
`prev_hash` = previous `row_hash`, all in one transaction; a failed write is audited with `result = <status>` in its
own transaction. The chain head is exported as `scaas_audit_head_seq` (OPS §4.2; the hash is logged, not a label) and
logged at every start, so a rewrite needs the logs too. Every row is also mirrored as a `warn` log event
(`event = "audit"`, OPS R237) for the off-host replay after a restore (R240); the chain is verified from the first row at
start and every 24 h (`scaas_audit_chain_ok`, `/readyz` reason `audit chain broken`, OPS R242 (b)). No secrets in before/after (`password_hash`, `secret_sha256` are written as `"***"`).
Logins (success and failure) and CLI actions are audited too. `request_id` echoed as `X-Request-Id`.
`# ponytail: audit kept forever; add a retention knob when it grows.`

### 7.6 Errors

`401 UNAUTHORIZED` (no/invalid token or password, locked user, unknown issuer, bad signature, expired, wrong aud,
stale session epoch — body never says which);
`403 NO_ROLE`/`FORBIDDEN`; `404`; `409 CONFLICT`/`LANE_BUSY`; `422 INVALID`; `429` (10 rps per `sub`);
`503 IDP_UNAVAILABLE`.

### 7.7 React+Vite app (`scaas/app/`) and app serving

The client side is normative in APP (R150–R179, §9); it keeps every rev-3.2 rule: no R92 key in the app (§7.1), user
actions signed with `clientkeys` through the gateway, admin tokens in memory only (APP R162 refines: only the OIDC
redirect state `{issuer, code_verifier, state, nonce, returnRoute}` sits in `sessionStorage`, ≤ 10 min), PKCE `S256`
public client, roles gate the UI only (the node enforces). Node obligations: `GET /v1/admin/auth-modes` (§7.3), admin
CORS for the static mode (§7.4), the gateway routes and error contract (§5.5), and **app serving** (N1, APP §13.2,
R160) on the admin listener only, when `[app] enabled`:

| Path | Serves |
|---|---|
| `GET\|HEAD /`, `/index.html` | `Cache-Control: no-cache` |
| `/assets/{file}` (`[A-Za-z0-9._-]+`) | immutable; `.wasm` = `application/wasm` |
| `GET /config.json` | the `[app] config` file, `no-store` |
| any other non-`/v1/`, non-health path | `404` |

Every app response carries the APP §10.1 headers (CSP with Trusted Types, COOP/CORP, `nosniff`, `no-referrer`,
Permissions-Policy); `connect-src` is computed at start from the served `config.json` and `extra_connect_src`.
`tower-http` `ServeDir` + a header layer; metric `scaas_app_requests_total{path_class}`. Node-served mode is same-origin
(`nodes[].admin = "self"`), so it needs no admin CORS; operators tunnel to `localhost` on a loopback `admin_bind`.

---

## 8. Configuration authority and bootstrap (R95)

Start: load toml → open store (it must exist: a new node runs `scaas-node store init` once, which creates the file
0600 and refuses an existing one; a missing file refuses to start, so an unmounted volume or a typo'd url never becomes a
fresh store with a new `store_id`; migrate, take owner lock on the canonical path, bump fencing epoch, new incarnation)
→ **import** toml entries
absent from the store (`[[chains]]` + tokens + lanes, `[[mesh.peers]]`, `[[mesh.policy]]`, `[[namespaces]]`) →
build runtime. Differing toml values set `scaas_config_toml_drift` and a warning. Until runtime reads the store
(P3/P4) every consumer still reads toml, so the warning says toml is used for now and the store value takes effect when
runtime reads the store. `rpc_urls`, keys, `params`, `coin_type`, `[store] url` always
come from toml.

Runtime snapshot: `tokio::sync::watch::Sender<Arc<ConfigSnapshot>>`, rebuilt after every admin commit (and every 30 s
as a guard). Consumers that refresh from Odoo today read it: gateway tokens (`main.rs:131-167`), EVM/Hedera/TON/Solana
token filters (`adapters/evm.rs:31`, `hedera.rs:14-15`, `ton.rs:940`), indexer tokens and finality
(`indexer.rs:106-117`, `adapter.rs:445-450`), drift pairs (`drift.rs:31-33`), breaker, chain state, mesh peers/policy;
rev 3.4: the deny set, sponsor policies, `chain_contract` rows, token `kind`/`features`/`active` (every door).

---

## 9. Submit and index paths: what changes, what is preserved

### 9.1 Code changes (node)

| Today | After |
|---|---|
| `odoo::Odoo` passed to `Submitter`, `lane_runner`, `index_runner`, `indexer::run`, `drift::step`, `admin::refresh_loop`, `Venue` (`main.rs:103-228`) | `Store` handle + `ConfigSnapshot` receiver. `odoo.rs` kept only for `// legacy(R104)` until P9. |
| `poll_outbox`: `relay_poll` → skip in-flight digest → `relay_claim` (`submit.rs:540-568`) | `poll_store`: queued rows of the chain with `hold = 0` and `lane_hint IS NULL OR = lane`, oldest first, ≤ 10 → skip in-flight digest (N2) → CAS `queued→leased`. |
| `report(…) -> bool` via `relay_report` (`submit.rs:244-261`, `adapter.rs:151-159`) | `store.transition(uid, from, to, fields) -> Ok \| Moved{state, tx_hash} \| Unknown(err)` (review H3). |
| Journal `signed` over HTTP before `send_raw`; `false` ⇒ `retry` queue (`submit.rs:308-316, 386-392`; `adapter.rs:419-423`) | CAS `WHERE uid=? AND (state='leased' OR (state='signed' AND tx_hash=?))` + `lane.journal_max` + fencing check. `Ok` ⇒ send. `Moved{signed, our hash}` ⇒ send (idempotent retry). `Moved{other}` (cancelled, consumed…) ⇒ drop the work, release the G2 guard, **do not** consume the nonce (`self.next` unchanged). `Unknown` ⇒ reconnect, re-read the row, decide as above; unreadable ⇒ keep in `retry` (no send). Same tri-state in non-EVM `step_once`, so a cancel costs no 60 s backoff. |
| `Submitter::start` / `recover_lane` from `node_config.inflight` + `journal_max_nonce` (`submit.rs:146-190`, `adapter.rs:232-248`) | `store.inflight(chain, lane)` = rows `leased/signed/broadcast` with `lane_label = lane`, state mapped `leased → "nonce_leased"` at this boundary (`nonce.rs:28` matches the literal); `journal_max = lane.journal_max`. Transitional: union with legacy `node_config`; **start refuses** (as today, `submit.rs:148-150`) when the legacy journal is unreachable and the chain has ever been `pull`. |
| Gateway: unjournaled `Work`, digest `None`, in-memory `mpsc` (`gateway.rs:139-150`, `main.rs:139-153`) | Gateway INSERTs a job in `~gateway` (origin key = `intent_id`, node-computed digest) and fires the chain's `Notify`; `GET /v1/intents/{id}` reads it. **Safety gain**: door A becomes journaled and G2-guarded. |
| `index_step`/`indexer::step` call `ingest` and read the cursor from Odoo (`adapter.rs:443-458`, `indexer.rs:106-118`) | Cursor from `chain_index`; one transaction writes `feed_item(range)` + advances `chain_index`. Runs for **every** chain in the transitional binary, `pull` ones included. |
| Drift: `node_config.indexed_block` + `balance_report` (`drift.rs:30-50`) | `chain_index` + `feed_item(balances)` inside the indexer loop. |
| `/readyz` via `relay_stats` (`admin.rs:125-153`) | store open + owner + RPC head + lag; `scaas_relay_jobs` from the store; `attention`/`drift_alerts` leave the node. **Per chain** (OPS M2): `200` iff node-scope ready (store open and owned, audit chain ok, ≥ 1 chain ready = `scaas_node_ready`); body `{"ready", "reasons": [...], "chains": {"<key>": {"ready", "reasons"}}}` (= `scaas_chain_ready`). The indexer re-reads the hash at `indexed_block` from ≥ quorum endpoints at start and every 600 s; a mismatch holds that chain (`finality violated at <block>`, OPS R242 (a)). |

**UA record cache** (F §11.1, R317; F5): per chain, `recordOf(from)` is read once from `chain.ua_registry`; records are
immutable, so hits stay in memory with no expiry and misses for 60 s; cheap kinds (webauthn-p256, p256, ed25519,
bip340, schnorr-bn254) are verified with the shared Rust kind library (F0), the rest by simulation. No store table.
**Unwrap jobs** (TW2 §7.6, T7): full outer simulation, re-simulated before signing; a post-simulation revert is
terminal with its decoded reason and counts toward `origin_grief_score` unless recipient-independent; never batched.

### 9.2 Safety properties — where each now lives

| Property | Mechanism after inversion |
|---|---|
| Journal before broadcast (F5/I5) | `leased→signed` committed (SQLite `synchronous = FULL`; PG/MySQL durable commit) before `send_raw`; failed or unknown commit never sends until re-read proves the row is ours. A stale owner cannot journal (fencing, A1) and therefore cannot broadcast. |
| `plan()` restart (R18, `nonce.rs:23-33`) | Inputs from the store; `journal_max` = monotonic `lane.journal_max` (never an aggregate over purgeable rows), bumped in the journal transaction and on every legacy `signed` report in the transitional binary. |
| In-flight digest set (G2, `submit.rs:63-90`) | Unchanged in memory **plus** durable `job_live_digest`; digests are node-computed (R89), so neither can be bypassed or squatted by a client. |
| R80/S2 consumption checks | Unchanged code; sink changes from `relay_report` to `transition`. |
| `consumed` (S1a) | Node table §4 mirrors `TRANSITIONS`/`LATE_NOOP`; shared vector file; Odoo keeps `_cron_expire` superseded rule and `_mark_final`. |
| No double broadcast | G2 + G3 (MESH §8.7); cancel/lease race is a CAS; published jobs are held, not cancelled (R98). |
| Journaled nonces (G4) | `job.outer_nonce` + `lane.journal_max`; `intent` no longer journals (R89). |
| R53 pause, R55 breaker | Block `poll_store` as they block `poll_outbox` (`submit.rs:574-583`); Odoo state blocks push. |
| R84/R100 normalization | Job API accept, gateway, mesh work builders. |
| Denylist (OPS R246) | intake on every door and again at lease (a job requeued from `signed` is re-checked). |
| Restore (OPS R240–R241) | `store restored` pauses every chain; `lane accept-nonce` adopts chain-ahead nonces without lowering `journal_max`. |

### 9.3 Durability vs `SKIP LOCKED` (R97)

`relay_claim` needed `FOR UPDATE SKIP LOCKED` because node processes or lanes competed over one Postgres table
(`blockchain_relay_job.py:121-138`). After inversion one process owns one store (owner lock + fencing epoch, R88/A1);
its lanes compete through the store and the CAS returns 0 rows to the loser. Odoo never claims: it pushes
(idempotent) and applies (ordered, idempotent).

### 9.4 Same lane keys in two stores (forbidden, detected)

Sequence families only (EVM, Hedera, Cosmos, Aptos, Soroban, TON; Sui and Solana have no lane nonce): at lane start,
`nonce_at(latest) > journal_max + 1 + tracked` ⇒ the lane does not lease, `/readyz` reason `lane <label> used outside
this store`, metric `scaas_lane_foreign_nonce_total`. A manual wallet send also trips it — the right default.

---

## 10. Odoo side

### 10.1 New models (`dms_blockchain`)

```python
class BlockchainNode(models.Model):
    _name = 'blockchain.node'
    _description = 'Relay node endpoint (Odoo is its client)'
    _inherit = ['mail.thread']

    name = fields.Char(required=True, tracking=True)
    url = fields.Char(required=True, tracking=True, help='https://host[:port] of the node job API.')
    key_id = fields.Char(required=True, tracking=True)
    namespace = fields.Char(readonly=True)                       # from GET /v1/info
    # Server-only (NODE_SERVER_ONLY, same mechanism as blockchain_relay_job.py:79-86):
    bound_db_uuid = fields.Char(readonly=True, copy=False)       # H10: database.uuid when the secret was set
    bound_base_url = fields.Char(readonly=True, copy=False)      # H10: web.base.url when the secret was set
    store_id = fields.Char(readonly=True, copy=False)
    incarnation = fields.Char(readonly=True, copy=False)
    restore_epoch = fields.Integer(readonly=True, copy=False)
    jobs_cursor = BigInteger(readonly=True, copy=False)
    jobs_last = fields.Char(readonly=True, copy=False)           # 'seq:uid:state' of the last applied item
    events_cursor = BigInteger(readonly=True, copy=False)
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
    watch_hash = fields.Char(readonly=True, copy=False)          # server-only: last pushed watch list
    tokens_hash = fields.Char(readonly=True, copy=False)         # server-only: last pushed token subset
    _company_chain_uniq = models.Constraint('UNIQUE(company_id, chain_id)', 'One node per company and chain (R97).')
```

`BigInteger` moves from `blockchain_relay_job.py:34-36` to `dms_blockchain/lib/fields.py` (shared). Secret:
`ir.config_parameter` key `dms_blockchain.node_secret.<id>` (CLAUDE.md §5.5), written by a `base.group_system` wizard
that also stamps `bound_db_uuid`/`bound_base_url`; the record shows `secret_set` (computed). `url` constraint: `https`,
or `http` only for loopback or with `dms_blockchain.allow_plain_node_url = '1'` (dev); no userinfo/path/query/fragment.
`action_acknowledge_store_change()` (group system, posts before/after in chatter) is the only way to accept a new
`store_id`/`restore_epoch` and clear `needs_attention`; it resets cursors and marks this node's non-terminal pushed jobs
`push_state = 'local'` for re-push (R110). Rev 3.4 (OPS R240): it also posts `POST /v1/jobs/cancel {origin}` for every
job Odoo holds `dead`/cancelled whose node snapshot is live, before re-push. `action_reset_event_cursor(block)` on
`blockchain.chain` (group system, chatter) moves the chain's event cursor to the block given to the node's `index reset
--to` (OPS R242 (c)), before the node restarts; re-delivered events are absorbed by the `(chain_key, tx_hash, log_index)`
dedup (OPS RB-06).

`blockchain.chain` gains `node_transport = Selection([('pull', 'Pulled by node (legacy)'), ('push', 'Pushed to node')],
default='pull', required=True, tracking=True)` (R104, deleted in P9) and `event_node_id = Many2one('blockchain.node')`.

`blockchain.relay.job` gains (server-only; `SERVER_ONLY` becomes a dict field → forced create value, so `push_state`
is `'local'`, not `False`; `write` strips them unless `env.su`):

```python
node_id = fields.Many2one('blockchain.node', readonly=True, index=True, copy=False)
node_job_uid = BigInteger(readonly=True, copy=False, index=True)
push_state = fields.Selection([('local', 'Not accepted'), ('sent', 'Accepted by node'),
                               ('cancel_requested', 'Cancel pending'), ('attention', 'Needs attention')],
                              default='local', readonly=True, required=True, index=True, copy=False)
push_attempted = fields.Boolean(readonly=True, copy=False)   # committed BEFORE the first HTTP call (C1)
push_generation = fields.Integer(readonly=True, copy=False)
node_event_seq = BigInteger(readonly=True, copy=False)
_node_uid_uniq = models.Constraint('UNIQUE(node_id, node_job_uid)', 'One Odoo job per node job.')
```

`blockchain.relay.job.create` raises `UserError` for a `push` chain when the company has no `blockchain.node.route`
for it (review M8), and calls `cron_node_push._trigger()`.

`dms_blockchain/data/neutralize.sql` (Odoo neutralization, as `addons/mail/data/neutralize.sql`): deletes
`ir_config_parameter` keys `dms_blockchain.node_secret.%` and sets every `blockchain_chain.node_transport = 'pull'`.
Push and sync additionally refuse (`needs_attention`) when `database.uuid` or `web.base.url` differs from the node's
`bound_*` values — a copied database without neutralization never talks to the production node (review H10).

### 10.2 Client library

`dms_blockchain/lib/node_client.py`: `requests` (Odoo dependency), `allow_redirects=False`, timeout `(5, 30)`, HMAC
byte-identical to `gwauth.rs` (shared KAT), response cap 4 MiB, error detail truncated to 300 chars, stored as text.
`blockchain.node._client()` is the seam tests replace.

### 10.3 Push (cron `cron_node_push`, `model._cron_node_push()`)

One batch per transaction (review M2):

```python
@api.model
def _cron_node_push(self, batch=50, rounds=4):
    for _ in range(rounds):
        jobs = self._lock_push_batch(batch)        # SELECT … FOR UPDATE SKIP LOCKED, re-checking
        if not jobs:                               # chain_state='queued' AND push_state='local', push chains,
            return                                 # Odoo chain state active, node bound_* match
        jobs.write({'push_attempted': True})
        self.env.cr.commit()                       # C1: the marker is durable BEFORE any HTTP call
        for node, node_jobs in jobs.grouped(lambda j: j._route().node_id).items():
            results = node._client().post_jobs([j._push_item() for j in node_jobs])
            for job, r in zip(node_jobs, results):
                job._apply_push_result(node, r)
        self.env.cr.commit()
```

- The push domain = `_poll_domain(chain) + [('push_state', '=', 'local')]` — reuses `_poll_domain` including the RS4-6
  prerequisite extension (`blockchain_subject_account.py:451-455`).
- `_push_item()`: `origin = {scope: f'{dbuuid}:{company_id}', producer, key: origin_key, generation:
  push_generation}`, `client_ref = f'odoo:{id}'`, `payload = _payload()` minus `id`, `bus = {scope, private_window_secs}`
  (MESH §10.4, built in S1b′).
- `_apply_push_result`: accepted ⇒ `push_state='sent'`, `node_id`, `node_job_uid`, then **apply the returned snapshot**
  through `_apply_node_snapshot` (§10.4) — a re-push after a rollback catches up immediately. Permanent item errors
  (`BAD_PAYLOAD`, `UNKNOWN_TOKEN`, `EXPIRED`, `VALID_TOO_LONG`, `RELAYER_NOT_OURS`, `CALL_NOT_ALLOWED`,
  `CHAIN_NOT_GRANTED`; rev 3.4: `SUBJECT_DENIED`, `FEATURE_UNSUPPORTED`, `UA_NOT_REGISTERED`, `BAD_SIGNATURE`) ⇒
  `dead`/`failed` with `last_error` and `_fail_dependents()` (the node holds no job for them).
  `IDEMPOTENCY_MISMATCH` / `PREVIOUS_GENERATION_LIVE` ⇒ `push_state='attention'`, `node_job_uid` from the 409 body,
  `needs_attention` on the node, then `GET /v1/jobs/{uid}` and apply that snapshot; **never `dead`** (review H8).
  `DUPLICATE_DIGEST`, `DUPLICATE_CALL` ⇒ stay `local`, `last_error`. Transport/`429` (incl. `SPONSOR_BUDGET`)/`503` ⇒
  stays `local`.
- HTTP after commit of the marker holds no row lock across the call except the batch's own rows, whose other writers
  (`_node_cancel`, `_fail_dependents`) lock with `FOR UPDATE` and wait ≤ one batch timeout.

### 10.4 Sync (cron `cron_node_sync`, every 1 min, `model._cron_node_sync()`)

Per `blockchain.node` with a secret and matching `bound_*`, each page in its own transaction, `wait=0`:

0. Retry `cancel_requested` jobs **first** (§10.5).
1. `GET /v1/jobs?cursor=max(0, jobs_cursor−200)`. Continuity checks of §5.3 (store_id, restore_epoch, head,
   incarnation) ⇒ halt this node on failure. Each item in a savepoint: `_apply_node_event(node, item)`; a `UserError`
   rolls back the savepoint, writes `last_error = 'node event rejected: …'` on the job (sudo), logs, continues.
   Then `jobs_cursor = next`, `jobs_last`.
2. `GET /v1/events?cursor=…` for chains whose `event_node_id` is this node: `range` ⇒ `_ingest_range`, `balances` ⇒
   `blockchain.balance.snapshot._record` when `height == chain.indexed_block` (else skip as stale), `dex_*` ⇒ §12.
   A range **gap** (`from_block > indexed + 1`) rolls back the page, sets `needs_attention`, stops event sync.
3. Watch and token sync per route, when their hash changed: `PUT /v1/watch/{chain}` with `_receiving_addresses()`
   (`blockchain_chain.py:215-219`); `PUT /v1/tokens/{chain}` with Odoo's active tokens; a non-empty `missing` in the
   response ⇒ `needs_attention` ("token active in Odoo but not registered on the node"). Approval of a receiving wallet
   and token activation call `cron_node_sync._trigger()` (review L9).
4. If any pushed job of this node is non-terminal, `_trigger(now + 10 s)`.

`_apply_node_event(node, item)`:

```python
job = Job.search([('node_id', '=', node.id), ('node_job_uid', '=', item['uid'])], limit=1)
if not job:                                                    # C1: adopt by origin
    job = Job._by_origin(item['origin'])                       # (company from scope, producer, key) + generation
    if not job or job.push_generation != item['origin']['generation']:
        return                                                 # not ours (other client of the namespace)
    job.write({'node_id': node.id, 'node_job_uid': item['uid'], 'push_state': 'sent'})
if item['seq'] <= job.node_event_seq:
    return                                                     # idempotent under overlap
job._apply_node_snapshot(item)
job.node_event_seq = item['seq']
```

`_apply_node_snapshot(snap)`: maps `leased → nonce_leased`, `cancelled → dead` (error `cancelled`); if Odoo's state is
in `FEED_LATE_NOOP` for the target (`{'final': ALL, 'consumed': {'mined', 'reverted', 'consumed'}, 'dead': {...}}` —
`final` absorbs every late node state, review M5) it is a no-op; otherwise it walks the **ladder**
`queued → nonce_leased → signed → broadcast → mined` up to the target (or to `signed` before `reverted`, or directly
for `consumed`/`dead`), applying each step through `_apply_report(state, …, table=FEED_TRANSITIONS)` with the
snapshot's journal fields. `FEED_TRANSITIONS = TRANSITIONS | {'queued': {'nonce_leased', 'dead', 'consumed',
'signed'}}`; the `queued → nonce_leased` step writes `claimed_by/claimed_datetime/attempt_count` as `relay_claim` did
(`blockchain_relay_job.py:135-137`). `_apply_report` gains the `table=TRANSITIONS` keyword (the RS4-6 override,
`blockchain_subject_account.py:457-460`, passes it through), so `dead` side effects (metatx/op `failed`,
`blockchain_relay_job.py:226-231`), `consumed`, `mined` of `call` jobs and `_fail_dependents` stay in one place.

`_ingest_range(chain, …)` = the body of `chain_event_ingest` (`blockchain_chain_event.py:84-103`) without
`check_service`, with two changes: (a) overlap/transition straddle — when `from_block ≤ indexed < to_block`, events
with `block_number ≤ indexed` are dropped and `from_block := indexed + 1`; `to_block ≤ indexed` stays a no-op;
`from_block > indexed + 1` raises (gap); (b) an event from a contract that is not an Odoo token is **dropped** with a
counter on the node record and a log line, not raised (review H9; `_decode` raises today, `:110-112`).

### 10.5 Cancel, requeue, expiry

- `blockchain.relay.job._node_cancel()` (used by `_cancel_unsent`, `blockchain_autopay.py:80-99`), after `SELECT … FOR
  UPDATE` on the job: `push_attempted` false ⇒ today's local `dead` (the push cron cannot be mid-flight on it: it sets
  the marker under the same row lock and commits before HTTP). Otherwise `POST /v1/jobs/cancel {origin}`:
  `cancelled` ⇒ local `dead` + existing side effects; `TOO_LATE` (signed, or `published`) ⇒ treated as "already sent"
  (chatter), request stays open until `final` or expiry; transport error ⇒ `push_state = 'cancel_requested'`, request
  and transaction **not** expired yet; sync step 0 retries.
- `action_requeue` (`blockchain_relay_job.py:249-261`): unchanged checks; plus `push_generation += 1`, `push_state =
  'local'`, `push_attempted = False`, `node_job_uid = False`, `node_event_seq = 0` (sudo) — R91.
- `_cron_expire` (`:275-291`): the first search adds `('push_attempted', '=', False)`; a pushed job's expiry is the
  node's. The `consumed` → superseded branch is unchanged.

### 10.6 Transitional gates (deleted in P9)

- `relay_poll`: `if chain.node_transport == 'push': return []` next to the R53 gate (l.110-111).
- `relay_claim`: SQL adds `AND push_attempted IS NOT TRUE` (l.130-132).
- `node_config` returns `'node_transport'`; the transitional node stops legacy ingest for `push` chains.
- `chain_event_ingest`: refuses `push` chains; uses `_ingest_range` otherwise.
- `action_switch_to_push()` on `blockchain.chain` (group manager): preconditions §11.2.

### 10.7 Deleted in P9

Public methods `relay_poll`, `relay_claim`, `relay_report`, `node_config` (+ `_node_config`, `_inflight`, the
`journal_max_nonce` SQL), `chain_event_ingest`, `relay_stats`, `balance_report`; DEX `dex_markets`, `dex_book_load`,
`dex_book_commit`, `dex_sync`, `dex_cursor`, `dex_fill_ingest`; groups `group_blockchain_relay_worker` and
`group_blockchain_indexer` and their service users' API keys (post-migration archives the users); `check_service` role
map (`blockchain_chain.py:13-25`); `node_transport`; `dms_blockchain_dex/models/relay_job.py:10-16`.
`blockchain.chain.finality_*` become informational and leave the form.

### 10.8 ACL and record rules

```
access_node_viewer,node viewer,model_blockchain_node,group_blockchain_viewer,1,0,0,0
access_node_system,node system,model_blockchain_node,base.group_system,1,1,1,1
access_node_route_viewer,node route viewer,model_blockchain_node_route,group_blockchain_viewer,1,0,0,0
access_node_route_manager,node route manager,model_blockchain_node_route,group_blockchain_manager,1,1,1,1
```

Only system users create/edit `blockchain.node` (dial target, key, SSRF §14 T1); managers read nodes and manage routes.
Rule `rule_node_route_company`: `[('company_id', 'in', company_ids)]`. `rule_relay_job_company`
(`blockchain_security.xml:61`) covers the new job fields.

---

## 11. Migration

### 11.1 Version matrix

| Node | Odoo | Chain flag | Works? |
|---|---|---|---|
| old (pull only) | old | — | today |
| old | new (P5) | `pull` | yes: pull path unchanged |
| old | new | `push` | refused: `action_switch_to_push` requires `GET /v1/info` `api ≥ 1` |
| transitional (P1–P4, `[odoo]` present) | old | — | yes: legacy path; job API idle; store indexer runs |
| transitional | new | `pull` | yes |
| transitional | new | `push` | yes: store path for new jobs; legacy path drains in-flight Odoo jobs |
| final (P9) | new, all chains `push` | `push` | target |
| final | any chain `pull` | — | refused by P9's Odoo pre-migration; the final node refuses `[odoo]` ("removed by R104") |

### 11.2 Per-chain cutover (`action_switch_to_push`)

Preconditions:

1. Every company with a non-terminal job **or an approved receiving/paying wallet** on the chain has a route;
   `event_node_id` set; secrets set; `bound_*` match.
2. `GET /v1/info`: `api ≥ 1`, chain granted, `state = active`; Odoo's active tokens ⊆ the node's tokens for the chain.
3. **Journal continuity**: for each lane the node reports, `journal_max ≥` Odoo's `max(outer_nonce)` for that signer.
   The transitional node bumps `lane.journal_max` on every successful legacy `signed` report (and imports it from each
   legacy `node_config`), so this holds exactly, not "as of the last read".
4. DEX chain: every market paused, no `pending` trade (§12.4).

Effects: `node_transport = 'push'`. `relay_poll` serves nothing for the chain; queued jobs are pushed; legacy in-flight
jobs keep reporting through `relay_report` until terminal; a legacy job the old path requeues is pushed like any other.
The store indexer has been running for the chain since the transitional binary started (cursor bootstrapped from the
legacy `node_config.indexed_block`); the straddle rule (§10.4) absorbs any misalignment.

Rollback for a chain: `node_transport = 'pull'`. New jobs go back to the pull path; pushed jobs stay with the node and
keep syncing.

### 11.3 Bootstrap of the Odoo namespace (once)

On the host: `scaas-node admin create <name> --role admin --role key_custodian` once; then (CLI or the admin API)
namespace `odoo-<db>` with `allow_call = true`, grant its chains, `scaas-node key create --namespace odoo-<db>
--scopes "submit read"`; a system user enters `key_id` + secret in Odoo.

### 11.4 Proof criterion and one-step removal (P9)

All chains `push` ≥ 14 days; zero Odoo jobs with `push_attempted = False` in `nonce_leased/signed/broadcast`; no
`needs_attention` in that window; §16.4 green on the release candidate. Then one node release and one Odoo upgrade
delete everything marked legacy (§9.1, §10.7). The Odoo pre-migration aborts when any chain is still `pull`.

---

## 12. DEX (R105)

### 12.1 Node

```sql
CREATE TABLE dex_market (id INTEGER PRIMARY KEY, chain_key TEXT NOT NULL, namespace TEXT NOT NULL,
  base TEXT NOT NULL, quote TEXT NOT NULL, fee_ppm INTEGER NOT NULL, fee_recipient TEXT,
  state TEXT NOT NULL CHECK (state IN ('active', 'paused')), body TEXT NOT NULL);   -- MarketCfg (dex.rs:187)
CREATE TABLE dex_order (order_hash BLOB PRIMARY KEY, market_id INTEGER NOT NULL, seq BIGINT NOT NULL,
  state TEXT NOT NULL, remaining TEXT NOT NULL, row TEXT NOT NULL);              -- Row (dex.rs:229)
CREATE TABLE dex_trade (tag BLOB PRIMARY KEY, market_id INTEGER NOT NULL, maker BLOB NOT NULL, taker BLOB NOT NULL,
  maker_fill TEXT NOT NULL, taker_fill TEXT NOT NULL, job_uid BIGINT,
  state TEXT NOT NULL CHECK (state IN ('pending', 'settled', 'failed')), restored INTEGER NOT NULL DEFAULT 0);
CREATE TABLE dex_cursor (chain_key TEXT PRIMARY KEY, indexed_block BIGINT NOT NULL);           -- RS5-8 stays separate
```

(`remaining`/fills are uint256 decimal text; they are never aggregated or ordered by the store.)

- `Venue::start` loads markets from the snapshot and the book from `dex_order` (replaces `dex_markets` +
  `dex_book_load`, `dex/venue.rs:179-199`); the on-chain market cross-check stays.
- A book change = one transaction (orders upsert + trades + settle `job` INSERT in `~dex` with origin key
  `keccak(calldata)` as `dex_order.py:151-152` + `feed_item(dex_order/dex_trade)` in the market's namespace) —
  replaces `dex_book_commit` (`dex/venue.rs:403-421`); the reload-on-timeout path (review D20) disappears.
- Settle job ends `dead`/`reverted` ⇒ the venue marks the trades `failed` and restores fills in the same transaction
  (replaces `dex_sync` + `restored` + the Odoo write hook). The DEX watcher writes `dex_range` items (today's
  `dex_fill_ingest` arguments) and advances `dex_cursor`.

### 12.2 Odoo (`dms_blockchain_dex`)

`blockchain.dex.order`/`trade` become mirrors with a server-only `node_seq` (BigInteger): `_apply_dex_order(item)` /
`_apply_dex_trade(item)` skip `item.seq <= node_seq`; a re-delivered terminal state is a no-op; otherwise upsert by
`order_hash`/`trade_ref` with the decode code of `_upsert` / `_create_from_node` (`dex_order.py:106-141`,
`dex_trade.py:58-76`); a `UserError` on one item follows the §10.4 poison rule. `_dex_ingest_range` = `dex_fill_ingest`
body with the straddle rule; `_book_fees` unchanged (idempotent via `move_ids`, `dex_trade.py:207`).
`blockchain.dex.market` keeps the accounting fields and gains `node_market_id` (server-only). The Odoo order expiry
cron (`dex_order.py:144-149`) is removed.

### 12.3 Gateway

`/v1/dex/*` routes unchanged (`gateway.rs:179-188`).

### 12.4 Cutover

Pause every market of the chain, wait for `pending` trades to settle or fail on the legacy path, flip the chain
(§11.2), the transitional node imports open orders once via legacy `dex_book_load`, resume markets in the node.

---

## 13. Interplay with the mesh spec

### 13.1 MESH sections superseded or amended

- **Superseded:** §1.1 item 3 (R99); §2 R71 "R6 unchanged … Odoo stays control plane", "(the DEX book stays as is)",
  "When `[mesh]` is on", `rusqlite` (R87, R88, R105, R111 `sqlx`); **R79 entirely** (R95, R99); R83 "one fake Odoo"
  (fake job-API client, §16.4); §3.1 shapes table (every shape is Odoo-free); §3.2 "`[odoo]` becomes optional",
  "standalone only" (toml bootstraps every node, R95); **§3.3 Standalone mode entirely** (one mode); §3.4 `rusqlite`
  (R111); §5.3 `NOT_READY` "`[odoo]` present and `mesh_config` never fetched" (store not open / not owner);
  **§10.1, §10.2, §10.5, §10.6** (node `chain.profile`, policy/peers in the node store, node-internal publication);
  §15.4 row "Node → Odoo channel … R6" (R87).
- **Amended:** §1.1 item 7 (setting in Odoo, delivered per job, R99; publication by the node); R73 last sentence (the
  node publishes `bus_scope = open` jobs still `queued` after `private_window_secs`, sets `published_at`); R74
  "through the Odoo outbox" → "through its job store"; R86 (node `token` table, admin API validation); §6
  `intent.source 'outbox'`, `odoo_job_id`, journal columns, Odoo-path sink rows, `AUTOINCREMENT` (R89, A1 counter
  row); §8.1 `outbox` row and DUPLICATE flip (`source = 'job'`, `job_uid`); §8.3 "try_send Work" (INSERT job in
  `~mesh`, R89); §8.4 `Origin::Odoo`, "Odoo path avoids churn", sink `relay_report`, R84 Odoo exception
  (`Origin::Job(uid)`, skip-before-lease in `poll_store`, tri-state `transition`, R100); §8.6 `journal_max = max(…)`
  (`lane.journal_max`, §9.2); §8.7 G2 via `relay_claim` (store CAS + `job_live_digest` + node digest); §12 `/readyz`
  `mesh_config` reason and `relay_stats` counts (store counts); §13.3 fake Odoo, §13.4 mesh-model Odoo tests (fake
  client; Odoo keeps S1a tests + §16.3).
- **Kept:** §10.3 (S1a, done); §10.4 company setting (S1b′, delivered per job, R99).

### 13.2 Mesh streams

| Stream | State | Change |
|---|---|---|
| S0, S1a, S2 | merged | their `relay_report` calls move to `transition` in P3 |
| S3 envelope/digest/hubsig/vectors | unchanged scope; **moved before P2** | P2 needs its per-family digest for accept (R89); add Soroban preimage digest to the vectors |
| **S4** store and configuration | **replaced by P1 (SQLite) + P1b (PG/MySQL)** | `[odoo]`-optional/standalone work and `mesh_config`/`mesh_publish_claim` dropped |
| **S1b** Odoo mesh models + publication | **replaced by S1b′** | Odoo part = company setting + `bus` in `_push_item()`; profile/policy/peers in P2b admin API |
| S5 mTLS transport and bus API | changed | peer table from the store snapshot |
| S6 pipeline integration | changed (S6′) | scheduler INSERTs jobs; node-internal publisher over `job` rows with `bus_scope = open` |
| S7 multi-node e2e | changed (S7′) | jobs enter through the job API; no fake Odoo |
| S8 spec corrections | extended (S8′) | adds §18.1 |

Rev 3.4 (F R316–R317, stream F5): `scaas-intent/1.3` adds the EVM body `evm.ua_meta_tx = {token, m, auth, from_kind}`
(`sig_kind` `ua`, `intent_id = uaDigest(m)`) with pre-gossip UA checks (§9.1 cache); 1.2 peers refuse 1.3 envelopes.
Mesh intents with a denylisted party are Ignored and not forwarded (OPS R246); managed markets are home-bound and not
gossiped by default (AS §8.3, A2 R124).

---

## 14. Security

| # | Threat | Mitigation |
|---|---|---|
| T1 | **SSRF from Odoo** (node `url` pointed at an internal service) | `blockchain.node` writable by `base.group_system` only; https (http only loopback/dev); no userinfo/path/query; no redirects; response cap; error detail truncated and stored as text |
| T2 | **SSRF from the node** | dial targets toml-only (`rpc_urls`, issuers, `[store] url`); mesh peer URLs admin-editable (owner, R95 exception) behind the §7.3 guard: `admin` only, audited, https/quic only, no loopback/link-local/metadata, private ranges only by per-peer opt-in, checked at write and at dial; JWKS: issuer allowlist, https, exact scheme/host/port, no redirects, 64 KiB, 5 s; unknown `iss` never fetches |
| T3 | **Machine credential leak** | secret in `ir.config_parameter` (system only); HMAC sends no secret; scopes + namespace bound; expiry; rotate = `generation + 1`; revoke hot (≤ 2 s) |
| T4 | **Replay** | HMAC ±300 s + nonce cache per key; job POST idempotent (R91); feeds read-only. OIDC: short TTL, `iat` required, `aud` bound, TLS only, no cookies |
| T5 | **Store / backup leak** | no secrets in the store (R92); payloads hold payer, payee, amounts — file mode 0600 / DB grants, encrypted backups (doc) |
| T6 | **Compromised Odoo** | bounded to its namespace: granted chains, registered tokens, `allow_call`, quota, rate limits, R55, R100; digests node-computed (cannot squat other tenants); no config access (R109); others' jobs 404. `call` jobs as powerful as today for that namespace. |
| T7 | **Compromised node** | lane keys (gas only, MESH T14); can lie on the feeds (fake `range` ⇒ Odoo books payments). Same trust as today's indexer key (`main.rs:103, 117`: both keys in one process). Follow-up §18.3. |
| T8 | **Cross-tenant leakage / squatting** | namespace-filtered SQL; events filtered by grant/token subset/watch; contract tests with two namespaces; node-computed digest (R89) |
| T9 | **Stolen OIDC access token** | ≤ 1 h, `aud`-bound, per-`sub` rate limit, audit; app keeps tokens in memory; IdP-side revocation |
| T10 | **Alg/key confusion** | per-issuer alg allowlist; JWK `kty/crv/alg` must match; RSA ≥ 2048; no symmetric path; `jku/x5u/jwk/x5c/crit` rejected; cache keyed `(iss, kid)` |
| T11 | **ID token as access token** | `audience ∉ client_ids` enforced at config; optional `typ = at+jwt` |
| T12 | **Clock skew** | 60 s OIDC, 300 s HMAC; NTP required (doc) |
| T13 | **CSRF** | bearer header only, no cookies, exact CORS origins without credentials |
| T14 | **Admin misuse** (fee redirection, attacker tokens) | role split; `fee_recipient`/tokens = `admin`, keys = `key_custodian`; hash-chained audit; alert metrics; admin bind loopback/VPN by default |
| T15 | **Host CLI abuse** | the CLI needs the service user's access to `node.toml` and the store (= host compromise already); every action audited with uid, metric `scaas_admin_cli_total` |
| T16 | **DoS** | per-key buckets, ≤ 4 long-polls per key, caps, `MAX_INFLIGHT`, `STORE_FULL`, quotas |
| T17 | **Client context forging server-only fields** | `SERVER_ONLY` on every new field of `blockchain.relay.job`, `blockchain.node`, `blockchain.node.route`, DEX mirrors; no context key consulted |
| T18 | **Copied Odoo database pushing to production** (staging restore) | `neutralize.sql` deletes node secrets and sets chains `pull`; push/sync refuse when `database.uuid` or `web.base.url` differs from `bound_*` |
| T19 | **Restore resurrects revoked keys / rewinds journal** | mandatory `store restored` CLI ⇒ `restore_epoch` ⇒ Odoo halts (R110); runbook: re-revoke or rotate `master_key` after a restore |
| T21 | **Password guessing / credential stuffing on built-in login** | Argon2id (m=19 MiB, t=2), per-name and per-address rate limits, lockout after 10 failures, uniform `401` + dummy hash for unknown names, passwords ≥ 12 chars; OIDC-only for deployments that want no node passwords (`modes = ["oidc"]`) |
| T23 | **Client API key embedded in a client-side app** (extracted from a bundle, APK or extension ⇒ full `submit`/`read` of the namespace) | hard rule §7.1: server-side only; client apps sign user actions themselves (`clientkeys`) via the gateway and read feeds through their own backend; job API has no CORS; per-key rate limits and quotas bound the damage; revoke/rotate by `key_custodian` is hot |
| T24 | **Automation credential sprawl** | only OIDC client credentials (short-lived, IdP-managed, audited by `iss`/`sub`) or the host CLI; no admin API keys or shared admin passwords in CI |
| T22 | **Stolen session token** | session 15 min, revocable by `session_epoch` (logout, password change, disable); bearer over TLS only, no cookies |
| T20 | **Two owners on one store / one key set** | owner lock + fencing epoch (A1); §9.4 heuristic for keys |
| T25 | **Gas drain through sponsored public doors** | explicit, concrete `~gateway`/`~mesh` policies only; local payer signature; budget, hourly and per-payer caps; max chargeable fee ≤ reservation at lease (TSS §B1.7) |
| T26 | **Admin-listener app files as an attack surface** | served only with `[app] enabled`, static paths only, APP §10.1 CSP + Trusted Types, never on gateway/job/mesh listeners (R160) |
| T27 | **Restore re-executes stopped work; denylist misuse** | chains start paused, client cancels before resume (OPS R240); deny add/lift `admin`, audited with order hash, address masked in logs (OPS R246) |

---

## 15. Observability

Node `/metrics` additions (R51 renderer, `admin.rs:72`):

| Metric | Type | Labels |
|---|---|---|
| `scaas_relay_jobs` | gauge | `chain`, `namespace`, `state` (from the store) |
| `scaas_job_api_requests_total` | counter | `route`, `code`, `namespace` |
| `scaas_job_accept_total` | counter | `chain`, `namespace`, `result` |
| `scaas_job_transition_total` | counter | `chain`, `result` (`ok`, `moved`, `unknown`) |
| `scaas_feed_client_cursor`, `scaas_feed_last_poll_seconds` | gauge | `namespace`, `feed` |
| `scaas_feed_head` | gauge | `feed` |
| `scaas_index_cursor` | gauge | `chain` |
| `scaas_store_owner_epoch`, `scaas_store_fencing_lost_total` | gauge / counter | — |
| `scaas_admin_mutations_total` | counter | `route`, `actor_kind`, `result` |
| `scaas_admin_cli_total` | counter | `action` |
| `scaas_admin_login_total` | counter | `result` (`ok`, `bad`, `locked`) |
| `scaas_audit_head_seq` (was `scaas_audit_head_info{hash}`, OPS §4.2) | gauge | — |
| `scaas_oidc_rejections_total` | counter | `issuer` (index, OPS R230), `reason` |
| `scaas_oidc_jwks_refresh_total` | counter | `issuer`, `result` |
| `scaas_fee_recipient_changed_total` | counter | `chain` |
| `scaas_lane_foreign_nonce_total`; `scaas_lane_foreign_nonce` (0/1, latched until the lane leases) | counter; gauge | `chain`, `lane` |
| `scaas_config_toml_drift` | gauge | — |
| `scaas_app_requests_total` | counter | `path_class` (APP §13.2) |
| `scaas_sponsor_jobs_total`, `scaas_sponsor_cost_spent`, `scaas_sponsor_budget_remaining_ratio`, `scaas_sponsor_reserved` | counter, gauges | `policy`, `chain`, `result` (TSS §B1.6; no payer label) |
| `scaas_deny_entries`; `scaas_deny_refused_total`; `scaas_deny_changes_total` | gauge; counters | `chain`; `chain`, `door`; `action` (OPS §4.5) |

**Plus every series of OPS §4.3** (names, types, labels and buckets normative there): build/process/snapshot, node and
chain readiness, job terminal outcomes and stages, simulation, submit, lane, RPC, indexer progress and finality,
audit chain, HTTP, store, mesh propagation, ops watch and FinOps series. R230 label allowlist and pre-emission at 0
apply to every series of this table too; `revert_streak` is a breaker of `scaas_breaker_open` (OPS R233).

`/readyz` reasons: store not open or not owner; final head missing; index lag; lane used outside the store; issuer
failed closed; `finality violated at <block>`; `audit chain broken` (per chain or node scope, §9.1). Logs: no payloads, tokens or HMAC headers.

Odoo: `blockchain.node` form shows cursors, incarnation, last sync, last error, dropped-event counter,
`needs_attention`; job views show `push_state`, `node_job_uid`.

---

## 16. Test plan

Heavy runs one at a time (owner rule, OOM cap).

### 16.1 Unit (`cargo test`, no network)

- `store.rs` (contract suite, run per backend, A1): migrations; second owner refused; **fencing**: a stale owner's
  journal transaction aborts; state machine = `transitions.json`; `job_event` atomic with the CAS; `job_live_digest`;
  idempotency incl. tombstone and generations; unique violations classified by constraint (name, or the SQLite column
  list); `transition` never enters `cancelled`; journal fields only on their transitions; purge never deletes an
  unexpired origin; lease vs cancel race; published-job cancel ⇒ hold + `TOO_LATE`; tri-state `transition` (`Moved`
  after cancel, `Moved{signed, own hash}` proceeds, injected commit-outcome-unknown ⇒ re-read); `lane.journal_max`
  monotonic with out-of-order writes; byte-exact keys (`'0xAB' != '0xab'`, base58 case); nonces as i64.
- `jobs_api.rs`: every accept check and code; node-computed digest vs client digest; JCS KAT; snapshot in accept
  results; namespace isolation; `wait`; `410`; continuity fields in pages.
- `gwauth.rs`: `HmacKeys` (two keys, revoked/expired/rotated, nonce per key); shared KAT; per-listener body caps.
- `oidc.rs`: RS256/ES256/EdDSA (keys from `ring`); wrong `iss`/`aud`, expired, `nbf` future, missing `iat`, lifetime
  too long, `alg = none`, `HS256`, `alg`/`kty` mismatch, JWK `alg` mismatch, `jku` header, `typ` required, unknown
  `kid` ⇒ one refetch then reject, refetch rate limit, rotation (old key removed ⇒ old token rejected), stale-JWKS fail
  closed, `(iss, kid)` collision across two issuers, discovery redirect refused, `scope` mapping refused for a user
  token, `audience ∈ client_ids` config refused, role mapping (`role` string/array, `realm_access.roles`).
- `admin_auth.rs`: Argon2id hash/verify round trip; login ok/bad/unknown (same status and comparable timing via
  dummy hash)/locked/disabled; session MAC, expiry, refresh window, `session_epoch` revocation, role change ⇒ old
  token rejected; dispatch by prefix with each mode off; roles ⊆ caller's on user create; API key
  create/rotate/revoke by `key_custodian` only (403 for `admin` alone); CLI writes while the node holds the owner lock.
- `admin.rs`: route × role matrix for both admin credential kinds; CORS preflight; audit row before/after + actor +
  hash chain, secrets masked; HMAC key on the admin listener ⇒ 401;
  session or OIDC token on the job API ⇒ 401 (R109); `LANE_BUSY`.
- `submit.rs`/`adapter.rs`: S2 tests rewritten on a temp store; `plan()` from `lane.journal_max`; `leased` mapped to
  `nonce_leased`; `lane_hint`; §9.4 heuristic; gateway job digest present.
- `config.rs`: bootstrap import, drift, toml-only fields refused by the API, `[odoo]` accepted (transitional) /
  refused (P9), OIDC config validation.

### 16.2 Contract tests (node ↔ Odoo)

`scaas/scaas-node/tests/api/`: `job_request.json`, `job_result.json`, `jobs_page.json`, `events_page.json` (one
`range` per family from the adapters' fixtures, plus `balances`), `transitions.json`, `hmac_kat.json`, `jcs_kat.json`.
Copies under `dms_blockchain/tests/data/`; CI `cmp`.

### 16.3 Odoo (`dms_blockchain/tests/test_node_client.py`, fake node via `_client()`)

Push: marker committed before HTTP; rollback after accept ⇒ re-push applies the returned snapshot; feed items for an
unknown uid adopted by origin; permanent vs transient errors; `IDEMPOTENCY_MISMATCH`/`PREVIOUS_GENERATION_LIVE` ⇒
`attention`, never `dead`; prerequisite not pushed until `mined`; paused chain; no route ⇒ create raises; `bound_*`
mismatch refuses. Sync: ladder from `queued` to every target; `FEED_LATE_NOOP` (`final` absorbs late `mined`);
overlap no-op; poison skipped; gap halts; straddle; unregistered contract dropped and counted; `balances` at the right
height; `store_id`/`restore_epoch` change, `head_seq < cursor`, incarnation mismatch ⇒ halt; acknowledge re-pushes.
Cancel: `push_attempted` false ⇒ local; `cancelled`; `TOO_LATE` signed and published; transport error ⇒
`cancel_requested` retried first. Requeue bumps generation. Server-only fields on all new models (explicit values and
`default_*` context, user and sudo). Transitional gates; `action_switch_to_push` preconditions incl. tokens ⊆ node and
journal continuity. Neutralize script effect. DEX mirrors seq guard (P7). `pg_constraint` shows the new UNIQUE
constraints (CLAUDE.md §5.2).

### 16.4 e2e

- `tests/e2e_push.rs` (`--ignored`, anvil + forge, no Odoo): fake client pushes through HMAC and follows both feeds to
  `mined` and a `range` with `MetaTransactionExecuted`; restart between `signed` and `broadcast` (no second outer tx);
  consumption by a second EOA ⇒ `consumed`; cancel/lease race; cancel of a published job ⇒ `TOO_LATE` and no lease by
  us; two namespaces isolation and digest squatting refused; gateway door A durable and deduplicated across restart;
  transitional run with a fake Odoo on the legacy path for one chain and the store path for another, same lane (shared
  nonce counter, `journal_max` bumped by legacy `signed`); store indexer running on a `pull` chain then switched.
- `tests/e2e_oidc.rs`: in-test mock issuer (discovery + JWKS + EdDSA/RS256 minting): admin flows per role, rotation
  mid-run, issuer down ⇒ cached keys ⇒ fail closed after max stale; built-in login and OIDC against the same
  routes; OIDC off ⇒ JWTs refused.
- `tests/e2e_store_backends.rs` (`--ignored`, docker PG + MySQL, A1): contract suite + lock loss (kill the lock
  session) ⇒ fencing stops journaling ⇒ second owner takes over without a double broadcast.
- `scripts/e2e_odoo_node.sh` (manual / nightly): real Odoo test DB + node + anvil: portal payment → push → mined →
  final; flip one chain `pull → push` with an in-flight legacy job.

### 16.5 Rev 3.4 additions (each in the gate of its stream, §17)

- Store: new tables on every backend + DDL equivalence; `DUPLICATE_CALL` classification; concurrent `usage_day` /
  `sponsor_usage` upserts and decimal sums; `breaker_latch` across restart; `store restored` pauses and purges, and a
  job cancelled after the backup point is never leased; `accept-nonce` refusals (OPS §13) and gap-filler; `index reset`.
- Gateway: `/v1/gateway` schema; R178 golden on every route; CORS preflight; `/v1/ops` accept order per family;
  64-byte signatures only on Hedera; UA routes (miss cached 60 s, `UA_KEY_IN_USE`, R320 target); app headers byte-exact.
- Accept/lease: denylist per party, door and lease re-check (no address in logs, labels, audit mirror); TSS §B1.7 list;
  `receiver_fee` rules; `traceparent` → `trace_id`; cost fields per family; golden metrics with pre-emitted zeros;
  `/readyz` per-chain body. Odoo (P5): acknowledgement cancels, cursor reset.
- Planned: R321 batch journal and cost split, unwrap terminal reverts (T7); kinds 0–7, managed-market codes,
  `merkle_dist_vectors.json` (AS7).

---

## 17. Work breakdown

Ordered streams for **one agent at a time**. "Gate" = the stream's heavy command; run it alone. Paths are under
`scaas-node/` unless an Odoo addon is named. Rev 3.4 streams (source-spec name) implement the NI parts listed; their
content and full gates live in the source spec.

| Stream | Scope (files) | Gate | Done / after |
|---|---|---|---|
| **S3** envelope, digests, hubsig, vectors (MESH; pure library) | MESH §14 S3 + Soroban preimage digest + `digest_of(job)` per family | `cargo test --lib --test mesh_vectors` | first: P2 derives digests from it |
| **P1** store v2 on SQLite + config (replaces MESH S4; **built**) | `Cargo.toml` (`sqlx`, `store-sqlite`), `src/store/{mod,sqlite}.rs` (trait, §4 + A1.3 DDL, owner lock + fencing, counters, tri-state CAS, janitor), `migrations/sqlite/`, `src/config.rs` (`[api]`, `[store]`, bootstrap lists, `[odoo]` `Option` + `// legacy(R104)`), `src/main.rs` (`store init`, `store restored`), `node.example.toml` | `cargo test` | reopen keeps `seq`/`store_id`; second process refused; fencing green |
| **P2** job API, machine keys, built-in admin auth | `src/gwauth.rs` (`HmacKeys`, per-listener caps), `src/jobs_api.rs` (§5), `src/job.rs` (`Job`, JCS), `src/admin_auth.rs`, `src/cli.rs` (`admin …`, `key …`), bootstrap admin routes (users, keys, namespaces, chains/tokens read, `auth-modes`), `argon2`, `tests/api/*.json` | `cargo test` | — |
| **OP2** (OPS) | `[log] format`, `traceparent` → `job.trace_id`, audit `warn` mirror | `cargo test` | with P2 |
| **N1** (APP) | `/v1/gateway`, gateway CORS, R178 error contract, `[app]` serving + CSP | `cargo test` + APP `node-served` e2e | any time; early (APP A2 needs it) |
| **P3** submit and lanes from the store (safety-critical) | `src/submit.rs` (`poll_store`, tri-state `transition`, store ∪ legacy start, fail-closed, `lane_hint`), `src/adapter.rs`, `src/nonce.rs`, `src/gateway.rs` (`~gateway` jobs, digest, `/v1/intents/{id}`), `src/odoo.rs` (legacy bump, `node_transport`), `src/metatx.rs` (R100) | `cargo test`, `e2e -- --ignored`, `e2e_push` job cases | no `dead`/`reverted` for a consumed job; no double broadcast on restart; R18 tests unchanged |
| **OP1**, **OP8** (OPS) | OPS series, `metrics_bind`, `revert_streak` + `breaker_latch`, per-chain `/readyz`, finality recheck; `deny_subject`, intake + lease checks on every door, metrics (deny routes with P2b) | `cargo test` (+ OP1 load test, alone) | with P3/P4 |
| **P4** indexer and events feed | `src/indexer.rs`, `src/adapter.rs` (`index_step`), `src/drift.rs`, `src/jobs_api.rs` (`/v1/events`, `/v1/watch`, `/v1/tokens`) | `cargo test`, `e2e.rs` + `e2e_cosmos.rs` (alone) | — |
| **P5** Odoo client (`dms_blockchain`, `dms_blockchain_payment`) | `models/blockchain_{node,relay_job,subject_account,chain,chain_event}.py`, `lib/node_client.py`, `lib/fields.py`, `data/ir_cron.xml`, `data/neutralize.sql`, security, views, `blockchain_autopay.py`, `tests/test_node_client.py`, `tests/data/*.json` | Odoo tests of both addons | incl. OP5's acknowledgement cancels and cursor reset |
| **OP5** (OPS, SQLite part) | `store restored` pause + purge, `lane accept-nonce` + `lane_adopted`, `index reset`, audit verification, token `active` route, `addresses --labels` | `cargo test` | before P6; PG/MySQL part with P1b |
| **P6** e2e push + cutover rehearsal | `tests/e2e_push.rs`, `scripts/e2e_odoo_node.sh`, `README.md` (job API, migration, restore runbook) | `cargo build --release`, `e2e_push -- --ignored`, then the script (alone) | **owner cutover per chain on SQLite (testnet first) may start** |
| **P2b** OIDC, full §7.3, audit export, CORS (after P6, M12) | `src/oidc.rs`, `src/admin.rs` (router split), `src/admin_api.rs`, `ring` direct, `tower-http` `cors` | `cargo test`, `e2e_oidc -- --ignored` | — |
| **N2** (APP) | `/v1/ops`, Hedera 64-byte signatures on `/v1/metatx` | `cargo test` + Cosmos `wasmd` e2e | P3, N1 |
| **SP1 + OP4** (TSS, OPS) | sponsor tables, sponsor + cost columns, `job_live_call`, accept/lease/end hooks, feed cost fields, `usage_day`, `report usage`, sponsorship and usage routes, metrics | `cargo test` + PG/MySQL concurrency cases | P3, P2b |
| **TB3**, **RP2** (TSS) | `chain_contract` + route, tender events; `receiver_fee`, `token.features`, `ReceiverFeePaid` | TSS gates | P2–P5 (RP2 after RP1) |
| **T7** (TW2) | `token.kind`, `payLane`, TW2 events, R321 batching, unwrap rules, `entryRef` (§18.2) | `cargo test` (token table, normaliser) | P3, P4 |
| **OP3** (OPS) | leg backing, watched events, `…/watch` route | `cargo test` | T7 (AS events with AS7) |
| **P1b** PostgreSQL and MySQL (A1) | `src/store/{postgres,mysql}.rs`, `migrations/{postgres,mysql}/`, `tests/e2e_store_backends.rs`, features; every rev-3.4 migration on both | `cargo test --features store-postgres,store-mysql`, `e2e_store_backends -- --ignored` (docker, alone) | contract suite + DDL equivalence on all three; PG/MySQL cutover allowed |
| **P7** DEX on the store (R105) | `src/dex/venue.rs`, `src/dex.rs`, DEX tables, `src/admin_api.rs` (markets), `dms_blockchain_dex/models/*` | `cargo test` + DEX e2e (alone), Odoo `dms_blockchain_dex` | — |
| **S1b′** | Odoo company bus scope (MESH §10.4) + `bus` in `_push_item()` | Odoo tests | — |
| **S5**, **S6′**, **S7′** | mesh as MESH §14 with §13.2 changes | MESH gates | — |
| **F5**, **N4** (F, APP) | `ua_metatx`, `chain.ua_registry*`, record cache, `scaas-intent/1.3`, UA events; `/v1/ua-metatx`, `/v1/ua/register` (R320) | mesh e2e on dev chains | F0, F2 (N4: F1, F5) |
| **AS7** (AS) | kinds 5–7 decoders before the first `*_REG` create, AS events, intake rules (AS §3.8), `token.reg_cache`, snapshot builder + API + CLI + vectors, managed markets (gossip part after P7/G3) | node `cargo test` (never beside forge) | AS1, AS4, P4 |
| **P9** removal (R104), after §11.4 | delete `src/odoo.rs`, legacy blocks, `OdooCfg`, `fake_odoo`; Odoo §10.7 deletions, post-migration, pre-migration abort on `pull` | `cargo test` + `e2e_push`; Odoo suites | `grep -r json/2 scaas-node/src` empty |
| **S8′** | spec corrections (§18.1), after owner approval | — | — |
| PLANNED: **N3**, **OP7**, **PL1** | non-EVM DEX books (after P7/G3, N2); OTLP `otel` feature; SponsorshipPool `call` routing | — | — |

Order: **S3 → P1 → P2 (+OP2) → N1 → P3 (+OP1, OP8) → P4 → P5 → OP5 (SQLite) → P6 → [owner cutover, SQLite] → P2b →
N2 → SP1 + OP4 → TB3 → RP2 → T7 → OP3 → P1b (+OP5 PG/MySQL) → P7 → S1b′ → S5 → S6′ → S7′ → F5 → N4 → AS7 → P9 →
S8′.** Heavy gates one at a time. P9 is gated by the calendar criterion of §11.4; if the proof window ends before S5,
run P9 first so the mesh never wires to legacy code.

---

## 18. Open follow-ups

### 18.1 Doc corrections required by R87–R111 (listed, not made)

| File | Where | Edit |
|---|---|---|
| PD | §13 R6 | superseded by R87: "Odoo calls the node job API; the node never calls Odoo". |
| PD | §13 R16, §3.4 l.287 | superseded by R88. |
| PD | R11 | finality config lives in the node store (R96). |
| PD | R20 | RPC URLs, database URLs and OIDC issuers are toml-only (R95). |
| R3D | R51 | `relay_stats` → store counts; Odoo-only gauges leave node metrics. |
| R3D | R53 | two gates (R96). |
| R3D | R54 | job API extends it with key ids (R92). |
| R3D | R56 | drift C via `balances` items (R94); receiving wallets via `PUT /v1/watch`. |
| MESH | §13.1 rows | as listed; envelope id `scaas-intent/1.2`. |
| `blockchain_security.xml` l.35, canon §C14.1 "two service keys" | | replaced by per-namespace key scopes. |
| `scaas/scaas-node/README.md` | operating invariants | job API, admin auth modes and CLI bootstrap, migration and restore runbook (P6). |
| everything | names | rename stream: node `scaas-node`, env `SCAAS_*`, metrics `scaas_*`, R54 headers `X-Scaas-*`, signer/domain tags `scaas.*` (e.g. PD R9 `scaas.pay.lane`) — the last one changes on-chain derivations and needs its own owner-reviewed plan. |
| `odoo.rs:1` module doc | | deleted with the file in P9. |
| APP §17, OPS/TSS "Amends NI" rows, F §11.2, AS §9.1, TW2 §14 | NI items | done in rev 3.4 (§20); those specs may point here. |

### 18.2 Interpretations to confirm with the owner

1. Odoo's namespace gets `allow_call = true` at migration (R103).
2. A paused node chain accepts jobs and holds them (R53 reading).
3. Several companies may share one namespace via `origin.scope` (R90/R91); default = one namespace per database.
4. Payment status latency ≤ ~10 s while jobs are live, ≤ 1 min otherwise (R101).
5. A cancel of a published job reports "already sent" and keeps the request open (R98).
6. TW2 T7 `entryRef` handling: TW2 R139 makes the first `PaymentSettled` per `entryRef` the payment and later ones
   reconciliation exceptions; whether the node flags repeats on the feed or leaves it to clients is fixed in T7.
7. Names chosen here where a source gave none: `chain.max_valid_for_secs`, `token.features` value `ua`,
   `token.reg_cache`, `action_reset_event_cursor`, the `/readyz` body (§4, §9.1, §10.1); R320/R321 are spec rulings.

### 18.3 Deferred

- HA: two nodes for one `(company, chain)`, or several nodes on one shared database, with a job-release protocol.
- A second, independent event source and Odoo-side agreement before booking (T7).
- OIDC introspection / revocation, DPoP or mTLS-bound tokens.
- Admin-API management of RPC URLs with a dial allowlist.
- Audit retention and export; per-key IP allowlists; signed feed pages (only with a second verifier).

---

## 19. Review disposition

### 19.1 Review 1 (`spec-review-1.md`, verdict FIX-THEN-GO)

36 findings (C1, H1–H10, M1–M12, L1–L10, 3 accuracy notes), **all fixed, 0 rejected**; the per-finding table is in
rev 3.3 (git history). Main landings: C1 §10.3–10.5; H1 R98; H2 R93/R110/§5.3; H3 §9.1; H4–H6, M10 A1; H7 R89; H8 R91;
H9 R95/§10.4; H10 §10.1; M12 §17. Ponytail notes accepted: Odoo long-poll dropped; `namespace_token` only as
client-pushed state; multi-issuer OIDC and cursor overlap kept as cheap.

### 19.2 Owner rulings folded into rev 3 (admin auth, rename)

R106 = built-in users + optional OIDC (rev 3's admin API keys `scaas_ak1.` removed; "API key" = R92 external-client
keys only; rev 2's OIDC hardening kept as R106a); R107 roles kept, `admin` ⇏ `key_custodian` (owner-confirmed);
R108 = host CLI (Unix socket removed); R109 symmetric; R110 actors `user:`/`oidc:`/`cli:`; rename to `scaas-*`.
Rev 3.2: automation = OIDC client credentials or the CLI; client API keys server-side only (§7.1, T23, T24).

### 19.3 P1 code review (rev 3.3)

The P1 code and its review (`p1/code-review.md`, F1–F15, fixed on `fix/node-p1-review`) corrected in place: SQLite
classifies unique violations by column list (§5.2 step 8, A1.3); `[api] bind` default `127.0.0.1:8548`, shared ports
refused; `mesh_peer.url` admin-editable under the SSRF guard (owner; R95, §7.3, T2); `409 SUPERSEDED` and in-transaction
`422 EXPIRED` (§5.2); `meta('<table>_floor')` for `410` (§5.3); `store init` creates, a missing store refuses to start
(§8); `CHECK`s tie `digest`/`payload_hash` to `kind` (§4).

---

## 20. Additions consolidated in rev 3.4

Sources: **APP** `2026-10-06-scaas-app-design.md` rev 1.1; **OPS** `2026-10-06-operations-design.md` rev 1.2;
**TSS** `2026-10-06-tender-sponsorship-shredding.md` rev 1.2; **F** `2026-10-06-universal-account-design.md` (current
rev; names referenced, internals stay in F); **D** `2026-10-06-signers-followups.md`; **AS**
`2026-10-06-asset-suite-design.md` rev 1.1; **TW2** `2026-10-06-token-wrappers-v2.md` rev 1.2 (its §18 notes I1–I9 hold
no node item; T7 is in its §15). Status SPECIFIED unless marked planned.

| Item | Source | NI place | Stream |
|---|---|---|---|
| `GET /v1/gateway`; `gateway_cors_origins`; error contract `{error, code, detail, revert_data}` | APP §9.6.1, R159, R178 | §3, §5.5 | N1 |
| App serving on the admin listener + CSP (`[app]`, `scaas_app_requests_total`) | APP §13.2, §10.1, R160 | §3, §7.7, §15 | N1 |
| `GET /v1/admin/auth-modes` in the route table and open routes | APP §17 (L6) | §3, §7.3 | P2 |
| `POST /v1/ops` (`signed_op` payload, accept order); Hedera 64-byte HIP-632 signatures on `/v1/metatx`, Hedera only | APP §9.6.2, R156 | §5.5 | N2 |
| `POST /v1/ua-metatx`, `POST /v1/ua/register` | APP §9.6.3 | §5.5, R320 | N4 |
| Non-EVM DEX books (planned) | APP §15 N3, §16 Q2 | §5.5, §17 | N3 |
| `deny_subject`, deny routes, intake and lease-time checks (R246) | OPS §4.5 | §4, §5.2 (7b), §7.3, §9.2 | OP8 |
| `usage_day`, `GET /v1/admin/usage`, `report usage`; cost columns on every job | OPS R238, §8.2–8.3 | §4, §5.2, §7.2–7.3 | OP4 |
| `job.trace_id`, `traceparent` intake; `[log] format`, audit `warn` mirror | OPS R236, R237 | §3, §4, §5.2, §7.5 | OP2 |
| `breaker_latch`, `metrics_bind`, per-chain readiness, finality recheck, label caps | OPS R230, R233, R242 (a), R244, §4.3 (M2) | §3, §4, §9.1, §15 | OP1 |
| `store restored` pause + purge; security re-apply from the audit mirror (H1); acknowledgement cancels | OPS R240 | §4, §7.2, §7.5, §10.1 | OP5, P5 |
| `lane_adopted` + `lane accept-nonce`; `index reset` + Odoo cursor reset; audit verification | OPS R241, R242 (b, c) | §4, §7.2, §7.5, §10.1 | OP5 |
| Token intake pause `PATCH …/tokens/{addr} {active}`; chain `breaker` merge patch; state/reset bodies | OPS §4.4, §10.0 | §7.3 | OP5, OP1 |
| `allow_call` replay precondition | OPS §11.2 (M11) | R103 | P2 |
| Metric renames (`scaas_audit_head_seq`, issuer index, latched foreign nonce) and §4.3 series | OPS §4.2–4.3 | §15 | OP1 |
| `sponsor_policy`, `sponsor_usage`; job `sponsor_policy_id`, `sponsor_reserved`, `sponsor_day`; sponsorship routes, metrics, local signature check | TSS §B1.2–B1.6, R189–R191 | §4, §5.2, §7.3, §15 | SP1 |
| `job_live_call` (`call_hash`, `409 DUPLICATE_CALL`) | TSS §B1.2–B1.3 | §4, §5.2 | SP1 |
| `chain_contract`, `…/contracts` routes, tender events, `PUT /v1/tokens` accepts contracts | TSS §A.6 | §4, §5.2, §6, §7.3 | TB3 |
| `receiver_fee` payload field, `token.features`, `ReceiverFeePaid` | TSS §B2.5 | §4, §5.2, §6 | RP2 |
| `ua_metatx` job kind, `chain.ua_registry`/`ua_registry_gen`, UA events | F §11.2 | §4, §5.2, §6 | F5 |
| UA record cache; mesh `scaas-intent/1.3` `evm.ua_meta_tx` | F §11.1, R316, R317 | §9.1, §13.2 | F5 |
| Nothing assigned to the node | D R252 (node intake never checks backups), R260 (simulation arbitrates `None`, R27) | — | — |
| Events, token kinds 5–7, `token.reg_cache`, intake and managed-market rules, snapshot API + CLI (planned) | AS §3.8, §5.4, §8.2–8.3, §9.1, R200 | §4, §5.2, §5.5, §6, §7.2 | AS7 |
| `token.kind`, `payLane`, TW2 events, `mtxBatch` batching, unwrap rules, `entryRef` (planned) | TW2 §7.3–7.6, §10.2, §14, §15 T7 | §4, §6, §9.1, R321, §18.2 | T7 |

**Conflicts between sources, resolved here:**

| # | Conflict | Resolution |
|---|---|---|
| X1 | APP N4 makes `/v1/ua/register` a `~gateway` `call` job "not a namespace grant"; R103 makes `call` a namespace capability | R320: gateway `call` jobs only to `chain.ua_registry` `register`; R103 unchanged |
| X2 | NI `scaas_audit_head_info{hash}` vs OPS `scaas_audit_head_seq` | OPS (one series; hash logged) |
| X3 | Gateway codes (`TOKEN_NOT_SERVED`, `EXPIRED` for too long) vs job API (`UNKNOWN_TOKEN`, `VALID_TOO_LONG`) | per-listener code sets over the same checks (§5.4 vs §5.5) |
| X4 | Job API accept does no RPC (§5.2) vs `/v1/ops` simulating at accept (APP) | gateway doors simulate before INSERT as today; job API at lease |
| X5 | TSS cost columns for sponsorship vs OPS "every job" | every job (OPS R238); sponsorship reads them |
| X6 | `max_valid_for_secs` used by NI, APP, TSS, OPS without a home (mesh: one global param) | `chain.max_valid_for_secs`, default 3600, hot |
| X7 | TW2 and AS each extend the token kind | one `token.kind` CHECK = `versionOf().kind` 0–7 (incl. `zether`) |
| X8 | R108 "CLI needs no owner lock" vs OPS CLIs that write lanes and the index | credential CLIs lock-free; maintenance CLIs: node stopped, owner lock, epoch + 1 |
| X9 | NI §7.7 "no `sessionStorage`" vs APP R162 OIDC redirect state there | tokens never; only the ≤ 10 min redirect state |
| X10 | OPS books gap-fillers to `~lane`, not reserved in R90 | `~lane` reserved, booking label only |
| X11 | TW2 batching vs one job = one tx; separate TW2/TSS never-batch lists | R321: journal per outer tx; lists merged, plus sponsored jobs |
| X12 | NI token `DELETE` vs OPS M1 (delete drops events) | both kept; `{active: false}` is the intake pause |

---

## Amendment A1 (owner, 2026-10-06): storage backends — R111 (rev 2, review H4/H5/H6/M10 applied)

**R111 — the node store runs on SQLite, PostgreSQL or MySQL; the backend is storage only.** One `[store] url`
(`sqlite:///var/lib/scaas/node.db`, `postgres://…`, `mysql://…`; toml/env only, R95) selects it; every backend carries
the same logical schema (§4) and the same semantics as R88. Multi-node HA on a shared database is **not** in scope
(owner: "chỉ là backend lưu trữ"); it stays in §18.3.

### A1.1 Single owner and fencing

- Owner lock, backend-native, on a **dedicated** connection: SQLite `flock` on `<db>.lock`; PostgreSQL
  `pg_try_advisory_lock(k)` with `k` = the first 8 bytes of `store_id` as `int8` (no 32-bit `hashtext`); MySQL
  `GET_LOCK('scaas-node:<store_id>', 0)`. Not obtained ⇒ refuse to start.
- **Fencing epoch**: after taking the lock, `UPDATE store_owner SET epoch = epoch + 1, incarnation = ?, owner = ?,
  since = ?` and remember `mine = epoch`. **Every** journal-bearing transaction (any job CAS, feed insert, audit
  insert) starts with `SELECT epoch FROM store_owner WHERE id = 1 FOR UPDATE` (PG/MySQL; SQLite: inside
  `BEGIN IMMEDIATE`) and aborts with `NOT_OWNER` when `epoch ≠ mine`. A process that lost its lock without noticing
  can therefore not journal, and so cannot broadcast (journal-before-broadcast). The host CLI (R108) is the one
  non-owner writer: it touches only credential tables and `audit_log` (taking the same `store_owner` row lock to
  serialize the audit chain, without comparing the epoch) and never a job or feed row.
- The lock connection is pinged every ≤ 2 s; a failed ping stops leasing and submission at once, re-takes the lock
  (new epoch) before resuming, and replays `plan()` from the store.
- PostgreSQL: refuse to start when the server answers `SHOW pool_mode` (PgBouncer) or when `pg_backend_pid()` of the
  lock connection changes between two pings. The Odoo stack's PgBouncer (`/home/dockers/odoo19/pgbouncer`) must not
  sit between the node and its database.

### A1.2 Transactions and outcomes

- SQLite: `max_connections = 1` (consistent with R88's single connection), WAL, `synchronous = FULL`,
  `foreign_keys = ON`, transactions opened with `begin_with("BEGIN IMMEDIATE")`; the owner `flock` replaces
  `locking_mode = EXCLUSIVE`.
- PostgreSQL: `REPEATABLE READ` + the fencing `SELECT … FOR UPDATE` row (all writers serialize on it; volume is low);
  MySQL: `REPEATABLE READ` + `SELECT … FOR UPDATE`. Serialization failure / deadlock (`40001`, `40P01`, MySQL 1213)
  ⇒ retry the whole transaction (≤ 3), never skip it.
- **Commit outcome unknown** (connection lost after `COMMIT` was sent): the caller gets `Unknown`; it reconnects and
  re-reads the row before any further action (§9.1). The idempotent journal CAS makes the retry safe.

### A1.3 Normative per-backend schema rules

| Logical | SQLite | PostgreSQL | MySQL 8 |
|---|---|---|---|
| key / hash / address / origin text (every PK, UNIQUE, join or compare column) | `TEXT` (binary collation is the default) | `TEXT COLLATE "C"` | `VARBINARY(n)` or `VARCHAR(n) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin` with explicit `n` (PK/UNIQUE need a length: `origin_key` 256, `origin_scope`/`producer` 128, `namespace` 40, `chain_key` 80, addresses 128, `tx_hash` 132) |
| digests, payload hashes, order hashes | `BLOB` (32) | `bytea` | `BINARY(32)` |
| payload / body / JSON metadata | `BLOB`/`TEXT` | `bytea`/`text` | `LONGBLOB`/`LONGTEXT` |
| nonces, heights, seq, uid, timestamps (ms) | `INTEGER` | `BIGINT` | `BIGINT` |
| uint256 amounts | decimal `TEXT`, never ordered or aggregated | same | same |
| `seq`/`uid` | `seq_counter` row incremented in the same transaction (no `AUTOINCREMENT`/`SERIAL`/`AUTO_INCREMENT`), so cursor semantics are identical everywhere | same | same |
| `job_live_digest` | partial UNIQUE index | partial UNIQUE index | generated column `live_digest BINARY(32) AS (IF(state IN ('queued','leased','signed','broadcast'), digest, NULL)) STORED` + `UNIQUE (chain_key, live_digest)` |
| `CHECK` | enforced | enforced | enforced (8.0.16+); minimum version 8.0.16 |
| unique-violation classification | the column list of `UNIQUE constraint failed: job.chain_key, job.digest` (SQLite reports columns, never the constraint or index name), mapped back to the DDL name by the backend; a classifier test pins the mapping, since a future unique index ending in the same columns would be misread | `constraint_name` of the error | index name in error 1062 |

Every query compares bytes; the contract suite asserts `'0xAB' != '0xab'` and base58 case on every backend.
Migrations: `sqlx::migrate!` with `migrations/{sqlite,postgres,mysql}/`; a DDL-equivalence test introspects the three
schemas and compares tables, columns (logical types), unique and check constraints.

### A1.4 Driver, secrets, tests, stream

- `sqlx` with features `store-sqlite` (default), `store-postgres`, `store-mysql`; `rusqlite` (MESH R71/§3.4) is not
  used.
- A database URL with a password is toml/env-only, never stored in config tables nor returned by the admin API.
- Store contract suite on all three (SQLite in-process; PostgreSQL and MySQL in docker, `--ignored`), including lock
  loss, fencing, serialization retry, commit-outcome-unknown injection and the byte-exact checks.
- Streams: **P1** builds the backend trait + SQLite; **P1b** (after P2b) adds PostgreSQL then MySQL, each green on the
  contract suite before the next (review M12).
