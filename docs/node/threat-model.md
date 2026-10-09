# Threat model

Threats to the node, its APIs, the mesh and gossip, with their controls. Contract-level threats are in
[contracts/metatx.md#security](../contracts/metatx.md#security) and the other contract docs. Ids are local to this file
(T* node, PT* payment path, MT* mesh bus, G-* gossip).

**Contents**

1. [Trust](#1-trust)
2. [Node](#node)
3. [Payment path](#3-payment-path)
4. [Mesh](#mesh)
5. [Gossip](#gossip)

## 1. Trust

The node is trusted for **liveness and for the truth of the event feed it serves** (a compromised node can lie on
`/v1/events`, T7). It is never trusted with subject funds or subject keys ([NODE-GEN-01](README.md#NODE-GEN-01)). The
event-set quorum ([NODE-IDX-01](indexer-feeds.md#NODE-IDX-01)) bounds what one dishonest RPC provider can inject; it does
not bound a compromised node; a second independent event source is PLANNED ([NODE-IDX-07](indexer-feeds.md#NODE-IDX-07)).

<a id="NODE-SEC-01"></a>**NODE-SEC-01** — **Merge processes, not privileges.** The node is one process, but its trust
boundaries stay explicit: it never writes a client's tables (it has no connection to any client), the store is storage
only, secrets and dial targets stay in toml/keystores, each listener accepts exactly one credential kind, and lane keys
hold gas only. A compromise of one listener's credential (an API key, an admin session, a peer key) is bounded to that
listener's powers.

## <a id="node"></a>2. Node

<a id="node"></a>

| # | Threat | Mitigation |
|---|---|---|
| T1 | **SSRF from a client** (the client's node URL pointed at an internal service) | the client's node record is writable by its system administrators only; https (http only loopback/dev); no userinfo/path/query; no redirects; response cap; error detail truncated and stored as text ([integration.md](../integration.md)) |
| T2 | **SSRF from the node** | dial targets toml-only (`rpc_urls`, issuers, `[store] url`); mesh peer URLs admin-editable behind the SSRF guard of [admin-auth.md#mesh-peer-url](admin-auth.md#mesh-peer-url): `admin` only, audited, https/quic only, canonical-IP normalization (mapped IPv6, non-decimal IPv4, zone ids, IDNA), no loopback/link-local/metadata, private ranges only by per-peer opt-in, checked at write and at dial; DHT dialing under the gossip address filter ([NODE-GSP-09](gossip.md#NODE-GSP-09)); JWKS: issuer allowlist, https, exact scheme/host/port, no redirects, 64 KiB, 5 s; unknown `iss` never fetches |
| T3 | **Machine credential leak** | secret in the client's secret store (system only); HMAC sends no secret; scopes + namespace bound; expiry; rotate = `generation + 1`; revoke hot (≤ 2 s) |
| T4 | **Replay** | HMAC ±300 s + nonce cache per key; job POST idempotent ([NODE-JOB-04](job-api.md#NODE-JOB-04)); feeds read-only. OIDC: short TTL, `iat` required, `aud` bound, TLS only, no cookies |
| T5 | **Store / backup leak** | no secrets in the store ([NODE-JOB-05](job-api.md#NODE-JOB-05)); payloads hold payer, payee, amounts — file mode 0600 / DB grants, encrypted backups |
| T6 | **Compromised client** | bounded to its namespace: granted chains, its pushed token subset, `allow_call`, the call table, quota, tombstone cap, live-call dedupe per namespace, rate limits, breakers, normalization; digests node-computed (cannot squat other tenants); no config access; others' jobs 404. `call` jobs are as powerful as the call table allows for that namespace |
| T7 | **Compromised node** | lane keys (gas only, MT14); can lie on the feeds (a fake `range` makes clients book payments). Same trust as an indexer key; a second event source is PLANNED ([NODE-IDX-07](indexer-feeds.md#NODE-IDX-07)) |
| T8 | **Cross-tenant leakage / squatting** | namespace-filtered SQL; events filtered by grant/token subset/watch; contract tests with two namespaces; node-computed digest; `job_live_call` per namespace; authority re-checked in the insert transaction ([NODE-JOB-14](job-api.md#NODE-JOB-14)) |
| T9 | **Stolen OIDC access token** | ≤ 1 h, `aud`-bound, per-`sub` rate limit, audit; app keeps tokens in memory; IdP-side revocation |
| T10 | **Alg/key confusion** | per-issuer alg allowlist; JWK `kty/crv/alg` must match; RSA ≥ 2048; no symmetric path; `jku/x5u/jwk/x5c/crit` rejected; cache keyed `(iss, kid)` |
| T11 | **ID token as access token** | `audience ∉ client_ids` enforced at config; optional `typ = at+jwt` |
| T12 | **Clock skew** | 60 s OIDC, 300 s HMAC; NTP required |
| T13 | **CSRF** | bearer header only, no cookies, exact CORS origins without credentials |
| T14 | **Admin misuse** (fee redirection, attacker tokens, takeover of a stronger admin) | role split; `fee_recipient`/tokens = `admin`, keys = `key_custodian`; user mutations need caller ⊇ target roles, no removal of the last `admin`/`key_custodian` ([NODE-ADM-08](admin-auth.md#NODE-ADM-08)); hash-chained audit; alert metrics; admin bind loopback/VPN by default; two-person procedure ([NODE-RUN-01](runbooks.md#NODE-RUN-01)) |
| T15 | **Host CLI abuse** | the CLI needs the service user's access to `node.toml` and the store (= host compromise already); every action audited with uid, metric `scaas_admin_cli_total` |
| T16 | **DoS** | per-key buckets, ≤ 4 long-polls per key, caps, `MAX_INFLIGHT`, `STORE_FULL`, quotas; tombstones: granted chain, TTL ≤ `max_valid_for_secs`, `max_tombstones`, 2 rps per key |
| T17 | **Client context forging server-only fields** | client-side rule: every node-sync field of the client is server-only, no context switch consulted ([integration.md](../integration.md)) |
| T18 | **Copied client database pushing to production** (staging restore) | client-side: neutralization deletes node secrets and returns chains to the legacy path; push/sync refuse when the database identity or base URL differs from the values bound when the secret was set |
| T19 | **Restore resurrects revoked keys / rewinds journal** | mandatory `store restored` CLI ⇒ `restore_epoch` ⇒ clients halt ([NODE-ADM-07](admin-auth.md#NODE-ADM-07)); runbook: re-revoke or rotate `master_key` after a restore ([NODE-RUN-02](runbooks.md#NODE-RUN-02)) |
| T20 | **Two owners on one store / one key set** | owner lock + fencing epoch ([store.md#backends](store.md#backends)); foreign-nonce heuristic for keys ([store.md#durability](store.md#durability)) |
| T21 | **Password guessing / credential stuffing on built-in login** | Argon2id (m=19 MiB, t=2), per-name and per-address rate limits, lockout after 10 failures, uniform `401` + dummy hash for unknown names, passwords ≥ 12 chars; OIDC-only for deployments that want no node passwords (`modes = ["oidc"]`) |
| T22 | **Stolen session token** | session 15 min, revocable by `session_epoch` (logout, password change, disable); bearer over TLS only, no cookies |
| T23 | **Client API key embedded in a client-side app** (extracted from a bundle, APK or extension ⇒ full `submit`/`read` of the namespace) | hard rule: server-side only ([NODE-ADM-06](admin-auth.md#NODE-ADM-06)); client apps sign user actions themselves (`clientkeys`) via the gateway and read feeds through their own backend; job API has no CORS; per-key rate limits and quotas bound the damage; revoke/rotate by `key_custodian` is hot |
| T24 | **Automation credential sprawl** | only OIDC client credentials (short-lived, IdP-managed, audited by `iss`/`sub`) or the host CLI; no admin API keys or shared admin passwords in CI |
| T25 | **Gas drain through sponsored public doors** | explicit, concrete `~gateway`/`~mesh` policies only; local payer signature; budget, hourly and per-payer caps; max chargeable fee ≤ reservation at lease ([sponsorship.md](sponsorship.md)) |
| T26 | **Admin-listener app files as an attack surface** | served only with `[app] enabled`, static paths only, CSP + Trusted Types, never on gateway/job/mesh listeners ([NODE-ADM-11](admin-auth.md#NODE-ADM-11)) |
| T27 | **Restore re-executes stopped work; denylist misuse** | chains start paused, clients cancel before resume ([NODE-RUN-02](runbooks.md#NODE-RUN-02)); deny add/lift `admin`, audited with order hash, address masked in logs ([NODE-OPS-14](ops.md#NODE-OPS-14)) |

## 3. Payment path

<a id="payment-path"></a>

| # | Threat | Mitigation |
|---|---|---|
| PT3 | Fake `PaymentSettled` from an unknown contract | the indexer only keeps events of registered tokens (`address ∈` registered tokens); the client matches token and receiving address too (e.g. its `token_id` and `receiving_address`) |
| PT8 | Theft of the legacy indexer key ⇒ forced bookings | a separate service user and group with one method; contiguous cursor + UNIQUE; key in a secret store, rotated (legacy pull path only) |
| PT14 | Griefing the relayer with meta-txs that will surely revert | simulation gate ([NODE-LANE-23](submit-lanes.md#NODE-LANE-23)); gateway body cap; the node drops expired orders; grief score ([NODE-LANE-15](submit-lanes.md#NODE-LANE-15)) |
| PT15 | Poisoned bytes against the node's parsers | strict `serde`, size caps, no `unwrap` on input; proptest/fuzz on every decoder ([NODE-GW-02](gateway.md#NODE-GW-02)) |
| PT19 | A lying RPC fabricates `PaymentSettled` (it learns `entryRef` from the node's own simulation) or reports a false `finalized` | quorum over the **event set** + min `finalized`/`latest` over the quorum ([NODE-IDX-01](indexer-feeds.md#NODE-IDX-01)) |
| PT20 | An operator (or a stolen session) rewrites a `call` job into `token.transfer(attacker, …)` signed by a lane | client-side: no write ACL for operators, immutable job fields ([INT-ERP-05](../integration.md#INT-ERP-05)); node-side: the selector/target call table ([NODE-JOB-01](job-api.md#NODE-JOB-01)) |
| PT21 | Spam of fee-0, `value 0` meta-txs from fresh keys ⇒ burns lane gas, trips the gas breaker | refuse `value 0`, `min_fee` floor / sponsor policy, per-`from` bucket ([NODE-GW-01](gateway.md#NODE-GW-01)) |

<!-- example:odoo -->
In the reference ERP client (Odoo) the booking that PT8 could force is `payment.transaction._set_done`.
<!-- /example -->

## <a id="mesh"></a>4. Mesh

<a id="mesh"></a>

| # | Threat | Mitigation |
|---|---|---|
| MT1 | **Spam / flood** | handshake gate (unknown peers never reach HTTP); handshake timeout and connection semaphore against unauthenticated TCP; per-peer `peer_rps` on requests and `peer_intents_per_sec` on ingest (in-process token buckets — correct here because the node is one process); page row and byte caps; 32 KiB envelope cap; `max_valid_for_secs`; `max_rows` + `STORE_FULL`; nothing persisted before L2 passes; suspension of the peer row |
| MT2 | **Replay** of an executed intent | contract nonce (G1); `valid_until`; dedup by `intent_id` |
| MT3 | **Peer impersonation** | TLS 1.3 client auth: the peer proves possession of the pinned key (`CertificateVerify`); pins are exact SPKI hashes, no CA, no name check |
| MT4 | **MITM on the client side** | server cert pinned per peer row; no fallback to WebPKI |
| MT5 | **Intent tampering** | `intent_id` recomputed (L2); every meta-tx field under the subject's signature; non-EVM routing fields decoded from the signed payload; unsigned parts bound by `body_hash` in `hub.sig`; `hop_count` unsigned but bounded |
| MT6 | **Censorship / exclusivity hijack** (a peer serves a poisoned copy first, or re-originates someone's intent with `exclusive` to itself) | no cache of rejections (a bad copy never blocks a good one); forwarders cannot alter a copy (`body_hash`); a re-originated bad copy fails simulation, its row is deleted and its `(intent_id, body_hash)` tombstoned (no re-simulation loop; the honest body is still evaluated); receivers clamp `until − published_at ≤ exclusive_ms`; violations metric; admission revocable |
| MT7 | **Leak of private intents** | `may_export` single gate; origin-only serving; signed, monotone visibility; private-chain intents from open peers rejected; open peers never see private chains in `/policy`; logs carry no payload. **Accepted side channel:** the global `seq` lets an open peer see gaps between served items and so count our hidden rows and their timing (no `head` field, but gaps remain) |
| MT8 | **SSRF** | the node dials only URLs from peer rows (admin or `node.toml`), never a URL from an envelope or a peer response; https only, no redirects; no callbacks |
| MT9 | **Parser attacks** | envelope decoder, canonical-body serializer and the Cosmos `MetaOp` JSON decoder are fuzz targets: arbitrary bytes never panic, every rejection has a code; family decoders have `decoders_never_panic` tests |
| MT10 | **Downgrade of spec** | only `1.x, x ≥ 2` accepted; no guessing |
| MT11 | **Clock games** | `published_at` in the future beyond skew rejected; a past `published_at` only expires `exclusive` early; the clamp uses the receiver's `exclusive_ms`; mesh nodes run time sync (chronyd) |
| MT12 | **Fee theft and gas drain** | normalization (fee of unbound intents goes to our wallet); submit only for registered tokens, effective-fee comparison; simulation before send; the token checks nonce before signature so race losers pay little; no allowance in the fee path, so an approve-withdraw grief does not apply |
| MT13 | **Compromised peer key** | suspend the row: takes effect at the next config refresh (≤ 60 s) for new handshakes **and** for every request on open connections (per-request check), and connections are recycled every `max_conn_age_secs`; rotate by adding a new row |
| MT14 | **Compromised node** | it holds no user funds and no subject keys; lane keys hold gas only; the node key can only sign `hub.sig`, announces and gossip messages and authenticate TLS |

## <a id="gossip"></a>5. Gossip

<a id="gossip"></a>

| # | Threat | Mitigation |
|---|---|---|
| G-E1 | **Eclipse** (attacker surrounds a node) | bootstrap from several operators (toml); `mesh_outbound_min = 2`; 20 outbound slots chosen by us, ≤ 10 from DHT-learned peers; Kademlia manual inserts with the /24 (/48) bucket cap and a capped record store; P6 colocation; `direct` partner peers; bus peers are independent of the mesh. Impact bound: liveness only — G1 (contract nonce), our own submit path and chain reads are unaffected; hints and books are chain-verified |
| G-E2 | **Self-inflicted eclipse** (honest peers penalized during join, partitions, upgrades) | Reject only for byte-decidable faults over keys carried in the message; announce/config/clock checks are Ignore; spec minor above ours ⇒ Ignore; auto-ban needs 2 Rejects in 1 h ([NODE-GSP-07](gossip.md#NODE-GSP-07), [NODE-GSP-08](gossip.md#NODE-GSP-08)) |
| G-S1 | **Sybil spam** | per-source/origin/`from` buckets (origin buckets charged once per `intent_id`); P4/P7; graylist/ban; V8 freshness; only `may_submit` rows stored, evicted by fee; no persist before L2 |
| G-S2 | **Sybil assignment delay** (announce `submit`, never submit) | assignment only with chain-credited track record (one `peer_id` per lane, no self-originated intents, ≥ 3 `from`) or admin trust; auto-trusted peers ≤ 1 rr slot in 3 and out after 1 miss ([NODE-GSP-10](gossip.md#NODE-GSP-10)) |
| G-S3 | **Re-originated / poisoned copies** | content-addressed msg-id + canonical bytes ([NODE-GSP-06](gossip.md#NODE-GSP-06)); receivers honour `exclusive` only for assignees in their own eligible set, never `assignee = hub.id`; store tombstones |
| G-S4 | **Replay / byte variants** | canonical payloads (one msg-id per message); `seen_intent` with TTL `valid_until`; announce `version` monotone; hint 10 s dedup and "intent known" gate |
| G-F1 | **Front-running via gossip visibility** | meta-tx outcome is fixed by the signer (G1); confidentiality: private chains never gossiped, tenants opt in with `bus_scope = public`, large B2B values belong on confidential tokens or the bus. Exclusivity binds only spec-following nodes: a bot may submit inside the window, and with an unbound `feeRecipient` normalization sends the fee to whoever submits — exclusivity does not protect the assignee's fee. DEX bound: resting orders are public by nature; taker orders posted directly to the home are not gossiped; `route_order` exposes a taker before matching (limit price + short expiry bound it). DEX unbound: anyone may settle within the maker's limit until the on-chain cancel is mined |
| G-B1 | **Book spoofing** | `book` requires the signer's key in the message and, for bound orders, the home's sole PoP of the order's relayer; maker EIP-712 signatures checked; ERC-1271 orders only via the home/claimant; only DEX-trusted homes replicated and advertised; firm quotes only at the home; chain events override |
| G-B2 | **Free option via an attacker venue** | wallets are shown DEX-trusted homes by default; untrusted homes only on request, with a blocking warning and ≤ 120 s routed expiry; auto-trust needs chain-credited settles; demotion on proof ([NODE-DEX-13](dex-venue.md#NODE-DEX-13)) |
| G-B3 | **Unbound claim races** | deterministic claimant (`claim_rank`) after a 2 s grace; fills published only at `mined`; on-chain `filled` arbitrates |
| G-B4 | **DEX trust farming** | credit only for settles sent by the home's own sole relayer, of orders visible ≥ 60 s in its signed book, with ≥ 5 counterparties not linked to its lanes, no self-trades; window 14 d; demotion 30 d on proof |
| G-H1 | **Hint poisoning / hint floods** | hints never change state ([NODE-GSP-11](gossip.md#NODE-GSP-11)); verified by the consumption read; signer gate (credited or trusted); separate RPC budget; false hints judged only at finality on a found receipt |
| G-A1 | **Announce replay / rollback; announce-cap filling** | strictly increasing `version`, `expires_at`; priority admission (connected/bus/trusted/track record), untrusted ≤ 4 per /24 |
| G-A2 | **Lane / relayer impersonation** | PoP signatures; shared lanes credit nobody |
| G-D1 | **Resource exhaustion on the swarm** | connection limits; QUIC/yamux windows; gossipsub handler queue 128 with timeouts; bounded validation queue; RPC budgets; payload caps before parse |
| G-D2 | **Amplification via sync** | 1 full sync per peer per 60 s, 2 MiB/s global egress, 1 MiB responses, public rows only |
| G-P1 | **Harvest-now-decrypt-later** | X25519MLKEM768-only on QUIC and HTTPS ([NODE-GSP-03](gossip.md#NODE-GSP-03)); TCP+Noise carries public data only; bus peers QUIC-only |
| G-P2 | **Future live forgery (quantum)** | not mitigated (Ed25519); seam in [gossip.md#transport](gossip.md#transport) |
| G-X1 | **SSRF via network addresses** | global-unicast filter on network-learned addresses; admin/toml addresses bypass it (no global `allow_private_addrs` needed for VPC partners); identify advertises only `external`; announce URLs never dialed ([NODE-GSP-09](gossip.md#NODE-GSP-09), [NODE-GSP-12](gossip.md#NODE-GSP-12)) |
| G-L1 | **Lane ↔ node linkage** | accepted side channel ([gossip.md#announce](gossip.md#announce)) |
