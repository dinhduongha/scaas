# Runbooks: RACI, incidents, backup/restore/DR, cutover, production gates

Recommended procedures for whoever runs a node ([NODE-OPS-15](ops.md#NODE-OPS-15)); default numbers are approved
defaults ([NODE-OPS-16](ops.md#NODE-OPS-16)). Status: **SPECIFIED** (the CLIs `store init`/`store restored` and the
cold-start `plan()` are BUILT).

## RACI

<a id="raci"></a><a id="NODE-RUN-01"></a>**NODE-RUN-01** — **RACI roles**: node operator, key_custodian, issuer,
compliance, guardian, rateAdmin, ERP admin, owner/SCaaS team. Recommended in production: `key_custodian` and `admin`
are **different people**; guardian, rateAdmin, issuer and compliance are **different keys**. Not enforced (the role
model allows one person on a dev box, [NODE-ADM-04](admin-auth.md#NODE-ADM-04)). A key-custodian-only user can grant
only its own roles, so `operator`/`admin` users are created with the host CLI by the node operator with the key
custodian's approval; the second person on `fee_recipient` changes is procedural (the audited change is checked
against `ScaasFeeRecipientChanged`). Two-person control between "mint credentials" and "change fee recipient" is the
cheapest defence against admin misuse ([threat-model.md#node](threat-model.md#node) T14); if not followed, the risk is
disclosed.

SCaaS means the smart contracts themselves are the API services that run the business services; the node is
infrastructure anyone can run to reach them. **Operating, monitoring and paging a node is accountable to whoever runs
that node** (customer, partner, third party, or the SCaaS team for its own nodes); the SCaaS team ships contracts,
software and the recommended `scaas/ops` bundle.

| Role | Who | Holds | Cannot |
|---|---|---|---|
| **Node operator** (NO) | whoever runs `scaas-node` (independent; sets its node's policies) and its on-call | host, `node.toml`, lane keystore passphrase, admin roles `viewer`/`operator`/`admin`, host CLI | mint client credentials through the API (needs `key_custodian`) |
| **key_custodian** (KC) | named person(s) in the operator organisation, not the `admin` holder in production | `key_custodian` role; `master_key` and lane-mnemonic custody (Shamir shares or KMS) | change chain config (unless also `admin`) |
| **Issuer** (IS) | token creator / asset issuer | on-chain `issuer` of regulated tokens; chooses guardian and rateAdmin; holder disclosures | move funds without a compliance record |
| **Compliance** (CO) | issuer's compliance function | on-chain `compliance`; client-side compliance officer (erasure) | execute orders |
| **Guardian** (GU) | issuer's on-call key | multi-underlying `disableWrap` only | re-enable, mint, move funds |
| **rateAdmin** (RA) | a multisig/timelock contract | propose/cancel/execute rate, renounce | act within `rateDelay`, exceed `maxRateStepBps` |
| **ERP admin** (EA) | system administrator of the client ERP | API key entry, push/sync jobs, per-chain cutover switch, store-change acknowledgement, DB neutralisation | node configuration ([NODE-ADM-06](admin-auth.md#NODE-ADM-06)) |
| **Owner / SCaaS team** (OW) | product owner and SCaaS engineering | contracts, releases, docs, recommended defaults, `scaas/ops`, factory registrar multisig, audits | operate, monitor or set policy for another operator's node; hold its keys |

Organisational functions (security, legal, finance) sit inside these roles. Matrix (R responsible · A accountable · C
consulted · I informed · — not involved):

| Operation | NO | KC | IS | CO | GU | RA | EA | OW |
|---|---|---|---|---|---|---|---|---|
| Lane key rotation (drain, `PUT …/lanes`, refund to treasury) | A/R | R (new key) | — | — | — | — | I | C |
| `master_key` rotation (revokes all API keys and sessions) | A | R | — | — | — | — | R (new keys) | I |
| Client API key create/rotate/revoke | C | A/R | — | — | — | — | R (enters it) | — |
| `operator`/`admin` users (host CLI) | R | A (approves) | — | — | — | — | — | — |
| `key_custodian`/`viewer` users (API) | I | A/R | — | — | — | — | — | — |
| Node identity key rotation (new `peer_id`, partners re-pin) | A/R | R | — | — | — | — | — | I |
| Chain pause / resume; chain halt | A/R | — | I | I (halt) | — | — | I | C (halt) |
| Breaker reset, fee-cap raise, gas budget / breaker parameters | A/R | — | — | — | — | — | I | C |
| Regulated token pause / unpause | I | — | A/R | C | — | — | I | — |
| `disableWrap` on a multi-underlying leg | I | — | A | — | R | — | I | I |
| Rate change propose / execute / cancel | I | — | A | C | — | R | I | — |
| `renounceRateAdmin` / `renounceGuardian` | — | — | A | C | R (own role) | R (own role) | — | — |
| Token registration / intake pause (`active`) on a node | A/R | — | C | — | — | — | I | — |
| `fee_recipient` change | A/R | C (second person, procedural) | — | — | — | — | — | — |
| Node policies (acceptance, fees, sponsorship, gossip, peers, mesh peer URLs) | A/R | — | C (own tokens) | — | — | — | C | — |
| Chain enablement `draft → active` on a node (production-gate evidence) | A/R | — | — | — | — | — | I | C (publishes evidence) |
| Cutover per chain / rollback | C ([cutover](#cutover) preconditions) | — | — | — | — | — | A/R | C |
| Store restore (node side, chains start paused) | A/R | R (re-revoke / rotate) | I | — | — | — | I | C |
| Restore acknowledgement, cancels and re-push (client) | C | — | — | — | — | — | A/R | — |
| Chains resumed after restore (after every EA ack) | A/R | — | — | — | — | — | C | — |
| Regulator order on a regulated token | I | — | R (freeze, execute) | A/R (record) | — | — | I | — |
| Regulator order on a permissionless token / denylist add or lift | A/R (order addressed to it) | — | I | C | — | — | I | I |
| Erasure request (client data) | I | — | — | A/R | — | — | R | — |
| Incident: node / store / chain / lane | A/R (commander) | C | I | — | — | — | I | C |
| Incident: token (backing, depeg, code hash, forced transfer) | R (watch, evidence) | — | A (commander) | R | R | C | I | C |
| Incident: software defect in a release | A/R (own node: roll back) | — | I | — | — | — | I | A/R (fix, release) |
| Post-mortem | R | C | C | C | — | — | C | A (defects) / C |
| Release upgrade of the node; DR drill | A/R | R (drill: shares, keys) | — | — | — | — | R (drill ack) | C / I |
| Monitoring, alert routing and paging of a node | A/R | — | — | — | — | — | I | — |
| Recommended rules, dashboards, scripts (`scaas/ops/`) | C (adopts or changes) | — | — | — | — | — | — | A/R |

Organisation-level view (security = CISO, legal and compliance, finance = CFO):

| Decision / task | Contract engineering | Security (CISO) | Legal & compliance | Finance (CFO) | Node operator |
|---|---|---|---|---|---|
| Implement and test contracts | R | C | I | I | I |
| Register a new implementation version in the factory | C | A (after independent audit) | C | I | R (registrar multisig signer) |
| Enable a chain (`draft → active`) | C | A | A | I | R |
| Open read-in of chain data to analytics (land gate phase 2) | I | C | A | I | R |
| Set gas and sponsorship budgets | C | I | I | A | R |
| Emergency pause of a chain / breaker override | C | A | I | C | R |
| Lane key, KMS/HSM and MPC custody | C | A | I | I | R |
| Admin users and external-client API keys (key_custodian) | I | A | I | I | R |
| Controlled-token interventions (court orders) | I | C | A | C | R (submits the quorum transaction) |
| Curve / confidentiality horizon for a Zether token | C | A | C | C | I |
| Store restore and re-push acknowledgement | I | C | I | I | A/R |

Human approval is mandatory (never delegated to an agent) for: opening the land gate, the confidentiality horizon,
credit/gas budgets per agent, registering a new factory implementation, controlled-token interventions.

## Incidents

<a id="incidents"></a><a id="NODE-RUN-05"></a>**NODE-RUN-05** — **Incident command = the accountable role of the
failing component**: node operator for node, store, chain and lane; issuer (with compliance for regulated tokens) for
tokens; owner/SCaaS team for release defects. Evidence first; never auto-cancel held or signed jobs (a broadcast tx can
still land); never rewind silently; communication from prepared templates. Escalation path in the matrix above.

| T | Action | Owner |
|---|---|---|
| T+0 | P1 alert (W3B breach, wrapper reserve below supply, foreign nonce on a lane, audit-chain mismatch) | on-call |
| T+1 min | Preserve evidence: node logs, `/metrics` snapshot, store backup, `audit_log` head | on-call |
| T+5 min | `PUT /v1/admin/chains/{key}/state paused` (stops new submissions; indexing continues) or `halted` (also stops indexing, for chain faults); pause DEX markets | operator |
| T+10 min | Rotate affected credentials: external-client API keys (`generation + 1`), admin users (disable, reset password — bumps `session_epoch`), OIDC service accounts at the IdP, `master_key` if the store or host is suspect; drain and replace lane keys (move gas to new lanes) | key_custodian |
| T+15 min | Declare or dismiss a security breach | CISO |
| T+30 min | Legal review of notification duties under the applicable data-protection regime | legal |
| T+60 min | Root cause; decide resume / wind-down of the affected token or chain | CISO + engineering |
| T+24 h | Post-mortem | all |

Contract-level response is limited by design: permissionless tokens have **no pause**. Containment is off-chain (stop
relaying, pause markets) plus user communication; a controlled token may use its bounded pause
([contracts/asset-suite.md](../contracts/asset-suite.md)).

Normal failure behaviour (no runbook needed):

| Situation | Behaviour |
|---|---|
| Node down | jobs stay `queued`; signatures live until `validUntil`; on expiry the client marks the request `dead` and its request stays `open`, so the subject can re-sign on the same lane |
| Node dies after broadcast, before the journal update reached the client | on restart: our `nonce_leased` job without `tx_hash` ⇒ back to `queued` ⇒ simulate ⇒ if already executed, `MetaTxBadNonce` ⇒ `dead` (or `consumed`); the feed still makes the job `final` from the event |
| Simulation revert (insufficient balance, expired, bad signature) | job `dead` + decoded `last_error`; the business request stays `pending`; the subject re-signs after funding |
| Stuck transaction | replacement at the same nonce, fees × 1.25 every `stuck_after_secs`, up to the cap `max_fee_cap`; never abandon a nonce — a dropped job ⇒ gap-filler at the same nonce |
| On-chain revert (state changed between simulation and inclusion) | `reverted`; the meta-tx nonce is **not** consumed (the token bubbles the revert); the subject's intent can be landed again |
| Reorg before finality | invisible to clients: only final ranges are sent |
| Reorg after hard finality | outside the model (Gnosis `finalized`, one-signer Clique); no automatic reversal of bookings ([NODE-IDX-03](indexer-feeds.md#NODE-IDX-03)) |
| RPC endpoints disagree | quorum not met ⇒ the indexer holds, `/readyz` red |
| Lost race / consumed jobs | not incidents; they resolve to `final` (landed elsewhere) or `dead` (superseded) by the normal rules |

### Common

Evidence first (T+1 min), before any change. The evidence directory is mode 0700 on an encrypted volume and deleted
when the incident closes (≤ 30 d):

```bash
CFG=/etc/scaas/node.toml; NODE=http://127.0.0.1:9108; E=/var/lib/scaas-evidence/$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$E" && curl -fsS $NODE/metrics > "$E/metrics.txt"; curl -sS $NODE/readyz > "$E/readyz.json"
journalctl -u scaas-node --since -2h -o cat > "$E/node.log"        # or the container's log
sqlite3 /var/lib/scaas/node.db "VACUUM INTO '$E/node.db'"          # PG: pg_dump -Fc; MySQL: mysqldump --single-transaction
```

Admin session (password never in argv) and helper used below:

```bash
read -rs PW; T=$(jq -n --arg n "$ADMIN" --arg p "$PW" '{name:$n,password:$p}' \
  | curl -fsS -X POST $NODE/v1/admin/login -H 'Content-Type: application/json' -d @- | jq -r .token); unset PW
adm() { m=$1 p=$2; shift 2; curl -fsS -X "$m" "$NODE$p" -H "Authorization: Bearer $T" -H 'Content-Type: application/json' "$@"; }
```

Request bodies: chain state `{"state": "active|paused|halted", "reason": "…"}`; breaker reset `{"lane": "<label>|*",
"breaker": "<name>|*"}`; chain patch with `breaker` merged (JSON merge patch).

#### RB-01 node down or not ready

<a id="rb-01-node-down-or-not-ready"></a>

1. `curl -sS $NODE/readyz | jq .reasons` — `rpc:` ⇒ RB-05; `indexer lag`/`finality violated` ⇒ RB-06; `store` /
   `not owner` ⇒ RB-07; `lane … used outside this store` ⇒ RB-04; `audit chain broken` ⇒ RB-10; `issuer failed
   closed` ⇒ OIDC (fix the IdP or `modes`). A single chain not ready is P2 (`ScaasChainNotReady`), not a node page.
2. Process down: `systemctl status scaas-node`; "store missing" ⇒ the volume is not mounted — **never** run `store init`
   on a production host (it creates an empty store; every client halts on the new `store_id`).
3. Disk low: grow the volume, never delete store files. Restart loop or memory: evidence, roll back to the previous
   release (OW informed), open a defect.

#### RB-02 breaker open

<a id="rb-02-breaker-open"></a>

1. `adm GET /v1/admin/chains/$C/lanes | jq '.[] | {lane, balance, breaker}'`.
2. `balance_floor` ⇒ RB-14 (closes after funding). `gas_budget` ⇒ wait for the next UTC hour, or the finance owner
   approves: `adm PATCH /v1/admin/chains/$C -d '{"breaker": {"gas_budget_per_hour": "…"}}'` (merge patch).
   `base_fee_spike` ⇒ wait; reset only if understood: `adm POST /v1/admin/chains/$C/breaker/reset -d
   '{"lane":"*","breaker":"base_fee_spike"}'`. `revert_streak` ⇒ RB-16 first (it survives restarts).
3. All lanes open (P1): work is held, nothing is lost; tell clients via the status page if > 30 min.

#### RB-03 stuck lane

<a id="rb-03-stuck-lane"></a>Symptom: `scaas_lane_head_stuck_seconds` high, `ScaasFeeCapReached`, W3B-01 burn.

1. `adm GET /v1/admin/jobs?chain=$C&state=broadcast` — lowest `outer_nonce` per lane; compare with `nonce_at(latest)`.
2. EVM at the cap: raise for this chain (hot): `adm PATCH /v1/admin/chains/$C -d '{"max_fee_cap_gwei": 1000}'`
   (finance informed), or wait. **Never** abandon the nonce (NODE-GEN-03) or re-sign the intent (NODE-GEN-05).
3. Nonce gap (head nonce has no tx on any endpoint): restart — cold start `plan()` gap-fills journaled nonces not in
   the mempool and requeues their jobs.
4. Head is an **adopted** nonce ([NODE-RUN-03](#NODE-RUN-03), no job row): the lane replaces it with a 0-value self-send
   at that nonce, bumped like any journaled tx; check `scaas_submit_replacements_total{kind="gapfill"}`. Not replaced ⇒
   defect (OW).
5. Generic lane (one tx in flight): check the family explorer for the journaled hash; Solana durable nonce account
   readable; Sui gas objects not locked.
6. Lane unrecoverable: `adm PUT /v1/admin/chains/$C/lanes -d '{"lanes":[…without it…]}'` (`409 LANE_BUSY` until its rows
   are terminal), restart, drain its balance to treasury.

#### RB-04 foreign nonce

<a id="rb-04-foreign-nonce"></a>Symptom: `ScaasLaneForeignNonce`, `/readyz` "lane … used outside this store". The lane
refuses to lease (correct).

1. Who else signs with this key? A second `scaas-node` on a copied mnemonic, a restored old store, a manual wallet send.
   `scaas-node addresses --config $CFG` on every host holding the mnemonic; explorer txs after `journal_max`.
2. Second user or unknown sender ⇒ the mnemonic is **exposed**: KC creates a new one, NO moves every lane (RB-03 step
   6) and drains old lanes; security incident.
3. Only after a restore of this store (RB-08), with node stopped: `scaas-node lane accept-nonce --chain $C --lane $L
   --config $CFG` without `--confirm` prints the adopted nonces; **any nonce whose digest matches no job of the restored
   store and no tx we sent ⇒ step 2**. Otherwise rerun with `--confirm <pending−1>`.
4. `ScaasConsumedOnPrivate` (P3) is the soft version: find the relayer from `MetaTransactionExecuted.relayer`.

#### RB-05 RPC divergence

<a id="rb-05-rpc-divergence"></a>

1. `curl -fsS $NODE/metrics | grep -E 'scaas_rpc_(head_lag|requests)'` — which `endpoint` lags, errors or disagrees.
2. Compare the block hash at the disputed height on every endpoint and one independent explorer.
3. Lying or forked endpoint: remove it from `rpc_urls` (toml-only), keep `len ≥ quorum` (add a replacement first),
   restart. Divergence with a correct endpoint set ⇒ RB-06.
4. The indexer holds while the quorum disagrees (NODE-GEN-08): nothing is booked; submission continues.

#### RB-06 chain halt or finality violation

<a id="rb-06-chain-halt-or-finality-violation"></a>Chain halt (network stalled, `ScaasIndexerStalled`, final-head age
rising on every endpoint):

1. Confirm on the network's status channel and two explorers.
2. `adm PUT /v1/admin/chains/$C/state -d '{"state":"paused","reason":"network halt"}'` — stops leasing, keeps indexing
   and tracking; jobs expire by `valid_until`. Do not bump or cancel broadcast txs. Resume with `"active"` after 5 min
   of steady head growth.

Finality violation (`ScaasFinalityViolated`, `/readyz` "finality violated at <block>"; the hold survives restarts):

1. Evidence; `adm PUT /v1/admin/chains/$C/state -d '{"state":"halted","reason":"finality violation"}'`.
2. Find the first differing final block with the quorum; every event at or after it is suspect.
3. Inform every ERP admin of a namespace granted the chain; clients reverse or re-verify bookings manually. **No
   automatic rewind** ([NODE-OPS-12](ops.md#NODE-OPS-12)).
4. After OW review: stop the node, `scaas-node index reset --chain $C --to <block> --confirm <block> --config $CFG` (not
   `store restored`), start. Every client resets its event cursor for the chain to `<block>` first; dedup by
   `(chain_key, tx_hash, log_index)` absorbs the rest.

#### RB-07 store owner loss

<a id="rb-07-store-owner-loss"></a>Symptom: `ScaasFencingLost`, `NOT_OWNER` (503), `ScaasStoreCommitUnknown`.

1. The node stops leasing/journaling and re-takes the lock with a new epoch ([store.md#backends](store.md#backends)); if
   it cannot, another process holds it: SQLite `fuser -v /var/lib/scaas/node.db.lock`; PostgreSQL `SELECT pid,
   application_name, client_addr FROM pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype =
   'advisory')`; MySQL `SELECT IS_USED_LOCK('scaas-node:<store_id>')`.
2. Stop the intruder (a second unit, a test container with the production `[store] url`); the node re-takes the lock;
   `scaas_store_owner_epoch` increases. PgBouncer in front of PostgreSQL is refused by design.
3. Repeated commit-unknown: database or network fault; re-read-before-act keeps it safe; fix the transport.

#### RB-08 restore

<a id="rb-08-restore"></a>Only when the store is lost or corrupt (not for a bad config change). Sequence
[NODE-RUN-02](#NODE-RUN-02), commands in [backup and DR](#backup-dr). Clients halt; chains stay paused until their ERP
admins have acknowledged.

#### RB-09 compromised API key

<a id="rb-09-compromised-api-key"></a>

1. `scaas-node key revoke $KEY_ID --config $CFG` (or `adm DELETE /v1/admin/keys/$KEY_ID`, KC) — hot, ≤ 2 s.
2. Scope: `adm GET "/v1/admin/audit?since=…"`, logs by `key_id`, `adm GET "/v1/admin/jobs?namespace=$NS"`. A key cannot
   forge subject signatures; it can push jobs of its namespace (`call` jobs if `allow_call`), cancel unpublished jobs,
   read the namespace feeds (pseudonymous payment data: legal assesses notification).
3. Cancel unwanted queued jobs: `adm POST /v1/admin/jobs/$UID/cancel`. Signed jobs run to completion.
4. KC issues a new key (`scaas-node key create --namespace $NS --scopes "submit read"`), EA enters it. Client server
   compromised ⇒ `adm PATCH /v1/admin/namespaces/$NS -d '{"state":"suspended"}'` until cleaned.

#### RB-10 compromised admin

<a id="rb-10-compromised-admin"></a>

1. `scaas-node admin disable $NAME --config $CFG` (bumps `session_epoch`). OIDC: disable the subject at the IdP; if the
   IdP is suspect remove the issuer from `[api.admin_auth]` and restart.
2. Review `adm GET "/v1/admin/audit?since=<last trusted>"`: `fee_recipient`, tokens, lanes, mesh peers and URLs,
   policy, sponsorship, namespaces, denylist, users, keys. Revert each change through the same routes.
3. `ScaasAuditChainBroken` ⇒ the store was edited outside the node: host compromised: evidence, rotate `master_key`,
   rotate lane keys, restore from a backup older than the break if config was altered (RB-08), security incident.
4. Rotating `master_key` revokes every client API key and session at once: EA re-enters new keys.

#### RB-11 wrapper shortfall or depeg

<a id="rb-11-wrapper-shortfall-or-depeg"></a>Shortfall (`scaas_wrapper_leg_backing_ratio < 1`: blacklist burn,
negative rebase, confiscation, bug):

1. Evidence: `adm GET /v1/admin/chains/$C/watch`; confirm `legOf(u)` and `underlying.balanceOf(token)` on two
   endpoints.
2. Issuer (commander) informs holders; the app shows per-leg backing before a wrap. Wrap into other legs is **not**
   stopped by the contract: the issuer asks integrators to pause intake; the guardian may `disableWrap` the leg.
   Permissionless token: migration to a new token is the remedy ([emergency](#emergency)).

Depeg on a multi-underlying leg (external price signal):

1. Guardian submits `disableWrap(u, reason)` **privately** (private relay or builder bundle), never through the public
   mempool or an open-mesh job.
2. Exits stay open; no re-enable exists (a new token if the leg must return). RA cancels pending rate changes during the
   incident (`RateDecreaseWithDisabledLeg` blocks decreases anyway).

#### RB-12 code-hash change

<a id="rb-12-code-hash-change"></a>

1. The `watch-code-hash` script's state file names the role, old and new hash/implementation.
2. Underlying upgraded: the issuer reviews the new behaviour (freeze, fee-on-transfer, rebase). Until reviewed, NO may
   pause intake for the token: `adm PATCH /v1/admin/chains/$C/tokens/$TOKEN -d '{"active": false}'` — every op refused
   (unwraps included: use when the risk outweighs blocking exits), **indexing continues**. Never `DELETE` the token for
   this: that drops its events from the feed for good (re-registration needs `index reset`).
3. Role contract changed (Safe upgraded, guardian contract): verify with the role owner; accept with `watch-code-hash
   --repin --chain $C --token $TOKEN`.
4. Token or registry code changed: impossible for EIP-1167 clones ⇒ wrong address or lying RPC ⇒ RB-05.

#### RB-13 regulator order

<a id="rb-13-regulator-order"></a>Regulated token:

1. Legal validates the order. CO records it: `recordOrder(orderId, docHash, subject, beneficiary, maxAmount)` from the
   compliance multisig (optionally submitted as a `call` job by the issuer's namespace, through its role-holder
   contract).
2. IS asks NO in writing for a silence of `ScaasForcedTransfer` with matchers `chain` **and `token`** for the planned
   window; NO creates it (the other tokens keep paging).
3. IS: `freeze(subject, ref)`, then `forceTransfer(recordId, amount)` ≤ `maxAmount`; `unfreeze` when the order says
   so; CO `revokeOrder` stops further execution.
4. `OrderRecorded` without a matching internal record (`ScaasWatchedEvent`) ⇒ compliance key compromise: CO revokes the
   record, rotates the multisig signer, IS refuses execution.

Permissionless token: no on-chain power exists; the order binds the operator it is addressed to. After its legal
validates the order, the operator lists the party ([NODE-OPS-14](ops.md#NODE-OPS-14)): `adm POST /v1/admin/deny -d
'{"chain_key":"*","address":"0x…","order_ref":"…","document_sha256":"<64 hex>"}'`; lift with `adm POST
/v1/admin/deny/$ID/lift -d '{"lift_ref":"…"}'`. Other operators and self-submission still reach the contract; legal
answers with that limit stated. `ScaasDenylistChanged` is checked against the order register.

#### RB-14 runway

<a id="rb-14-runway"></a>

1. `scaas-node addresses --config $CFG`; fund from treasury to the float target (~50 tx); the `balance_floor` breaker
   closes on the next 15 s sample.
2. Runway falling at flat volume ⇒ fee regime changed (base-fee spike, rollup L1 data fee): finance reviews budget.
3. Sponsor budget exhausted: the policy follows `on_exhausted`; the sponsor owner raises it (`adm PATCH
   /v1/admin/sponsorship/policies/$ID`) or accepts rejects.

#### RB-15 feed client stalled

<a id="rb-15-feed-client-stalled"></a>

1. `scaas_job_api_requests_total{namespace=$NS}` — none ⇒ client stopped; `401` ⇒ key revoked or clock skew (> 300 s,
   NTP); `410 CURSOR_EXPIRED` ⇒ client recovery ([indexer-feeds.md#cursors](indexer-feeds.md#cursors)).
2. Client side: its push and sync jobs active, its node record's attention flag (store change ⇒ acknowledge after RB-08
   confirmation), the last error ([integration.md#runbook](../integration.md#runbook)).

#### RB-16 simulation-gap revert

<a id="rb-16-simulation-gap-revert"></a>

1. `adm GET "/v1/admin/jobs?chain=$C&state=reverted"`; logs by `job_uid` (`span=scaas.job.simulate` vs `include`).
2. State changed between simulation and inclusion (front-run, attestation expiry, pause) ⇒ expected drift, document;
   simulation on a different block/endpoint ⇒ RB-05; an error simulation should have seen ⇒ defect (OW): keep
   `revert_streak` open, pause the chain if needed.
3. Reset after explanation: `adm POST /v1/admin/chains/$C/breaker/reset -d '{"lane":"*","breaker":"revert_streak"}'`.

#### RB-17 gossip degraded

<a id="rb-17-gossip-degraded"></a>

1. `adm GET /v1/admin/gossip` (mesh size per topic), `adm GET /v1/admin/gossip/peers` (scores, carriers).
2. Zero peers: bootstrap multiaddrs (toml), UDP/TCP 4001 reachability, `scaas_tls_handshake_failures_total` (PQ-only
   QUIC vs classical peers). Thin mesh with healthy peers: graylisting from our own rejects (version skew) — upgrade or
   check the clock.

## Emergency

<a id="emergency"></a>Circuit breakers and emergency procedures:

- Automatic breakers: [submit-lanes.md#breaker](submit-lanes.md#breaker). They stop new work, never rescues,
  gap-fillers, tracking or indexing (NODE-GEN-09).
- **Stuck outer transaction:** automatic replacement at ×1.25 every `stuck_after_secs` up to the fee cap; at the cap the
  operator may raise `max_fee_cap_gwei` (hot) or wait; never abandon the nonce.
- **Foreign nonce on a lane** (key used elsewhere): the lane stops leasing; the operator verifies no second store or
  wallet uses the key, then retires the lane (RB-04).
- **Store fencing lost:** the node stops leasing/journaling immediately (`NOT_OWNER`), re-takes the lock with a new
  epoch, replays `plan()` (RB-07).
- **RPC disagreement:** quorum not met ⇒ indexer holds, `/readyz` red; add or replace endpoints (toml, restart).
- **Wrapper reserve mismatch:** stop relaying for the token, notify holders; no admin key exists to "fix" a
  permissionless token — migration to a new version is the remedy.
- **Lost race / consumed jobs:** not incidents; they resolve to `final` (landed elsewhere) or `dead` (superseded).

## Backup and DR

<a id="backup-dr"></a><a id="NODE-RUN-02"></a>**NODE-RUN-02** — **Restore is one fixed sequence and starts paused**:
stop → evidence → restore → integrity check → `store restored` (bumps `restore_epoch`, **sets every chain `paused`**,
runs the retention purge, audited) → `lane accept-nonce` for every sequence-family lane (refuses where nothing is to
adopt) → start (paused chains accept, index and track, never lease) → re-apply, through the admin API, every
security-relevant mutation newer than the backup point from the off-host audit events (key revokes, admin disables,
deny add/lift, token `active`/removal, chain state, `fee_recipient`, namespace suspension, peer bans) **or** rotate
`master_key` → each ERP admin acknowledges; the acknowledgement also posts `cancel {origin}` for every job the client
holds as dead/cancelled whose node snapshot is live → the node operator resumes each chain after every namespace granted
it has acknowledged. A restored store holds as `queued` jobs that were cancelled after the backup point, and
`max_valid_for_secs` (3 600 s) outlives the RTO; leasing before the client reconciles would execute stopped payments.
Cost: one manual resume per chain.

<a id="NODE-RUN-03"></a>**NODE-RUN-03** — **CLI `scaas-node lane accept-nonce --chain <key> --lane <label> --confirm
<n> --config node.toml`** (sequence families; node stopped; owner lock, epoch + 1). Reads `nonce_at(latest)` and
`nonce_at(pending)` from **every** configured endpoint (all must answer) and uses the **maximum** `pending` (on Cosmos,
Aptos, Soroban and TON `pending` = the committed sequence). **Refuses unless `pending − 1 > lane.journal_max`**
(monotonicity). Prints every nonce in `[journal_max + 1, pending)` with its tx hash, `to`, and whether its meta-tx
digest matches a job of the restored store; requires `--confirm` = `pending − 1`; sets `lane.journal_max` and inserts one
`lane_adopted (chain_key, lane_label, nonce, tx_hash, adopted_at)` row per adopted nonce, audited. The lane tracks
adopted nonces like journaled ones: a stuck adopted head is replaced by a 0-value self-send at that nonce, bumped ×1.25
over the observed fee (the lost intents were re-pushed by clients and stay protected by subject nonces); rows are
deleted once `latest` passes them. Sui and Solana have no lane nonce: after `store restored` the lane re-reads its gas
objects (and waits until none is locked by a pending certificate) or its durable-nonce account at start and never
re-sends journaled bytes from the restored store. After a restore the chain is ahead of the journal by design; the
foreign-nonce check refuses such a lane, and the only other way out is a new lane. An operator could adopt a nonce
advanced by a second user; the unmatched-digest listing makes that visible (RB-04).

RPO = after loss of the store's disk (on the same disk every committed journal transaction is durable). RTO = start of
restore → `/readyz` green, for a store ≤ 20 GB ([ops.md#capacity](ops.md#capacity)). Backups and copies are encrypted
and kept ≤ 7 d.

| Backend | Continuous | Periodic | RPO | RTO | Reason |
|---|---|---|---|---|---|
| SQLite | Litestream (WAL shipping to an S3-compatible bucket, `sync-interval: 1s`) | `VACUUM INTO` every 5 min to a second disk, last 24 kept; one daily copy off-site | ≤ 10 s with Litestream; ≤ 5 min without | 30 min | `VACUUM INTO` is one consistent statement (the CLI `.backup` restarts under concurrent writes); the owner lock is on `<db>.lock`; Litestream is external |
| PostgreSQL | WAL archiving (`archive_mode = on`, `archive_timeout = 60`), pgBackRest or `pg_basebackup` + `archive_command` | daily base backup | ≤ 60 s (0 with a synchronous standby) | 30 min | PITR is per cluster: give the store its own cluster |
| MySQL 8 | binlog (`ROW`, `sync_binlog = 1`) streamed off-host (`mysqlbinlog --read-from-remote-server --raw --stop-never`) | daily XtraBackup or `mysqldump --single-transaction` | ≤ 60 s | 45 min | binlog replay is slower than WAL replay |

| Component | RPO | RTO | Mechanism |
|---|---|---|---|
| Node store | 0 for committed journal (SQLite `synchronous = FULL`; PG/MySQL durable commit); backups ≤ 5 min | 30 min | restore on another host, then **mandatory** `scaas-node store restored`; clients halt sync until an operator acknowledges; re-push is an operator action; re-revoke keys revoked after the backup or rotate `master_key` (T19) |
| Lane state | — | minutes | cold start `plan()`: gap-fill journaled nonces, track signed txs, requeue the rest; never re-sign a tracked tx; after restore `lane accept-nonce` |
| `master_key`, lane mnemonic | must never be lost | 15 / 30 min | secret store or KMS; Shamir 2-of-3 held by KC (or KMS-native backup of lane mnemonics); loss ⇒ re-issue every API key and session / new lanes, lane gas lost |
| Node identity key | — | 30 min | secret store; loss ⇒ new `peer_id`; bus partners re-pin SPKI |
| `node.toml` | per change | 15 min | version control without secrets (secrets are references) |
| Logs (off-host) | stream | — | ≤ 30 d; needed for the post-backup audit replay |
| Private chain | 0 | 60 min | validator snapshots every 6 h + archive node; quarterly restore drill |
| Client outbox | per ERP database policy | per ERP | the outbox is the client's source of truth for "must go on chain" |
| Subject keys | — | — | passkey PRF backup, seed, guardians ([clients/signers-clientkeys.md](../clients/signers-clientkeys.md)); the operator holds none |

No hot failover for one (company, chain) in v1: two nodes may serve one company only on different chains. Backup
scripts write `scaas_backup_last_success_timestamp_seconds{backend}` and `scaas_backup_interval_seconds` to the
textfile collector (seeded with 0 at install).

What a restore loses and how it is recovered:

| Lost after the backup point | Recovered by |
|---|---|
| Jobs accepted after the backup | client re-push after acknowledgement (idempotent; [NODE-JOB-04](job-api.md#NODE-JOB-04)) |
| Cancels and client-side kills after the backup | chains start paused; the client acknowledgement re-sends `cancel {origin}` for jobs it holds dead |
| Journal entries (`signed`) after the backup | the chain: txs land or drop; `lane accept-nonce` adopts the nonces; **meta-tx and op jobs** are protected by subject nonces (G1); **`call` jobs** have no node digest and no subject nonce — a target qualifies for `allow_call` only if it enforces its own replay protection (`MandateWallet` `refUsed[entryRef]`, idempotent account deploy, DEX fills consumed, [NODE-JOB-09](job-api.md#NODE-JOB-09)), and paused chains give the client time to cancel |
| Feed items after the backup | indexer re-delivers from the restored `chain_index` (ranges idempotent) |
| Credential, denylist, token, chain-state, fee-recipient, namespace and peer changes after the backup | re-applied from the off-host audit events before resume; incomplete logs ⇒ rotate `master_key` |
| Purged rows resurrected by an old backup | `store restored` runs the retention purge before the node serves |
| Sponsor reservations | recomputed from live jobs at start |

Restore commands:

```bash
systemctl stop scaas-node
mv /var/lib/scaas/node.db /var/lib/scaas/node.db.broken-$(date -u +%s) 2>/dev/null   # evidence, never overwritten
litestream restore -o /var/lib/scaas/node.db s3://<bucket>/scaas/node.db             # or: cp <copy> node.db
sqlite3 /var/lib/scaas/node.db 'PRAGMA integrity_check'                              # must print "ok"
chown scaas:scaas /var/lib/scaas/node.db && chmod 0600 /var/lib/scaas/node.db
# PostgreSQL (into the store's own empty cluster): pgbackrest --stanza=scaas --type=time --target='<UTC>' restore
# MySQL: base backup, then mysqlbinlog --start-position=<from backup> --stop-datetime='<UTC>' binlog.0* | mysql scaas
scaas-node store restored --config $CFG               # restore_epoch + 1, every chain paused, purge; audited
for L in $(scaas-node addresses --config $CFG --chain $C --labels); do      # per sequence-family chain
  scaas-node lane accept-nonce --chain $C --lane $L --config $CFG; done     # review listing (RB-04 step 3), then --confirm
scaas-node key revoke <key_id> --config $CFG; scaas-node admin disable <name> --config $CFG   # from audit events
systemctl start scaas-node                            # paused: accepts, indexes, tracks; never leases
# re-apply post-backup deny / token active / fee_recipient / namespace / peer-ban changes through adm
# after every ERP admin of a namespace granted chain $C acknowledged (and sent its cancels):
adm PUT /v1/admin/chains/$C/state -d '{"state":"active","reason":"restore acknowledged"}'
```

`scaas-node addresses --labels` prints lane labels per chain. ERP admins acknowledge the store change and re-push
([integration.md#runbook](../integration.md#runbook)).

<a id="NODE-RUN-04"></a>**NODE-RUN-04** — **DR drills are scheduled, timed and exported**: each run writes
`scaas_dr_drill_last_success_timestamp_seconds{drill}` and `scaas_dr_drill_cadence_seconds{drill}` to the textfile
collector of the **production** node host (seeded with 0 at install, so a drill never run alerts); older than 1.5 ×
cadence ⇒ P3. An untested restore is not a restore.

| Drill (`drill` label) | Cadence | Pass criterion |
|---|---|---|
| `restore_<backend>` — latest backup to a scratch host, `store restored`, start paused against a testnet, acknowledge, resume | quarterly per backend in use | RTO met; no job leased before the acknowledgement; `/readyz` green |
| `lane_accept_nonce` — restore an older testnet backup, adopt nonces, land a new job | quarterly | listing shows every adopted nonce; no lane stuck after 10 min |
| `dead_man` — stop Prometheus | quarterly | external switch alerts within 10 min |
| `key_recovery` — reconstruct `master_key` and the lane mnemonic from shares offline | semi-annually | both reconstruct; shareholders reachable |

Optional when the risk applies: indexer kill (stall alert), lying RPC (divergence, no range written), guardian
`disableWrap` on a testnet multi-underlying token, cutover rehearsal (per production cutover). A failed drill is a P3
with an owner and a date. Tests: `accept-nonce` refuses when `pending − 1 ≤ journal_max`, when an endpoint is missing,
or with a wrong `--confirm`, and lists an unmatched digest; an adopted head is replaced by a gap-filler; restore drill:
a job cancelled after the backup point is never leased; start-time final-hash recheck on a forked devnet; audit
verification detects one edited row.

## Cutover

<a id="cutover"></a>Moving a chain from the legacy pull path to the store ([NODE-JOB-10](job-api.md#NODE-JOB-10)).
Preconditions (checked by the client before it flips the chain, [integration.md](../integration.md); worked example:
[migration from pull](../integration-odoo-example.md#migration-from-pull)):

1. Every client entity with a non-terminal job **or an approved receiving/paying wallet** on the chain has a route to
   the node; the chain's event node is set; secrets are set; the client's copy-protection binding matches.
2. `GET /v1/info`: `api ≥ 1`, chain granted, `state = active`; the client's active tokens ⊆ the node's tokens for the
   chain; every route's token subset pushed ([NODE-JOB-12](job-api.md#NODE-JOB-12)).
3. **Journal continuity**: for each lane the node reports, `journal_max ≥` the client's `max(outer_nonce)` for that
   signer. The transitional node bumps `lane.journal_max` on every successful legacy `signed` report (and imports it
   from each legacy configuration read), so this holds exactly, not "as of the last read".
4. DEX chain: every market paused, no `pending` trade; wait for `pending` trades to settle or fail on the legacy path,
   flip the chain, the transitional node imports open orders once via the legacy book load, resume markets in the node.
5. TON chain: the forward-TON cap ([NET-TON-14](../networks/ton.md#NET-TON-14)) is enforced, and payload-sourced
   fields, cost metering, value-out and deposit caps ([NODE-LANE-13](submit-lanes.md#NODE-LANE-13),
   [NODE-LANE-16](submit-lanes.md#NODE-LANE-16)–[NODE-LANE-18](submit-lanes.md#NODE-LANE-18)) are live before the
   first push cutover.

Effects: the chain flag becomes `push`. The legacy poll serves nothing for the chain; queued jobs are pushed; legacy
in-flight jobs keep reporting through the legacy report until terminal; a legacy job the old path requeues is pushed
like any other. The store indexer has been running for the chain since the transitional binary started (cursor
bootstrapped from the legacy indexed block); the straddle rule absorbs any misalignment. Rollback for a chain: flag back
to `pull`. New jobs go back to the pull path; pushed jobs stay with the node and keep syncing.

Proof criterion and one-step removal: all chains `push` ≥ 14 days; zero client jobs that were never pushed in
`nonce_leased/signed/broadcast`; no client "needs attention" state in that window; the push e2e suite green on the
release candidate. Then one node release and one client upgrade delete everything marked legacy; the client's
pre-migration aborts when any chain is still `pull`, and the final node refuses the legacy config section.

## Production gates

<a id="production-gates"></a>Standing rules before production funds (operator and owner steps; tasks are tracked
outside these docs):

- **Audits**: a third-party audit of every contract family before it holds real funds; confidential-payment contracts
  stay behind their dev gate until an independent cryptographic audit ([contracts/README.md#production-gates-unaudited](../contracts/README.md#production-gates-unaudited)).
  The factory registrar is a multisig, not an EOA, before mainnet.
- **Chain enablement** (`draft → active`, tooling PLANNED): only after (1) a working simulation path, (2) 7 days of
  measured finality depth on the real network, (3) ≥ 2 independent RPC endpoints for the quorum
  ([indexer-feeds.md#finality](indexer-feeds.md#finality)). Real deployments (chain 7622 — formerly 9000 — and Gnosis first, then the other
  families) are recorded per chain in `deployments/<chain>.json`.
- **Open gateway**: a per-IP rate limit at the reverse proxy in front of any gateway open to the public
  ([gateway.md#auth](gateway.md#auth)).
- **Custody**: production custody adapters (KMS/HSM/broker) for custodial or delegated client wallets — an env-held key
  is development only ([INT-ERP-08](../integration.md#INT-ERP-08)); a KMS/HSM signer for lane keys on public chains
  ([NODE-LANE-03](submit-lanes.md#NODE-LANE-03)).
- **Lane funding**: fund and monitor lane balances from a treasury (`scaas_relayer_balance`, RB-14); auto-refill is
  PLANNED.
