# Gas sponsorship

The node already pays gas for every job it lands. A **sponsorship policy** decides which account that gas is booked
to, how much of it is allowed, and whether a door's fee floor is waived. Status: policies, budgets, rate counts, feed
cost fields, admin routes and metrics **SPECIFIED**; `SponsorshipPool` **PLANNED**.

## Scope

<a id="scope"></a>In scope: node sponsorship policy — matching, fee-floor waiver, budgets, rate caps, accounting,
metrics, admin API; the node side of receiver-pays (a payee co-signature carried by the job,
[contracts/metatx.md#receiver-pays](../contracts/metatx.md#receiver-pays)); `SponsorshipPool`: the rule
([NODE-SPN-04](#NODE-SPN-04)) and the constraints its design must meet. Not in scope: a fee market or any in-protocol
mesh reward ([NODE-MESH-05](mesh.md#NODE-MESH-05) stays); fiat valuation in the node; receiver-pays on v1 tokens,
non-EVM families (no fee fields) and Zether tokens (hidden amounts).

Typical use: "inbound to wallet W, value ≥ X ⇒ accept with fee 0, book gas to account Y" (an inbound-payment subsidy
by the payee) and a tenant's cost control. Sponsorship is a node policy row, never a contract feature.

## Policy

<a id="policy"></a><a id="NODE-SPN-01"></a>**NODE-SPN-01** — **A sponsorship policy is a node store row that matches
jobs and (a) waives the fee floor of the door the job came through, (b) books its gas to a sponsor account, (c)
enforces that account's budget and rate caps.** It never changes a signed field and never adds a fee. Matching uses
only job data (no RPC at accept). Doors: client namespaces (no fee floor: the policy books and limits), `~gateway` and
`~mesh` (the mesh policy `min_fee` floor, [mesh.md#acceptance](mesh.md#acceptance), is waived for matching jobs; the
door-A defaults per profile are in [NODE-GW-01](gateway.md#NODE-GW-01)). Policies are data; nothing on chain depends
on them. One mechanism serves inbound subsidies ("to wallet W, value ≥ X ⇒ fee 0, gas to account Y") and tenant cost
control.

**Client namespaces: `unsponsored` means "booked to the namespace".** (A review finding said the node "silently spends
lane gas" on unmatched jobs: that is the namespace's default; what was missing was the statement and the mark.) The node pays gas for every client job and books
unmatched jobs to the namespace (`sponsor_policy_id NULL`, `usage_day.sponsor_policy = ''`), which is the tenant's own
billed spend; a fallback is that and nothing more, and is marked (`sponsor_fallback`, [feed](#feed); metric
`result="unsponsored"`), never booked to the sponsor account. A policy is therefore a cap on the **sponsor account** in
every case, and a cap on a **tenant's** spend only with `on_exhausted = reject` on a policy that covers the tenant's
jobs (e.g. `contract = '*'`, `selector = '*'`). The admin API refuses `unsponsored` on a client-namespace policy unless
the request sets `fallback_to_namespace: true` (stored in the audit row), so the fallback is a recorded decision.

**Value thresholds are token base units per (chain, token).** Conversion from a reporting currency is the client's
business (it pushes new rows when its rates change). The node holds no prices and no oracle; a stale threshold
sponsors slightly more or less.

Store tables `sponsor_policy`, `sponsor_usage` and the job columns `sponsor_policy_id`, `sponsor_reserved`,
`sponsor_day`, `sponsor_hour`, `sponsor_fallback`, `gas_used`, `gas_price`, `cost_native` are in
[store.md#schema](store.md#schema).

## Budgets

<a id="budgets"></a><a id="NODE-SPN-02"></a>**NODE-SPN-02** — **Budget unit = the family's smallest native unit**
(wei, tinybar, lamports, uatom-equivalent, MIST, octa, nanoton, stroops), measured from receipts (`gas_used ×
effective price`, or the family's fee field). Budget per UTC day; rate caps per hour per policy and per payer.
Admission reserves `max_cost_per_tx` per sponsored job and stores the reserved amount and day on the job; the
reservation is replaced by the measured cost, booked to that same day, at `mined`/`reverted`. A sponsored transaction
is built so that its maximum chargeable fee (`gas_limit × max_fee_cap` on EVM, fee bumps included) is `≤
max_cost_per_tx`, so measured ≤ reserved and a day's spend never exceeds its budget. **Rate counters are taken at
accept with the reservation**: the job stores `sponsor_hour`, the hour and payer-hour `tx_count` are checked and
incremented in the same transaction as the day reservation, and a job that ends before broadcast releases all three
(otherwise one payer could reserve a whole day's budget with jobs that never reach lease). A sponsored job needs
`valid_until ≥ now + p.min_valid_secs` (default 120) at accept, or it is not sponsored (`on_exhausted` decides), so
near-expiry jobs cannot cycle reservations. `on_exhausted ∈ {reject, unsponsored}`. Arithmetic at accept,
measurement at the end; no oracle. A too-low cap leaves some sponsored jobs `dead` (`SPONSOR_TX_CAP`); the client
re-pushes them unsponsored.

Cost per family: Hedera reports cost in tinybar from the record (gas price conversion is the network's); Cosmos the
`fee` coin of the outer tx; Sui `gasUsed` total; Aptos `gas_used × gas_unit_price`; TON total fees of the outer message
chain charged to the lane; Solana `meta.fee` (+ priority fee); Soroban `fee_charged` (stroops). Every family books and
limits at node level; `signed_op` matches on the decoded op; non-EVM families book and limit only (no fee floor to
waive).

## Evaluation

<a id="evaluation"></a>Matching and the budget reservation happen at accept on job data only (plus a local signature
check on public doors), with the rate counts; the fee cap at lease; booking at the end. The result is stored on the
job.

```
match(job) -> Option<policy>:                                  -- accept, after intake step 7
  candidates = active policies of job.chain_key, now within [valid_from, valid_to], ordered (priority, id)
  first p where  p.namespace ∈ {job.namespace, '*'}          -- '*' never matches '~mesh'/'~gateway' (explicit only)
             ∧ p.job_kind ∈ {job.kind, '*'}
             ∧ p.contract ∈ {contract_of(job), '*'}         -- metatx/signed_op: token_of; call: target
             ∧ p.selector ∈ {selector_of(job), '*'}
             ∧ (p.receiver IS NULL ∨ p.receiver == receiver_of(job))   -- call jobs: receiver must be NULL
             ∧ value_of(job) ≥ p.min_value                   -- call jobs: min_value must be '0'
admit(job, p):                                                 -- accept, inside the step-8 transaction
  public door (~gateway, ~mesh) ∧ metatx/signed_op ⇒ verify the payer signature locally (ECDSA secp256k1, Ed25519,
      P-256: no RPC); contract (ERC-1271) payers are not sponsored on public doors; bad signature ⇒ 422 BAD_SIGNATURE
  job.valid_until < now + p.min_valid_secs ⇒ ¬ok (TOO_SHORT)
  lock bucket rows: INSERT … ON CONFLICT DO NOTHING, then SELECT … FOR UPDATE (day, hour, payer-hour; SQLite: the
      single writer suffices)
  ok = day.cost_spent + day.cost_reserved + p.max_cost_per_tx ≤ p.budget_per_day        (BUDGET)
     ∧ hour.tx_count < p.max_tx_per_hour ∧ (p.max_tx_per_payer_hour = 0 ∨ payer-hour.tx_count < it)   (RATE)
  ok         ⇒ job.sponsor_policy_id = p.id, sponsor_reserved = p.max_cost_per_tx, sponsor_day = today,
               sponsor_hour = this hour; day.cost_reserved += sponsor_reserved;
               day/hour/payer-hour tx_count += 1
  ¬ok, reject      ⇒ 429 SPONSOR_BUDGET | SPONSOR_RATE | SPONSOR_TOO_SHORT {policy: p.name}
  ¬ok, unsponsored ⇒ no sponsor, sponsor_fallback = p.name; the door's normal fee floor applies
                     (client namespace: booked to the namespace)
no match ⇒ no sponsor; the door's normal fee floor applies
lease (after simulation succeeds):
  max chargeable fee of the tx as built (EVM: gas_limit × max_fee_cap) > job.sponsor_reserved ⇒ dead SPONSOR_TX_CAP
  fee bumps of a stuck tx stop at gas_limit × price = sponsor_reserved
end (mined/reverted): day(sponsor_day).cost_reserved −= sponsor_reserved; cost_spent += cost_native
end (dead/consumed-before-broadcast/cancelled): release the reservation and the three tx_count (buckets of
     sponsor_day/sponsor_hour, payer_of(job)), in the terminal transaction; lost races after broadcast book their
     measured cost and keep their counts
startup: cost_reserved recomputed as Σ sponsor_reserved of live jobs per sponsor_day (tx_count is transactional)
```

Payer (`payer_of`) for per-payer caps: `m.from` / op signer for metatx/signed_op; for `call` jobs to a registered
tender, `m.from` decoded from `commitBid` and the `bidder` argument of `revealBid`/`withdrawDeposit`; any other `call`
has no payer and its policy must set `max_tx_per_payer_hour = 0`. Live `call` jobs of one namespace with the same
target and calldata are refused (`job_live_call`, per namespace, [NODE-JOB-13](job-api.md#NODE-JOB-13)), so a retried
reveal or refund cannot be broadcast twice from one tenant; the `409 DUPLICATE_CALL` body carries the live job's `uid`
(same namespace, so it leaks nothing) and the client follows that job, or cancels it before publication and re-pushes.
Two namespaces may each hold the same tender call; the tender refuses the second (the bid is no longer `COMMITTED`, or
already `DONE`): simulation makes it `dead`, a lost race after broadcast books as `reverted`. Dedupe stays on live
states rather than signed ones: two queued copies in one namespace would otherwise both broadcast.

Fee floor per door: client namespaces — none (jobs are accepted as today); `~gateway` and `~mesh` — the `min_fee` of
the matching mesh policy row, compared with the effective fee ([NODE-MESH-13](mesh.md#NODE-MESH-13)). A sponsored
job's floor is 0. A policy never makes a job acceptable that the job-API intake or mesh acceptance would refuse for any
other reason (unregistered token, `support = none`, expiry, `allow_call`).

## Feed

<a id="feed"></a>Job feed items in states `mined`, `reverted` (and the final snapshot) add `gas_used`, `gas_price`,
`cost_native`, `sponsor: {policy, account} | null`, and `sponsor_fallback: <policy name> | null` (a policy matched but
was exhausted and `on_exhausted = unsponsored`). Clients book `cost_native` (converted at transaction time to the
reporting currency) to the business document of the job ([ops.md#finops](ops.md#finops)) and, when `sponsor` is set,
to the sponsor account named by `account` (e.g. "inbound subsidy, customer programme Y"). The node never receives fiat
values.

## Admin

<a id="admin"></a><a id="NODE-SPN-03"></a>**NODE-SPN-03** — **Sponsorship admin routes and audit**: create, patch and
delete need `admin`, state changes `operator`, reads `viewer`; every mutation is audited
([NODE-ADM-07](admin-auth.md#NODE-ADM-07)); hot reload ≤ 2 s; metrics `scaas_sponsor_*` ([metrics](#metrics)). Routes
in [admin-auth.md#routes](admin-auth.md#routes): `GET /v1/admin/sponsorship/policies[/{id}]`; `POST`, `PATCH …/{id}`,
`DELETE …/{id}` (refused while live jobs reference it ⇒ `409 POLICY_BUSY`; pause instead); `PUT …/{id}/state`
(`active`/`paused`); `GET /v1/admin/sponsorship/usage?policy=&since=&bucket=day|hour`; `GET/POST/DELETE
/v1/admin/chains/{key}/contracts`.

Write validation: canonical addresses (`addresses.canonical`), lowercase selectors, `contract = '*'` ⇒ `min_value =
'0'`, `job_kind = call` ⇒ `receiver IS NULL ∧ min_value = '0'` (and `max_tx_per_payer_hour = 0` unless the target is a
registered tender), policies on `~gateway`/`~mesh` need a concrete `contract` and (`min_value > 0` or a `receiver`) —
except the one `~gateway` `call` shape of UA registration ([NODE-GW-03](gateway.md#NODE-GW-03)): `contract =
chain.ua_registry`, `selector` = `register`, `max_tx_per_payer_hour = 0` (sponsored registration; budget and hourly cap
bound it); every uint256 field parses, `namespace` exists or is reserved/`*`, `30 ≤ min_valid_secs ≤
chain.max_valid_for_secs`, and `on_exhausted = unsponsored` on a client namespace (or `*`) only with
`fallback_to_namespace: true` in the request (recorded in the audit row) ⇒ else `422 POLICY_INVALID`. A `PATCH` never
changes the reservation of live jobs (they keep `sponsor_reserved`). Bootstrap from `node.toml`
`[[sponsorship.policies]]` follows [NODE-STO-03](store.md#NODE-STO-03) (import if absent, never overwrite).

### Metrics

<a id="metrics"></a>`scaas_sponsor_jobs_total{policy,chain,result="admitted|rejected_budget|rejected_rate|rejected_too_short|unsponsored|tx_cap|bad_sig"}`,
`scaas_sponsor_cost_spent{policy,chain}` (gauge, current UTC day, native smallest unit as float),
`scaas_sponsor_budget_remaining_ratio{policy}`, `scaas_sponsor_reserved{policy}`. No payer labels (cardinality, and
payers are pseudonymous personal data).

## Security

| Threat | Defence |
|---|---|
| Gas drain through a public door with fee 0 | `~gateway`/`~mesh` need an explicit, concrete policy (`*` namespace does not match them; `min_value > 0` or `receiver`); budget, hourly and per-payer caps |
| Garbage-signature jobs burn rate caps or forge per-payer keys | local signature check before sponsoring on public doors; a job that dies before broadcast releases its counts |
| Reservation starvation: one payer reserves the day budget with jobs that never reach lease | hour and payer-hour counts taken at accept with the reservation; `min_valid_secs` refuses near-expiry jobs |
| Exhausted client-namespace policy with `unsponsored` spends gas unseen | booked to the namespace, marked `sponsor_fallback`; `unsponsored` on a client namespace needs an explicit, audited `fallback_to_namespace`; tenant caps use `reject` |
| Another namespace's queued copy of a reveal blocks the bidder | dedupe per namespace ([NODE-JOB-13](job-api.md#NODE-JOB-13)); `DUPLICATE_CALL` names the own live `uid` |
| Duplicate `call` jobs (retried reveal/refund) both broadcast and the loser's revert is booked | `job_live_call` unique index (per namespace) |
| Concurrent accepts lose bucket updates (MySQL REPEATABLE READ) | bucket rows locked `FOR UPDATE` in the step-8 transaction |
| Farming an inbound subsidy ("≥ X to wallet W") | the farmer pays ≥ X to W per sponsored tx; per-payer cap |
| Simulation-passes-then-reverts griefing | measured cost counts against the budget; the grief score ([NODE-LANE-15](submit-lanes.md#NODE-LANE-15)) applies to `~mesh` |
| Expensive calldata (huge batch, heavy ERC-1271) | maximum chargeable fee ≤ `sponsor_reserved` at lease, bumps capped |
| Policy edit by a low role | create/patch/delete `admin` only, audited |
| Over-reservation starving a policy | released on every terminal state from the job's own `sponsor_reserved`/`sponsor_day`; recomputed at startup |

Tests: matching precedence and every wildcard rule; `'*'` vs reserved namespaces; budget boundary (exactly equal
admits); hour and payer-hour caps; `reject` vs `unsponsored`; reservation release on each terminal state; restart
recomputes reservations; lease-time `SPONSOR_TX_CAP`; day rollover (reserved D, mined D+1 books to D) and hour rollover
(counts released to `sponsor_hour`); `PATCH` of `max_cost_per_tx` while jobs are live; a job `dead` before broadcast
releases its counts; **one payer cannot reserve beyond `max_tx_per_payer_hour × max_cost_per_tx`** and queued jobs count
toward `max_tx_per_hour`; `valid_until < now + min_valid_secs` ⇒ `SPONSOR_TOO_SHORT` / unsponsored; **an exhausted
client-namespace policy with `unsponsored` books to the namespace, sets `sponsor_fallback`, never touches the sponsor
account; the write without `fallback_to_namespace` ⇒ `422`**; the `~gateway` UA-registration policy accepted, any other
`~gateway` `call` policy refused; bad-signature and ERC-1271 jobs on public doors; duplicate `call` jobs in one
namespace ⇒ `DUPLICATE_CALL {uid}`, the same call in two namespaces accepted in both; concurrent accepts on PostgreSQL
and MySQL; feed fields per family (EVM, Hedera, one non-EVM); admin route roles and audit rows; toml import precedence.

## Receiver pays

<a id="receiver-pays"></a>The node side of receiver-pays ([CTR-MTX-05](../contracts/metatx.md#CTR-MTX-05),
[CTR-MTX-06](../contracts/metatx.md#CTR-MTX-06)):

- **Job payload** (`kind = metatx`): optional `receiver_fee: {fee, feeRecipient, validUntil, signature}`. Digest = the
  payer digest (G2 unchanged). Accept adds: the shape checks of the contract function (pay op `pay(entryRef)`, payer fee mode `NONE`,
  relayer bound, `batch = payLane(entryRef)`, `nonce = 0` — once per `(payer, entryRef)` —, `feeRecipient ≠ 0`, `feeRecipient ≠ m.to`, `0 < fee ≤ m.value`) without RPC;
  `valid_until = min(m.validUntil, receiver_fee.validUntil)`; `bus.scope` forced `restricted`
  ([NODE-MESH-17](mesh.md#NODE-MESH-17): the mesh envelope has no slot for the co-signature); never batched.
  Normalization may rewrite the payer's unbound `feeRecipient`; the contract ignores it. The co-signed `feeRecipient`
  is signed and untouched. Submit calls `mtxPayReceiverFee`.
- **Payee client:** the payment request carries "fee paid by receiver" and the receiver fee amount (base units); once
  the payer's address is known the payee's server builds the payer's typed data (fee `NONE`, relayer = its lane),
  computes the payment digest and signs `ReceiverFee` with the receiving wallet's key. That key controls the wallet (a
  `SubjectAccount` key validates any digest), so the receiving wallet for this mode is a dedicated **hot collection
  wallet** holding only incoming receiver-pays funds, swept to a cold treasury; a cold receiving wallet cannot
  co-sign and must not offer this mode. Booking: receipt `N` from `PaymentSettled`, fee expense `F` from
  `ReceiverFeePaid` matched by digest. E-cheque flow: the payee's request names the relayer lane; the payer signs
  offline with that relayer bound and hands the intent to the payee, which co-signs and pushes it to that relayer's
  node.
- Contract size: the token families stay under the 24576-byte (EIP-170) CI gate; if one exceeds it, the receiver-fee
  hashing moves to an external library (`ReceiverFeeLib`).
- Token capability: admin flag `token.features` contains `receiver_fee` (set at registration; simulation is the final
  check) ⇒ else `422 FEATURE_UNSUPPORTED`.
- **Indexer:** decodes `ReceiverFeePaid` into `range` items; the payee books receipt `N` from `PaymentSettled(…, N, entryRef)` and fee
  expense `F` from `ReceiverFeePaid`, matched by digest ([integration.md#inbound](../integration.md#inbound)).
- The payee names the relayer's fee address (the node's `chains.fee_recipient`) in its co-signature. A co-signing
  receiving wallet is a **hot collection wallet**: its key controls the wallet, so it holds only incoming
  receiver-pays funds and is swept to a cold treasury.

## Pool

<a id="pool"></a><a id="NODE-SPN-04"></a>**NODE-SPN-04** (PLANNED) — **`SponsorshipPool` is an opt-in application
contract, not a mesh reward**; the mesh pays only the intent's own fee ([NODE-MESH-05](mesh.md#NODE-MESH-05) is not
amended). A pool is a `call` target any relayer may use, like the tender. In v1 the mesh does not carry pool-bound
intents (an envelope slot would be a mesh change; if that proves wrong, a later mesh revision adds a `via_pool` envelope
field). **Pool reward = native-gas refund**, `min((gasMeasured +
overheadGas) × min(tx.gasprice, block.basefee + maxPriorityFee), maxRewardPerIntent, balance)`, paid to `msg.sender`
after the intent executes inside `settle`. Sponsor withdrawals wait `withdrawDelay ≥ 3600 s + finality` (≥
`max_valid_for_secs`). A refund, not a profit, removes the incentive to farm the pool with self-made intents; the delay
stops a sponsor from pulling funds from under an in-flight relayer. Caveat: where the relayer can be the block producer
and receives base or priority fees (PoA/private chains, some L2 or fee-currency handlers), a refund is profit and
self-farming pays; the design restricts programs to chains where lanes do not produce blocks, or pays a fixed capped
reward. Token-denominated rewards would be a second mode later.

Constraints for the pool design: an immutable contract; programs funded by a sponsor in native coin, scoped to one
registered token, optional receiver, selector and minimum value; `settle(program, m, sig)` executes the intent (fee
`NONE`) and pays `msg.sender` the refund; per-payer daily cap; withdrawals after `withdrawDelay`; events for funding,
withdrawal and each sponsored intent; transient reentrancy guard (EIP-1153). Open points: the Hedera formula (HSCS
charges ≥ 80 % of the gas limit), the block-producer caveat, and node routing (a `call` job to `settle` on a
registered `sponsorship_pool` contract, not carried by the mesh).
