# Spec review 1: Round 4 relayer mesh (2026-10-05-relayer-mesh-design.md)

**Verdict: FIX-THEN-GO**

The architecture follows every owner ruling: HTTP pull bus, SQLite store, SPKI-pinned mTLS, per-company scope, round-robin
exclusive, fee-only reward, private profile, R77 family set. No ruling needs to be revisited. Two problems are serious:
one Critical and six High findings let an admitted peer steal fees, censor intents or drain gas, or make our own node
double-submit or mark a job failed. Every fix is local to one section, and none changes the transport, the store or the
rulings.

Reviewed against `main` 3a789d2. Read-only; no builds.

---

## Critical

### C1. A forwarder can take the fee by rewriting the unsigned `feeRecipient` (§4.3, §4.4, §7.2 L3, §8.4)

**Problem.** When `MODE_RESTRICT_FEE_RECIPIENT` is off, the canonical digest zeroes `feeRecipient` (`metatx.rs:111-120`,
vector case 2 "garbage ⇒ same intent_id"). The contract still pays the fee to `m.feeRecipient` when it is non-zero:
`address feeRecipient = m.feeRecipient == address(0) ? msg.sender : m.feeRecipient;`
(`smartcontracts/src/metatx/ERC20MetaTx.sol:87`, `:96`). The envelope carries `feeRecipient` as received. Nothing signs
it: not `intent_id`, not `hub.sig`. The default policy is `fee_recipient_allow = any` (§7.1, §10.2). So any origin or
forwarder can put its own address in the field: the submitter pays the gas and the forwarder collects the fee. R75 makes
that fee the **only** reward.

**Fix.** In the submit path, for any origin other than `Odoo`: when the fee-recipient mode bit is off, overwrite
`feeRecipient` with our `chains.fee_recipient`, or with `0` so the contract pays `msg.sender`. When the relayer bit is
off, overwrite `relayer` with `0`. Never submit wire values for fields that canon zeroes. The digest is unchanged, so
`intent_id` still matches. `fee_recipient_allow` then only matters in bound mode. Add one vector (garbage `feeRecipient`
is normalized before `Work` is built) and one e2e assertion (fee lands in our wallet). The gateway (door A) has the same
hole today (`gateway.rs:136-157` passes `r.m` through); fix it in the same place.

---

## High

### H1. An admitted peer can censor any intent by serving a poisoned copy first (§5.4, §6 `seen_rejected`, §7.2 L1, §4.4)

**Problem.**
- (a) L1 checks "`intent_id` in store **or seen_rejected** ⇒ DUPLICATE" *before* L2 recomputes the digest. A peer serves
  `{intent_id: X, body: garbage}`, gets `DIGEST_MISMATCH` or `BAD_HUB_SIG`, and `X` goes into `seen_rejected`. The
  genuine `X` from an honest peer is then a no-op until `valid_until`.
- (b) First-seen-wins also stores a copy whose **unbound** parts were tampered with. Neither `intent_id` nor `hub_msg`
  covers:
  - `evm.signature` when `sig_kind = erc1271` (no local check);
  - `sig_kind` itself (flip `eoa` to `erc1271` to skip ecrecover);
  - non-EVM `signature`, `public_key`, `auth_kind`, `extra`;
  - the "clear" `from`, `valid_until`, `extra.lane`, `extra.nonce`, `extra.relayer`.

  §4.4 says such a lie only makes simulation fail. Combined with first-seen-wins, a failed simulation means the real copy
  is never taken. A forged lower `extra.nonce` is worse: `op_consumed` reports `consumed` and the node stops on a live
  intent.

**Fix.**
1. Drop `seen_rejected`, or key it by `sha256(envelope bytes)` and fill it only after L2. Never cache codes that are not
   intrinsic to the body (`RATE_LIMITED`, `STORE_FULL`, `HOP_LIMIT`, `PRIVATE_FROM_OPEN_PEER`, `BAD_HUB_SIG`).
2. Take the non-EVM routing and consumption fields from the signed payload with the parsers the adapters already have.
   For example `adapters/ton.rs:1065-1080` does `boc_parse` + `parse_metaop` and reads `m.nonce`, `m.relayer`,
   `m.valid_until`. The other adapters have equivalents. "No new family encoder" still holds, because the decoders exist.
3. Add `sha256(canonical body JSON)` to `hub_msg` so a forwarder cannot swap the signature.
4. A row that ends `failed` for a reason other than consumption is deleted, so a later copy from another source can be
   ingested.

### H2. The `published_at` window rejects every intent older than about 36 s, which breaks catch-up (§7.2 L2, §11 T11)

**Problem.** `|hub.published_at − now| ≤ clock_skew_secs + max_hops × (poll_ms + lag)/1000` is 30 + 4×1.5 = 36 s. A
pull bus holds intents for up to `valid_until` (≤ 3600 s). A puller that was down for a minute, or that just joined,
rejects everything older than 36 s. R70's own rationale ("catch-up after downtime for free") and E7 fail. With H1(a) the
rejection is also cached.

**Fix.** Reject only a future time: `published_at > now + clock_skew_secs`. A past `published_at` only means that
`exclusive` has already expired. The §8.2 clamp already bounds `until`.

### H3. Losing a race still marks the job `failed`: R80 is only partly implemented (§8.4, §10.5)

**Problem.** The spec handles consumption on simulate-revert and before bump or resend. It does not handle the common
B2/B3 outcome: our tx is mined and **reverts** with `MetaTxBadNonce` because a peer landed first.
- EVM: `submit.rs:285-289` reports `reverted`.
- Non-EVM: `adapter.rs` `follow()` `TxStatus::Reverted` reports `reverted`.
- Odoo: `_apply_report('reverted')` sets `business_state = 'failed'` (`blockchain_relay_job.py:217-219`), and the
  subject-account override fires `_fail_dependents()` (`blockchain_subject_account.py:456-459`, `FAILED_STATES` l.35).

This breaks R80's "a job is never dead/failed because someone else landed it" until the indexer's `final` arrives.
`_fail_dependents` is not undone at all.

**Fix.** On a reverted receipt or status with `meta` set, or for a `signed_op`, run the consumption check (`metaNonce` /
`op_consumed`). If consumed, report `consumed` instead of `reverted`. Add `'mined': {'reverted', 'consumed'}` if needed,
and Odoo and node tests for "our tx reverted because the nonce was used elsewhere ⇒ consumed, pending, no dependents
failed".

### H4. Gas drain: `submit` is allowed for any contract (`*`), and `fee_ok` compares the raw fee field (§7.1, §7.2, §10.2)

**Problem.**
- (a) A `(*, *)` or `(*, selector)` row with `support = full, submit = true` makes the node simulate and submit for any
  token contract. A peer can feed us at 50 intents/s for attacker-deployed `MetaToken` clones with worthless "fees" that
  simulate fine. Today both the gateway and Odoo paths only serve registered tokens (`gateway.rs:100-104`
  `tokens.contains`, filled from `node_config.submittable_tokens()`). The mesh path loses that gate.
- (b) `fee ≥ min_fee` compares `m.fee`. The contract computes `FeePolicy.compute(mode, value, fee)`
  (`smartcontracts/src/common/FeePolicy.sol`): NONE ⇒ 0 whatever `m.fee` is, and PERCENT ⇒ `fee` is ppm. A NONE-mode
  intent with `fee = 10^30` passes `min_fee` and pays nothing.

**Fix.** (a) `may_submit` also requires `contract ∈ registered tokens` (Odoo `submittable_tokens`, or a toml list when
standalone). Add the Odoo constraint `CHECK(NOT submit OR contract_address <> '*')`. (b) Compute the effective fee the
way `FeePolicy.compute` does before comparing, and expose that value as `fee` in the summary.

### H5. A private intent travels past the origin's allowlist (§9 `may_export`, R76, owner ruling "allowlisted private peers only")

**Problem.** A private peer B re-serves our private-chain intent to any peer that **B** lists as private for that chain.
`may_export` only uses the local peer table, and "visibility only gets stricter" does not limit *who* is trusted. So the
intent leaves the set the origin admitted. A correct B does this by design, so it is a spec leak, not a malicious-peer
one.

**Fix.** Serve `visibility = private` rows only when `source != 'peer'`, so only the origin serves them (hop 0), and add
that to `may_export` with a unit test. Each private recipient must then be admitted by the origin directly. If the owner
wants multi-hop private routing, that needs a ruling and an origin-signed recipient set; v1 should not do it.

### H6. G2 is false: our node can submit one intent twice, at two outer nonces (§8.1, §8.7 G2, §10.5 `mesh_publish_claim`)

**Problem.** G2 assumes an Odoo job and its store row are always `source = outbox`. Suppose a `relayer = 0` meta-tx of an
open company reaches a peer first, for example because the payer's wallet also posted it to another gateway. Our node
then ingests it as `source = peer, may_submit = true`. Later `mesh_publish_claim` returns the same job, its insert is a
DUPLICATE no-op, and `may_submit` stays true. The scheduler (lane 0) and `poll_outbox` (any lane) then both sign it,
which is a double broadcast by our node, at two outer nonces. One reverts, and H3 then reports `failed`. The cold-start
requeue (M2) also breaks G2 as worded.

**Fix.**
1. Keep one per-chain in-process set of in-flight digests, shared by every Submitter lane and the mesh scheduler. A path
   that finds the digest present does not sign.
2. On a duplicate during outbox publish, flip the existing row to `may_submit = 0` (Odoo path owns it).
3. Reword G2 to "at most one *live* outer tx per intent per node".

---

## Medium

### M1. Adding `rustls` / `tokio-rustls` as direct dependencies with default features pulls in `aws-lc-rs` (§3.3)

**Problem.** The lock has only `ring` (no `aws-lc-rs`). `rustls-0.23.45` defaults to `["aws_lc_rs", "prefer-post-quantum",
…]`, and `tokio-rustls-0.26.6` defaults to `["aws_lc_rs", …]`. A plain `rustls = "0.23"` adds a C/cmake crate, which
contradicts "already in Cargo.lock". With both providers compiled in, `ServerConfig::builder()` panics because there is
no process default provider. Separately, `ed25519-dalek = "2"` has no `pkcs8`/`pem` features, so it cannot read the PEM
key named in §3.2 as specified.

**Fix.** Use `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "logging", "tls12"] }`
and `tokio-rustls = { version = "0.26", default-features = false, features = ["ring"] }`, and call
`builder_with_provider(rustls::crypto::ring::default_provider().into())`. For `hub.sig`, either parse the fixed 48-byte
PKCS#8 (`302e020100300506032b657004220420` ‖ seed) or enable `ed25519-dalek` `pkcs8`. Verified as correct:
`webpki::EndEntityCert::subject_public_key_info()` re-wraps the outer SEQUENCE (`rustls-webpki-0.103.15`); the Ed25519
SPKI prefix; the 13-byte domain tag.

### M2. Restart rules for store rows conflict with `nonce::plan` (§8.6)

**Problem.** `plan()` gap-fills every journaled nonce `≥ pending` and requeues its job (`nonce.rs:23-33`). The spec says
"store rows with `tx_hash` ⇒ tracked". For a row whose `outer_nonce ≥ pending`, the code would gap-fill `n` and then
`inflight.insert(n, meta-tx)` would overwrite the gap-filler entry (`submit.rs:105-117`). The lane would then bump a
meta-tx at a nonce it just gap-filled. `chain.nonce_at(lane, latest)` (§8.4) does not exist either; `chain.rs` has only
`pending_nonce()`.

**Fix.** Feed store rows into `plan()` as `Inflight` keyed by `Origin`, with the same rules as Odoo rows: below `pending`
⇒ track, otherwise ⇒ requeue. Simpler and safer for mesh rows: journal the **raw signed tx** in the row and rebroadcast
it at restart (same hash, no new nonce, no gap-fill). State that `nonce_at` is new (`get_transaction_count(addr, latest)`).

### M3. Store state machine is incomplete: rows get stuck, and RPC errors are not fail-closed (§6, §8.3, §8.4)

**Problem.**
- After the CAS `submittable → submitting`, `try_send` to the lane channel can fail (full or closed, e.g. breaker open).
  The row then sits in `submitting` with no tx. The janitor ignores `submitting` (§6 rule 2), and restart only resets
  rows with no `tx_hash`.
- `Submitter::requeue()` / `fail()` do nothing when `job_id` is `None` (`submit.rs:247-259`). The spec gives no Mesh
  outcome for transient errors, gas over `max_gas_per_tx`, expiry in the channel, or the `retry` queue.
- Nothing says what happens when the `metaNonce` / `nonce_at` / `op_consumed` RPC fails before a bump. It must skip the
  bump this round (fail closed), not fall through to the existing bump.
- `consumed` has no outgoing transitions, so a late `mined` report (classification `unknown` with a lagging RPC, then our
  earlier hash's receipt) raises a `UserError` in `_apply_report`.

**Fix.** Add an explicit transition table (from, event, to, who):
- `submitting → submittable` on send failure or transient error;
- `submitting → failed` / `expired`;
- `broadcast → landed` / `consumed` / `failed` / `expired`;
- Odoo `consumed → final` (indexer) and `consumed → mined`, ignored (no error).

State that a failed consumption read means "no bump, retry next round".

### M4. A suspended peer keeps its open connection, and handshakes have no timeout (§5.1, §11 T1, T13)

**Problem.** The admission check runs only in the TLS verifier, once per handshake. HTTP/1.1 keep-alive or h2 lets a
suspended or rotated peer keep pulling indefinitely. The ≤ 60 s claim in T13 is wrong. Unauthenticated TCP clients can
also hold handshakes open.

**Fix.** The handler looks up the `peer_id` extension against the current snapshot on every request (403 if not
active). Add a max connection age (for example 5 min), `tokio::time::timeout` around `TlsAcceptor::accept`, and a
semaphore on concurrent connections.

### M5. A peer's lost or recreated store leaves our cursor permanently ahead (§5.2, §6, R71 "lost disk")

**Problem.** A fresh SQLite file restarts `seq` at 1. Our `peer_cursor` (for example 9123) is greater than their `head`,
so we skip all their new intents until their seq passes the old value.

**Fix.** Put a random `store_id` in `meta` and in every page and policy response. Reset the cursor when it changes (and,
as a fallback, when `head < cursor`).

### M6. `op_consumed` "next > nonce" is wrong for some op kinds (§8.4 adapter.rs, R77)

**Problem.**
- TON: a revoke executes when `next == nonce + 1` (`chains/ton/contracts/jetton.tact:229`; `adapters/ton.rs` build
  checks `m.op == 4 && next == m.nonce + 1`). A pending revoke would read as "consumed" and stop being resent, so the
  cancel never lands.
- Solana: `mandate_revoke_signed` uses the mandate *generation* as the nonce, not the lane PDA
  (`chains/solana/programs/bamboo/src/mandate.rs:208-231`).

The S2 fix also applies these checks to Odoo jobs of every op kind, so the damage is not limited to the mesh.

**Fix.** Return `Ok(None)` (unknown, do not stop) for every op kind except those whose replay guard is the lane nonce.
Add TON revoke as `next > nonce + 1`. Limit the non-EVM policy selectors for v1 to `pay`, which matches
`mesh_publish_claim`.

### M7. Non-EVM `relayer_ok` compares against lane labels, which never match (§7.2 L3)

**Problem.** Lane labels are `pk:<hex>` (`main.rs:28-33`). The contracts compare a family address: Cosmos `op.relayer !=
info.sender` (`chains/cosmos/token/src/lib.rs:191`), Sui `op.relayer == ctx.sender()` (`meta.move:318`), TON lane wallet
address. A relayer-bound non-EVM intent for our own lane is therefore never `may_submit`.

**Fix.** Compare the relayer decoded from the payload (H1 fix 2) against `adapter.lanes()[i].address` in canonical form
(R61).

### M8. Standalone mode (no `[odoo]`) is under-specified (§3.1, §3.2)

**Problem.** These all require Odoo today, and §3.2 only says "no relay_poll":
- `Submitter::start` (`submit.rs:80-91`: `node_config_ref`, journal, `plan`);
- `lane_runner` / `recover_lane` (`adapter.rs:161`, `:225`);
- `adapters::build` callers take `odoo::Odoo`;
- `main.rs` builds the admin refresh from `cfg.odoo`;
- `Config.odoo` is a required struct (`config.rs:12`).

**Fix.** Specify the standalone cold start (store journal only), the token allowlist source (toml), the admin refresh
without Odoo, and `Option<Odoo>` in the submit, lane and admin paths. Or drop the "Mesh relayer without Odoo" shape from
v1 if no partner needs it yet.

### M9. `PRIVATE_FROM_OPEN_PEER` checks the envelope's visibility instead of the chain (§7.2 L3 vs R76)

**Problem.** R76 says "a node rejects a **private-chain** intent arriving from an open peer". L3 tests
`env.visibility == private`, so an open peer can deliver an `open`-labelled intent for our private chain and we accept it
silently.

**Fix.** `(env.visibility == private OR chain_profile(chain_key) == private) AND peer.class == open ⇒
PRIVATE_FROM_OPEN_PEER`. Add a vector for the open-label, private-chain case.

### M10. Test plan defects and gaps (§13)

**Problem.**
- E1: A is `forward_only`, so `may_submit = false` and it never checks. "A's row ends consumed/landed_elsewhere" cannot
  happen.
- E4: the fee cap is in gwei (`max_fee_cap_gwei`), so "1 wei above base fee" cannot be configured. At the cap,
  `track()` takes the wait branch (`submit.rs:301-311`), and a same-fee gap-filler is rejected as underpriced, so the
  expected "gap-filler at the same outer nonce" cannot happen.
- No test covers C1, H1(a)(b), H2 (catch-up after > 36 s), H3, H4, H5, H6, M4 or M5.
- No Odoo test covers `reverted ⇒ consumed`.

**Fix.**
- E4: use anvil `evm_setAutomine false` with a node whose fee cap has headroom, then mine.
- Add the missing scenarios as unit tests where possible: `accept.rs` for H1/H2/H4/M9, `export.rs` for H5, `submit.rs`
  fakes for C1/H3/H6.
- Add one e2e for catch-up after downtime and one for suspension of a connected peer.

---

## Low

- **L1. Wrong code references.**
  - The TON vectors are at `chains/ton/vectors/ton-vectors.json`, not `tests/vectors/ton-vectors.json`.
  - `blockchain_autopay.py:267` is the **mandate** path, which creates a `call` job (`blockchain_payment_request.py:249`)
    and is excluded from the bus. The custodial autopay path goes through `payment_transaction.py:47` (`_chain_start`),
    so it is covered by the l.47 change, not by "already relayer = 0".
  - `op_consumed(&Value)` cannot serve Hedera, whose jobs are `metatx`, not `op`; take `&Job`.
  - R72's "Ed25519 is the only curve usable as a TLS key" is wrong (P-256 and RSA also work). The argument for Ed25519
    stands on determinism and the existing signer.
- **L2. Upgrade.** `data/blockchain_chain_data.xml` is `noupdate="1"`, so adding `chain_profile=public` there does not
  reach existing databases. Every existing chain (Gnosis, Celo) becomes `private` on upgrade and the bus is silently dead
  for them (liveness only). Add an explicit post-upgrade step or `<function>`, or document the operator step. Existing
  relay jobs need no migration: the new fields default empty or false, and `consumed` is additive.
- **L3. Side channel.** The global AUTOINCREMENT `seq` (gaps between served items) and `head` let an open peer count our
  private intents and when they occur. Either accept this and say so in T7, or keep `head` per caller.
- **L4. Server-only fields can be set by clients.** `landed_elsewhere` and `mesh_published_datetime` are only
  `readonly=True` in the UI. `group_blockchain_operator` has write on `blockchain.relay.job` (`ir.model.access.csv`,
  `access_relay_job_operator 1,1,0,0`), and `default_*` keys in the client context reach job creation on portal paths.
  Strip both fields in `create`/`write` unless the call comes from the service path (owner rule: no context-key guards).
- **L5.** §8.5 `eth_getLogs` needs a block number, but the store keeps only `received_at` in ms. Add `from_block` to the
  row. `mesh_publish_claim(evm_chain_number)` must accept `chain_key` for non-EVM; `_by_number` already does
  (`blockchain_chain.py:144`), so rename the argument to `chain`.
- **L6.** `pool_visibility` is a stored compute with `readonly=False`. Changing `chain_profile` re-triggers it, and the
  policy constraint does not fire on a `blockchain.chain` write. Node-side `strictest()` covers safety. Make the compute
  keep an existing value, and add the check to `blockchain.chain` `write`.
- **L7.** Unbounded `fields=full` page bytes: 200 × 32 KiB ≈ 6.4 MB per pull, × `peer_rps`. Cap the response bytes
  (for example 1 MB) and end the page early.
- **L8.** The Odoo-path outcome sink does not touch the store. A `source = outbox` row stays `pooled` and keeps being
  served after our Odoo path lands it, so peers keep simulating it (B4). In the sink, CAS the row to `landed` by digest.

---

## Over-engineering (v1)

- **O1. Drop the summary/by-id two-step from the puller.** Pull `fields=full` and dedup locally. Summary-then-by-id costs
  a second round trip per hop, which R70's latency budget does not include. Summary carries no privacy value either:
  an admitted peer can ask for `full`. Keep by-id only if E5 needs it as an existence-oracle check.
- **O2. Drop `seen_rejected`.** After the H1 fix it only saves microseconds of L0–L2 work, apart from ecrecover, and is
  bounded by per-peer rate limits anyway.
- **O3. Defer `mesh_report` and the peer counter fields in Odoo.** They duplicate `/metrics`.
- **O4. Split S1 for stream order (§14).** S2 needs only the `consumed` state, the `reverted ⇒ consumed` handling (H3) and
  `landed_elsewhere`. Ship that as **S1a** (relay job and `_mark_executed` only) so the R80 fix lands first. Policy,
  peer, company and settings go to S1b, before S4. The other streams are ordered correctly and each can be tested alone:
  S3 is a pure library, S4 store and config, S5 transport over S3 and S4, S6 integration, S7 e2e.

## Verified correct (no action)

- `executeMetaTransaction` and `_metaNonce` line references (`ERC20MetaTx.sol:26,44,62-103`), nonce checked before
  signature, event topics (topic1 from, topic2 relayer, topic3 batch).
- `metaTxDigest` and `metaNonce` in `abi.rs`.
- Cosmos `NONCES` / `QueryMsg::Nonce`; Sui `personal_digest` l.322 and `lane_nonce` l.484; Aptos `lane_nonce` l.666;
  TON `get_lane_nonce` l.359; Solana `LanePda` l.160-203.
- Existing Odoo pieces: `check_service`, `_payload`, `relay_claim` SKIP LOCKED, `_cron_expire`, `_EXPIRY_GRACE`,
  `blockchain.chain` inheriting `mail.thread` (so `tracking=True` works).
- Ruling numbering: R68 is unused.
- New-model conventions: `models.Constraint` used, no field named after a type, no `child_of`, service methods public.
