# Review 1 — Amendment A2 (mesh gossip + PQ transports, R112–R127)

Reviewed: `scaas/docs/superpowers/specs/2026-10-06-mesh-gossip-amendment.md` (main checkout, incl. "Owner answers"),
against MESH (R70–R86), NI rev 3 (R87–R111), DEX design, `bamboo-node/src/mesh/*` (S3, e8e430e),
`smartcontracts/evm/src/dex/OrderBookDex.sol`, `bamboo-node/Cargo.toml`/`Cargo.lock`, reqwest 0.12.28 and
alloy-transport-http 1.6.3 manifests in `~/.cargo/registry`. Read-only; only `cargo tree --offline` was run (no build).
libp2p is **not** in the local registry, so gossipsub/yamux/libp2p-tls claims are checked from knowledge of
rust-libp2p and marked "verify" where I could not confirm them.

## Verdict: **FIX-THEN-GO**

The architecture holds: one `accept()`, two enumerated exits, chain-arbitrated state, no new submission path around
`job_live_digest`. **On-chain double settlement of one DEX fill is impossible in both modes**:
`OrderBookDex._accept` l.263 (`relayer ∈ {0, sender}`) and l.267 (`Overfill`), with each pair isolated by
`try settleOne` → `MatchFailed`. The two Criticals are spec defects with local fixes. (1) The Reject-class rules
depend on announce state, and a single Reject bans the sender for an hour, so a node that is joining bans honest peers.
(2) Owner ruling 2 (relayer-unbound orders in G3) is not written into the normative text, and the most dangerous
RS5-9 case is unhandled: an order cancelled off-chain can still be settled by anyone.

Verified OK (no action):
- Signing contexts are prefix-free (`scaas-hub/v1`, `scaas-{announce,hint,dexbook,dexhead}/ed25519/1`, the TLS/Noise
  contexts). `hubsig.rs` l.11 already uses `scaas-hub/v1`.
- `may_gossip` excludes `source = 'peer'`, private visibility and private profile. The exit list in §12 is complete
  for intents.
- `job_live_digest` remains the single admission point for every submission path (§8.2), so the same intent arriving
  over gateway, bus and gossip still yields at most one live outer tx (G2).
- The decay arithmetic is correct: P4 counter 1 → 0.894 takes ≈ 187 s, matching "≈ 3 min".
- The gossipsub thresholds are ordered as rust-libp2p validates them (0 ≥ gossip ≥ publish ≥ graylist), and
  `mesh_outbound_min 2 ≤ mesh_n/2`.

---

## Critical

### C1 — State-dependent "Reject" plus one-strike ban ⇒ ban storm while a node joins (§6, §7.2, §11.4, R118, R119)

**Problem.** R118 says Reject is only for "deterministic, source-independent faults". Several Reject checks in the
spec break that rule:

- Hint V4 requires that the "signer has a live announce".
- Dex V4 requires that "`home` = the announcer that proved `order.relayer` (else Reject: book spoofing)".
- V5 rejects when "our `chain_profile(chain) = private`", which depends on our own config. It matters during the
  ≤ 2 s unsubscribe window and for in-flight validation.
- Announce V4 lists "`expires_at` bounds" without separating `now > expires_at`, which depends on the clock.

The hint, `book` and `head` messages also carry only `signer`/`home` as a `peer_id` (a SHA-256 of the SPKI) and **no
public key**. Their Ed25519 signatures therefore *cannot* be verified without the announce, so even the signature
check depends on state.

§7.2 makes a single Reject cost P4 −100 on the intent topic, which graylists the peer for about 187 s. §7.2 also bans a
peer that stays graylisted for more than 60 s for 1 h (§7.2 "ban"). Together they mean **one Reject = 1 h ban** of the
forwarding peer.

A fresh node receives `book` traffic (up to 200/s per source) and hints before its first `/scaas/sync/1 announces`
round trip completes. It would Reject honest forwarders and ban its whole mesh within seconds, which amounts to a
self-inflicted eclipse. A partition heal or an announce expiry (1 h) does the same.

**Evidence.**
- §5.3: the hint JSON has `signer` but no `pubkey`; the dex JSON has `home` but no `pubkey`.
- §6 last paragraph; §11.4 V4.
- §7.2 rows P4 and "ban". E-G4 even asserts "graylisted after the first; banned after 60 s".
- The S3 API cannot express the needed split either. `accept.rs` l.168 returns `Code::BadEnvelope` for a future
  `hub.published_at` (clock-dependent), which is the same code as for malformed JSON. `UnknownChain` and
  `FamilyNotSupported` depend on config.

**Fix.**
1. Add `pubkey` (32 B hex) to hint, `book` and `head` JSON, and put it into `hint_msg`/`dexbook_msg`/`dexhead_msg`.
   Verify `SHA-256(SPKI ‖ pubkey) == signer/home` and the Ed25519 signature *deterministically*. Only that is Reject.
2. Make every announce-dependent binding Ignore. This covers "signer has a live announce", "home proved
   `order.relayer`" and the expiry checks. Optionally park the message ≤ 30 s keyed by the missing `peer_id` and
   re-run it when the announce arrives.
3. V5: keep Reject for `visibility = private` in the envelope. Make the "our profile is private" branch Ignore.
4. In `accept.rs`, split `Code::BadEnvelope` (future `published_at` → e.g. `Code::FuturePublished`). Add a single
   `fn gossip_acceptance(Code) -> MessageAcceptance` table with a unit test per code. `UnknownChain`/
   `FamilyNotSupported` map to Ignore.
5. Ban rule: ban only after ≥ 2 Reject-class events within the retention window, or after a graylist that lasts
   longer than one P4 event can explain (e.g. > 10 min). Add e2e "fresh node joins under book + hint traffic ⇒ no
   honest peer's P4 > 0".

### C2 — Owner ruling 2 (relayer-unbound orders, G3) not folded in; cancelled/IOC orders become settleable by anyone (§1.2, R124, §11.6, §17, §16)

**Problem.**
- The answers make unbound orders (`relayer = 0`) G3 scope, enabled per market. Yet the normative text still lists
  them as a non-goal (§1.2). R124 still says "matched and settled **only by the home node**", §11.6 says "defined, not
  built", and §16 has no test for them.
- Taken literally, §11.4 V4 makes **every unbound `book` a Reject**: no announce can prove `order.relayer = 0`, so
  every claimant gets banned (C1).
- More important for safety: `settle` is permissionless. With `relayer = 0` and `feeRecipient = 0`, any EOA settles
  and even receives the relayer fee (`OrderBookDex.sol` `_relayerFee`: `to = … sender`). The settle-claim window binds
  only honest nodes. The DEX spec names this as the RS5-9 danger: "relayer khác settle lại phần IOC/lệnh đã huỷ
  off-chain" (DEX design, RS5-9 bullet). Off-chain cancels are immediate, while on-chain cancels are batched and capped
  at 20/maker/h. So in an unbound market:
  - **an order the maker cancelled stays settleable by anyone who saw it on gossip until expiry**: the maker is filled
    at a price they withdrew;
  - an IOC taker that found no match (no settle tx, so `_closeIoc` never runs) becomes good-till-expiry.
- The claimant rule "first-seen claimant wins locally" is not deterministic. Two nodes that receive the same unbound
  order each see their own claim first. Both match it and one pair fails on-chain. Funds are safe because `filled[]`
  arbitrates, but each node had optimistically published `book` at `signed` (§11.3) and must roll back, and the losing
  taker sees a phantom fill.

**Fix (normative text for G3).**
1. Fold the ruling into §1.2, R124, §11.6, §17 G3 and §16. Add `dex_market.open_orders`, and add `claimant` and
   `claim_until` to `dex_replica` (the `home` column is NOT NULL today).
2. V4 for unbound orders: the claimant's signature is deterministic (Reject on failure). The "is this the claimant"
   check is Ignore.
3. **Cancel in unbound markets is on-chain only.** The order counts as closed only when `OrderCancelled` is mined, the
   20/h cap does not apply, and the API/UI says "cancel final when mined". Unbound IOC/FOK orders must carry
   `expiry ≤ now + MIN_TTL` and are **never** gossiped (`route_order`) or placed in `book`.
4. Deterministic claimant: the lowest `SHA-256(order_hash ‖ peer_id)` among claims seen within `claim_grace`
   (≥ gossip p99, e.g. 2 s). No node matches an unbound order before `published_at + claim_grace`.
5. State plainly in F1 that the claim window does not bind non-node settlers. Makers in unbound markets accept
   execution by anyone at any price within their limit.
6. Tests: e2e "maker cancels an unbound order at A; B and a raw EOA try to settle it before the on-chain cancel mines
   ⇒ the order is not offered or settled by nodes; the cancel lands first in a test with a 1-block wait". Unit: the
   claimant tie-break is deterministic over permuted arrival orders.

---

## High

### H1 — Open-mesh re-origination lets any sybil self-assign exclusivity on every intent (§8.3, §14 S2/S3, MESH T6)

**Problem.** R121 only controls whom an *honest* origin assigns. The receivers' rule is unchanged from MESH §8.2: they
honour any `exclusive` whose `hub.sig` verifies and whose span fits within the clamp (`accept.rs` l.~188 `honored`).
On the open mesh any sybil can:
1. re-originate a public intent under its own hub (MESH §4.5: "does not stop … re-originating");
2. sign `exclusive{relayer_id = sybil2, until = +10 s}`;
3. use `flood_publish` to reach nodes before the honest copy.

Store dedup is first-seen by `intent_id` (MESH R78), so those nodes keep the sybil's copy and wait out a window that
nobody will use. That is a 10 s delay per intent, with no penalty. "Misses" are counted only for intents *we*
assigned, and the copy never fails simulation, so the T6 tombstone path does not trigger. Content-addressed msg-ids
(R117) keep the honest copy flowing at the gossip layer, but the store still discards it.

**Fix.**
- For `Source::Gossip` (and for open bus peers), honour `exclusive` only when the assignee is in **our own** eligible
  set: live announce with `submit`, and trusted or `landed_7d ≥ 3`. Also require `assignee ≠ hub.id`. Otherwise store
  `exclusive_until = NULL`.
- Optionally, keep the earliest `published_at` among copies with the same `intent_id` that arrive within 2 s.
- Test E-G11: sybil re-originates with a self or sybil exclusive ⇒ honest nodes do not wait.

### H2 — Automatic trust (ruling 3) is farmable: shared-lane PoP multiplies credit; self-dealt landings cost 3 txs (§8.3, §10.3, R121)

**Problem.** §10.3 "Two announces proving the same address ⇒ both rows kept … attribution counts for both". A lane
key holder can sign PoPs for any number of `peer_id`s, so one lane with 3 landings crosses `assign_min_landed` for N
sybils at once.

The landings themselves can be self-dealt: the attacker's own EOA signs 3 cheap meta-txs on a registered token,
originates them from a sybil hub and lands them with its own lane. `landed_7d` counts them because they are
"`landed_elsewhere` whose `relayer` ∈ lanes g proved".

Each trusted sybil may then miss 3 assignments per hour before exclusion. With N sybils in the round-robin, almost
every intent we originate is delayed by `exclusive_ms`. The ruling (automatic after 3) stands; the counting is what
needs fixing.

**Fix.**
1. Attribution uses one `peer_id` per lane address. If two live announces prove the same lane, **neither** gets
   credit (metric only).
2. Count a landing only if the intent's origin `hub.id ≠ g` and was not proved by g. Also require landings from
   ≥ 3 distinct `from` addresses.
3. Auto-trusted peers (as opposed to admin-trusted) get at most one rr slot per k assignments (e.g. ≤ 1/3) and are
   excluded after **1** miss for 1 h.
4. Unit tests for shared-lane credit = 0 and for self-dealt landings not counting.

### H3 — Untrusted DEX homes: replica caps are sybil-fillable, and the gateway advertises attacker venues to wallets (§11.1, §11.5, §7.3, §10.4)

**Problem.** Becoming a "home" costs one key and a PoP (§10.3). Each sybil home may fill 10 000 replica orders, and
the global cap is 100 000. The makers can be attacker EOAs: ERC-1271 needs the home anyway, and only the home runs
`checkOrder`. So 10 sybil homes evict or refuse every honest home's depth.

Worse, `GET /v1/dex/depth?scope=network` and `/v1/dex/homes` hand the attacker's gateway URL and relayer to *our*
wallets as liquidity. A taker who signs an order bound to that relayer gives the attacker a free option until expiry:
only that home can settle it, and it settles only when the market has moved in its favour, within the taker's limit.
§14 F1 calls "a home can always see its own takers first" inherent. That holds for the operator you chose. It does not
hold for a venue our gateway recommended.

**Fix.**
- Replicate and advertise only homes in an admin allowlist (`dex_home_trusted`, or reuse `gossip_trusted` with a
  `dex` flag). Size the per-home caps by trust (untrusted: 0 or forward-only).
- Responses with `scope=network` label each level `trusted: bool`, and wallets default to trusted homes.
- Require `expiry ≤ now + N min` for taker orders routed to another home.
- Test: an untrusted home's book is forwarded but neither stored nor listed.

### H4 — V8 freshness drops pipelined intents network-wide (§6 V8)

**Problem.** "subject nonce == intent nonce … stale nonce ⇒ Ignore". If a subject signs nonces n and n+1 (same
`(from, batch)` lane), every RPC-equipped node Ignores n+1, i.e. does not forward it. The origin publishes once
(§8.1), so n+1 reaches the open mesh only through a later `/scaas/sync/1` on reconnect, possibly never. That loses a
legitimate payment silently. The balance check has the same flaw when intent n funds intent n+1.

**Fix.**
- Treat the intent as stale iff `intent nonce < subject nonce`. Accept `subject ≤ nonce ≤ subject + K` (K = 16), and
  Ignore beyond that.
- Make the balance check advisory: Accept but do not store when the balance is short.
- Unit test: n+1 is Accepted.

### H5 — Bus over QUIC: request-response cannot pick the connection, and gossip bans cut admitted peers (R113, §5.4, §7.2 "ban", §7.4)

**Problem.**
- §7.4 allows "1 per peer" connection. If an admitted partner first connects or is dialled over TCP (Kademlia or
  identify addresses), there is no QUIC connection. `/scaas/bus/1.2` is then refused (`TRANSPORT_NOT_PQ`) for as long
  as the TCP connection lives.
- rust-libp2p `request_response::send_request(peer, …)` chooses among the peer's connections itself (verify for
  0.56). With two connections, a request may go out on TCP even on the client side.
- Separately, an automatic gossip ban goes through `allow_block_list`, which drops **all** connections to that
  `PeerId`. One false Reject (C1) therefore also cuts the consortium bus over QUIC, which is the only exit for private
  data.

**Fix.**
- In `handle_established_{inbound,outbound}_connection`, deny TCP for any `PeerId` in the bus peer table, and allow
  QUIC only (QUIC-first dial from the peer row's `multiaddr`).
- Exempt bus-table peers from automatic bans. Use gossipsub-level `blacklist_peer` for them and keep the connection.
- Client side: the puller refuses to send on a non-QUIC `ConnectionId`.
- e2e: partner dials TCP first ⇒ the TCP connection is refused and the bus still works over QUIC; gossip ban of a
  partner ⇒ the bus is unaffected.

---

## Medium

### M1 — Dedup and per-origin buckets assume the store; replays and byte variants exhaust a victim's bucket (§6 V3/V6, §7.3, R117)

**Problem.** V3 dedup checks the store only. Rows that are not stored (`support = forward_only` nodes, the
`gossip_max_rows`/200 rows/s overflow "Accept without storing") pass V3 every time. The 120 s seen-cache is far
shorter than `valid_until` (≤ 1 h).

An attacker can therefore, at its own 20/s source bucket:
- replay old valid intents after 120 s;
- or send byte variants of them: whitespace or key order, unknown fields "ignored but counted", or a changed
  `hop_count`, which is unsigned.

Each copy has a new msg-id (content-addressed) and costs every node V4 crypto plus a V8 RPC read. It also **spends
the honest origin's `hub.id` 10/s bucket and the subject's `from` 10/min bucket**, so the genuine new intents are then
Ignored (V6), which is censorship. The first-stored variant can also set `hop_count = max_hops`, which blocks bus
re-serving.

**Fix.**
- Keep an in-memory `intent_id` set with TTL = `valid_until`, bounded (≈ 32 B × 1 M), and check it before V4. Charge
  V6 buckets only on the first `intent_id`.
- Reject payloads whose bytes are not the canonical serialisation (deterministic). Then one intent has one msg-id.
- Store `hop_count = 1` for `source = 'gossip'`.
- Move the V2 source bucket before the V0 parse (it is cheaper).

### M2 — Store caps are DoS-able by valid-but-worthless content (§7.3 caps, §8.4)

**Problem.**
- Intents: fresh EOAs give 100/h each, with zero value and zero fee. V8 passes because a balance ≥ 0 always holds,
  and it fails open without RPC. These rows fill `gossip_max_rows` 100 000 and push honest public intents into
  "Accept without storing", so our node stops submitting them.
- Announces: 5 000 sybil identities fill the announce cap. Honest announces are then refused, so eligibility, DEX
  homes and hint signers disappear, and with C1 unfixed that leads to Rejects.

**Fix.**
- Store a gossip row only if `may_submit` (fee ≥ `min_fee`). Keep forward-only rows out of the store, which also
  shrinks the sync surface. Evict by effective fee, then by age.
- Admit announces with priority for connected, bus, trusted and track-record peers. Cap untrusted announces per /24
  and evict them LRU.

### M3 — Auto-ban for exclusivity "violations" punishes honest peers (§8.3, MESH B1)

**Problem.** Copies diverge on the open mesh: re-originated ones (H1), clamp differences between receivers, and clock
skew under 1-second `until` granularity. An honest g may legitimately see "no exclusive" and land inside *our*
window. "3 in 24 h ⇒ auto-ban 24 h" then bans honest submitters. Nothing distinguishes that case from abuse.

**Fix.** Make violations a P5 term plus metric only. Bans are an admin action. Drop the auto-ban.

### M4 — Hints: false-hint accounting misfires; hint floods disable V8 (§9, §7.3)

**Problem.**
- "Not moved 2 blocks after `hint.block`" penalises an honest lander when its tx is reorged out or when *our* RPC
  lags. Receipt "not found" and "found without the log" are different outcomes.
- Hints and V8 share the per-chain 50/s RPC budget, and V8 fails **open** when the budget is exhausted. A sybil with a
  free announce can send one hint per pooled `intent_id` every 10 s (1 000 pooled ⇒ 100 reads/s) and thereby turn off
  freshness checking for intent spam.

**Fix.**
- Use separate budgets (hints ≤ 10/s per chain) and a per-signer hint bucket.
- Process hints only from signers with ≥ 1 credited landing or `gossip_trusted`; Ignore the rest.
- Judge a false hint only once our head ≥ `hint.block + finality_depth`, and only on "receipt found, no
  `MetaTransactionExecuted(digest)`".
- The hint-triggered read must enter the ordinary `track()` order: receipts among `s.hashes` first, then
  `metaNonce`. It must not jump straight to the gap-filler. Spell this out; "the ordinary R80 path" is ambiguous when
  the job is not yet `stuck`.

### M5 — RAM budget (≤ 64 MiB) is not backed by bounded queues (§7.4, §15.2, R126)

**Problem.** "Worst-case buffered bytes ≈ 50 × 1 MiB" covers QUIC only. It misses three things:
- yamux receive windows are per stream, and rust-yamux's connection-level receive window defaults large (verify
  `Config::set_max_connection_receive_window` in the version libp2p 0.56 pins);
- the gossipsub per-peer send queue is bounded in *messages* (`connection_handler_queue_len`, default in the
  thousands): 50 slow-reading sybils × thousands × 32 KiB is GiB-scale on a box with an OOM rule;
- the validation pool has a semaphore (16) but no bounded *queue*. Messages left unvalidated past
  `history_length` (6 s) are silently dropped from mcache.

**Fix.**
- Set yamux connection window = 1 MiB and max streams = 32.
- Set gossipsub `connection_handler_queue_len` ≈ 128 with publish/forward queue timeouts.
- Bound the validation queue at e.g. 1 024; on overflow report Ignore.
- Measure RSS under a slow-reader test in G1.

### M6 — `head` digest projection unspecified; `home_seq` not restart-safe (§11.2, §11.3)

**Problem.**
- The replica's view mixes chain facts (`max`, `or`) and wall-clock `expiry`. If the replica digests that view, it
  differs from the home's digest whenever a chain event leads the home's next `book` or an expiry falls between head
  and compare. That gives a perpetual mismatch and a sync every 30 s per (market, home).
- The home's `home_seq` has no rule for store restore. After a restore it goes backwards, every replica Ignores the
  home's new updates (V3 `home_seq ≤ stored`), and they stay stale until expiry.

**Fix.**
- The digest is computed over the **home register only** (`home_seq` state, `home_filled`, `home_closed`). `head`
  carries `max_home_seq`, so the cheap compare comes first.
- `home_seq = max(stored + 1, unix_ms)`, as for announce `version`, and it is bumped by `restore_epoch`.

### M7 — Sync serving is an egress amplifier (§5.4, §7.3, D2)

**Problem.** Requests of ~100 B return ≤ 1 MiB at 2 req/s per peer. 30 inbound sybils can draw ≈ 60 MiB/s. "≤ 3
concurrent" bounds parallelism but not rate.

**Fix.** Serve ≤ 1 full `intents`/`announces` sync per peer per 60 s, matching the trigger rule in R125. Add a global
egress budget, e.g. 2 MiB/s for sync. Page `book` per home.

### M8 — S3 API fit (`src/mesh/accept.rs`)

**Problem.**
- `Source` (l.79) has no `Gossip`.
- `PrivateFromOpenPeer` (l.175) is keyed on `Peer(PeerClass::Open)`.
- `hop_count` only increments for `Peer` (l.~143).
- `BadEnvelope` is overloaded (C1).
- `Unsupported` (l.180) is returned *as an error*. That works for "V7 forward, don't store", but the gossip mapping
  must special-case it.

`Seen` is a single store probe and has no in-memory set (M1). `hub_msg` builders fit the new message style; the API
otherwise fits.

**Fix.** In S3′:
- add `Source::Gossip` (treated as open class, hop stored 1);
- split the clock code out of `BadEnvelope`;
- add `gossip_acceptance(Code)` with a table test;
- add a `Seen` impl that layers memory over the store.

### M9 — Version skew turns into bans (§4.3 seam, §6 V0)

**Problem.** §4.3 plans a `hub.alg` field "in a 1.3 envelope minor". An old node computes `hub_msg` without it, gets
`BAD_HUB_SIG` and Rejects. One Reject bans for 1 h (C1). During a rolling upgrade the mesh partitions by version.

**Fix.** Crypto and digest faults are Reject only when `spec minor ≤ max minor we implement`. For a higher minor,
**any** failure is Ignore. Add a test.

### M10 — Scoring arithmetic and gossipsub config claims (§7.1, §7.2; verify against libp2p-gossipsub in 0.56)

**Problem.**
- (a) P4 is **squared** (`weight × count²`), and the topic score is multiplied by `topic_weight`. One invalid
  therefore costs −100 on intent, −50 on dex and hint, and −20 on announce. "One invalid graylists" holds only on the
  intent topic.
- (b) `topic_score_cap` 50 caps the positive sum, so "+56 survives one" is really +50 → −50, which sits exactly at
  the publish threshold.
- (c) P6 (−50, threshold 3) graylists all of E-G1's 6 loopback nodes unless 127.0.0.1 is whitelisted. The whitelist
  takes `IpAddr`, so `/dns4` bootstrap entries need resolving.
- (d) `gossip_retransimission` caps repeated IWANTs for the same id; it is not the broken-promise counter (that is
  P7 via `iwant_followup_time`).
- (e) V3: `protocol_id_prefix` most likely also emits `<prefix>/1.0.0`, so "v1.0 not offered" may need a custom
  `ProtocolId` list. `ValidationMode::Anonymous` must be paired with `MessageAuthenticity::Anonymous`.
- (f) Per-topic `max_transmit_size` and mesh params changed recently in rust-libp2p. Pin the exact builder names in
  V4.

**Fix.** Correct the §7.2 note, add a unit test that computes the score after 1 and 2 invalids per topic kind, and
use a test profile with `ip_colocation_factor_weight = 0`.

### M11 — Address filter blocks admin-configured private peers; identify leaks private interfaces (R120, §5.4)

**Problem.**
- MESH says private peers "usually live in a VPC". Their QUIC `multiaddr` (admin data) is RFC 1918, and the
  global-unicast filter refuses it unless `allow_private_addrs = true`. That switch then also opens SSRF for
  DHT-learned addresses.
- Identify pushes all listen addresses, including VPC interfaces, to every open-mesh peer.

**Fix.**
- Apply the filter only to network-learned addresses (DHT, identify, announce). Peer rows, `bootstrap` and `direct`
  bypass it.
- Configure identify to advertise only `[gossip] external` (hide listen addrs; verify the identify `Config` method in
  0.56).

### M12 — ERC-1271 `route_order` is Reject-class, so our own gateway would get itself banned (§11.4)

**Problem.** "`erc1271` … Reject as a `route_*` from a non-home". Passkey wallets are a target user group (§5.2: the
8 KiB cap exists for them). If our gateway publishes their routed taker orders, every node Rejects them, and **our**
node is graylisted and then banned network-wide.

**Fix.** Add a publish-side rule: the gateway never publishes `route_*` for `sig_kind = erc1271` and tells the wallet
to post to the home's gateway. Add a unit test on the publish path.

### M13 — Over-engineering for v1: Kademlia (R120, §7.4)

**Problem.** Announces already carry signed `endpoints.multiaddrs` and per-chain capabilities. Bootstrap, identify and
announce-driven dials cover discovery for a network of tens of nodes.

Kademlia brings:
- DHT server/client modes;
- provider records per chain;
- `BucketInserts::Manual` with a /24 cap;
- 48 h records and republish timers.

It is also the main eclipse and SSRF surface the spec then has to defend (E1, X1).

**Fix.** Defer Kademlia to a later stream. v1 discovery = bootstrap + `direct` + announce multiaddrs (R120 filter) +
gossipsub's own subscription view. Two smaller simplifications as well:
- P5 with five inputs plus `gossip_peer_stat` could be reduced to landed/missed/false-hint;
- E-G3's head and sync for books stays (replicas are ruled in).

### M14 — Test plan gaps against the safety properties (§16)

| Property | Missing test |
|---|---|
| No honest-peer penalty | fresh-join under traffic (C1), version skew (M9), config-private chain (C1.3) |
| Unbound DEX | cancel-then-settle, IOC remainder, deterministic claimant (C2) |
| Exclusivity | sybil re-origination (H1), shared-lane PoP and self-dealt landings (H2) |
| Freshness | pipelined nonce n+1 (H4) |
| Private scope | TCP-first partner, partner gossip ban leaves the bus intact (H5); identify addrs (M11) |
| Replay | announce `version` replay to a fresh node, then the newer one wins; hint replay after a terminal row ⇒ Ignore; intent replay after 120 s with a store cap reached (M1) |
| Our double broadcast | the same intent via gateway + bus + gossip concurrently ⇒ one job row, one outer tx (E-G1 asserts only "exactly one submitter lands") |
| Budgets | slow-reader RSS (M5), sync egress (M7), hint flood vs V8 budget (M4) |

---

## Low

- **L1 §0 evidence is stale.** `src/mesh/` exists (S3, e8e430e) and already uses `scaas-intent/1.2` and
  `scaas-hub/v1`. "Nothing to migrate" is still true (nothing is deployed). Update the sentence.
- **L2 §8.4 DDL.** `CREATE INDEX dex_replica_book … (…, closed, side)` refers to a column that does not exist (the
  table has `home_closed` and `chain_closed`).
- **L3 §4.3 "no tls12".** reqwest and hyper-rustls enable rustls `tls12` additively
  (`cargo tree -e features -i rustls`: `tokio-rustls feature "tls12"` ← `hyper-rustls`). Enforce TLS 1.3 per config
  with `with_protocol_versions(&[&TLS13])` for the bus and QUIC. Drop the claim; RPC clients must keep 1.2.
- **L4 §15.1 / V2 reqwest feature breaks HTTPS RPC.** `rustls-tls-no-provider` = `rustls-tls-manual-roots-no-provider`
  (reqwest 0.12.28 manifest), which has **no root store**, so every `https://` RPC or Odoo call fails with
  UnknownIssuer. Use `rustls-tls-webpki-roots-no-provider` (or `-native-roots-no-provider`). alloy's `reqwest` feature
  does not enable TLS (alloy-transport-http 1.6.3: `default-features = false`), so V2 is otherwise reachable. Also
  call `install_default()` before any alloy provider is built. (This is the most likely immediate S5′ breakage;
  promote to Medium if you prefer.)
- **L5 §4.2 table.** On QUIC, libp2p-TLS `CertificateVerify` is signed by the ephemeral cert key. The identity key
  only signs the `libp2p-tls-handshake:` extension.
- **L6 §5.2/§5.3 length prefixes.** `u8(len(topic))` is fine for EVM dex topics today (~150 B), but use `u16` before
  non-EVM addresses appear in topics.
- **L7 §10.2 vs §7.3.** A republish "within 2 s of an admin change" collides with the receiver's "1 version / 60 s"
  bucket, so a second change within 60 s is dropped until the 10-min republish. Coalesce publishes to ≥ 60 s.
- **L8 §5.4 sync cursor.** `since_ms` on `received_at` with no tiebreak loses or duplicates rows with equal ms. Use
  `(received_at, intent_id)` or the store `seq`.
- **L9 §11.3.** Replica chain facts need RPC plus a DEX event watcher per gossiped market. Say what RPC-less nodes do
  (forward only, no replica).
- **L10 §14 F1/S2.** On the open mesh, exclusivity does not bind non-announcing submitters (bots). With an unbound
  `feeRecipient`, R84 normalisation sends the fee to whoever submits. One sentence in F1 avoids implying that R121
  protects the assignee's fee.
- **L11 §9.** Hints are forwarded only by nodes that hold the intent, so forward-only and full-store nodes create
  holes in hint propagation. This is acceptable; note it.
- **L12 §10.3 lane PoP** links our lane addresses to our node identity publicly, including lanes that also submit
  private-visibility intents on public chains. On-chain senders are public anyway; mention it as an accepted side
  channel next to MESH T7.

## Feasibility notes (crate claims, build)

- V1 (libp2p-tls provider) and V3/V4 cannot be checked locally: there is no libp2p in `~/.cargo/registry`. The
  vendor-patch fallback (b) is realistic, but expect more than "≤ 10 lines": the cipher-suite constants are imported
  from the ring module, and the crate's `rustls` feature line must change too. quinn may keep `ring` compiled for
  token/reset HMAC keys, which is fine under V2's wording.
- Build box: `cmake`, `gcc` and `clang` are present, 23 GiB RAM (8 GiB free at review time), 8 cores, rustc 1.90.
  aws-lc-sys plus about 200 libp2p crates is feasible with `CARGO_BUILD_JOBS=4` run alone. Measure peak RSS in G1 as
  the spec says.
- CPU budget is plausible. alloy's pure-Rust k256 `ecrecover` is closer to 100–150 µs than 60 µs, which still keeps
  < 5 % at 200 msg/s.
