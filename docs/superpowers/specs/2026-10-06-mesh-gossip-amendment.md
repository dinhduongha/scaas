# Amendment A2 to the round-4 relayer mesh — gossip P2P for the nodes

Status: draft rev 2, 2026-10-06 — review 1 (FIX-THEN-GO) and the owner answers folded in; disposition §20. Repo `scaas` (`custom-addons/bamboo-dms/scaas`) at `main` 02a71f3.
Rulings: **R112–R127** (§2), continuing R70–R86 (MESH) and R87–R111 (NI incl. Amendment A1).
Owner inputs folded in (all 2026-10-06):

1. **Gossip is required in round 4, alongside the HTTP pull bus** (amends R70).
2. **Post-quantum transport**: hybrid X25519MLKEM768 key exchange; one process-wide rustls provider = `aws-lc-rs`;
   identities stay Ed25519 with a seam for ML-DSA.
3. **QUIC is the default transport**; TCP+Noise and the HTTPS mTLS bus are also supported; all three selectable in
   config, same envelope/topics/validation; **private peers: QUIC or HTTPS only, never Noise**.
4. **`bamboo` → `scaas` rename approved everywhere**: crate `scaas-node` (directory today `bamboo-node/`), protocol
   ids `/scaas/…`, envelope `scaas-intent/1.2`, env `SCAAS_*`, metrics `scaas_*`. This document uses the new names.
5. **Answers to rev 1's open questions** (§19): `bus_scope = public` is a separate opt-in; DEX builds **both**
   home-bound and relayer-unbound orders in round 4, per market; exclusive-assignment trust is automatic after 3
   verified landings; QUIC offers only the PQ group.

| Short | File | How amended |
|---|---|---|
| MESH | `docs/superpowers/specs/2026-10-05-relayer-mesh-design.md` | sections listed in §18.1 |
| NI | `docs/superpowers/specs/2026-10-06-node-independence-design.md` | sections listed in §18.2 |
| §05 | `docs/superpowers/specs/blockchain-research/05-open-relayer-network.md` | §5.1 conclusion (bản 3) is now built; corrections §18.3 |
| UD | `docs/superpowers/specs/blockchain-research/_USER-DECISIONS.md` | MESH §15.1 rows for §22.2 C / §23.6 rewritten (§18.3) |
| DEX | `docs/superpowers/specs/2026-10-03-dex-design.md` | RS5-9 kept; book replication added (§11) |
| node | `scaas-node/` (today `bamboo-node/`) | |

Nothing is deployed, so every wire string below changes **in place** without a version bump. S3 exists as a
library (`src/mesh/`, e8e430e) and already uses `scaas-intent/1.2` (`envelope.rs` l.9) and `scaas-hub/v1`
(`hubsig.rs` l.11); `Cargo.lock` has no `libp2p` and no `aws-lc-rs`. The crate rename `bamboo-node` → `scaas-node`
is in progress; paths below say `src/…` relative to the crate.

---

## 1. Scope and non-goals

### 1.1 In scope

1. **Three carriers, one pipeline.** (a) libp2p **QUIC** (default), (b) libp2p **TCP + Noise + yamux**, (c) the
   **HTTPS mTLS pull bus** of MESH §5. Gossip (open mesh) runs over (a)/(b); the pull bus runs over (c) **and** over
   (a) as a libp2p request-response protocol carrying the same pages (R113). All carriers feed the same `accept()`
   (MESH §7.2), the same store, the same dedup, the same scheduler.
2. **Four gossip payloads**: intents (`scaas-intent/1.2` envelopes), landed hints, DEX book traffic (orders, cancels,
   book state), node announces (R117–R124).
3. **Open admission**: Kademlia discovery + bootstrap list, gossipsub v1.1 peer scoring, graylist/ban, per-peer and
   per-origin rate limits replace the allowlist **for the open mesh only**; the allowlist (SPKI pins) stays for the
   pull bus (R72).
4. **Anti-entropy** for late joiners and healed partitions (`/scaas/sync/1`, R125).
5. **PQ key exchange** on QUIC and HTTPS; Ed25519 authentication everywhere (R114).
6. Admin API, metrics and app screens for gossip (R127).

### 1.2 Non-goals

| Out | Why |
|---|---|
| Private-visibility or private-chain data on any gossip topic | R76/R85 unchanged; §12 proves it |
| Private gossip topics among a consortium | gossipsub re-forwards to any subscriber; R85 (origin-only serving) cannot hold. Consortium exchange is the pull bus, over HTTPS or QUIC |
| NAT traversal (relay v2, DCUtR, AutoNAT), mDNS, WebRTC/WebTransport, browser nodes | nodes are servers; a NAT'ed node is a DHT client with outbound connections only. Wallets use the gateway (§05 §5.1 "client nhẹ") |
| Gossipsub peer exchange (PX) | discovery is Kademlia; PX is an eclipse vector with no gain here |
| Rewards, stake, PoW, lottery | R75 unchanged; scoring is a network control, not an economy |
| Zether intents on gossip | MESH §1.2 unchanged (needs `W = 0` + single-flight design); gossip removes only the latency objection |
| Cross-home matching of **home-bound** orders | RS5-9: a bound order is settled only by its home. Network-wide liquidity is the per-market **relayer-unbound** mode (§11.6), built in G3 (owner answer 2) |
| ML-DSA / hybrid signatures | libp2p has no ML-DSA key type; seam only (R114) |
| Compression (snappy) of gossip payloads | ≤ 32 KiB messages at ~10 msg/s; decompression bombs are a cost with no gain |

---

## 2. Rulings

Format of PD §13: **ruling — why — cost if wrong.** "Arbitrary" = a number with no measurement behind it (UD §22.10.1).

| # | Ruling | Why | Cost if wrong |
|---|---|---|---|
| **R112** | (owner) **Gossip is required in round 4, alongside the pull bus.** Amends **R70**: the pull bus is no longer "transport v1, libp2p later"; it is the **admitted-peer** transport (consortium/private), and libp2p gossipsub v1.1 is the **open-mesh** transport. Same envelope, same store (NI R88/R111), same `accept()`, same dedup/tombstones, same policy table. Admission on the open mesh = scoring + limits (R119), not an allowlist. | Owner; §05 §5.1 bản 3 ("CHỌN libp2p"), UD §6 point 2, SRS §5.1. The pull bus keeps what gossip cannot give: cursor catch-up and a single export function for private data (MESH §9). | Two transports to operate; mitigated by one pipeline behind them (§3). |
| **R113** | (owner input 3) **Carriers selectable in `[transport]`**: `quic` (default on), `tcp` (Noise, default on), `https` (default on). Open-mesh gossip runs on `quic` and `tcp`. The pull bus runs on `https` (MESH §5) **and** on `quic` as request-response protocol `/scaas/bus/1.2` with the same two operations (`policy`, `intents?since`) and the same `may_export`. **Admitted peers (any class) are served only over `https` or `quic`, never over a TCP+Noise connection** — the bus handler refuses (`TRANSPORT_NOT_PQ`) on a TCP connection. | Owner: QUIC default; private peers QUIC or HTTPS. Putting the bus over QUIC (not over gossip topics) keeps R85 and the cursor discipline; one connection per peer serves both bus and gossip. | A partner without QUIC/UDP egress uses HTTPS. |
| **R114** | (owner input 2) **PQ key exchange, classical identity.** One process-wide rustls `CryptoProvider` = **`aws-lc-rs`** with **X25519MLKEM768** (codepoint `0x11EC`); installed once at start and passed explicitly to every rustls builder. **QUIC and the HTTPS bus offer only X25519MLKEM768** (no classical group: a QUIC/HTTPS connection is PQ by construction). TCP+Noise (XX, X25519) is classical and carries **only** open-mesh gossip, i.e. data that is public by definition. Identity and every signature stay **Ed25519**: PQ here protects **confidentiality against harvest-now-decrypt-later only**; a future quantum adversary could forge identities *live*, not retroactively. Seam: every new signed message names its algorithm in its domain tag (§5.3) and the announce reserves `pq_pubkey` (§10). **Reverses MESH §3.4 ("ring provider") and review-1 M1** ("ring provider explicit, no aws-lc-rs"). | Owner. rustls ≥ 0.23.27 ships the hybrid group in `aws-lc-rs` (ring has no ML-KEM). Two providers compiled in make `ServerConfig::builder()` panic, so the rule "always `builder_with_provider`" of MESH §3.4 stays — only the provider changes. PQ-only offer removes the need to inspect the negotiated group per connection. | `aws-lc-sys` is C + cmake: one long first build; a third-party node must speak X25519MLKEM768 on QUIC or fall back to TCP (open mesh only). |
| **R115** | (owner input 4) **Names**: envelope `scaas-intent/1.2` (MESH R81 string), `hub_msg` domain tag `scaas-hub/v1` (12 bytes; MESH §4.5 `bamboo-hub/v1`), protocol ids `/scaas/…`, topics §5.1, env `SCAAS_*`, metrics `scaas_*`, store/key paths `/var/lib/scaas`, `/etc/scaas`. Topics carry the **`chain_key`** (`evm:100`), not CAIP-2 — MESH §4.2 already keys every wire object on `chain_key`. | Owner rename; nothing is signed or deployed with the old strings (§0 evidence). | — |
| **R116** | **One node key** (Ed25519, 32-byte seed) is: the `hub.sig` key (R72), the self-signed TLS cert key of the HTTPS bus (R72), the libp2p identity (`PeerId` = identity-multihash of the protobuf Ed25519 public key; QUIC's libp2p-TLS cert and Noise static-key signature are made with it). The canonical id everywhere in envelopes, store and admin API stays `peer_id = SHA-256(SPKI DER)` (R72); `PeerId ↔ peer_id` is a pure function of the public key. Config: `[identity] key` (replaces MESH `[mesh] key`, never built). | One thing to pin, one thing to rotate; an announce, a `hub.sig` and a gossip connection are attributable to the same operator without a binding certificate. Cross-protocol confusion is excluded by distinct signing contexts (§4.2). A split key would need a signed binding message and buys nothing: all three uses live in one process (MESH T14 already bounds a compromise). | Compromise of the key = all three identities; rotation = new identity (MESH §5.1 rule). |
| **R117** | **Wire**: every gossip payload is the **same UTF-8 JSON** as on the pull bus (MESH R81), one object per message, kind determined by the topic and by `spec`. New kinds are signed over **fixed binary messages** like `hub_msg` (§5.3), never over JSON. No CBOR, no protobuf. gossipsub runs **`ValidationMode::Anonymous`** (StrictNoSign: no `from`, `seqno`, `signature` fields); authorship is in the payload. **Message-id = `SHA-256("scaas-msgid/1" ‖ topic ‖ payload)[0..20]`**, not `intent_id`. | JSON is already mandatory for `body_hash` (MESH §4.2) and the vectors; a second encoding doubles the conformance surface for ~30 % bytes at ~10 msg/s. Signatures in the payload are transport-neutral (the same object is served by the bus and `/scaas/sync/1`). Message-id = `intent_id` would let a poisoned copy (MESH T6/H1: same `intent_id`, other `body_hash`) occupy the seen-cache and **censor the honest copy at the gossip layer**; content addressing makes only identical bytes dedup, and the store dedups by `intent_id` (MESH R78). | — |
| **R118** | **Validation pipeline** (§6): gossipsub `validate_messages()`; every message is held until the node reports `Accept` (forward), `Reject` (drop + P4 penalty) or `Ignore` (drop, no penalty). **Reject only for faults decidable from the message bytes alone** — size, non-canonical encoding, spec major, digest, signatures **over a public key carried in the message**, topic/chain mismatch, a `private` label — and only when the message's spec minor ≤ the highest minor we implement (otherwise every failure is `Ignore`, so a rolling upgrade never penalizes). Anything that depends on announces, our config (chain profile, known chains), the clock or the store is `Ignore`. One table `gossip_acceptance(Code) -> MessageAcceptance` (§6.1) maps every code. Policy outcomes never stop forwarding (§05 §5.1.0 "từ chối thì chuyển tiếp"). One bounded RPC freshness read (subject nonce, balance) runs **off the event loop**, ≤ 500 ms, and **fails open for forwarding**; full simulation stays on the submit path (MESH L4). Nothing is persisted before L2 passes (MESH T1). | Honest forwarders validate before forwarding, so a Reject-class message is evidence against the sender; anything that two honest nodes can judge differently must not penalize. RPC-less pool nodes (UD §21.4 "pool thuần") must still forward. | A spam intent with a valid signature and a fresh nonce reaches every node's store (bounded by R119 caps); submitters still simulate. |
| **R119** | **Scoring and limits** = the numbers of §7, all config, **all arbitrary** except where a source is cited. Score thresholds gossip −10 / publish −50 / graylist −80; one Reject on the intent topic graylists a fresh peer for ~3 min (other topics: no graylist); **auto-ban 1 h only after ≥ 2 Reject-class events within 1 h** (store `gossip_ban`); admitted bus peers are never auto-banned (gossipsub-level blacklist only, the connection and the bus stay); per-propagation-source token buckets (`Ignore` on overflow); per-origin and per-`from` buckets (UD §22.2 C "trần intent/giây/peer", §05 §5.5 tier 1, in process: single process, MESH T1). Gossip rows are capped separately from the store (`gossip_max_rows`) so the open mesh cannot `STORE_FULL` our own and consortium work. | gossipsub v1.1 scoring is the network-layer anti-spam the research chose (§05 §5.5 "tầng −1"); P3 (mesh delivery deficit) is off because traffic is bursty and low (it punishes honest peers on quiet topics). | Re-tune after a multi-site run (as R82). |
| **R120** | (owner: Kademlia kept) **Discovery**: Kademlia protocol **`/scaas/kad/1.0.0`** (its own DHT, never the IPFS one); bootstrap multiaddrs are **toml-only** (NI R95: dial targets); DHT server mode only when `[gossip] external` is set, else client; provider records `SHA-256("scaas-provider/1" ‖ chain_key)` per subscribed chain. **Network-learned addresses** (DHT, identify, announces) are dialed only if global unicast (`allow_private_addrs = true` for tests/LAN); admin/toml addresses (bus peer `multiaddr`, `bootstrap`, `direct`) bypass the filter. Routing-table inserts are manual with ≤ 2 peers per /24 (IPv4) or /48 (IPv6) per bucket; DHT-learned peers fill at most half of the outbound slots; ≥ 2 outbound mesh peers (`mesh_outbound_min`); Kad record store capped (1 024 records, 1 024 provider keys), inbound Kad requests ≤ 10/s per peer; no Kad record content is trusted beyond "this PeerId may be reachable here". Identify (`/ipfs/id/1.0.0`, agent `scaas-node/<ver>`) advertises **only `[gossip] external`** (listen/VPC interfaces hidden); ping on. | Eclipse resistance is cheapest at the routing table and the outbound slots (§14 E1). Address filtering is the libp2p form of MESH T8 (no SSRF via network-supplied addresses). | A LAN-only deployment must set `allow_private_addrs`. |
| **R121** | (owner: automatic trust) **Exclusivity over gossip** (amends R74). *Origin side*: the eligible set adds gossip peers that (a) have a live announce advertising `submit` for `(chain, token_of, selector)` (§10), **and** (b) are in the admin list `gossip_trusted.assign = 1` **or** have ≥ `assign_min_landed = 3` **credited** landings in 7 days (§8.3: one `peer_id` per lane, intents not originated by the peer, ≥ 3 distinct `from`); (c) not excluded for misses (admin-trusted: 3 misses in 1 h ⇒ out 1 h; auto-trusted: 1 miss ⇒ out 1 h, and at most one round-robin slot in three). *Receiver side*: an `exclusive` arriving from gossip or an open bus peer is honoured only if its assignee is in **our own** eligible set and `assignee ≠ hub.id`; otherwise `exclusive_until = NULL`. The origin signs `exclusive.until = published_at + chain.exclusive_ms`, per-chain, **default 7 000 ms** (arbitrary: gossip p99 ≤ 1 s + one 5 s Gnosis block + 1 s). Receivers keep MESH's clamp `[mesh] exclusive_ms = 10 000`. Own jobs are still never assigned (R74). | Permissionless peers cannot get assignments by announcing alone (sybil delay attack, §14 S2); track record is measured from chain logs, not claims. W must cover propagation **and inclusion**: other submitters simulate first, so after inclusion they see the consumed nonce and spend nothing. | A new honest partner waits for 3 landings (or an admin flag) before it receives assignments. |
| **R122** | **Landed hints** (§9): published only by the node whose lane landed the intent; processed only from signers with ≥ 1 credited landing or `gossip_trusted`, on their own RPC budget; a hint is **a trigger for the MESH R80 consumption read, never a state change**. Our row/job changes state only from the chain read (subject nonce moved + §8.5 classification). A hint never cancels, bumps or gap-fills our job by itself. Nodes without RPC for the chain ignore hints. Hints exist only for rows that pass `may_gossip` (§8.1). | Closes MESH B4 ("no receipt gossip in v1") with zero new trust: the proof is on chain, the hint only saves the wait. | One nonce read per hinted intent (deduped, rate-limited). |
| **R123** | **Announce** (§10): `scaas-announce/1`, signed by the node key, `version` strictly increasing, `expires_at ≤ issued_at + 24 h`, re-published every 10 min and on change; carries public policy (the `/v1/mesh/policy` shape filtered as for an **open** peer), fees, chains, lanes with **proof of possession**, DEX homes, client endpoints. It **replaces `/policy` for gossip peers**; `/policy` stays for bus peers. URLs in announces are **never dialed** by the node (MESH T8); multiaddrs go through the R120 filter. | Signed and versioned ⇒ replayable copies cannot roll a node back; PoP stops a node from claiming another's track record or DEX relayer. | — |
| **R124** | (owner answer 2) **DEX book gossip, two order modes per market** (§11). **Home-bound** (default, RS5-9, `dex.rs` l.552–554): an order bound to relayer `r` is matched and settled **only by the home** that proved `r` in its announce; `OrderBookDex._accept` (`relayer ∈ {0, sender}`) makes this **hard**. Other nodes keep read-only replicas — a home register (highest `home_seq` wins) joined with chain facts (`filled = max`, `closed = or`) — and replicate/advertise only **DEX-trusted homes**. **Relayer-unbound** (`dex_market.unbound = 1`, maker opts in per order with `relayer = 0`): resting GTC orders only; one deterministic **claimant** may match during `claim_ms`, then any node matches its own (bound) takers against it; cancel is final only when mined (§11.6). In both modes `filled[orderHash]` (no overfill, pair-isolated `MatchFailed`) is the arbiter. Topics per market. | Bound: one sender can settle, RS5-9's anti-MEV kept. Unbound: network-wide liquidity the owner asked for; honest nodes avoid racing by claim + grace, and the chain arbitrates the rest. | Bound liquidity is fragmented per home. Unbound makers accept execution by **anyone** (not only nodes) within their limit, and an off-chain cancel does not bind until mined. |
| **R125** | **Anti-entropy** `/scaas/sync/1` (libp2p request-response, JSON codec): `intents` (stored gossip-eligible rows, cursor = store `seq`), `announces`, `book` (one market, one home/claimant, after `home_seq`). Items are the same signed objects and go through the same validator (without gossip forwarding). Triggered on first contact and on reconnection (≤ 1 per peer per 60 s, ≤ 3 peers at once) and by book-head mismatch; served ≤ 1 full `intents`/`announces` sync per peer per 60 s within a global sync egress budget of 2 MiB/s. | gossipsub only caches ~6 heartbeats; the pull bus's cursor catch-up (MESH E10) must exist on the open mesh too. | — |
| **R126** | **Crates and budget** (§15): `libp2p` **0.56.x** pinned, `default-features = false`, features of §15.1; `rustls` with `aws_lc_rs` + `prefer-post-quantum`; reqwest switched to its no-provider rustls feature. Gossip subsystem budget: ≤ 64 MiB added RSS at 50 peers, < 5 % of one core at 200 msg/s validated. | Owner: the node runs small; the box runs one heavy job at a time. | — |
| **R127** | **Admin API and observability** (§13): `/v1/admin/gossip/*` routes in NI §7.3, gossip columns on `chain`/policy/`dex_market`, `scaas_gossip_*` metrics, app screens Peers/Topics/Announces/Bans. Bootstrap, listen addrs, external addrs, direct peers and the key stay toml-only (NI R95). | Same split as NI: dial targets and secrets in toml, behaviour in the store. | — |

---

## 3. Architecture

```
  wallets / ERPs ──HTTP──► gateway (door A) ─┐
  Odoo cron ──HMAC──► job API (NI §5) ───────┤
                                              ▼
                     ┌──────────────── accept() L0–L3 (MESH §7.2) ───────────────┐
  libp2p swarm       │                                                            │
   QUIC (PQ) ─┐      │  gossip validator (§6) ──► accept(source = gossip)        │
   TCP+Noise ─┼─► gossipsub ── topics §5.1                                       ├──► store (intent, job,
              │      │                                                            │     dex_*, gossip_*)
              ├─► /scaas/bus/1.2 (QUIC only) ──► bus server/puller ──┐           │        │
              ├─► /scaas/sync/1  ───────────────► validator ─────────┤           │        ▼
              └─► /scaas/kad/1.0.0, identify, ping                   │           │   scheduler (MESH §8.3)
  HTTPS mTLS (PQ) ─► /v1/mesh/* (MESH §5) ─► bus server/puller ──────┴► accept(source = peer)
                     └────────────────────────────────────────────────────────────┘
  publishers: may_export (bus, MESH §9) · may_gossip (gossip + sync, §8.1) — the only two exits
```

`src/mesh/` (S3, S5) keeps the transport-neutral parts; new `src/gossip/` holds the swarm task, validator, scoring
glue, announce, hints, sync and the DEX replica. The swarm runs in **one tokio task** that owns the `Swarm`; every
store or RPC call it needs goes through `spawn_blocking`/a bounded channel, so the event loop never blocks on I/O
(R118).

### 3.1 `node.toml`

```toml
[identity]
key = { file = "/etc/scaas/node.key" }      # Ed25519 PKCS#8 PEM (R116); SecretSource like [keys]

[transport]
quic  = true                                # default carrier (R113)
tcp   = true                                # TCP + Noise + yamux, open-mesh gossip only
https = true                                # MESH §5 bus on [mesh] bind

[mesh]                                      # pull bus (MESH §3.2) minus `key` (moved to [identity])
bind = "0.0.0.0:8550"
cert = "/etc/scaas/mesh.crt"                # self-signed X.509 holding [identity] key

[gossip]
enabled = true
listen   = ["/ip4/0.0.0.0/udp/4001/quic-v1", "/ip4/0.0.0.0/tcp/4001"]
external = ["/dns4/node.example.net/udp/4001/quic-v1"]   # announced + DHT server mode; empty = DHT client
bootstrap = ["/dns4/boot1.example.net/udp/4001/quic-v1/p2p/12D3KooW…"]
direct = []                                 # explicit gossipsub peers (multiaddr with /p2p/), e.g. partners
allow_private_addrs = false                 # network-learned addresses only (R120)
max_established = 50                        # in 30, out 20 (§7.4)
```

All other numbers of §7 have defaults in code and are overridable under `[gossip.limits]` / `[gossip.score]`.
Toml-only (NI R95 list extended): `[identity]`, `[transport]`, `[gossip] listen/external/bootstrap/direct/
allow_private_addrs`. Hot from the store: per-chain/per-policy/per-market `gossip` switches, `exclusive_ms`,
`gossip_trusted`, bans.

---

## 4. Identity and transport security

### 4.1 Key and ids (R116)

- Seed: `[identity] key` (same PKCS#8 parsing as MESH §3.4). `libp2p::identity::Keypair::ed25519_from_bytes(seed)`.
- `peer_id = SHA-256(302a300506032b6570032100 ‖ pubkey)` (MESH §4.3); `PeerId` from the same pubkey. A received
  `PeerId` is converted by extracting the Ed25519 key from its identity multihash; a non-Ed25519 `PeerId` is refused
  at connection establishment (`handle_established_*_connection` returns a denial).
- `scaas-node mesh-id` prints `peer_id`, `PeerId` and the SPKI pin.

### 4.2 Signing contexts with the one key

| Use | Signed bytes begin with | Defined by |
|---|---|---|
| TLS 1.3 `CertificateVerify` (HTTPS bus only; on QUIC it is signed by libp2p-TLS's ephemeral cert key, not ours) | 64 × `0x20` ‖ `"TLS 1.3, server/client CertificateVerify"` | RFC 8446 §4.4.3 |
| libp2p-TLS cert extension (QUIC: the identity key signs only this) | `"libp2p-tls-handshake:"` | libp2p TLS spec |
| Noise static-key binding | `"noise-libp2p-static-key:"` | libp2p Noise spec |
| `hub.sig` | `"scaas-hub/v1"` | MESH §4.5 (renamed, R115) |
| announce / hint / dex book / dex head | `"scaas-announce/ed25519/1"`, `"scaas-hint/ed25519/1"`, `"scaas-dexbook/ed25519/1"`, `"scaas-dexhead/ed25519/1"` | §5.3 |

All prefixes are distinct and none is a prefix of another, so no signature is valid in two contexts.

### 4.3 PQ key exchange (R114)

- `rustls = { version = "0.23.27+", default-features = false, features = ["aws_lc_rs", "prefer-post-quantum", "std",
  "logging"] }`. `tls12` stays compiled in (hyper-rustls/reqwest enable it additively; RPC endpoints may need 1.2);
  the bus and QUIC configs pin `with_protocol_versions(&[&rustls::version::TLS13])`. At start, **before any alloy
  provider or reqwest client is built**: `rustls::crypto::aws_lc_rs::default_provider().install_default()`; every
  bus/QUIC config is built with
  `builder_with_provider(provider_pq())` where `provider_pq()` = the aws-lc-rs provider with
  `kx_groups = vec![X25519MLKEM768]`.
- **HTTPS bus** (MESH §5.1 server and client): `provider_pq()`. A client without the hybrid group fails the handshake
  (`HandshakeFailure`). Metric `scaas_tls_handshake_failures_total{listener="mesh",reason}`.
- **QUIC** (libp2p-quic → quinn → rustls via libp2p-tls): `provider_pq()` on both sides.
  **VERIFY V1** (at the start of G1): whether `libp2p-tls` in the pinned version builds its rustls configs from a
  caller-supplied provider. If it hardcodes `rustls::crypto::ring::default_provider()` (as earlier versions did),
  then, in order of preference: (a) a `libp2p-quic` config hook that accepts our `QuicClientConfig`/`QuicServerConfig`;
  (b) `[patch.crates-io] libp2p-tls = { path = "vendor/libp2p-tls" }` switching the provider, the cipher-suite
  imports and the crate's rustls feature line (small, but more than one line; upstream PR opened in parallel); (c) a custom QUIC transport wrapping quinn with the libp2p-TLS verifier. G1 is not
  done until a test asserts the negotiated group on a QUIC connection (§16.1) — through quinn's
  `handshake_data()`/rustls `negotiated_key_exchange_group()` if exposed, otherwise by a classical-only client that
  must fail to connect.
- **VERIFY V2**: feature resolution leaves exactly one rustls provider feature in use: `cargo tree -e features -i
  rustls` shows `aws_lc_rs`; `reqwest` uses **`rustls-tls-webpki-roots-no-provider`** (picks the installed default
  provider; plain `rustls-tls-no-provider` has no root store and would break every `https://` RPC call);
  `quinn-proto` uses its aws-lc-rs feature; alloy's `reqwest` feature does not re-enable `reqwest/rustls-tls`. The
  `ring` crate may remain in the lock as a library (e.g. quinn token/reset keys); what is forbidden is a second rustls
  provider in use.
- **TCP + Noise**: XX handshake, X25519, ChaChaPoly — classical. Allowed only for gossip, sync of public data,
  identify, ping and Kademlia. The bus handler checks `ConnectedPoint`'s transport and refuses on TCP (R113).
- PQ costs: the hybrid ClientHello is ~1.2 KiB larger (ML-KEM-768 share 1 184 B); on QUIC the Initial spans two
  packets. Irrelevant at our connection rates.
- **Limit (stated)**: authentication (TLS certs, Noise binding, `hub.sig`, announces) is Ed25519. PQ here defends
  recorded traffic, not live impersonation by a future quantum adversary. Upgrade path: an announce field
  `pq_pubkey` (ML-DSA-65) signed by **both** keys, then new domain tags `scaas-*/mldsa65/1` or hybrid
  `scaas-*/ed25519+mldsa65/1` for payload signatures and a `hub.alg` field in a 1.3 envelope minor. libp2p PeerIds
  stay Ed25519 until libp2p defines a PQ key type.

### 4.4 Consequences for the private profile (R76, R85)

Admitted peers (bus) are reachable only over carriers with a PQ-only offer (HTTPS, QUIC). Private-chain and
private-visibility rows travel only on the bus (§12). Hence **every byte of private data on the wire is under a
hybrid ML-KEM key exchange.**

---

## 5. Wire

### 5.1 Topics (gossipsub `IdentTopic`, R115)

| Topic | Payload `spec` | Who publishes | Subscribed when |
|---|---|---|---|
| `/scaas/intent/1.2/<chain_key>` | `scaas-intent/1.2` | origin only (§8.1); everyone else forwards via gossipsub | chain known, `profile = public`, `chain.gossip = 1` |
| `/scaas/hint/1/<chain_key>` | `scaas-hint/1` | lander only (R122) | same as the intent topic |
| `/scaas/dex/1/<chain_key>/<dex>/<base>/<quote>` | `scaas-dex/1` | home (book, head), anyone (route) | market known and `dex_market.gossip = 1`, chain public |
| `/scaas/announce/1` | `scaas-announce/1` | every node, its own | always (gossip on) |

Addresses in topics are the family's canonical lowercase form (MESH §4.2); `base < quote` bytewise. gossipsub
protocol ids are prefixed **`/scaas/meshsub/1.2.0`, `/scaas/meshsub/1.1.0`** (custom prefix: our mesh never merges
with an IPFS/Ethereum mesh); v1.0 and floodsub are not offered (no scoring there). **VERIFY V3**: the config method
for the prefix in the pinned gossipsub version.

### 5.2 Message-id and size (R117)

```
msg_id = SHA-256("scaas-msgid/1" ‖ u16be(len(topic)) ‖ topic ‖ payload)[0..20]
```

**Canonical payloads** (M1): a gossip payload must be byte-identical to the canonical JSON of the parsed object
(MESH §4.2 rules applied to the whole object: keys sorted, no whitespace) and intents are published with
`hop_count = 0`; anything else is `Reject` (deterministic). One message therefore has exactly one msg-id, and byte
variants cannot be minted from a valid message. Length prefixes in every signed message below are `u16be`.

`max_transmit_size = 65 536` (whole RPC frame). Per-kind payload caps (checked first in V0): intent 32 KiB (MESH
§4.2), dex 8 KiB (ERC-1271 passkey signatures), announce 16 KiB, hint 512 B.

### 5.3 New message schemas

Same JSON rules as MESH §4.2 (hex/decimal strings, `chain_key`, canonical addresses). Unknown top-level fields:
ignored on the bus (MESH rule), **ignored but counted** on gossip (they are inside the canonical bytes, so they do not
create variants). Every node-signed message carries its signer's raw Ed25519 `pubkey`; receivers check
`SHA-256(SPKI_ED25519_PREFIX ‖ pubkey) == signer/home` and the signature **without any announce** (C1).

**Hint** (`scaas-hint/1`):

```json
{"spec": "scaas-hint/1", "chain_key": "evm:100", "intent_id": "0x…", "kind": "landed",
 "tx": "0x…", "block": 41233001, "signer": "64 hex", "pubkey": "64 hex", "issued_at": 1756500030, "sig": "128 hex"}
```
```
hint_msg = "scaas-hint/ed25519/1" ‖ u16be(len) ‖ chain_key ‖ intent_id(32) ‖ u8(kind: 0 landed)
         ‖ u16be(len) ‖ tx (ASCII, family tx id) ‖ u64be(block) ‖ signer peer_id(32) ‖ pubkey(32) ‖ u64be(issued_at)
```

**Announce** (`scaas-announce/1`, §10): `{spec, peer_id, pubkey, version, issued_at, expires_at, body, sig}` with
`body` = `{chains: [...], endpoints: {...}, agent, pq_pubkey?}` and

```
announce_msg = "scaas-announce/ed25519/1" ‖ peer_id(32) ‖ u64be(version) ‖ u64be(issued_at)
             ‖ u64be(expires_at) ‖ SHA-256(canonical JSON of body)
```

**DEX** (`scaas-dex/1`, §11), `type` ∈ `route_order | route_cancel | route_invalidate | book | head`:

```json
{"spec": "scaas-dex/1", "type": "book", "chain_key": "evm:100", "dex": "0x…", "base": "0x…", "quote": "0x…",
 "order": {…Order fields of DEX §1.1…}, "signature": "0x…", "sig_kind": "eoa",
 "home": "64 hex", "pubkey": "64 hex", "home_seq": 812, "state": "resting", "filled_total": "0",
 "claim_until": 0, "published_at": 1756500040, "sig": "128 hex"}
```
```
dexbook_msg = "scaas-dexbook/ed25519/1" ‖ u16be(len) ‖ chain_key ‖ dex(20) ‖ order_hash(32) ‖ home(32) ‖ pubkey(32)
            ‖ u64be(home_seq) ‖ u8(state: 0 resting, 1 closed) ‖ filled_total(32, uint256 BE)
            ‖ u64be(claim_until)                     # 0 for home-bound orders; unbound: the claim window (§11.6)
            ‖ u64be(published_at)
dexhead_msg = "scaas-dexhead/ed25519/1" ‖ u16be(len) ‖ chain_key ‖ dex(20) ‖ base(20) ‖ quote(20) ‖ home(32)
            ‖ pubkey(32) ‖ u64be(max_home_seq) ‖ digest(32) ‖ u32be(count) ‖ u64be(published_at)
```

For an unbound order `home` is the **claimant** (the node that ran intake and signs the `book`).

`route_*` messages carry only maker-signed objects (`order`+`signature`, `CancelOrder`, `InvalidateNonces` with
their signatures, DEX §1.3) and **no node signature**: the maker's EIP-712 signature is the authenticity; rate limits
attach to the propagation source and to the maker. `order_hash` is always recomputed (EIP-712, DEX domain).

### 5.4 Protocols over libp2p connections

| Protocol | Kind | Carrier | Purpose |
|---|---|---|---|
| `/scaas/meshsub/1.2.0`, `/1.1.0` | gossipsub | QUIC, TCP | §5.1 |
| `/scaas/kad/1.0.0` | Kademlia | QUIC, TCP | R120 |
| `/scaas/sync/1` | request-response, JSON | QUIC, TCP | R125 (public data only) |
| `/scaas/bus/1.2` | request-response, JSON | **QUIC only** | MESH §5.2 `policy` / `intents?since` for admitted peers (R113) |
| `/ipfs/id/1.0.0`, `/ipfs/ping/1.0.0` | identify, ping | QUIC, TCP | standard |

`/scaas/bus/1.2` request `{"op": "policy"}` or `{"op": "intents", "since": n, "limit": n}`; responses are byte-for-byte
the MESH §5.2 bodies. Admission = the connection's `peer_id` is an **active** row of the bus peer table (same check as
the TLS verifier, MESH §5.1), evaluated per request; suspended ⇒ `{"error": "PEER_SUSPENDED"}`. Rate limits
`peer_rps` as MESH. The puller prefers QUIC when the peer row has a `multiaddr`, HTTPS when it has a `url`
(peer row gains optional `multiaddr`, admin-validated: `/dns|ip4|ip6/…/udp/<p>/quic-v1/p2p/<PeerId>` whose PeerId
matches the pin). **Connections to bus peers are QUIC-only**: `handle_established_{inbound,outbound}_connection`
denies a TCP connection for any `PeerId` in the bus peer table, and the swarm dials bus peers only at their row's
`multiaddr`; the puller sends `/scaas/bus/1.2` only on a QUIC `ConnectionId` and the server re-checks the carrier
(`TRANSPORT_NOT_PQ`). A bus peer may still take part in gossip over that same QUIC connection.

`/scaas/sync/1`:

| Request | Response |
|---|---|
| `{"kind": "intents", "chains": [...], "since": seq, "limit": ≤200}` | `{"store_id", "items": [envelope…], "next": seq, "more": bool}`; rows with `may_gossip(row)`, non-terminal, `valid_until > now`, ordered by store `seq` (no ties); a first sync starts at `since = 0`; ≤ 1 MiB |
| `{"kind": "announces"}` | `{"items": [announce…]}`, live only, ≤ 1 MiB |
| `{"kind": "book", "chain_key", "dex", "base", "quote", "home", "after_seq": n}` | `{"items": [book…], "more": bool}` ordered by `home_seq`, ≤ 200 per page |

---

## 6. Validation pipeline (R118)

Cheapest first; the first failing stage decides. V0–V3 run inline on the swarm task (pure CPU, ≤ ~100 µs); later
stages run on the validation pool: semaphore 16, **bounded queue 1 024** (overflow ⇒ Ignore), and a message not
reported within 5 s ⇒ Ignore (before it ages out of mcache).

| Stage | Check (intent topic; other kinds below) | Fail ⇒ |
|---|---|---|
| V0 rate | propagation-source bucket (§7.3), before any parse; graylisted/banned peers are dropped by gossipsub earlier | Ignore |
| V1 shape | payload ≤ cap; UTF-8 JSON object; **canonical bytes** and `hop_count = 0` (§5.2); spec major known | Reject; unknown major, or minor above ours ⇒ Ignore |
| V2 topic | `chain_key` in payload = topic's | Reject; chain unknown to us or family we do not run ⇒ Ignore |
| V3 dedup | in-memory `seen_intent` (`intent_id`, TTL = `valid_until + clock_skew_secs`, ≤ 262 144 entries ≈ 16 MiB, evicting the soonest-expiring), then store row / `(intent_id, body_hash)` tombstone (MESH §6) | Ignore |
| V4 crypto | MESH L2: digest recompute, EVM sig low-s, `hub.pubkey ↔ hub.id`, `hub.sig` | Reject (only if minor ≤ ours, R118) |
| V4 clock | `EXPIRED`, `VALID_TOO_LONG`, `FUTURE_PUBLISHED` | Ignore |
| V5 isolation | envelope `visibility = private` | Reject + metric. Our `chain_profile(chain) = private` (config) ⇒ Ignore + metric |
| V6 origin limits | per `hub.id` 10/s, per `from` 10/min (EVM `from`, decoded subject otherwise) — charged **only on the first sight of an `intent_id`** (after V3), so replays cannot spend an honest origin's bucket | Ignore |
| V7 policy (L3) | `support = none` or `!may_submit` ⇒ forward, **do not store** (M2); otherwise continue | Accept |
| V8 freshness | node has RPC for the chain and `gossip_rpc_checks = true`: one batched read of subject nonce `n_s` (MESH §4.1 view). `nonce < n_s` ⇒ stale; `n_s ≤ nonce ≤ n_s + 16` ⇒ fresh (pipelined nonces pass, H4); `nonce > n_s + 16` ⇒ Ignore. Balance (EVM) is **advisory**: short ⇒ Accept, do not store. RPC error, timeout 500 ms or the per-chain V8 budget exhausted ⇒ Accept | stale ⇒ Ignore |
| store | INSERT `source = 'gossip'`, `source_peer` = propagation source `peer_id`, **`hop_count = 1`**. `gossip_max_rows` full ⇒ evict the gossip row with the lowest effective fee, then the oldest (never `gateway`/`job`/`peer` rows) | Accept |

Accept ⇒ gossipsub forwards the original bytes. Simulation (MESH L4) runs only on the submit path. A node that stores
nothing (forward-only, no RPC) still dedups through `seen_intent`.

### 6.1 `gossip_acceptance(Code)` (S3′, one table test per code)

| MessageAcceptance | Codes |
|---|---|
| Reject (only when spec minor ≤ ours) | `BAD_ENVELOPE` (shape only), `NON_CANONICAL`, `TOPIC_MISMATCH`, `DIGEST_MISMATCH`, `BAD_SIGNATURE`, `RELAYER_BOUND_ZERO`, `BAD_HUB_SIG`, `PRIVATE_LABEL`, `BAD_NODE_SIG` (hint/announce/dex `pubkey ↔ id` or signature), `BAD_POP`, `BAD_MAKER_SIG` (EOA) |
| Ignore | `UNSUPPORTED_SPEC`, `UNKNOWN_CHAIN`, `FAMILY_NOT_SUPPORTED`, `EXPIRED`, `VALID_TOO_LONG`, `FUTURE_PUBLISHED`, `DUPLICATE`, `RATE_LIMITED`, `PRIVATE_CHAIN_LOCAL`, `STALE_NONCE`, `UNKNOWN_SIGNER`, `NOT_HOME`, `NOT_CLAIMANT`, `UNTRUSTED_HOME`, `STALE_VERSION`, `QUEUE_FULL` |
| Accept | `UNSUPPORTED` (policy `none`), forward-only outcomes, `STORE_FULL` |

S3's `accept.rs` returns `Code::BadEnvelope` for a future `hub.published_at` (l.168); S3′ splits it into
`FUTURE_PUBLISHED` and splits `PRIVATE_FROM_OPEN_PEER` into `PRIVATE_LABEL` (envelope) and `PRIVATE_CHAIN_LOCAL`
(our profile).

### 6.2 Other kinds

- **hint**: V0; V1; V2; V3 (one per `intent_id` per 10 s; `intent_id` neither in `seen_intent` nor stored ⇒
  Ignore — we only forward hints about intents we know); V4 `pubkey ↔ signer` + Ed25519 over `hint_msg` ⇒ Reject;
  signer not credited/trusted (R122) ⇒ `UNKNOWN_SIGNER` Ignore; per-signer bucket ⇒ Ignore. Then Accept; the chain read
  happens after (§9).
- **announce**: V0; V1; V4 `pubkey ↔ peer_id`, Ed25519 over `announce_msg`, every lane PoP, `expires_at ≤
  issued_at + 24 h` ⇒ Reject; `version ≤ stored` ⇒ `STALE_VERSION` Ignore; `now > expires_at` ⇒ Ignore; admission
  priority when the announce cap is reached (§7.3).
- **dex**: §11.4.
## 7. Numbers (R119) — all config; **arbitrary** unless a source is given

### 7.1 gossipsub

| Parameter | Value | Note |
|---|---|---|
| `mesh_n / mesh_n_low / mesh_n_high / mesh_outbound_min` | 6 / 4 / 12 / 2 | small mesh, low rate; outbound min against eclipse |
| `gossip_lazy`, `heartbeat_interval` | 6, 1 s | |
| `history_length / history_gossip` | 6 / 3 | IWANT window ≈ 3 s |
| `duplicate_cache_time` (seen) | 120 s | `seen_intent` (§6 V3) covers up to `valid_until` |
| `max_ihave_length / max_ihave_messages` | 500 / 10 per heartbeat | IHAVE/IWANT budget (default 5 000 is for high-rate meshes) |
| `iwant_followup_time` | 3 s | broken IWANT promise ⇒ P7 |
| `gossip_retransimission` (rust-libp2p spelling) | 3 | max IWANT retransmissions of one id per peer (not the P7 counter) |
| `connection_handler_queue_len` | 128 | bounded per-peer send queue (default is in the thousands: 50 slow readers × 32 KiB × thousands is GiB-scale) |
| publish / forward queue timeouts | 5 s / 1 s | slow peers lose messages, not our RAM |
| `flood_publish` | true | origin latency on a small mesh |
| `prune_backoff / unsubscribe_backoff` | 60 s / 10 s | |
| PX (`do_px`) | off | R120 |
| IDONTWANT (v1.2) | on when both peers speak 1.2 | saves duplicate large intents |
| protocols | explicit `ProtocolId` list `/scaas/meshsub/1.2.0`, `/scaas/meshsub/1.1.0` | a bare `protocol_id_prefix` may also emit `/1.0.0` (**VERIFY V3**) |
| authenticity | `MessageAuthenticity::Anonymous` **with** `ValidationMode::Anonymous` | R117 |

### 7.2 Score

rust-libp2p computes P4 as `weight × counter²` and multiplies every topic term by `topic_weight`; positive topic
contributions are capped by `topic_score_cap`.

| Item | Value |
|---|---|
| thresholds gossip / publish / graylist / opportunistic graft | −10 / −50 / −80 / +5 |
| decay interval / decay to zero / retain score | 1 s / 0.01 / 3 600 s |
| topic weight | intent 1.0, dex 0.5, hint 0.5, announce 0.2; `topic_score_cap` 50 |
| P1 time in mesh | weight 0.01, quantum 1 s, cap 3 600 (≤ +36) |
| P2 first deliveries | weight 1, decay 0.999/s, cap 20 |
| P3, P3b mesh delivery / failure | **0** (off, R119 why) |
| P4 invalid deliveries | weight −100, decay 0.9994/s. One Reject costs −100 (intent), −50 (dex, hint), −20 (announce). Only the intent topic graylists a fresh peer (≈ 187 s: counter 1 → 0.894); a peer at the +50 cap drops to −50 (publish threshold), not graylisted. Two intent Rejects (−400) graylist anyone |
| P5 application | weight 1, clamped [−100, +20] = +0.5 × credited landings 7 d (cap +10) + 5 if `gossip_trusted` − 10 × exclusive violations 24 h − 20 × false hints 24 h − 10 × missed assignments 24 h |
| P6 IP colocation | weight −50, threshold 3; whitelist = IPs of `bootstrap`, `direct` and bus peers resolved at start (`IpAddr` list); test profile weight 0 |
| P7 behaviour | weight −10, threshold 6, decay 0.99/s |
| ban | **auto 1 h only after ≥ 2 Reject-class events from the peer within 1 h** (any topic); never for exclusivity violations (P5 + metric only); **never for bus-table peers** (gossipsub `blacklist_peer`, connection and bus kept); admin bans persistent, via `allow_block_list` |

Unit test (G1): the score after 1 and 2 Rejects per topic kind, for a fresh and a capped peer, equals the table.

### 7.3 Rate limits (token buckets, burst = 2 × rate)

| Bucket | Rate | Overflow |
|---|---|---|
| per source: intent / hint / dex route / dex book+head / announce | 20/s / 50/s / 20/s / 200/s / 1/s | Ignore |
| per origin `hub.id` / per `from` (intents, first sight only) | 10/s / 10/min, 100/h (§05 §5.5 tier 1) | Ignore |
| per hint signer | 5/s | Ignore |
| per maker (dex route) / per claimant (unbound `book`) | 5/s / 20/s | Ignore |
| per announcer | 1 version / 60 s; publishers coalesce to ≥ 60 s (§10.2) | Ignore |
| RPC: V8 freshness / hint reads / DEX `checkOrder` | 50/s / 10/s / 20/s per chain, separate budgets, 4 concurrent each | V8: Accept; hints: Ignore; checkOrder: defer |
| sync serving | ≤ 1 full `intents`/`announces` per peer per 60 s; `book` pages 2/s per peer; ≤ 3 concurrent; global egress 2 MiB/s | refused |
| gossip ingest into the store | 200 rows/s global | Accept without storing + metric |
| caps | `gossip_max_rows` 100 000 (`may_submit` rows only, evict lowest effective fee then oldest); replica orders 100 000 total, ≤ 10 000 per DEX-trusted home, **0 for untrusted homes**; unbound orders ≤ 1 000 per claimant; announces 5 000 admitted in priority order connected/bus/trusted/track record, untrusted ≤ 4 per /24 (/48), LRU-evicted | as above |

### 7.4 Connections and DHT

`max_established` 50 (inbound 30, outbound 20, ≤ 10 outbound from DHT-learned peers), 1 per peer (bus peers: QUIC
only, §5.4), pending inbound 16, idle timeout 60 s; QUIC `max_stream_data` 256 KiB, `max_connection_data` 1 MiB,
keep-alive 15 s; yamux connection receive window 1 MiB, ≤ 32 streams (**VERIFY V4**: `yamux::Config` method names in
the pinned version). Kad: k = 20, α = 3, record/provider TTL 48 h, republish 12 h, max packet 16 KiB, ≤ 2 peers per
/24 (/48) per bucket, store ≤ 1 024 records / 1 024 provider keys, inbound requests ≤ 10/s per peer.

## 8. Intents over gossip

### 8.1 Publish rule — `may_gossip`, the second and last exit (amends MESH §9 rule 1)

```
may_gossip(row) =
      row.visibility == open                                  # after MESH §9 strictest()
  and chain_profile(row.chain_key) == public
  and chain.gossip(row.chain_key)
  and ( row.source == 'gateway' and policy(row).gossip        # door A, per policy row
     or row.source == 'job'     and job(row).bus_scope == 'public'   # NI R99 value added (§8.4)
     or row.source == 'gossip' )                              # only for /scaas/sync/1 re-serving
```

- A row whose `source = 'peer'` (pulled from an admitted peer) **never** satisfies it: a partner's intent is not
  introduced to the open mesh by us, whatever its label (provenance rule).
- The origin publishes once, when the row is created (`gateway`, `job` after its private window). Forwarding is
  gossipsub's own; we never re-publish. `/scaas/sync/1` serves rows with `may_gossip`.
- `may_export` (MESH §9, bus) is unchanged. A gossip-received row (`source = 'gossip'`, open, public chain) may be
  served on the bus to admitted peers like any open row.

### 8.2 Ingest

The validator calls `accept(env, Source::Gossip{peer})` (new variant in S3′, treated as an `open`-class peer,
stored `hop_count = 1`); MESH §7.2 L1 `hop` and `peer_intents_per_sec` are replaced by V0/V6 for this source; L3
`PRIVATE_FROM_OPEN_PEER` is V5. Rows go `pooled`/`submittable` exactly as MESH §7.3; the
scheduler turns submittable rows into `job` rows in `~mesh` (NI R89), so the `job_live_digest` UNIQUE index (NI §4)
is the single admission point for every submission path — **gossip adds no path around G2**.

### 8.3 Exclusivity (R121)

```
eligible(chain, token, selector, visibility) = sorted_by_peer_id(
      {self if may_submit}
    ∪ {bus peers as MESH §8.2}
    ∪ {g : announce(g) live, lists submit for (chain, token|*, selector|*),
           (trusted(g).assign or credited_7d(g) ≥ assign_min_landed),
           not excluded(g), visibility == open})
auto-trusted members (not admin-trusted) take at most one round-robin slot in three
until = published_at + chain.exclusive_ms / 1000            # default 7 000 ms; receiver clamp 10 000 ms unchanged
```

- **Credit** (`credited_7d(g)`): our own §8.5 classifications `landed_elsewhere` whose log `relayer` is a lane that
  **only g** proves (a lane proved by two live announces credits nobody, §10.3), plus verified hints (§9); a landing
  counts only if the intent's origin `hub.id ≠ g`; the 3 landings must come from ≥ 3 distinct `from`. Only facts read
  from the chain.
- **Misses**: for every intent we assigned to g, at `until + one block` the origin's scheduler does its R80 read; not
  consumed, or consumed by a lane not proved by g ⇒ `missed`. Admin-trusted: 3 in 1 h ⇒ `excluded` 1 h.
  Auto-trusted: 1 ⇒ `excluded` 1 h.
- **Receiver rule** (H1): an `exclusive` on an envelope from `Source::Gossip` or an open bus peer is honoured only if
  `relayer_id ≠ hub.id` and `relayer_id` ∈ **our** eligible set (computed as above) or is ourselves; otherwise
  `exclusive_until = NULL` (MESH vector 24 behaviour). A sybil that re-originates a public intent with an exclusive to
  itself or another sybil therefore delays nobody. Admitted private/consortium peers keep MESH §8.2 as is.
- **Violation** (MESH B1): a lane proved by g lands an intent inside another assignee's window ⇒ P5 −10, metric
  `scaas_mesh_exclusive_violations_total{peer}`. No auto-ban: copies legitimately diverge on the open mesh
  (re-origination, clamps, skew), so a ban is an admin decision.
- Jitter after `until` unchanged (MESH §8.3). On the open mesh exclusivity binds only nodes that follow this spec;
  bots that submit without announcing are bounded only by G1 and R84 (§14 F1).

### 8.4 Store and scope changes

- `intent.source` CHECK gains `'gossip'`; `source_peer` holds the propagation source's `peer_id`.
- `job.bus_scope` CHECK: `restricted | open | public` (NI R99). `open` = admitted bus peers (unchanged meaning);
  `public` = also the open mesh. Odoo `res.company.blockchain_bus_scope` (S1b′) gains `public` with the same
  private window. Rationale: MESH R73's cost column ("exposes … to admitted peers") was the owner's consent for
  partners, not for the world.
- `mesh_policy` (NI admin table) gains `gossip INTEGER NOT NULL DEFAULT 0` — door-A intents on that row are published.
- `chain` gains `gossip INTEGER NOT NULL DEFAULT 0`, `exclusive_ms INTEGER NOT NULL DEFAULT 7000`; a `private`
  profile forces `gossip = 0` (admin-API validation and toml load check, as MESH §9 rule 3).
- `dex_market` (NI §12.1) gains `gossip INTEGER NOT NULL DEFAULT 0` and `unbound INTEGER NOT NULL DEFAULT 0`
  (owner answer 2: relayer-unbound orders allowed in this market); `unbound = 1` requires `gossip = 1` and a public
  chain.

```sql
CREATE TABLE gossip_announce (peer_id BLOB PRIMARY KEY, version BIGINT NOT NULL, expires_at BIGINT NOT NULL,
  body TEXT NOT NULL, received_at BIGINT NOT NULL);
CREATE TABLE gossip_lane (chain_key TEXT NOT NULL, address TEXT NOT NULL, peer_id BLOB NOT NULL,
  PRIMARY KEY (chain_key, address, peer_id));                       -- from announces with a valid PoP only
CREATE TABLE gossip_peer_stat (peer_id BLOB NOT NULL, day BIGINT NOT NULL, assigned BIGINT NOT NULL DEFAULT 0,
  landed BIGINT NOT NULL DEFAULT 0, missed BIGINT NOT NULL DEFAULT 0, violations BIGINT NOT NULL DEFAULT 0,
  false_hints BIGINT NOT NULL DEFAULT 0, invalid BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (peer_id, day));
CREATE TABLE gossip_trusted (peer_id BLOB PRIMARY KEY, label TEXT NOT NULL, assign INTEGER NOT NULL DEFAULT 1,
  dex INTEGER NOT NULL DEFAULT 0);                                  -- dex = 1: replicate/advertise as a DEX home
CREATE TABLE gossip_ban (peer_id BLOB PRIMARY KEY, until_ms BIGINT, reason TEXT NOT NULL, actor TEXT NOT NULL,
  created_at BIGINT NOT NULL);                                      -- until_ms NULL = until lifted
CREATE TABLE dex_replica (order_hash BLOB PRIMARY KEY, chain_key TEXT NOT NULL, dex TEXT NOT NULL,
  base TEXT NOT NULL, quote TEXT NOT NULL,
  home BLOB NOT NULL,                                               -- bound: the home; unbound: the winning claimant
  bound INTEGER NOT NULL CHECK (bound IN (0, 1)), relayer TEXT NOT NULL, maker TEXT NOT NULL,
  claim_rank BLOB, claim_until BIGINT, first_seen_ms BIGINT NOT NULL,                  -- unbound only (§11.6)
  side TEXT NOT NULL CHECK (side IN ('ask', 'bid')), sell_amount TEXT NOT NULL, buy_amount TEXT NOT NULL,
  home_seq BIGINT NOT NULL, home_filled TEXT NOT NULL, home_closed INTEGER NOT NULL DEFAULT 0,
  chain_filled TEXT NOT NULL DEFAULT '0', chain_closed INTEGER NOT NULL DEFAULT 0, expiry BIGINT NOT NULL,
  checked_ok INTEGER NOT NULL DEFAULT 0,                            -- unbound: our checkOrder passed
  body TEXT NOT NULL, updated_at BIGINT NOT NULL);
CREATE INDEX dex_replica_book ON dex_replica (chain_key, dex, base, quote, home_closed, chain_closed, side);
```

Portable per A1 (R111): `BIGINT`/`TEXT`, no backend types; `gossip_peer_stat` rows older than 8 days and expired
announces/bans are deleted by the janitor.

---

## 9. Landed hints (R122)

1. **Publish**: our submit path reaches `mined` (receipt success, our lane) for a row/job whose intent row passes
   `may_gossip` ⇒ one hint on `/scaas/hint/1/<chain_key>`. Nobody else publishes (no "consumed" hints, no
   re-publication of others' hints; gossipsub forwards).
2. **Gate**: hints are processed only from signers with ≥ 1 credited landing (§8.3) or `gossip_trusted`, within the
   per-signer bucket and the per-chain hint budget (10/s, separate from V8, so a hint flood cannot switch V8 off).
3. **Receive**: after Accept, if we hold a non-terminal row for `intent_id` and have RPC for the chain, queue one
   **R80 consumption read** (deduped per `intent_id` for 10 s). For our own live job the read runs in the ordinary
   `track()` order of MESH §8.4 — receipts among our `s.hashes` first, then `metaNonce` — exactly as if the job had
   become `stuck` now; only the chain's answer decides:
   - subject nonce moved past the intent's nonce ⇒ §8.5 classification ⇒ `landed` (an earlier hash of ours) /
     `landed_elsewhere` / `superseded` / `unknown`; our job then follows R80 (no bump, gap-filler, `consumed`).
   - not moved ⇒ nothing changes.
   - read error ⇒ nothing changes (fail closed, as R80).
4. **False hint**: judged only once our head ≥ `hint.block + finality_depth`, and only if
   `eth_getTransactionReceipt(tx)` **is found** without `MetaTransactionExecuted(digest = intent_id)`
   ⇒ `false_hints[signer]++`, P5 −20. Receipt not found (reorg, lagging RPC) ⇒ no verdict.
5. **Never**: a hint does not move a row or job, does not cancel (NI R98), does not stop serving, and feeds
   `credited_7d` only through the §8.3 attribution of the chain log.
6. Non-EVM families: the read is `ChainAdapter::op_consumed` (MESH §8.4); classification `unknown` (MESH §8.5).
7. Hints are forwarded only by nodes that know the intent (§6.2), so forward-only and RPC-less nodes leave holes in
   hint propagation. Accepted: a hint only saves a wait; the scheduler's own R80 reads still happen.

---

## 10. Announce (R123)

### 10.1 Body

```json
{"chains": [{"chain_key": "evm:100", "submit": true, "fee_recipient": "0x…",
             "contracts": [{"contract": "0x…", "selector": "*", "min_fee": "0", "fee_recipient_allow": "any"}],
             "lanes": [{"address": "0x…", "pop": "0x…65 bytes"}],
             "dex": [{"dex": "0x…", "relayer": "0x…", "markets": [["0x…base", "0x…quote"]]}]}],
 "endpoints": {"gateway": "https://gw.example.net", "multiaddrs": ["/dns4/…/udp/4001/quic-v1"]},
 "agent": "scaas-node/0.x", "spec": ["scaas-intent/1.2", "scaas-dex/1", "scaas-hint/1"]}
```

`chains` = what `GET /v1/mesh/policy` would return to an **open** bus peer (MESH §5.2): public chains only, `submit`
rows on registered tokens only (R86). Private chains never appear (§12). `pq_pubkey` reserved (R114).

### 10.2 Lifecycle

Version = unix ms at signing (strictly increasing per node; a restored store that would go backwards uses
`max(stored + 1, now)`). Re-published every 10 min and after a relevant admin change, coalesced so that two versions
are ≥ 60 s apart (the receivers' 1 version / 60 s bucket, §7.3); `expires_at = issued_at
+ 3 600` by default (≤ 24 h). Receivers keep the highest valid version until `expires_at`; an expired announce
removes the peer from §8.3 and from DEX homes. Discovery of `/policy` for gossip peers is the announce only;
bus peers keep `GET /v1/mesh/policy` (60 s cache).

### 10.3 Lane proof of possession

EVM/Hedera lanes (and the DEX relayer address): `pop = secp256k1_sign(keccak256("scaas-lane-pop/1" ‖ u16be(len) ‖
chain_key ‖ peer_id(32)))`, verified by `ecrecover == address`. Stable across versions (rotation = new lane).
Non-EVM lanes are listed without `pop` and are not used for attribution in v1 (assignment then needs
`gossip_trusted`). Two live announces proving the same address ⇒ both rows kept in `gossip_lane`, **neither gets
credit for that lane** (§8.3; a lane key could otherwise sign PoPs for any number of sybils) and neither is a DEX home
for it; metric `scaas_gossip_shared_lane_total`.

Accepted side channel (next to MESH T7): PoPs link our lane addresses to our node identity publicly, including lanes
that also submit private-visibility intents on public chains. The on-chain sender of those txs is public anyway.

### 10.4 What a node does with an announce

Builds §8.3 eligibility, the DEX home map (§11, DEX-trusted homes only), the app's peer view, and nothing else. It never dials `endpoints.
gateway`; it may hand it to clients (gateway `GET /v1/dex/homes`, §11.5). Multiaddrs are added to Kademlia through
the R120 filter.

---

## 11. DEX book gossip (R124)

Two order modes, selected per market (owner answer 2). `OrderBookDex._accept` checks `relayer ∈ {0, sender}`
(l.263) and `filled + fill ≤ sellAmount` (l.267), and each pair runs in `try settleOne` (`MatchFailed`): **no fill can
be settled twice in either mode**; the rules below only keep honest nodes from wasting gas and from showing phantom
fills.

### 11.1 Roles

- **Home** of a home-bound order = the node that alone proved the order's `relayer` (DEX §1.1) in its live announce
  (§10.3). Only the home holds it in its `Venue` (NI §12.1 `dex_order`) and matches/settles it. RS5-9 stays the
  default: our venue accepts bound orders only for our relayer (`dex.rs` l.552–554).
- **DEX-trusted homes**: we replicate and advertise only homes with `gossip_trusted.dex = 1` (admin). Other homes'
  `book`/`head` are forwarded (Ignore `UNTRUSTED_HOME` for storage purposes: Accept-forward, not stored) and never
  listed to wallets: a taker who signs an order bound to an untrusted home gives that home a free option until
  expiry (H3).
- **Claimant** of an unbound order (`relayer = 0`, market `unbound = 1`) = the node that won the deterministic claim
  (§11.6); every node may later match it.
- **Replica** = `dex_replica` rows for orders we do not hold as home. Bound replicas are read-only; unbound replicas
  that passed our `checkOrder` are matchable in our venue (§11.6).
- RPC-less nodes keep no replica: they forward dex traffic only (replicas need chain events, §11.3).

### 11.2 Messages

| `type` | From | Effect at the home / claimant | Effect elsewhere |
|---|---|---|---|
| `route_order` | anyone: a gateway that received a **bound** order for another home | intake exactly as `POST /v1/dex/orders` (DEX §3.4: `checkOrder`, per-maker caps, cumulative commitment) | forward only (V7) |
| `route_cancel`, `route_invalidate` | anyone | bound: as `POST /v1/dex/cancel` / `cancel-all` (remove now, on-chain job). Unbound: stop matching it now, submit the on-chain cancel | bound: replica `closed` only after the home's `book` or the chain event. Unbound: stop matching it now (honest nodes); `closed` only when `OrderCancelled`/`NoncesInvalidated` is mined |
| `book` | home / claimant only, on every change: rest, partial fill, close (fill, cancel, expiry, IOC rest) | — | replica merge |
| `head` | home / claimant, every 30 s per market | — | compare `max_home_seq` then `digest` ⇒ `/scaas/sync/1` `book` when different |

`digest = SHA-256(concat over open orders sorted by order_hash of order_hash ‖ home_filled(32) ‖ u8(home_closed))`,
computed over the **home register only** (no chain facts, no wall clock), so a replica that has every update
reproduces it exactly. Immediately-filled taker orders are not published as `book` (only resting state is book state).

Publish-side rule (M12): the gateway never publishes `route_*` for `sig_kind = erc1271` (receivers cannot verify it
without RPC); it answers the wallet with the home's gateway URL instead.

### 11.3 Merge and convergence

```
on book(upd)  if upd.home_seq > rep.home_seq:            # home register: highest home_seq wins
                  rep.home_seq, rep.home_filled, rep.home_closed = upd.home_seq, upd.filled_total, upd.state == closed
on chain(ev)  rep.chain_filled = max(rep.chain_filled, ev.filledTotal)       # OrderFilled (DEX §3.6 watcher)
              rep.chain_closed = rep.chain_closed or ev is OrderCancelled / NoncesInvalidated covering it
view          filled_total = max(rep.chain_filled, rep.home_filled)
              closed       = rep.chain_closed or rep.home_closed or now > expiry
```

The home register is last-writer-wins on a total order (`home_seq`, assigned by the single home); the chain part is
`max`/`or`. Both are commutative, associative and idempotent, so any two replicas that have seen the same set of
updates hold the same state whatever the delivery order; `head`/sync supplies missing updates. For **bound** orders
the home publishes a `book` for a fill when the settle job is `signed` (optimistic), and once more when it is
`mined`; if the settle fails (`dead`/`reverted`, NI §12.1 restore) it publishes `state = resting` with the restored
`filled_total` at a higher `home_seq`. For **unbound** orders fills are published **only at `mined`** (several nodes
may race; nobody shows a phantom fill). A chain `closed` is final.

`home_seq` is restart-safe: `home_seq = max(stored + 1, unix_ms)` (as announce `version`), so a restored store never
goes backwards.

### 11.4 Validation (dex topic)

- V0 (8 KiB), V1 (canonical bytes), V2 (topic = chain/dex/market; the order's `base`/`quote` match the topic pair).
- V3: `book` with `home_seq ≤ stored` ⇒ Ignore; `route_*` whose `order_hash` is already in our venue or replica ⇒
  Ignore.
- V4 deterministic ⇒ Reject: maker EIP-712 recover for `sig_kind = eoa` (low-s); `pubkey ↔ home` and the Ed25519
  signature over `dexbook_msg`/`dexhead_msg`; `claim_until ≠ 0` on a bound order or `= 0` on an unbound one.
- V4 state-dependent ⇒ Ignore: `home` is not the sole prover of `order.relayer` (`NOT_HOME`); home not DEX-trusted
  (`UNTRUSTED_HOME`, forwarded, not stored); unbound order in a market that is not `unbound` for us; unbound claimant
  that loses the claim (`NOT_CLAIMANT`, forwarded, not stored); `erc1271` order outside a home/claimant `book`.
- V6: per-maker 5/s; per home ≤ 10 000 replica orders, ≤ 50 open per (home, maker) (`MAX_OPEN_PER_MAKER`); per
  claimant ≤ 1 000 unbound orders.
- V7: market unknown to us ⇒ forward, do not store.

### 11.5 Matching, settling, routing (home-bound)

- Only the home matches (DEX §3.3 unchanged) and settles (settle `job` in `~dex`, NI R105).
- Gateway `GET /v1/dex/depth?…&scope=network` aggregates our book and **DEX-trusted** replicas per home (levels
  tagged with `home`, `trusted: true` and the home's gateway URL from the announce); `GET /v1/dex/homes?chain&market`
  lists trusted homes with their relayer addresses. A wallet that wants a replica's liquidity signs a taker order
  with `relayer =` that home's relayer and `expiry ≤ now + 300 s` (the gateway refuses longer ones for another home),
  and posts it to that home's gateway directly (preferred: not visible on gossip before matching) or to any gateway,
  which publishes `route_order`.
- A firm quote exists only at the home; replica depth is indicative (lag ≤ gossip latency, ≤ 30 s after a missed
  update via `head`).

### 11.6 Relayer-unbound orders (built in G3, market option `unbound = 1`)

1. **What may be unbound.** Only resting GTC maker orders. Unbound IOC/FOK orders are refused at intake (they are
   takers: bound to the matching node, RS5-9) and are never gossiped. A maker chooses per order (`relayer = 0`) and
   only where the market allows it.
2. **Intake** at any node: DEX §3.4 checks incl. `checkOrder` (RPC). The node then publishes a `book` with
   `claim_until = published_at + claim_ms` (default 10 s, arbitrary) and becomes a **candidate claimant**.
3. **Deterministic claim.** Several nodes may receive the same order (the wallet posted it twice). Every node keeps,
   per `order_hash`, the candidate with the **lowest** `claim_rank = SHA-256(order_hash ‖ peer_id)` among valid
   `book`s seen within `claim_grace = 2 s` (≥ gossip p99) of its own `first_seen_ms`. No node matches an unbound order
   before `first_seen_ms + claim_grace`. Each node independently computes the same winner from the same set of
   candidates; a candidate arriving after the grace is ignored.
4. **Claim window.** Until `claim_until`, only the claimant matches the order (honest nodes). After it, any node with
   the order in its replica and `checked_ok = 1` (its own `checkOrder`, budget §7.3) loads it into its venue and
   matches its **own bound** takers against it; settle simulation (`eth_call settle`) must succeed before sending.
   Two nodes that match the same maker in one block: the second pair fails `Overfill`/`MatchFailed` on chain, the
   loser restores its taker; a batch with no surviving pair reverts `NothingSettled`, which the simulation usually
   catches.
5. **Cancel is on-chain only.** An unbound order is `closed` only when `OrderCancelled` (or `NoncesInvalidated`) is
   mined. On a maker-signed cancel every honest node stops matching at once and the receiving node submits the
   on-chain `cancel` at once; the per-maker 20/h cap of DEX §3.4 does not apply to unbound orders (bounded by
   `MAX_OPEN_PER_MAKER`). The API and wallet say "cancel final when mined".
6. **What makers accept** (stated in the wallet before signing `relayer = 0`): `settle` is permissionless, so
   **anyone** — not only nodes — may settle the order at any price within its limit until it is cancelled on chain
   or expires; with `feeRecipient = 0` the relayer fee goes to whoever settles. The claim window binds only honest
   nodes.
7. Fees, `maxFeePpm`, partial fills and price checks are the contract's (DEX §1.2–§1.5), unchanged.

## 12. Private-scope isolation — proof sketch

Claim: no byte derived from a private-visibility row or from a private-profile chain leaves the node on a libp2p
gossip topic, on `/scaas/sync/1`, in an announce or in a hint; it leaves only on the bus, PQ-protected, to admitted
private peers, from the origin.

1. **Exits are enumerated.** Code that writes to the network: bus server (HTTPS, `/scaas/bus/1.2`) → `may_export`;
   gossip publish and `/scaas/sync/1` intents → `may_gossip`; hints → published only for rows passing `may_gossip`;
   announce → built from the open-peer view of `/policy`; DEX `book`/`head` → markets with `dex_market.gossip = 1` on
   public chains. A CI guard (grep test, as MESH §9 rule 1) asserts `gossipsub.publish(` and the sync handler appear
   only in `gossip/publish.rs`, whose entry points take a row and call `may_gossip` first.
2. **`may_gossip` excludes private.** It requires `visibility == open` (strictest of envelope, policy, chain —
   MESH §9, monotone) **and** `chain_profile == public`. Private visibility or profile ⇒ false.
3. **Provenance.** `source = 'peer'` never passes, so a private peer's row (even if mislabelled) is never introduced
   by us; R85 (origin-only bus serving of private rows) is untouched.
4. **Subscriptions.** Topics exist only for chains with `profile = public` and `gossip = 1`; switching a chain to
   `private` sets `gossip = 0` in the same transaction and unsubscribes within one config reload (≤ 2 s); its
   chain_key never appears in a SUBSCRIBE frame or a provider record. (Already-published public intents stay public:
   visibility never relaxes, so nothing published was private at the time.)
5. **Ingress.** A private-labelled envelope on any topic ⇒ V5 Reject; one for a chain we hold private ⇒ V5 Ignore
   (config-dependent, §6.1). Either way it is neither stored nor forwarded.
6. **Carriers.** Bus traffic (the only private exit) runs on HTTPS or QUIC with an X25519MLKEM768-only offer; bus
   peers get QUIC-only libp2p connections and the bus refuses TCP+Noise (R113, R114, §5.4). A gossip-level ban of a
   bus peer never drops that connection (§7.2).
7. **Logs** unchanged (MESH §9 rule 5).

Each step is a unit test (§16.1) and E-G5 (§16.2) is the end-to-end check.

---

## 13. Admin API, app and observability (R127)

### 13.1 Admin routes (added to NI §7.3)

| Route | Role | Hot |
|---|---|---|
| `GET /v1/admin/gossip` — PeerId, peer_id, listen/external addrs, carriers on, topics (mesh size, peers), DHT mode/table size | viewer | — |
| `GET /v1/admin/gossip/peers` — per peer: PeerId, carrier (quic/tcp), PQ (bool), score + P1…P7 components, app score, announce version, landed/missed 7 d, connected since, banned | viewer | — |
| `GET /v1/admin/gossip/announces[/{peer_id}]` | viewer | — |
| `PUT /v1/admin/gossip/peers/{peer_id}/ban` `{until_ms?, reason}`, `DELETE …/ban` | operator | hot (disconnect now) |
| `GET/PUT/DELETE /v1/admin/gossip/trusted[/{peer_id}]` (`assign`, `dex`) | viewer / admin / admin | hot |
| `PATCH /v1/admin/chains/{key}` — `gossip`, `exclusive_ms` (refused: `gossip = 1` on a private chain) | admin | hot |
| `PATCH /v1/admin/mesh/policy/{id}` — `gossip`; `PATCH /v1/admin/dex/markets/{id}` — `gossip`, `unbound` | admin | hot |
| `PATCH /v1/admin/mesh/peers/{id}` — `multiaddr` (bus over QUIC) | admin | hot |

Every mutation audited (NI R110). Bootstrap/listen/key are not routes (R95).

### 13.2 App (`scaas/app`) screens — requirements only

Peers (table, sortable by score; ban/unban for operator), Topics (per topic: mesh peers, msgs/s accepted/ignored/
rejected), Announces (policy of others, read-only), Network depth per market (from the gateway), Trusted list.

### 13.3 Metrics (prefix `scaas_`; existing `bamboo_*` metrics are renamed by the owner-approved rename)

| Metric | Type | Labels |
|---|---|---|
| `scaas_gossip_peers` | gauge | `carrier` (quic, tcp), `direction` |
| `scaas_gossip_mesh_peers` | gauge | `topic_kind` (intent, hint, dex, announce), `chain` |
| `scaas_gossip_messages_total` | counter | `topic_kind`, `chain`, `result` (accept, ignore, reject), `code` |
| `scaas_gossip_published_total` | counter | `topic_kind`, `chain` |
| `scaas_gossip_validation_seconds` | histogram | `topic_kind`, `stage` |
| `scaas_gossip_rpc_checks_total` | counter | `chain`, `result` (fresh, stale, skipped, error) |
| `scaas_gossip_score` | histogram | — (distribution, no per-peer label) |
| `scaas_gossip_graylisted`, `scaas_gossip_banned` | gauge | — |
| `scaas_gossip_hints_total` | counter | `chain`, `result` (consumed, not_yet, false, ignored) |
| `scaas_gossip_sync_total` | counter | `kind`, `direction`, `result` |
| `scaas_gossip_dex_replica_orders` | gauge | `chain`, `market` |
| `scaas_gossip_dex_head_mismatch_total` | counter | `chain`, `market` |
| `scaas_gossip_dex_unbound_total` | counter | `chain`, `result` (claimed, lost_claim, settled, lost_race, cancel_pending) |
| `scaas_gossip_validation_queue` | gauge | — |
| `scaas_gossip_assign_total` | counter | `chain`, `result` (assigned, landed, missed) |
| `scaas_tls_handshake_failures_total` | counter | `listener`, `reason` |
| `scaas_bus_requests_total` | counter | `carrier` (https, quic), `op`, `code` |

`/readyz` adds a reason when `[gossip] enabled` and no peer has been connected for 5 min (not fatal for submission).
Per-peer details stay in the admin API (no per-peer metric labels on the open mesh: unbounded cardinality).

---

## 14. Threat model (additions to MESH §11 / NI §14)

| # | Threat | Mitigation |
|---|---|---|
| E1 | **Eclipse** (attacker surrounds a node) | bootstrap from several operators (toml); `mesh_outbound_min = 2`; 20 outbound slots chosen by us, ≤ 10 from DHT-learned peers; Kademlia manual inserts with the /24 (/48) bucket cap and a capped record store; P6 colocation; `direct` partner peers; bus peers are independent of the mesh. Impact bound: liveness only — G1 (contract nonce), our own submit path and chain reads are unaffected; hints and books are chain-verified |
| E2 | **Self-inflicted eclipse** (honest peers penalized during join, partitions, upgrades) | Reject only for byte-decidable faults over keys carried in the message; announce/config/clock checks are Ignore; spec minor above ours ⇒ Ignore; auto-ban needs 2 Rejects in 1 h (R118, R119) |
| S1 | **Sybil spam** | per-source/origin/`from` buckets (origin buckets charged once per `intent_id`); P4/P7; graylist/ban; V8 freshness; only `may_submit` rows stored, evicted by fee; no persist before L2 |
| S2 | **Sybil assignment delay** (announce `submit`, never submit) | R121: assignment only with chain-credited track record (one `peer_id` per lane, no self-originated intents, ≥ 3 `from`) or admin trust; auto-trusted peers ≤ 1 rr slot in 3 and out after 1 miss |
| S3 | **Re-originated / poisoned copies** (MESH T6) | content-addressed msg-id + canonical bytes (R117, §5.2); receivers honour `exclusive` only for assignees in their own eligible set, never `assignee = hub.id` (§8.3); store tombstones as MESH |
| S4 | **Replay / byte variants** | canonical payloads (one msg-id per message); `seen_intent` with TTL `valid_until`; announce `version` monotone; hint 10 s dedup and "intent known" gate |
| F1 | **Front-running via gossip visibility** | meta-tx outcome is fixed by the signer (G1, §05 §5.4.1); confidentiality: private chains never gossiped, companies opt in with `bus_scope = public` (§8.4), large B2B values belong on Zether or the bus (§05 §5.4.5 rule 2). Exclusivity binds only spec-following nodes: a bot may submit inside the window, and with an unbound `feeRecipient` R84 sends the fee to whoever submits — R121 does not protect the assignee's fee. DEX bound: resting orders are public by nature; taker orders posted directly to the home are not gossiped; `route_order` exposes a taker before matching (limit price + short expiry bound it). DEX unbound: anyone may settle within the maker's limit until the on-chain cancel is mined (§11.6 point 6) |
| B1 | **Book spoofing** | `book` requires the signer's key in the message and, for bound orders, the home's sole PoP of the order's relayer; maker EIP-712 signatures checked; ERC-1271 orders only via the home/claimant; only DEX-trusted homes replicated and advertised; firm quotes only at the home; chain events override |
| B2 | **Free option via an attacker venue** | wallets are shown only DEX-trusted homes; routed taker orders ≤ 300 s expiry |
| B3 | **Unbound claim races** | deterministic claimant (`claim_rank`) after a 2 s grace; fills published only at `mined`; on-chain `filled` arbitrates |
| H1 | **Hint poisoning / hint floods** | hints never change state (R122); verified by the R80 read; signer gate (credited or trusted); separate RPC budget; false hints judged only at finality on a found receipt |
| A1 | **Announce replay / rollback; announce-cap filling** | strictly increasing `version`, `expires_at`; priority admission (connected/bus/trusted/track record), untrusted ≤ 4 per /24 |
| A2 | **Lane / relayer impersonation** | PoP signatures (§10.3); shared lanes credit nobody |
| D1 | **Resource exhaustion on the swarm** | connection limits; QUIC/yamux windows; gossipsub handler queue 128 with timeouts; bounded validation queue; RPC budgets; payload caps before parse |
| D2 | **Amplification via sync** | 1 full sync per peer per 60 s, 2 MiB/s global egress, 1 MiB responses, public rows only |
| P1 | **Harvest-now-decrypt-later** | X25519MLKEM768-only on QUIC and HTTPS (R114); TCP+Noise carries public data only; bus peers QUIC-only |
| P2 | **Future live forgery (quantum)** | not mitigated (Ed25519); seam §4.3 |
| X1 | **SSRF via network addresses** | global-unicast filter on network-learned addresses; admin/toml addresses bypass it (no global `allow_private_addrs` needed for VPC partners); identify advertises only `external`; announce URLs never dialed (R120, R123) |
| L1 | **Lane ↔ node linkage** | accepted side channel (§10.3) |

## 15. Crates and budget (R126)

### 15.1 Dependencies (`scaas-node/Cargo.toml`)

| Crate | Status | Use |
|---|---|---|
| `libp2p = { version = "=0.56.x", default-features = false, features = ["tokio", "quic", "tcp", "noise", "yamux", "dns", "gossipsub", "kad", "identify", "ping", "request-response", "json", "macros", "ed25519"] }` | **new** | swarm. `allow_block_list` and `connection_limits` behaviours from the facade. **VERIFY V4**: newest 0.56 patch and exact feature names at G1 start; MSRV ≤ our 1.90 |
| `rustls` features `aws_lc_rs`, `prefer-post-quantum`, `std`, `logging` (no default features) | changed (MESH §3.4 had `ring`) | R114 |
| `tokio-rustls` `default-features = false, features = ["aws_lc_rs"]` | changed | HTTPS bus |
| `reqwest` `rustls-tls-webpki-roots-no-provider` instead of `rustls-tls` | changed | single provider with a root store (V2); `install_default()` runs before any alloy provider is built |
| `aws-lc-rs` | **new** (pulled by rustls) | also the JWT verification library of NI R106 (ring-compatible `signature` API), replacing the direct `ring` dep planned in NI P2b |

No CBOR/protobuf crate of our own (R117); `serde_json` canonical body unchanged.

### 15.2 Budget

| Item | Bound |
|---|---|
| RSS added by gossip | ≤ 64 MiB at 50 peers / 10 msg/s. Bounded by: QUIC 1 MiB and yamux 1 MiB connection windows per peer, gossipsub handler queue 128 × ≤ 64 KiB per peer with timeouts, validation queue 1 024 × ≤ 64 KiB, `seen_intent` ≈ 16 MiB. **Measured** in G1 with a slow-reader test (50 peers reading nothing) |
| caches | seen 120 s × ≤ 200 msg/s × 20 B; mcache 6 s; Kademlia ≈ 1 MiB |
| replica books | on disk (`dex_replica`), not RAM; depth aggregation cached 1 s |
| CPU | Ed25519 verify ≈ 50 µs, ecrecover (alloy, pure-Rust k256) ≈ 100–150 µs, parse + canonical check ≈ 20 µs / 2 KiB ⇒ < 5 % of one core at 200 msg/s |
| build | first build with `libp2p` + `aws-lc-sys` (C, cmake): one long compile; run alone with `CARGO_BUILD_JOBS=4` (owner OOM rule); peak RAM not measured — **measure in G1** and record in the stream log |

---

## 16. Tests

Heavy runs one at a time (MESH §13). In-process tests use one tokio runtime, loopback, ephemeral ports,
`allow_private_addrs = true`, P6 weight 0.

### 16.1 Unit (`cargo test`, no network beyond loopback)

- `mesh/accept` (S3′): `Source::Gossip` (open class, hop 1); `FUTURE_PUBLISHED` split from `BAD_ENVELOPE`;
  `PRIVATE_LABEL` vs `PRIVATE_CHAIN_LOCAL`; `gossip_acceptance` table test per code (§6.1); a spec minor above ours
  turns every failure into Ignore.
- `gossip/msgid`: identical bytes ⇒ same id; non-canonical bytes or `hop_count ≠ 0` ⇒ Reject; poisoned copy then
  honest copy ⇒ both validated, honest one stored (MESH H1 through gossip).
- `gossip/validate`: table over §6 — every stage and mapping; `support = none` / `!may_submit` ⇒ Accept, not stored;
  V8 timeout ⇒ Accept; stale nonce ⇒ Ignore; **pipelined nonce n+1 ⇒ Accept** (H4); short balance ⇒ Accept, not
  stored; replay after 120 s ⇒ Ignore via `seen_intent`, origin/`from` buckets not charged; queue overflow ⇒ Ignore.
- `gossip/score`: score after 1 and 2 Rejects per topic kind, fresh and capped peer (§7.2); ban only after 2 Rejects;
  a bus-table peer is never auto-banned and keeps its connection.
- `gossip/publish`: `may_gossip` every branch (gateway+policy, job `public`/`open`/`restricted`, `peer` never,
  private visibility, private profile); CI grep guard (§12.1); no `route_*` for `erc1271`.
- `gossip/announce`: sig with the carried key, version monotone (replay of an old version to a fresh node, then the
  newer one wins), expiry, PoP valid/invalid, **shared lane ⇒ credit 0 for both**, body = open-peer `/policy` view (no
  private chain), publish coalescing ≥ 60 s, priority admission at the cap.
- `gossip/hint`: hint never changes state alone; consumed read ⇒ classification; RPC error ⇒ nothing; uncredited
  signer ⇒ Ignore; false hint only at finality with a found receipt; reorged tx ⇒ no verdict; our live job + hint ⇒
  `track()` order (receipts first), then the R80 gap-filler path (fake chain); hint for a terminal row ⇒ Ignore.
- `gossip/exclusive`: eligible set (announce, trust, credit rules: shared lane, self-originated, < 3 `from` ⇒ no
  credit), auto-trusted 1-in-3 slots and 1-miss exclusion; **receiver rule**: re-originated envelope with an
  exclusive to `hub.id` or to a non-eligible peer ⇒ `exclusive_until = NULL` (H1); violation ⇒ P5 only.
- `gossip/dex`: merge commutativity/idempotence (proptest over update orders ⇒ equal replicas and equal `head`
  digest); restore at higher `home_seq`; `home_seq` after store restore > before; spoofed `book` (bad key ⇒ Reject;
  not the sole prover ⇒ Ignore); untrusted home ⇒ forwarded, not stored, not listed (H3); unbound claimant tie-break
  identical over permuted arrival orders within the grace, late candidate ignored (C2); unbound IOC/FOK refused at
  intake; unbound fills published only at `mined`.
- `transport/pq`: HTTPS bus negotiates X25519MLKEM768 (rustls `negotiated_key_exchange_group`); classical-only
  client fails; QUIC assertion (V1); bus request on a TCP+Noise connection ⇒ `TRANSPORT_NOT_PQ`; TCP connection to a
  bus-table peer denied at establishment (H5); reqwest reaches an `https://` RPC with webpki roots (L4).
- `identity`: `PeerId ↔ peer_id` vectors; non-Ed25519 PeerId refused; signing-context prefixes distinct.
- `addr`: network-learned private addresses refused, admin/toml ones dialed; identify advertises only `external`.
- Conformance file `tests/vectors/scaas-gossip-v1.json` (hint, announce, dexbook, dexhead, msg-id, canonical-bytes
  golden cases) next to the MESH §4.6 vector file; the Odoo copy is not needed (Odoo never parses gossip).

### 16.2 Multi-node e2e (`tests/e2e_gossip.rs`, `--ignored`, anvil + forge, in-process nodes, then 2 cases as processes)

| # | Scenario | Pass when |
|---|---|---|
| E-G1 | **Propagation + no double broadcast**: 6 nodes; the same intent posted concurrently to A's gateway, to B as a bus peer and on gossip from C | all 6 hold it < 2 s; per node one row and at most one `job` row; exactly one outer tx lands; no node ingests twice |
| E-G2 | **QUIC default, TCP fallback**: node F with `quic = false` | F joins over TCP, receives intents; F's bus request to a consortium peer is refused |
| E-G3 | **Partition and heal**: block A,B,C ↔ D,E,F for 60 s; intents and DEX orders on both sides; heal | via `/scaas/sync/1` and heads, every node holds every live intent; replica digests equal to home digests ≤ 35 s |
| E-G4 | **Scoring**: node M forwards invalid intents (bad `hub.sig`) | M graylisted after the first, auto-banned after the second within 1 h; honest traffic unaffected; M's spam never stored |
| E-G4b | **Fresh join under traffic**: N joins while A publishes `book`, hints and announces at full rate | no honest peer has P4 > 0 at N after 5 min; N's mesh intact |
| E-G4c | **Version skew**: A sends a `scaas-intent/1.3` envelope whose extra signed field old nodes cannot verify | old nodes Ignore it; nobody's P4 > 0 |
| E-G5 | **Private isolation**: chain private at A with B as private bus peer (QUIC) and C as open-mesh peer; B first dials A over TCP | A denies B's TCP connection and the bus works over QUIC; B lands the intent; C never receives it, never sees the chain in A's announce, A never subscribes the topic (inspect SUBSCRIBE); a private-labelled intent injected by M ⇒ Rejected everywhere; a chain private only at C ⇒ C Ignores, nobody penalized; a gossip ban of B at A leaves the bus up |
| E-G6 | **Exclusivity**: A assigns trusted G; G stopped; after `until` + jitter H lands | no tx before `until`; G's miss counted; untrusted sybil S with a `submit` announce is never assigned |
| E-G6b | **Re-origination**: sybil S re-originates A's public intent with an exclusive to itself, flooding first | honest nodes do not wait (`exclusive_until = NULL`); H lands within one block of A's own schedule |
| E-G7 | **Hints**: B lands, C has the intent `pooled` with `may_submit` after exclusivity | C publishes no tx; C's row `consumed/landed_elsewhere` from its own read; a forged hint from uncredited M changes nothing, costs no RPC read |
| E-G8 | **DEX across homes**: maker order rests at trusted home A; taker signs bound to A and posts to B's gateway (`route_order`) | A matches and settles once; B and C replicas show the fill and the close; B never attempts a settle |
| E-G9 | **Book spoofing / untrusted home**: M publishes `book` for an order bound to A's relayer; untrusted home U publishes its own book | M's ⇒ Ignored, replicas unchanged; U's forwarded, not stored, not in `/v1/dex/homes` |
| E-G10 | **Restart**: kill B during sync; restart | announces/replica reload from store; resync completes; no duplicate job rows; B's `home_seq` continues upward |
| E-G11 | **Unbound order, two takers**: market `unbound = 1`; maker order posted to A and C; after `claim_ms` B and C each hold a crossing bound taker | both nodes agree on the claimant; at most the remaining size fills on chain; the losing pair fails `MatchFailed`, its taker restored; no node showed a fill before `mined` |
| E-G12 | **Unbound cancel**: maker cancels at A; B and a raw EOA try to settle it before the on-chain cancel mines | A and B stop matching at once; A's cancel tx is sent at once; in the 1-block-wait variant the cancel lands first and the EOA's settle reverts; the wallet shows "final when mined" |
| E-G13 | **Budgets**: 50 slow-reader peers; sync flood from 30 peers; hint flood | RSS stays ≤ budget; sync egress ≤ 2 MiB/s; V8 keeps running |

Pull-bus cases E1–E12 of MESH §13.3 also run with the bus over QUIC (parameterized carrier).

## 17. Streams

Current order (NI §17): S3 → P1 → P2 → P2b → P3 → P4 → P5 → P6 → [cutover] → P7 → S1b′ → S5 → S6′ → S7′ → P9 → S8′.

| Stream | Change |
|---|---|
| **S3′** (envelope library) | renames (R115: `scaas-intent/1.2`, `scaas-hub/v1`, vector file); adds `gossip/msgid` + canonical-bytes check, `hint_msg`/`announce_msg`/`dexbook_msg`/`dexhead_msg` builders + `scaas-gossip-v1.json` vectors; `accept.rs`: `Source::Gossip`, `FUTURE_PUBLISHED` split, `PRIVATE_LABEL`/`PRIVATE_CHAIN_LOCAL`, `gossip_acceptance()`, a `Seen` impl layering `seen_intent` over the store. Pure library, still "any time". Gate `cargo test --lib --test mesh_vectors` |
| P1 | store schema: §8.4 tables and CHECK changes; `[identity]`, `[transport]`, `[gossip]` config parsing (no networking) |
| P2b | JWT verification on `aws-lc-rs` instead of `ring` (§15.1); routes of §13.1 are **not** added here (they need G1 state) |
| **S5′** (bus) | provider switch to aws-lc-rs + PQ-only groups for the whole process (R114, V2), reqwest `rustls-tls-webpki-roots-no-provider`, `install_default()` before alloy; HTTPS bus as MESH §5 + `TRANSPORT_NOT_PQ` plumbing. Gate `cargo test` + `cargo tree` provider check. **First aws-lc-sys build: run alone** |
| S6′ | adds `may_gossip` hook points (publish queue drained by G1; no-op without it) |
| **G1 — libp2p core** (new) | swarm task, QUIC (V1 resolved) + TCP/Noise, Kademlia, identify, ping, connection limits, address filter, bans, gossipsub config/scoring, intent topic validator + publish, `/scaas/sync/1` intents, `/scaas/bus/1.2` over QUIC, admin routes §13.1 + metrics. Gate `cargo test` (in-process multi-node unit tests) |
| **G2 — announce, exclusivity, hints** (new) | §8.3, §9, §10; `gossip_*` stats; E-G6/E-G7 in-process. Gate `cargo test` |
| **G3 — DEX book gossip** (new; needs P7) | §11 incl. **relayer-unbound orders** (§11.6: claim, grace, on-chain-only cancel, publish-at-mined), DEX-trusted homes, gateway `scope=network`, `/v1/dex/homes`, `dex_market.unbound`. Gate `cargo test` + DEX e2e alone |
| **S7″** (e2e) | MESH E1–E12 (both bus carriers) + E-G1…E-G10. Gate `cargo build --release` then `cargo test --test e2e_mesh --test e2e_gossip -- --ignored`, nothing else running |
| S8″ | spec corrections incl. §18.3 |

**New order: S3′ (any time) → P1 → P2 → P2b → P3 → P4 → P5 → P6 → [owner cutover] → P7 → S1b′ → S5′ → S6′ → G1 → G2 →
G3 → S7″ → P9 → S8″.** Gossip comes after S6′ because it publishes and ingests through the job-backed pipeline; G3
needs P7's store-backed venue. NI's rule stands: if the P9 proof window ends first, P9 runs before S5′, so neither the
bus nor gossip ever wires to legacy Odoo code. The aws-lc-rs switch sits in S5′ (first stream that needs PQ TLS); if
P2b lands first it already compiles `aws-lc-rs`, which only moves the long build earlier.

---

## 18. Changes to existing specs (exact lists; edits made in S8″)

### 18.1 MESH

| Section | Change |
|---|---|
| §1.1 item 1 | "federated intent bus" ⇒ "bus for admitted peers (HTTPS or QUIC) + open-mesh gossip (R112, R113)" |
| §1.2 rows "libp2p / gossipsub…", "Open (unadmitted) peers…" | removed / reduced to "PoW, stake, lottery, beacon" (R112, R119) |
| §2 R70 | amended by R112 |
| §2 R72 | key in `[identity]` and also the libp2p identity (R116); admission statement scoped to the bus |
| §2 R74 | eligible set extended, per-chain `exclusive_ms`, receiver honours an open-mesh `exclusive` only for assignees in its own eligible set (R121) |
| §2 R81 | string `scaas-intent/1.2` (R115) |
| §2 R82 | adds `chain.exclusive_ms = 7000`; §7 numbers |
| §3.2 | `[mesh] key` removed; `[identity]`, `[transport]`, `[gossip]` (§3.1); paths `/etc/scaas` |
| §3.4 | rustls/tokio-rustls provider `aws_lc_rs` + `prefer-post-quantum`; reqwest no-provider; libp2p; "No `aws-lc-rs`" and the S5 gate "gains no aws-lc-rs" reversed (R114) |
| §4.3, §4.5, §4.6 | spec string, domain tag `scaas-hub/v1`, vector file name (R115) |
| §5 intro, §5.1 | carriers HTTPS and QUIC `/scaas/bus/1.2`; X25519MLKEM768-only (R113, R114); peer row optional `multiaddr` |
| §5.3 | adds `TRANSPORT_NOT_PQ` |
| §5.4 | `hop_count` applies to bus re-serving; gossip loops are broken by msg-id + store dedup |
| §6 | `intent.source` + `'gossip'` |
| §7.2 L1, L3 | source `gossip` uses §6 V2/V5/V6 |
| §8.1 | row `gossip` (exclusive as received, clamped) |
| §8.2 | R121 (origin and receiver rules) |
| §8.7 | B1 extends to gossip peers (auto-ban); B4 replaced by R122 (hints) |
| §9 rule 1 | two exits: `may_export` (bus) and `may_gossip` (§8.1) |
| §11 | rows E1–X1 of §14 |
| §12 | §13.3 metrics; prefix `scaas_` |
| §13 | §16 |
| §14 | §17 |
| §15.1 rows for UD §22.2 C, §23.6, §23.3, §21.4 and §05 §5.0/§5.1 | rewritten: "gossip **and** pull" instead of "pull instead of gossip" (§18.3) |
| §15.3 | remove "libp2p transport" and "done hints"; add §11.6 build, ML-DSA, NAT traversal |
| §15.4 row "Transport" | followed: owner R112 (gossip + pull) |
| §16.1 M1 disposition | superseded by R114 (ring → aws-lc-rs) |

### 18.2 NI

| Section | Change |
|---|---|
| §1.2 | adds gossip (this amendment) |
| §3 diagram and listener table | libp2p listener (`[gossip] listen`), bus over QUIC |
| §4 | `job.bus_scope` + `public`; `chain.gossip`, `chain.exclusive_ms`; `mesh_policy.gossip`; `dex_market.gossip`; tables §8.4; `intent.source` + `'gossip'` |
| R95 (§2, §8) | toml-only list + `[identity]`, `[transport]`, gossip addrs/bootstrap/direct |
| R99 | `bus_scope` values `restricted | open | public` |
| R106 | "verification uses `ring`" ⇒ `aws-lc-rs` (R114, one crypto library) |
| §7.3 | routes §13.1 |
| §7.7 | app screens §13.2 |
| §12 | `dex_replica`, `dex_market.gossip`/`unbound`, gateway `scope=network`, `/v1/dex/homes` |
| §13.2 | streams per §17 |
| §14 T2 | DHT dialing under the R120 filter |
| §15 | §13.3 metrics; prefix `scaas_` |
| §16 | §16 |
| §17 | order per §17 |

### 18.3 Research and decision docs (text only, S8″)

| File | Where | Edit |
|---|---|---|
| UD | §22.2 row C | "gossipsub v1.1 topic `/scaas/intent/1.2/<chain_key>` (open mesh) + bus HTTPS/QUIC cho peer đã duyệt"; auth "libp2p Ed25519 + peer score / mTLS SPKI"; rate limit "peer score + token bucket theo nguồn/origin/from" |
| UD | §23.6, §23.3 `mesh` | "gossip + pull" |
| §05 | §5.1, §5.0 | libp2p built (R112); private profile = bus, PQ (R114) |
| §05 | §5.2 | `scaas-intent/1.2` |
| SRS (owner WIP, `/home/ha/work/ainative/SRS/ai/ai-enterprise-blockchain-architecture.md`) | §5.1 diagram "Topic: /metatx/v1"; rule 1 "metaTxDigest + simulate before gossip"; rule 3 "private ⇒ mesh off, single hub" | for the owner to reconcile: topics per chain (§5.1); simulation is on the submit path, gossip runs a bounded nonce/balance freshness read (R118); private ⇒ never on gossip, admitted peers over the PQ bus (not a single hub) |

---

## 19. Owner answers (2026-10-06) and open questions

Answers to rev 1's questions, folded into the body:

1. **Open-mesh opt-in: yes.** `bus_scope` gains a third level: `restricted` (default, R10) < `open` (admitted
   pull-bus peers) < `public` (also the open gossip mesh). A company must turn `public` on explicitly (§8.4).
2. **DEX relayer binding: both, per market.** Home-bound orders (RS5-9) stay the default; relayer-unbound orders are
   built in round 4 (G3) and enabled per market by `dex_market.unbound`, per order only where the market allows it
   (R124, §11.6).
3. **Exclusive-assignment trust: automatic** after 3 verified landings in 7 days, or admin-trusted (R121; the
   counting is hardened in §8.3).
4. **QUIC offers only X25519MLKEM768: accepted.** A third-party node without ML-KEM joins only over TCP+Noise and
   receives public open-mesh data only (R114).

Open:

1. **DEX home trust** (§11.1, review H3): the spec replicates and advertises only admin-listed DEX homes
   (`gossip_trusted.dex`), because a wallet that signs for an attacker's home hands it a free option until expiry.
   Should DEX homes also become trusted automatically (like R121, e.g. after N settled trades verified on chain), or
   stay admin-only?

---

## 20. Review disposition

Review 1 (`review-1.md`, verdict FIX-THEN-GO): 33 findings — **32 fixed, 1 rejected in part** (M13: Kademlia kept by
owner ruling; its mitigations applied).

| # | Finding | Disposition | Where |
|---|---|---|---|
| C1 | State-dependent Reject + one-strike ban ⇒ ban storm on join | fixed: signer `pubkey` in hint/book/head and their signed messages; Reject only byte-decidable; announce/config/clock ⇒ Ignore; `gossip_acceptance` table; `FUTURE_PUBLISHED` split; auto-ban after 2 Rejects/1 h; join e2e | R118, R119, §5.3, §6, §6.1, §7.2, E-G4b |
| C2 | Owner ruling 2 not folded; cancelled/IOC unbound orders settleable by anyone | fixed: §1.2, R124, §11.6 normative (unbound GTC only; deterministic claimant + grace; on-chain-only cancel; publish at `mined`; maker disclosure); `dex_market.unbound`; DDL; tests | §1.2, R124, §8.4, §11, E-G11, E-G12 |
| H1 | Sybil re-origination self-assigns exclusivity | fixed: receiver honours `exclusive` only for assignees in its own eligible set, `≠ hub.id` | R121, §8.3, E-G6b |
| H2 | Automatic trust farmable (shared lanes, self-dealt landings) | fixed (automatic trust kept): shared lane credits nobody; no credit for self-originated intents; ≥ 3 `from`; auto-trusted ≤ 1 slot in 3, out after 1 miss | R121, §8.3, §10.3 |
| H3 | Untrusted DEX homes fill caps and are advertised to wallets | fixed: DEX-trusted homes only (`gossip_trusted.dex`); untrusted cap 0 (forward only); `trusted` label; routed taker expiry ≤ 300 s. Open question §19 | §7.3, §11.1, §11.5 |
| H4 | V8 drops pipelined nonces | fixed: window `n_s ≤ nonce ≤ n_s + 16`; balance advisory | §6 V8 |
| H5 | Bus over QUIC vs TCP connection; gossip ban cuts the bus | fixed: TCP denied for bus-table peers at establishment; puller QUIC-only; bus peers never auto-banned | §5.4, §7.2, §12 |
| M1 | Store-only dedup; replays and byte variants exhaust buckets | fixed: `seen_intent`; canonical bytes; buckets charged once per `intent_id`; hop stored 1; rate before parse | §5.2, §6 |
| M2 | Store caps DoS-able by worthless content | fixed: store only `may_submit`, evict by fee then age; announce priority admission | §6, §7.3 |
| M3 | Auto-ban for exclusivity violations | fixed: P5 + metric only | §7.2, §8.3 |
| M4 | False-hint misfires; hint floods disable V8 | fixed: separate budget, signer gate, finality + found receipt, `track()` order | §9, §7.3 |
| M5 | RAM budget not backed by bounded queues | fixed: yamux window, handler queue 128 + timeouts, validation queue 1 024, slow-reader test | §6, §7.1, §7.4, §15.2, E-G13 |
| M6 | `head` projection unspecified; `home_seq` not restart-safe | fixed: digest over the home register; `max_home_seq` in head; `home_seq = max(stored+1, unix_ms)` | §5.3, §11.2, §11.3 |
| M7 | Sync egress amplifier | fixed: 1 full sync/peer/60 s, 2 MiB/s global, paged books | R125, §7.3 |
| M8 | S3 API fit | fixed in S3′ scope (verified: `accept.rs` l.79 `Source`, l.143 hop, l.168 `BadEnvelope`, l.175, l.180) | §6.1, §8.2, §17 |
| M9 | Version skew turns into bans | fixed: minor above ours ⇒ Ignore | R118, E-G4c |
| M10 | Scoring arithmetic and config claims | fixed: P4 squared × topic weight, cap 50; P6 whitelist/test profile; `gossip_retransimission` meaning; explicit protocol ids; Anonymous pairing; V3/V4 | §7.1, §7.2 |
| M11 | Address filter blocks VPC partners; identify leaks interfaces | fixed: filter only network-learned addresses; identify advertises `external` only | R120, §3.1 |
| M12 | ERC-1271 `route_order` gets our gateway banned | fixed: publish-side rule; non-home ERC-1271 ⇒ Ignore | §11.2, §11.4 |
| M13 | Defer Kademlia | **rejected** (owner: Kademlia kept); applied: half of outbound slots max from DHT, capped record store, inbound rate limit, address filter, record content untrusted; P5 simplified (overflow term dropped) | R120, §7.2, §7.4, §14 E1 |
| M14 | Test plan gaps | fixed: rows of §16 (E-G1 concurrency, E-G4b/c, E-G5 additions, E-G6b, E-G11–13, unit list) | §16 |
| L1 | §0 evidence stale | fixed | header |
| L2 | Index on a missing column | fixed | §8.4 |
| L3 | "no tls12" | fixed: TLS 1.3 pinned per bus/QUIC config | §4.3 |
| L4 | reqwest no-provider has no roots | fixed: `rustls-tls-webpki-roots-no-provider`, `install_default()` first | §4.3, §15.1, §17 |
| L5 | QUIC CertificateVerify key | fixed | §4.2 |
| L6 | `u8` length prefixes | fixed: `u16be` | §5.2, §5.3 |
| L7 | Announce republish vs receiver bucket | fixed: coalesce ≥ 60 s | §10.2, §7.3 |
| L8 | Sync cursor ties | fixed: store `seq` | §5.4, R125 |
| L9 | RPC-less nodes and replicas | fixed: forward only | §11.1 |
| L10 | F1 implies fee protection | fixed | §14 F1, §8.3 |
| L11 | Hint propagation holes | noted | §9 item 7 |
| L12 | Lane PoP side channel | noted as accepted | §10.3, §14 L1 |
