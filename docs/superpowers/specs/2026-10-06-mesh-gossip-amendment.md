# Amendment A2 to the round-4 relayer mesh — gossip P2P for the nodes

Status: draft rev 1, 2026-10-06, unreviewed. Repo `scaas` (`custom-addons/bamboo-dms/scaas`) at `main` 02a71f3.
Rulings: **R112–R127** (§2), continuing R70–R86 (MESH) and R87–R111 (NI incl. Amendment A1).
Owner inputs folded in (all 2026-10-06):

1. **Gossip is required in round 4, alongside the HTTP pull bus** (amends R70).
2. **Post-quantum transport**: hybrid X25519MLKEM768 key exchange; one process-wide rustls provider = `aws-lc-rs`;
   identities stay Ed25519 with a seam for ML-DSA.
3. **QUIC is the default transport**; TCP+Noise and the HTTPS mTLS bus are also supported; all three selectable in
   config, same envelope/topics/validation; **private peers: QUIC or HTTPS only, never Noise**.
4. **`bamboo` → `scaas` rename approved everywhere**: crate `scaas-node` (directory today `bamboo-node/`), protocol
   ids `/scaas/…`, envelope `scaas-intent/1.2`, env `SCAAS_*`, metrics `scaas_*`. This document uses the new names.

| Short | File | How amended |
|---|---|---|
| MESH | `docs/superpowers/specs/2026-10-05-relayer-mesh-design.md` | sections listed in §18.1 |
| NI | `docs/superpowers/specs/2026-10-06-node-independence-design.md` | sections listed in §18.2 |
| §05 | `docs/superpowers/specs/blockchain-research/05-open-relayer-network.md` | §5.1 conclusion (bản 3) is now built; corrections §18.3 |
| UD | `docs/superpowers/specs/blockchain-research/_USER-DECISIONS.md` | MESH §15.1 rows for §22.2 C / §23.6 rewritten (§18.3) |
| DEX | `docs/superpowers/specs/2026-10-03-dex-design.md` | RS5-9 kept; book replication added (§11) |
| node | `scaas-node/` (today `bamboo-node/`) | |

Evidence for "nothing to migrate": `bamboo-node/src/` has no `mesh/` module yet (S3 is the next stream), and
`Cargo.lock` has no `libp2p` and no `aws-lc-rs`. Every wire string below can therefore change **in place** without a
version bump.

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
| Cross-home DEX matching, relayer-unbound (`relayer = 0`) orders in network books | RS5-9 kept; the settle-claim rule for unbound orders is **defined** (§11.6) but not built |
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
| **R118** | **Validation pipeline** (§6): gossipsub `validate_messages()`; every message is held until the node reports `Accept` (forward), `Reject` (drop + P4 penalty) or `Ignore` (drop, no penalty). **Reject only for deterministic, source-independent faults** (size, encoding, spec major, digest, signatures, topic/chain mismatch, private on an open topic). State-, clock- or config-dependent outcomes are `Ignore`. Policy outcomes never stop forwarding (§05 §5.1.0 "từ chối thì chuyển tiếp"). One bounded RPC freshness read (subject nonce, balance) runs **off the event loop**, ≤ 500 ms, and **fails open for forwarding**; full simulation stays on the submit path (MESH L4). Nothing is persisted before L2 passes (MESH T1). | Honest forwarders validate before forwarding, so a Reject-class message is evidence against the sender; anything that two honest nodes can judge differently must not penalize. RPC-less pool nodes (UD §21.4 "pool thuần") must still forward. | A spam intent with a valid signature and a fresh nonce reaches every node's store (bounded by R119 caps); submitters still simulate. |
| **R119** | **Scoring and limits** = the numbers of §7, all config, **all arbitrary** except where a source is cited. Score thresholds gossip −10 / publish −50 / graylist −80; one deterministic-invalid message graylists a fresh peer for ~3 min; graylisted > 60 s ⇒ ban 1 h (store `gossip_ban`); per-propagation-source token buckets (`Ignore` on overflow); per-origin and per-`from` buckets (UD §22.2 C "trần intent/giây/peer", §05 §5.5 tier 1, in process: single process, MESH T1). Gossip rows are capped separately from the store (`gossip_max_rows`) so the open mesh cannot `STORE_FULL` our own and consortium work. | gossipsub v1.1 scoring is the network-layer anti-spam the research chose (§05 §5.5 "tầng −1"); P3 (mesh delivery deficit) is off because traffic is bursty and low (it punishes honest peers on quiet topics). | Re-tune after a multi-site run (as R82). |
| **R120** | **Discovery**: Kademlia protocol **`/scaas/kad/1.0.0`** (its own DHT, never the IPFS one); bootstrap multiaddrs are **toml-only** (NI R95: dial targets); DHT server mode only when `[gossip] external` is set, else client; provider records `SHA-256("scaas-provider/1" ‖ chain_key)` per subscribed chain; **dials only global unicast addresses** unless `allow_private_addrs = true` (tests, LAN); routing-table inserts are manual with ≤ 2 peers per /24 (IPv4) or /48 (IPv6) per bucket; ≥ 2 outbound mesh peers (`mesh_outbound_min`). Identify (`/ipfs/id/1.0.0`, agent `scaas-node/<ver>`) and ping on. | Eclipse resistance is cheapest at the routing table and the outbound slots (§14 E1). Address filtering is the libp2p form of MESH T8 (no SSRF via network-supplied addresses). | A LAN-only deployment must set `allow_private_addrs`. |
| **R121** | **Exclusivity over gossip** (amends R74): the origin's eligible set adds gossip peers that (a) have a live announce advertising `submit` for `(chain, token_of, selector)` (§10), **and** (b) are in the admin list `gossip_trusted.assign = 1` **or** have ≥ `assign_min_landed = 3` verified landings in 7 days attributed through lane proof-of-possession (§10.3); (c) not excluded for misses (3 missed assignments in 1 h ⇒ out 1 h). The origin signs `exclusive.until = published_at + chain.exclusive_ms`, per-chain, **default 7 000 ms** (arbitrary: gossip p99 ≤ 1 s + one 5 s Gnosis block + 1 s). Receivers keep MESH's clamp `[mesh] exclusive_ms = 10 000`. Own jobs are still never assigned (R74). | Permissionless peers cannot get assignments by announcing alone (sybil delay attack, §14 S2); track record is measured from chain logs, not claims. W must cover propagation **and inclusion**: other submitters simulate first, so after inclusion they see the consumed nonce and spend nothing. | A new honest partner waits for 3 landings (or an admin flag) before it receives assignments. |
| **R122** | **Landed hints** (§9): published only by the node whose lane landed the intent; a hint is **a trigger for the MESH R80 consumption read, never a state change**. Our row/job changes state only from the chain read (subject nonce moved + §8.5 classification). A hint never cancels, bumps or gap-fills our job by itself. Nodes without RPC for the chain ignore hints. Hints exist only for rows that pass `may_gossip` (§8.1). | Closes MESH B4 ("no receipt gossip in v1") with zero new trust: the proof is on chain, the hint only saves the wait. | One nonce read per hinted intent (deduped, rate-limited). |
| **R123** | **Announce** (§10): `scaas-announce/1`, signed by the node key, `version` strictly increasing, `expires_at ≤ issued_at + 24 h`, re-published every 10 min and on change; carries public policy (the `/v1/mesh/policy` shape filtered as for an **open** peer), fees, chains, lanes with **proof of possession**, DEX homes, client endpoints. It **replaces `/policy` for gossip peers**; `/policy` stays for bus peers. URLs in announces are **never dialed** by the node (MESH T8); multiaddrs go through the R120 filter. | Signed and versioned ⇒ replayable copies cannot roll a node back; PoP stops a node from claiming another's track record or DEX relayer. | — |
| **R124** | **DEX book gossip = home-node model** (§11). An order bound to relayer `r` (RS5-9, `dex.rs` l.552–554) is matched and settled **only by the home node** that proved `r` in its announce; the contract's `relayer ∈ {0, sender}` check makes this exclusivity **hard** and on-chain `filled[orderHash]` is the arbiter of every fill. Other nodes keep **read-only replica books**: a home register (highest `home_seq` wins) joined with chain facts (`filled = max`, `closed = or`) from DEX events (§11.3); heads + anti-entropy make replicas converge. Takers reach other homes by **signing orders bound to that home's relayer** (client-side routing over the network depth). Topics per market. | Two nodes can never settle the same fill: only one sender passes the on-chain relayer check. Keeps RS5-9's anti-MEV property. Monotone merge converges regardless of delivery order. | Liquidity is fragmented per home; a cross-home taker splits client-side. |
| **R125** | **Anti-entropy** `/scaas/sync/1` (libp2p request-response, JSON codec): `intents` (gossip-eligible rows by `received_at`), `announces`, `book` (one market, one home, after `home_seq`). Items are the same signed objects and go through the same validator (without gossip forwarding). Triggered on first contact and on reconnection (≤ 1 per peer per 60 s, ≤ 3 peers at once) and by book-head mismatch. | gossipsub only caches ~6 heartbeats; the pull bus's cursor catch-up (MESH E10) must exist on the open mesh too. | — |
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
allow_private_addrs = false
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
| TLS 1.3 `CertificateVerify` (HTTPS bus, QUIC libp2p-TLS) | 64 × `0x20` ‖ `"TLS 1.3, server/client CertificateVerify"` | RFC 8446 §4.4.3 |
| libp2p-TLS cert extension | `"libp2p-tls-handshake:"` | libp2p TLS spec |
| Noise static-key binding | `"noise-libp2p-static-key:"` | libp2p Noise spec |
| `hub.sig` | `"scaas-hub/v1"` | MESH §4.5 (renamed, R115) |
| announce / hint / dex book / dex head | `"scaas-announce/ed25519/1"`, `"scaas-hint/ed25519/1"`, `"scaas-dexbook/ed25519/1"`, `"scaas-dexhead/ed25519/1"` | §5.3 |

All prefixes are distinct and none is a prefix of another, so no signature is valid in two contexts.

### 4.3 PQ key exchange (R114)

- `rustls = { version = "0.23.27+", default-features = false, features = ["aws_lc_rs", "prefer-post-quantum", "std",
  "logging"] }` (no `tls12`: every rustls use in the node is TLS 1.3). At start:
  `rustls::crypto::aws_lc_rs::default_provider().install_default()`; every config is built with
  `builder_with_provider(provider_pq())` where `provider_pq()` = the aws-lc-rs provider with
  `kx_groups = vec![X25519MLKEM768]`.
- **HTTPS bus** (MESH §5.1 server and client): `provider_pq()`. A client without the hybrid group fails the handshake
  (`HandshakeFailure`). Metric `scaas_tls_handshake_failures_total{listener="mesh",reason}`.
- **QUIC** (libp2p-quic → quinn → rustls via libp2p-tls): `provider_pq()` on both sides.
  **VERIFY V1** (at the start of G1): whether `libp2p-tls` in the pinned version builds its rustls configs from a
  caller-supplied provider. If it hardcodes `rustls::crypto::ring::default_provider()` (as earlier versions did),
  then, in order of preference: (a) a `libp2p-quic` config hook that accepts our `QuicClientConfig`/`QuicServerConfig`;
  (b) `[patch.crates-io] libp2p-tls = { path = "vendor/libp2p-tls" }` changing only the provider line (≤ 10 lines,
  upstream PR opened in parallel); (c) a custom QUIC transport wrapping quinn with the libp2p-TLS verifier. G1 is not
  done until a test asserts the negotiated group on a QUIC connection (§16.1) — through quinn's
  `handshake_data()`/rustls `negotiated_key_exchange_group()` if exposed, otherwise by a classical-only client that
  must fail to connect.
- **VERIFY V2**: feature resolution leaves exactly one rustls provider feature in use: `cargo tree -e features -i
  rustls` shows `aws_lc_rs`; `reqwest` uses `rustls-tls-no-provider` (it then picks the installed default);
  `quinn-proto` uses its aws-lc-rs feature; alloy's `reqwest` feature does not re-enable `reqwest/rustls-tls`. The
  `ring` crate may remain in the lock as a library of some dependency; what is forbidden is a second rustls provider
  in use.
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
msg_id = SHA-256("scaas-msgid/1" ‖ u8(len(topic)) ‖ topic ‖ payload)[0..20]
```

`max_transmit_size = 65 536` (whole RPC frame). Per-kind payload caps (checked first in V0): intent 32 KiB (MESH
§4.2), dex 8 KiB (ERC-1271 passkey signatures), announce 16 KiB, hint 512 B.

### 5.3 New message schemas

Same JSON rules as MESH §4.2 (hex/decimal strings, `chain_key`, canonical addresses; canonical JSON only where a
`*_hash` is defined). Unknown top-level fields: ignored on the bus (MESH rule), **ignored but counted** on gossip.

**Hint** (`scaas-hint/1`):

```json
{"spec": "scaas-hint/1", "chain_key": "evm:100", "intent_id": "0x…", "kind": "landed",
 "tx": "0x…", "block": 41233001, "signer": "64 hex", "issued_at": 1756500030, "sig": "128 hex"}
```
```
hint_msg = "scaas-hint/ed25519/1" ‖ u8(len) ‖ chain_key ‖ intent_id(32) ‖ u8(kind: 0 landed)
         ‖ u8(len) ‖ tx (ASCII, family tx id) ‖ u64be(block) ‖ signer peer_id(32) ‖ u64be(issued_at)
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
 "home": "64 hex", "home_seq": 812, "state": "resting", "filled_total": "0", "published_at": 1756500040,
 "sig": "128 hex"}
```
```
dexbook_msg = "scaas-dexbook/ed25519/1" ‖ u8(len) ‖ chain_key ‖ dex(20) ‖ order_hash(32) ‖ home(32)
            ‖ u64be(home_seq) ‖ u8(state: 0 resting, 1 closed) ‖ filled_total(32, uint256 BE) ‖ u64be(published_at)
dexhead_msg = "scaas-dexhead/ed25519/1" ‖ u8(len) ‖ chain_key ‖ dex(20) ‖ base(20) ‖ quote(20) ‖ home(32)
            ‖ u64be(home_seq) ‖ digest(32) ‖ u32be(count) ‖ u64be(published_at)
```

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
matches the pin).

`/scaas/sync/1`:

| Request | Response |
|---|---|
| `{"kind": "intents", "chains": [...], "since_ms": t, "limit": ≤200}` | `{"items": [envelope…], "next_ms": t', "more": bool}`; rows with `may_gossip(row)`, non-terminal, `valid_until > now`, ordered by `received_at`; ≤ 1 MiB |
| `{"kind": "announces"}` | `{"items": [announce…]}`, live only, ≤ 1 MiB |
| `{"kind": "book", "chain_key", "dex", "base", "quote", "home", "after_seq": n}` | `{"items": [book…], "more": bool}` ordered by `home_seq` |

---

## 6. Validation pipeline (R118)

Stages run in order; the first failing stage decides. V0–V2 run inline on the swarm task only when they are pure CPU
and ≤ ~100 µs; otherwise the message is moved to the validation pool (semaphore 16) and reported later.

| Stage | Check (intent topic; other kinds analogous) | Fail ⇒ |
|---|---|---|
| V0 size/shape | payload ≤ cap; UTF-8 JSON object; `spec` major known | Reject (unknown **major** ⇒ Ignore: version skew is not malice) |
| V1 topic | `chain_key` in payload = topic's; family supported (MESH R77) | Reject |
| V2 limits | propagation-source bucket (§7.3); peer graylisted/banned (gossipsub drops earlier) | Ignore + app −1 |
| V3 dedup | `intent_id` row exists, or `(intent_id, body_hash)` tombstoned (MESH §6) | Ignore |
| V4 crypto | MESH L2 (digest recompute, EVM sig low-s, `hub.pubkey ↔ hub.id`, `hub.sig`) | Reject |
| V4 clock | `EXPIRED`, `VALID_TOO_LONG`, future `published_at` | Ignore |
| V5 isolation | `visibility = private` **or** our `chain_profile(chain) = private` ⇒ `PRIVATE_FROM_OPEN_PEER` | Reject + metric |
| V6 origin limits | per-`hub.id` 10/s, per-`from` 10/min (EVM `from`, decoded subject otherwise) | Ignore |
| V7 policy (L3) | `support = none` ⇒ forward, do not store; else `may_submit`, `visibility` | **never** Reject; Accept |
| V8 freshness | node has RPC for the chain and `gossip_rpc_checks = true`: one batched read — subject nonce == intent nonce (MESH §4.1 view), payer balance ≥ value + effective fee (EVM) | stale nonce/insufficient balance ⇒ Ignore; RPC error, timeout 500 ms or the per-chain RPC budget (50/s) exhausted ⇒ **Accept** |
| store | INSERT `source = 'gossip'`, `source_peer` = propagation source `peer_id`, `hop_count = env.hop_count + 1` (bounded by MESH `max_hops` only for re-serving on the bus) | `STORE_FULL`/`gossip_max_rows` ⇒ Accept (still forward) + metric |

Accept ⇒ gossipsub forwards the original bytes. Simulation (MESH L4) runs only on the submit path.

Per kind: **hint** V0, V1, V2, V3 (one per `intent_id` per 10 s; unknown `intent_id` in our store ⇒ Ignore — we only
forward hints about intents we hold), V4 (Ed25519 over `hint_msg`; signer has a live announce) ⇒ then Accept; the
R80 read happens after Accept (§9). **announce** V0, V4 (sig, `pubkey ↔ peer_id`, `version` > stored, `expires_at`
bounds, each lane PoP), size of lists; stale version ⇒ Ignore. **dex** §11.4.

---

## 7. Numbers (R119) — all config; **arbitrary** unless a source is given

### 7.1 gossipsub

| Parameter | Value | Note |
|---|---|---|
| `mesh_n / mesh_n_low / mesh_n_high / mesh_outbound_min` | 6 / 4 / 12 / 2 | small mesh, low rate; outbound min against eclipse |
| `gossip_lazy`, `heartbeat_interval` | 6, 1 s | |
| `history_length / history_gossip` | 6 / 3 | IWANT window ≈ 3 s |
| `duplicate_cache_time` (seen) | 120 s | store dedup covers longer |
| `max_ihave_length / max_ihave_messages` | 500 / 10 per heartbeat | IHAVE/IWANT budget (default 5 000 is for high-rate meshes) |
| `iwant_followup_time`, `gossip_retransimission` | 3 s, 3 | broken IWANT promises ⇒ P7 |
| `flood_publish` | true | origin latency on a small mesh |
| `prune_backoff / unsubscribe_backoff` | 60 s / 10 s | |
| PX (`do_px`) | off | R120 |
| IDONTWANT (v1.2) | on when both peers speak 1.2 | saves duplicate large intents |

### 7.2 Score

| Item | Value |
|---|---|
| thresholds gossip / publish / graylist / opportunistic graft | −10 / −50 / −80 / +5 (accept-PX unused) |
| decay interval / decay to zero / retain score | 1 s / 0.01 / 3 600 s |
| topic weight | intent 1.0, dex 0.5, hint 0.5, announce 0.2; `topic_score_cap` 50 |
| P1 time in mesh | weight 0.01, quantum 1 s, cap 3 600 (≤ +36) |
| P2 first deliveries | weight 1, decay 0.999/s, cap 20 |
| P3, P3b mesh delivery / failure | **0** (off, R119 why) |
| P4 invalid deliveries | weight −100, decay 0.9994/s (half-life ≈ 19 min). One invalid at weight 1 ⇒ −100 < −80: a fresh peer is graylisted ≈ 3 min; a peer with full P1+P2 (+56) survives one, not two |
| P5 application | weight 1, value clamped [−100, +20] = +0.5 × attributed landings 7 d (cap +10) + 5 if `gossip_trusted` − 10 × exclusive violations 24 h − 20 × false hints 24 h − 1 × bucket overflows 1 h (cap −20) |
| P6 IP colocation | weight −50, threshold 3; bootstrap/direct IPs whitelisted |
| P7 behaviour | weight −10, threshold 6, decay 0.99/s |
| ban | graylisted > 60 s continuous ⇒ `gossip_ban` 1 h (auto); admin bans persistent; banned peers refused by `allow_block_list` |

### 7.3 Rate limits (token buckets, burst = 2 × rate)

| Bucket | Rate | Overflow |
|---|---|---|
| per source: intent / hint / dex route / dex book+head / announce | 20/s / 50/s / 20/s / 200/s / 1/s | Ignore, P5 −1 |
| per origin `hub.id` (intents) | 10/s | Ignore |
| per `from` (intents) | 10/min, 100/h (§05 §5.5 tier 1) | Ignore |
| per maker (dex route) | 5/s | Ignore |
| per announcer | 1 version / 60 s | Ignore |
| sync requests per peer | 2/s, ≤ 3 concurrent syncs total | refused |
| RPC freshness reads per chain | 50/s, 4 concurrent | skip check, Accept |
| gossip ingest into the store | 200 rows/s global | Accept without storing + metric |
| caps | `gossip_max_rows` 100 000; replica orders 100 000 (≤ 10 000 per home = `MAX_RESTING`); announces 5 000 | as above |

### 7.4 Connections and DHT

`max_established` 50 (inbound 30, outbound 20), 1 per peer, pending inbound 16, idle timeout 60 s; QUIC
`max_stream_data` 256 KiB, `max_connection_data` 1 MiB, keep-alive 15 s; yamux ≤ 32 streams. Kad: k = 20, α = 3,
record/provider TTL 48 h, republish 12 h, max packet 16 KiB, ≤ 2 peers per /24 (/48) per bucket.

---

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

The validator calls `accept(env, Source::Gossip{peer})`; MESH §7.2 L1 `hop` and `peer_intents_per_sec` are replaced
by V2/V6 for this source; L3 `PRIVATE_FROM_OPEN_PEER` is V5. Rows go `pooled`/`submittable` exactly as MESH §7.3; the
scheduler turns submittable rows into `job` rows in `~mesh` (NI R89), so the `job_live_digest` UNIQUE index (NI §4)
is the single admission point for every submission path — **gossip adds no path around G2**.

### 8.3 Exclusivity (R121)

```
eligible(chain, token, selector, visibility) = sorted_by_peer_id(
      {self if may_submit}
    ∪ {bus peers as MESH §8.2}
    ∪ {g : announce(g) live, lists submit for (chain, token|*, selector|*),
           (trusted(g).assign or landed_7d(g) ≥ assign_min_landed),
           not excluded(g), visibility == open})
until = published_at + chain.exclusive_ms / 1000            # default 7 000 ms; receiver clamp 10 000 ms unchanged
```

- `landed_7d(g)` counts **our own** §8.5 classifications (`landed_elsewhere` whose `relayer` log field ∈ lanes that g
  proved, §10.3) plus verified hints (§9) — only facts read from the chain.
- Misses: for every intent we assigned to g, at `until + one block` the origin's scheduler does its R80 read; not
  consumed ⇒ `missed`; consumed by a lane not proved by g ⇒ `missed`. 3 in 1 h ⇒ `excluded` 1 h (`gossip_peer_stat`).
- Violation (MESH B1): a lane proved by g lands an intent inside another assignee's window ⇒ P5 −10, metric
  `scaas_mesh_exclusive_violations_total{peer}`; 3 in 24 h ⇒ auto-ban 24 h.
- Jitter after `until` unchanged (MESH §8.3).

### 8.4 Store and scope changes

- `intent.source` CHECK gains `'gossip'`; `source_peer` holds the propagation source's `peer_id`.
- `job.bus_scope` CHECK: `restricted | open | public` (NI R99). `open` = admitted bus peers (unchanged meaning);
  `public` = also the open mesh. Odoo `res.company.blockchain_bus_scope` (S1b′) gains `public` with the same
  private window. Rationale: MESH R73's cost column ("exposes … to admitted peers") was the owner's consent for
  partners, not for the world.
- `mesh_policy` (NI admin table) gains `gossip INTEGER NOT NULL DEFAULT 0` — door-A intents on that row are published.
- `chain` gains `gossip INTEGER NOT NULL DEFAULT 0`, `exclusive_ms INTEGER NOT NULL DEFAULT 7000`; a `private`
  profile forces `gossip = 0` (admin-API validation and toml load check, as MESH §9 rule 3).

```sql
CREATE TABLE gossip_announce (peer_id BLOB PRIMARY KEY, version BIGINT NOT NULL, expires_at BIGINT NOT NULL,
  body TEXT NOT NULL, received_at BIGINT NOT NULL);
CREATE TABLE gossip_lane (chain_key TEXT NOT NULL, address TEXT NOT NULL, peer_id BLOB NOT NULL,
  PRIMARY KEY (chain_key, address, peer_id));                       -- from announces with a valid PoP only
CREATE TABLE gossip_peer_stat (peer_id BLOB NOT NULL, day BIGINT NOT NULL, assigned BIGINT NOT NULL DEFAULT 0,
  landed BIGINT NOT NULL DEFAULT 0, missed BIGINT NOT NULL DEFAULT 0, violations BIGINT NOT NULL DEFAULT 0,
  false_hints BIGINT NOT NULL DEFAULT 0, invalid BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (peer_id, day));
CREATE TABLE gossip_trusted (peer_id BLOB PRIMARY KEY, label TEXT NOT NULL, assign INTEGER NOT NULL DEFAULT 1);
CREATE TABLE gossip_ban (peer_id BLOB PRIMARY KEY, until_ms BIGINT, reason TEXT NOT NULL, actor TEXT NOT NULL,
  created_at BIGINT NOT NULL);                                      -- until_ms NULL = until lifted
CREATE TABLE dex_replica (order_hash BLOB PRIMARY KEY, chain_key TEXT NOT NULL, dex TEXT NOT NULL,
  base TEXT NOT NULL, quote TEXT NOT NULL, home BLOB NOT NULL, relayer TEXT NOT NULL, maker TEXT NOT NULL,
  side TEXT NOT NULL CHECK (side IN ('ask', 'bid')), sell_amount TEXT NOT NULL, buy_amount TEXT NOT NULL,
  home_seq BIGINT NOT NULL, home_filled TEXT NOT NULL, home_closed INTEGER NOT NULL DEFAULT 0,
  chain_filled TEXT NOT NULL DEFAULT '0', chain_closed INTEGER NOT NULL DEFAULT 0, expiry BIGINT NOT NULL,
  body TEXT NOT NULL, updated_at BIGINT NOT NULL);
CREATE INDEX dex_replica_book ON dex_replica (chain_key, dex, base, quote, closed, side);
```

Portable per A1 (R111): `BIGINT`/`TEXT`, no backend types; `gossip_peer_stat` rows older than 8 days and expired
announces/bans are deleted by the janitor.

---

## 9. Landed hints (R122)

1. **Publish**: our submit path reaches `mined` (receipt success, our lane) for a row/job whose intent row passes
   `may_gossip` ⇒ one hint on `/scaas/hint/1/<chain_key>`. Nobody else publishes (no "consumed" hints, no relaying of
   others' hints by re-publication; gossipsub forwards).
2. **Receive**: after Accept, if we hold a non-terminal row for `intent_id` and have RPC for the chain, queue one
   **R80 consumption read** (deduped per `intent_id` for 10 s, part of the 50/s RPC budget):
   - subject nonce moved past the intent's nonce ⇒ §8.5 classification ⇒ `landed_elsewhere` / `superseded` /
     `unknown` exactly as if our scheduler had found it. **For our own live job this is the ordinary R80 path**
     (no bump, gap-filler, `consumed`) — triggered earlier, decided by the chain.
   - not moved ⇒ nothing changes. If still not moved 2 blocks after `hint.block` and `eth_getTransactionReceipt(tx)`
     has no `MetaTransactionExecuted(digest = intent_id)` ⇒ `false_hints[signer]++`, P5 −20.
   - read error ⇒ nothing changes (fail closed, as R80).
3. **Never**: a hint does not move a row or job, does not cancel (NI R98), does not stop serving, does not feed
   `landed_7d` unless the classification attributes the log's `relayer` to a lane the signer proved.
4. Non-EVM families: the read is `ChainAdapter::op_consumed` (MESH §8.4); classification `unknown` (MESH §8.5).
5. Nodes without RPC for the chain forward hints (if they hold the intent) and otherwise ignore them.

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
`max(stored + 1, now)`). Re-published every 10 min and within 2 s of a relevant admin change; `expires_at = issued_at
+ 3 600` by default (≤ 24 h). Receivers keep the highest valid version until `expires_at`; an expired announce
removes the peer from §8.3 and from DEX homes. Discovery of `/policy` for gossip peers is the announce only;
bus peers keep `GET /v1/mesh/policy` (60 s cache).

### 10.3 Lane proof of possession

EVM/Hedera lanes (and the DEX relayer address): `pop = secp256k1_sign(keccak256("scaas-lane-pop/1" ‖ u8(len) ‖
chain_key ‖ peer_id(32)))`, verified by `ecrecover == address`. Stable across versions (rotation = new lane).
Non-EVM lanes are listed without `pop` and are not used for attribution in v1 (assignment then needs
`gossip_trusted`). Two announces proving the same address ⇒ both rows kept in `gossip_lane` (the key is shared;
attribution counts for both; metric `scaas_gossip_shared_lane_total`).

### 10.4 What a node does with an announce

Builds §8.3 eligibility, the DEX home map (§11), the app's peer view, and nothing else. It never dials `endpoints.
gateway`; it may hand it to clients (gateway `GET /v1/dex/homes`, §11.5). Multiaddrs are added to Kademlia through
the R120 filter.

---

## 11. DEX book gossip (R124)

### 11.1 Roles

- **Home** of an order = the node that proved the order's `relayer` address (DEX §1.1 field) in its live announce.
  Only the home holds the order in its `Venue` (NI §12.1 `dex_order`) and matches/settles it. RS5-9 stays: our venue
  accepts only orders bound to our DEX relayer (`dex.rs` l.552–554).
- **Replica** = `dex_replica` rows for orders whose home is another node. Read-only, never matched, never settled.

### 11.2 Messages

| `type` | From | Effect at the home | Effect elsewhere |
|---|---|---|---|
| `route_order` | anyone (a gateway that received an order bound to another home) | intake exactly as `POST /v1/dex/orders` (DEX §3.4: `checkOrder`, per-maker caps, cumulative commitment) | forward only (V7) |
| `route_cancel`, `route_invalidate` | anyone | as `POST /v1/dex/cancel` / `cancel-all` (remove now, on-chain job) | apply to replica as `closed` **only after** the home's `book` or the chain event |
| `book` | home only, on every change: rest, partial fill (settle job `mined`… see §11.3), close (fill, cancel, expiry, IOC rest) | — | replica merge |
| `head` | home, every 30 s per market | — | compare digest ⇒ `/scaas/sync/1` `book` from the home (or the sender) when different |

`digest = SHA-256(concat over open orders sorted by order_hash of order_hash ‖ filled_total(32))`, `count` = open
orders. Immediately-filled taker orders are **not** published as `book` (only resting state is book state).

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
updates hold the same state whatever the delivery order; `head`/sync supplies missing updates. The home publishes a
`book` for a fill when the settle job is `signed` (optimistic), and once more when it is `mined`; if the settle fails
(`dead`/`reverted`, NI §12.1 restore) it publishes `state = resting` with the restored `filled_total` at a higher
`home_seq` — the register takes it, and the view never drops below what the chain proved. A `closed` from the chain is
final; a `closed` from the home can be reopened only by the home's own later `home_seq`.

### 11.4 Validation (dex topic)

V0 (8 KiB), V1 (topic = chain/dex/market; `base`/`quote` of the order match the topic pair), V2, V3 (`book`:
`home_seq` ≤ stored ⇒ Ignore; route: `order_hash` already in `dex_replica`/venue ⇒ Ignore), V4: EIP-712 maker
signature recover for `sig_kind = eoa` (low-s) — `erc1271` cannot be checked without RPC ⇒ accepted only inside a
home-signed `book` (the home ran `checkOrder`), Reject as a `route_*` from a non-home; home `sig` over `dexbook_msg`
and `home` = the announcer that proved `order.relayer` (else Reject: book spoofing). V6: per-maker 5/s; per home
≤ 10 000 replica orders, ≤ 50 open per (home, maker) (`MAX_OPEN_PER_MAKER`). V7: market unknown to us ⇒ forward,
don't store.

### 11.5 Matching, settling, routing

- Only the home matches (DEX §3.3 unchanged) and settles (settle `job` in `~dex`, NI R105). Two nodes cannot settle
  one fill: the maker order passes the contract's relayer check for one `msg.sender` only; `filled[orderHash]` makes
  any overfill revert (DEX §1.8).
- Gateway `GET /v1/dex/depth?…&scope=network` aggregates our book and replicas **per home** (levels tagged with
  `home` and its gateway URL from the announce); `GET /v1/dex/homes?chain&market` lists homes with relayer
  addresses. A wallet that wants a replica's liquidity signs a taker order with `relayer =` that home's relayer and
  posts it to that home's gateway directly (preferred: not visible on gossip before matching) or to any gateway,
  which publishes `route_order`.
- A firm quote exists only at the home; replica depth is indicative (lag ≤ gossip latency, ≤ 30 s after a missed
  update via `head`).

### 11.6 Settle-claim rule for relayer-unbound orders (defined, not built)

For a future per-market `open_orders = 1`: an unbound order (`relayer = 0`) enters network books only inside a
`book` message whose signer becomes its **claimant**, with `claim_until = published_at + dex_exclusive_ms` signed in
an extended `dexbook_msg`; first-seen claimant wins locally (as MESH first-seen dedup); during the window only the
claimant may include the order in a `settle`; after it any node may, each node pairing it at most once per block
and only after `eth_call settle` succeeds; the on-chain `filled` arbitrates and losers pay one `MatchFailed`
pair or a `NothingSettled` revert (simulate catches most). Not built in round 4: RS5-9's MEV argument still holds.

---

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
5. **Ingress.** A private-labelled envelope, or one for a chain we hold private, on any topic ⇒ V5 Reject; it is
   neither stored nor forwarded.
6. **Carriers.** Bus traffic (the only private exit) runs on HTTPS or QUIC with an X25519MLKEM768-only offer; the
   bus refuses TCP+Noise connections (R113, R114).
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
| `GET/PUT/DELETE /v1/admin/gossip/trusted[/{peer_id}]` | viewer / admin / admin | hot |
| `PATCH /v1/admin/chains/{key}` — `gossip`, `exclusive_ms` (refused: `gossip = 1` on a private chain) | admin | hot |
| `PATCH /v1/admin/mesh/policy/{id}` — `gossip`; `PATCH /v1/admin/dex/markets/{id}` — `gossip` | admin | hot |
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
| `scaas_gossip_assign_total` | counter | `chain`, `result` (assigned, landed, missed) |
| `scaas_tls_handshake_failures_total` | counter | `listener`, `reason` |
| `scaas_bus_requests_total` | counter | `carrier` (https, quic), `op`, `code` |

`/readyz` adds a reason when `[gossip] enabled` and no peer has been connected for 5 min (not fatal for submission).
Per-peer details stay in the admin API (no per-peer metric labels on the open mesh: unbounded cardinality).

---

## 14. Threat model (additions to MESH §11 / NI §14)

| # | Threat | Mitigation |
|---|---|---|
| E1 | **Eclipse** (attacker surrounds a node) | bootstrap from several operators (toml); `mesh_outbound_min = 2` and 20 outbound slots chosen by us; Kademlia bucket /24 cap; P6 colocation; `direct` partner peers; bus peers are independent of the mesh. Impact bound: liveness only — G1 (contract nonce), our own submit path and chain reads are unaffected; hints and books are chain-verified |
| S1 | **Sybil spam** | per-source/origin/`from` buckets; P4/P7; graylist/ban; V8 freshness Ignore; `gossip_max_rows`; no persist before L2 |
| S2 | **Sybil assignment delay** (announce `submit`, never submit) | R121: assignment only with chain-attributed track record or admin trust; miss exclusion; worst case one `exclusive_ms` delay per assigned intent |
| S3 | **Re-originated / poisoned copies** (MESH T6) | content-addressed msg-id (R117): the honest copy is never deduped at gossip level; store tombstones as MESH |
| F1 | **Front-running via gossip visibility** | meta-tx outcome is fixed by the signer (G1, §05 §5.4.1); confidentiality: private chains never gossiped, companies opt in with `bus_scope = public` (§8.4), large B2B values belong on Zether or the bus (§05 §5.4.5 rule 2). DEX: resting orders are public by nature; taker orders posted directly to the home are not gossiped; `route_order` exposes a taker before matching (documented; limit price + IOC bound it); a home can always see its own takers first (inherent to any operated book, unchanged from today) |
| B1 | **Book spoofing** | `book` requires the home's signature **and** the home's PoP of the order's relayer; maker EIP-712 signatures checked; ERC-1271 orders only via the home; replica depth labelled per home; firm quotes only at the home; chain events override |
| H1 | **Hint poisoning** | hints never change state (R122); verified by the R80 read; false hints cost P5 −20; per-intent 10 s dedup bounds RPC use |
| A1 | **Announce replay / rollback** | strictly increasing `version`, `expires_at`; stored highest wins |
| A2 | **Lane / relayer impersonation** | PoP signatures (§10.3) |
| D1 | **Resource exhaustion on the swarm** | connection limits; QUIC/yamux flow-control windows (§7.4) bound buffered bytes; validation pool semaphore; RPC budget; payload caps before parse |
| D2 | **Amplification via sync** | 2 req/s/peer, 1 MiB responses, only public rows |
| P1 | **Harvest-now-decrypt-later** | X25519MLKEM768-only on QUIC and HTTPS (R114); TCP+Noise carries public data only |
| P2 | **Future live forgery (quantum)** | not mitigated (Ed25519); seam §4.3 |
| X1 | **SSRF via network addresses** | global-unicast dial filter; announce URLs never dialed (R120, R123) |

---

## 15. Crates and budget (R126)

### 15.1 Dependencies (`scaas-node/Cargo.toml`)

| Crate | Status | Use |
|---|---|---|
| `libp2p = { version = "=0.56.x", default-features = false, features = ["tokio", "quic", "tcp", "noise", "yamux", "dns", "gossipsub", "kad", "identify", "ping", "request-response", "json", "macros", "ed25519"] }` | **new** | swarm. `allow_block_list` and `connection_limits` behaviours from the facade. **VERIFY V4**: newest 0.56 patch and exact feature names at G1 start; MSRV ≤ our 1.90 |
| `rustls` features `aws_lc_rs`, `prefer-post-quantum`, `std`, `logging` (no default features) | changed (MESH §3.4 had `ring`) | R114 |
| `tokio-rustls` `default-features = false, features = ["aws_lc_rs"]` | changed | HTTPS bus |
| `reqwest` `rustls-tls-no-provider` instead of `rustls-tls` | changed | single provider (V2) |
| `aws-lc-rs` | **new** (pulled by rustls) | also the JWT verification library of NI R106 (ring-compatible `signature` API), replacing the direct `ring` dep planned in NI P2b |

No CBOR/protobuf crate of our own (R117); `serde_json` canonical body unchanged.

### 15.2 Budget

| Item | Bound |
|---|---|
| RSS added by gossip | ≤ 64 MiB at 50 peers / 10 msg/s; worst-case buffered bytes ≈ 50 × 1 MiB (flow control) |
| caches | seen 120 s × ≤ 200 msg/s × 20 B; mcache 6 s; Kademlia ≈ 1 MiB |
| replica books | on disk (`dex_replica`), not RAM; depth aggregation cached 1 s |
| CPU | Ed25519 verify ≈ 50 µs, ecrecover ≈ 60 µs, parse + canonical body ≈ 20 µs / 2 KiB ⇒ < 5 % of one core at 200 msg/s |
| build | first build with `libp2p` + `aws-lc-sys` (C, cmake): one long compile; run alone with `CARGO_BUILD_JOBS=4` (owner OOM rule); peak RAM not measured — **measure in G1** and record in the stream log |

---

## 16. Tests

Heavy runs one at a time (MESH §13). In-process tests use one tokio runtime, loopback, ephemeral ports,
`allow_private_addrs = true`.

### 16.1 Unit (`cargo test`, no network beyond loopback)

- `gossip/msgid`: identical bytes ⇒ same id; changed unsigned field ⇒ different id; poisoned copy then honest copy
  ⇒ both validated, honest one stored (MESH H1 through gossip).
- `gossip/validate`: table over §6 — every stage, every Accept/Ignore/Reject mapping; unknown major ⇒ Ignore;
  `support = none` ⇒ Accept, not stored; V8 timeout ⇒ Accept; stale nonce ⇒ Ignore; buckets.
- `gossip/publish`: `may_gossip` every branch (gateway+policy, job `public`/`open`/`restricted`, `peer` never,
  private visibility, private profile); CI grep guard (§12.1).
- `gossip/announce`: sig, version monotone, expiry, PoP valid/invalid/shared, body = open-peer `/policy` view (no
  private chain).
- `gossip/hint`: hint never changes state alone; consumed read ⇒ `landed_elsewhere`; RPC error ⇒ nothing; false
  hint accounting after 2 blocks; our live job + hint ⇒ R80 gap-filler path (fake chain).
- `gossip/exclusive`: eligible set (announce, trust, track record, exclusion), `until` per chain, misses, violation.
- `gossip/dex`: merge commutativity/idempotence (proptest over random update orders ⇒ equal replicas); restore at
  higher `home_seq` (§11.3); spoofed `book` (wrong home / no PoP) ⇒ Reject; ERC-1271 `route_*` from non-home ⇒
  Reject; head digest.
- `transport/pq`: HTTPS bus negotiates X25519MLKEM768 (rustls `negotiated_key_exchange_group`); classical-only
  client fails; QUIC assertion (V1); bus request on a TCP+Noise connection ⇒ `TRANSPORT_NOT_PQ`.
- `identity`: `PeerId ↔ peer_id` vectors; non-Ed25519 PeerId refused; signing-context prefixes distinct.
- Conformance file `tests/vectors/scaas-gossip-v1.json` (hint, announce, dexbook, dexhead, msg-id golden bytes) next
  to `scaas-intent-v1.2.json` (MESH §4.6 renamed); the Odoo copy is not needed (Odoo never parses gossip).

### 16.2 Multi-node e2e (`tests/e2e_gossip.rs`, `--ignored`, anvil + forge, in-process nodes, then 2 cases as processes)

| # | Scenario | Pass when |
|---|---|---|
| E-G1 | **Propagation**: 6 nodes, line + random bootstrap; intent at A (gateway, policy `gossip`) | all 6 store it < 2 s; exactly one submitter lands it; no node ingests twice |
| E-G2 | **QUIC default, TCP fallback**: node F with `quic = false` | F joins over TCP, receives intents; F's bus request to a consortium peer is refused |
| E-G3 | **Partition and heal**: block A,B,C ↔ D,E,F for 60 s; intents and DEX orders on both sides; heal | via `/scaas/sync/1` and heads, every node holds every live intent; replica digests equal to home digests ≤ 35 s |
| E-G4 | **Scoring**: node M forwards invalid intents (bad `hub.sig`) | M graylisted after the first; banned after 60 s; honest traffic unaffected; M's spam never stored |
| E-G5 | **Private isolation**: chain profile private at A with B as private bus peer (QUIC carrier) and C as open-mesh peer | B lands the intent; C never receives it, never sees the chain in A's announce, A never subscribes the topic (inspect SUBSCRIBE); a private-labelled intent injected by M on an open topic ⇒ Rejected everywhere |
| E-G6 | **Exclusivity**: A assigns trusted G; G stopped; after `until` + jitter H lands | no tx before `until`; G's miss counted; untrusted sybil S with a `submit` announce is never assigned |
| E-G7 | **Hints**: B lands, C has the intent `pooled` with `may_submit` after exclusivity | C publishes no tx; C's row `consumed/landed_elsewhere` from its own read, before its scheduler would have simulated; a forged hint from M changes nothing and costs M P5 |
| E-G8 | **DEX across homes**: maker order rests at A; taker signs bound to A and posts to B's gateway (`route_order`) | A matches and settles once; B and C replicas show the fill and the close; B never attempts a settle |
| E-G9 | **Book spoofing**: M publishes `book` for an order bound to A's relayer | Rejected; replicas unchanged |
| E-G10 | **Restart**: kill B during sync; restart | announces/replica reload from store; cursor-free resync completes; no duplicate job rows |

Pull-bus cases E1–E12 of MESH §13.3 also run with the bus over QUIC (parameterized carrier).

---

## 17. Streams

Current order (NI §17): S3 → P1 → P2 → P2b → P3 → P4 → P5 → P6 → [cutover] → P7 → S1b′ → S5 → S6′ → S7′ → P9 → S8′.

| Stream | Change |
|---|---|
| **S3′** (envelope library) | renames (R115: `scaas-intent/1.2`, `scaas-hub/v1`, vector file); adds `gossip/msgid`, `hint_msg`/`announce_msg`/`dexbook_msg`/`dexhead_msg` builders + `scaas-gossip-v1.json` vectors; `accept()` takes `Source::Gossip`. Pure library, still "any time". Gate `cargo test --lib --test mesh_vectors` |
| P1 | store schema: §8.4 tables and CHECK changes; `[identity]`, `[transport]`, `[gossip]` config parsing (no networking) |
| P2b | JWT verification on `aws-lc-rs` instead of `ring` (§15.1); routes of §13.1 are **not** added here (they need G1 state) |
| **S5′** (bus) | provider switch to aws-lc-rs + PQ-only groups for the whole process (R114, V2), reqwest no-provider; HTTPS bus as MESH §5 + `TRANSPORT_NOT_PQ` plumbing. Gate `cargo test` + `cargo tree` provider check. **First aws-lc-sys build: run alone** |
| S6′ | adds `may_gossip` hook points (publish queue drained by G1; no-op without it) |
| **G1 — libp2p core** (new) | swarm task, QUIC (V1 resolved) + TCP/Noise, Kademlia, identify, ping, connection limits, address filter, bans, gossipsub config/scoring, intent topic validator + publish, `/scaas/sync/1` intents, `/scaas/bus/1.2` over QUIC, admin routes §13.1 + metrics. Gate `cargo test` (in-process multi-node unit tests) |
| **G2 — announce, exclusivity, hints** (new) | §8.3, §9, §10; `gossip_*` stats; E-G6/E-G7 in-process. Gate `cargo test` |
| **G3 — DEX book gossip** (new; needs P7) | §11, gateway `scope=network`, `/v1/dex/homes`. Gate `cargo test` + DEX e2e alone |
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
| §2 R74 | eligible set extended, per-chain `exclusive_ms` (R121) |
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
| §8.2 | R121 |
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
| §12 | `dex_replica`, gateway `scope=network`, `/v1/dex/homes` |
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

## 19. Open questions for the owner

1. **`bus_scope = public`** (§8.4): is a separate company opt-in for the open mesh wanted, or should the existing
   `open` mean "partners and the world"? The spec assumes separate (fails closed).
2. **DEX relayer-unbound orders** (§11.6): build the settle-claim rule in round 4, or keep RS5-9 (home-bound only)
   and fragment liquidity per home? The spec keeps RS5-9.
3. **Assignment trust bootstrap** (R121): `assign_min_landed = 3` in 7 days, or admin-trusted only on the open mesh
   (no automatic trust at all)?
4. **QUIC PQ-only** (R114): a third-party node without X25519MLKEM768 can then join the open mesh only over
   TCP+Noise. Accept, or allow a classical group on QUIC for open peers (and then inspect the negotiated group
   before serving the bus)?

---

## Owner answers (2026-10-06) to the open questions

1. **Open-mesh opt-in: yes.** `bus_scope` gains a third level: `restricted` (default, R10) < `open` (admitted
   pull-bus peers) < `public` (also the open gossip mesh). A company must turn `public` on explicitly.
2. **DEX relayer binding: both, selected by option.** Home-node orders (RS5-9, bound to the home relayer) remain
   the default; relayer-unbound orders (`relayer = 0`, network-wide liquidity, settle-claim rule of R124) are
   built in round 4 and enabled per market by a configuration option (and per order only where the market allows
   it). The settle-claim rule moves from "defined, not built" to G3 scope.
3. **Exclusive assignment trust: automatic** after 3 verified landings in 7 days (R121), or admin-trusted.
4. **QUIC offers only the PQ group (X25519MLKEM768): accepted.** A third-party node without ML-KEM joins only over
   TCP+Noise and receives public open-mesh data only.
