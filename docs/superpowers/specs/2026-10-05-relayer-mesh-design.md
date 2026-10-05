# Round 4 — Relayer mesh: design spec

Status: draft rev 3 (reviews 1 and 2 folded in, §16), 2026-10-05. Repo `custom-addons/bamboo-dms` at `main` 3a789d2.
Rulings: R70–R86 (§2). The highest ruling in force before this spec is R67
(`docs/superpowers/specs/2026-10-03-blockchain-round3-design.md` §E); R68–R69 are left unused because the owner
asked for "R70+".

Sources are cited inline. Short forms:

| Short | File |
|---|---|
| UD | `docs/superpowers/specs/blockchain-research/_USER-DECISIONS.md` |
| §05 | `docs/superpowers/specs/blockchain-research/05-open-relayer-network.md` |
| §06 | `docs/superpowers/specs/blockchain-research/06-relay-pool-enterprise.md` |
| §10 | `docs/superpowers/specs/blockchain-research/10-odoo-addon-design.md` |
| PD | `docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` |
| R3D | `docs/superpowers/specs/2026-10-03-blockchain-round3-design.md` |
| node | `bamboo-node/` |

---

## 1. Scope and non-goals

### 1.1 In scope (v1)

0. **A live bug fixed first, independent of the mesh** (stream S0, R84): the gateway `POST /v1/metatx` forwards the
   client's `feeRecipient`/`relayer` unchanged; when the signer left them unbound, the client can route our relayer's
   fee to itself while we pay gas.
1. A **federated intent bus** between `bamboo-node` processes: admitted peers pull each other's intents over HTTPS
   with mutual TLS (R70, R72). Each node keeps its intents in a node-local SQLite store with a `bus_seq` cursor (R71).
2. A **transport-neutral envelope** `bamboo-intent/1.2` for every qualifying family (R77, R81), with conformance
   vectors (UD §21.3 point 2).
3. **Acceptance policy** as one lookup table, authoritative in Odoo (`blockchain.target.policy`), delivered to the node,
   evaluated before any RPC (UD §21.4, §22.4; R79). Submission only on registered tokens (R86).
4. **Soft exclusivity** assigned by the origin node, round-robin over eligible admitted peers (R74).
5. **Cancel/dedup correctness on every submit path**: re-check consumption before every bump or resend and after every
   reverted receipt; the states `LANDED_ELSEWHERE` and `SUPERSEDED` (UD §22.1, §22.8); Odoo learns of consumption at
   detection time, not only at finality (R80). This part also fixes the existing single-node relayer and ships right
   after S0 (streams S1a + S2, §14).
6. **Private profile**: `blockchain.chain.chain_profile`; private-chain intents only travel from the origin to
   private peers it admitted itself (R76, R85; §05 §5.4.5).
7. **Per-company bus scope**: default keeps R10 (company relayer only, never on the bus); opt-in publishes
   relayer-unbound outbox jobs after a private window (R73).

### 1.2 Non-goals (v1)

| Out | Why / where it goes |
|---|---|
| libp2p / gossipsub, peer discovery, DHT, bootstrap multiaddr | R70. Envelope and state machine are transport-neutral so a libp2p transport can be added without a format change (§15). |
| Open (unadmitted) peers, PoW, stake, lottery, `beacon`, reputation / forward score | R70, R75. Admission is the anti-sybil control in v1 (§05 §5.0 already says private profile = allowlist, no market). |
| Rewards other than the intent's own `fee` / `feeRecipient` | R75: no `SponsorshipPool`, no statement payouts, no forwarder pay. |
| Soroban on the bus | R77: replay protection is the host's auth nonce, not a per-subject nonce in our contract. |
| Zether intents on the bus | `W = 0` and single-flight per `from_schnorr` (§05 §5.1.1, §5.4.3) need their own design; a 20 s budget does not survive pull latency (§5.4). |
| EVM `call` jobs (MandateWallet calldata, R25), DEX `settle` jobs, non-EVM op kinds other than `pay` | No subject-signed digest whose replay guard is a lane nonce a peer can check (M6: TON revoke uses `next == nonce + 1`, Solana mandate revoke uses a generation). |
| Multi-hop private routing | R85: private intents are served by their origin only. Needs an origin-signed recipient set and a ruling. |
| Callback subject registry (UD §22.10.4), ban-list sharing (§05 §5.5 tier 5) | Owner accepted defaults. |
| Promote-to-open of pooled intents (UD §21.4 "private pool") | The only "private then open" path in v1 is the per-company window on own outbox jobs (R73). A pooled bus intent never changes visibility. |
| Non-EVM intents from third parties (door A) | v1 gateway stays EVM-only (`POST /v1/metatx`). Non-EVM intents reach the bus from Odoo outbox jobs and from peers. |
| `nonce_unverified` cache tiers of UD §22.3; a cache of rejected intents | Federation volume (admitted peers, rate-limited) does not need them; the submitter's simulation is the check. |
| Odoo-side mesh counters (`mesh_report`) | `/metrics` on the node is the only place for them in v1 (§12). |

---

## 2. Rulings

Format of PD §13: **ruling — why — cost if wrong.**

| # | Ruling | Why | Cost if wrong |
|---|---|---|---|
| **R70** | (owner) Transport v1 = **federated HTTP pull bus** between admitted peers: each node serves `GET /v1/mesh/intents` and pulls its peers'. No push, no publish/claim/receipt routes between peers. The envelope (§4) and store state machine (§6) are transport-neutral; libp2p can be added later as a second transport. UD §22.2 door C and §23.6 must be corrected (§15, list only). | Owner. Pull gives catch-up after downtime (cursor), and puts the export filter for private intents in one server-side function (§9). §05 §5.1 numbers: 1 Hz poll adds ≤ 1 s on a 5 s chain. | Latency ≤ (poll + lag) per hop, ≤ 6 s at 4 hops. Fine for EVM `validUntil` 300 s; wrong for Zether (out). |
| **R71** | (owner) Intent store = **node-local SQLite file** (`rusqlite`, bundled), owned by `bamboo-node`. `bus_seq` = `INTEGER PRIMARY KEY AUTOINCREMENT`; a random `store_id` names the file and is sent with every page so a peer whose store was recreated is detected (cursor reset). R6 unchanged: the node never touches Postgres; Odoo stays control plane. When `[mesh]` is on, gateway meta-tx intents are written to the store before `202` — this supersedes R16 for `/v1/metatx` (the DEX book stays as is). | Owner. One writer process ⇒ rowids are assigned in commit order, so the §05 §5.1.2 bug 3 (seq allocated before commit) cannot happen. | A lost disk loses pooled intents and the mesh outer-nonce journal; signers re-send, cold start falls back to `pending` (§8.6). |
| **R72** | (owner) Peer identity = **TLS 1.3 mutual auth with self-signed X.509 certs; trust = SPKI SHA-256 pin per peer row; no CA.** Key type **Ed25519**. The same key signs `hub.sig` and is the `pubkey` in `/v1/mesh/policy`. `peer_id` = SHA-256 of the DER SubjectPublicKeyInfo. Admission is checked at the handshake **and** on every request. | Ed25519, P-256 and RSA are all valid TLS 1.3 cert keys in `rustls`+`ring`; Ed25519 is chosen because its signatures are deterministic (the vectors need fixed `hub.sig` bytes, §4.6), it is already the node's ed25519 signer (`ed25519-dalek`), and keys are 32 bytes. secp256k1 is not a TLS signature scheme, so the relayer lane keys cannot double as peer keys. | An HSM that only does P-256 cannot hold this key. |
| **R73** | (owner) **Bus scope is a per-company setting** `res.company.blockchain_bus_scope`: `restricted` (default) keeps R10 — the portal pins `MODE_RESTRICT_RELAYER` to the company relayer and **no outbox job of the company ever reaches the bus**. `open`: the portal signs with `relayer = 0`; a still-`queued` relayer-unbound job is published on the bus after `blockchain_bus_private_window_secs` (default 120 s). | Owner. 120 s, not UD §22.7's 300 s: with ERC-20 `validUntil` 300 s a 300 s window never opens (UD §22.10.2). | A company that opts in exposes payer, payee, amount and timing to admitted peers of the matching class (§05 §5.4.5). |
| **R74** | (owner) **Exclusivity**: the origin node signs `exclusive{relayer_id, until}` in `hub.sig`, choosing `relayer_id` round-robin over the eligible set = admitted active peers that advertise `submit` for `(chain, contract)` and may see the intent, **plus the origin itself when it can submit** (owner-confirmed). After `until` any admitted peer may submit, after a deterministic per-node jitter. **Own outbox jobs are never assigned to a peer**: they are published without `exclusive`, and the origin keeps processing them through the Odoo outbox (SLA). Only still-`queued` outbox jobs are published (owner-confirmed). | Owner. Deterministic assignment needs no round-trip (§05 §5.4.4a); round-robin replaces the lottery that §05 §5.0 already switches off for permissioned sets. | `exclusive` is a courtesy, not a lock (UD §22.5). A peer that ignores it causes at most one reverted outer tx per loser (§8.7). |
| **R75** | (owner) **Reward = only the intent's own `fee` / `feeRecipient`.** No `SponsorshipPool`, no statement payouts, forwarders unpaid. Non-EVM `MetaOp` has no fee field (R3D §D.0), so peers relay non-EVM intents unpaid. | Owner; UD §21.5: a relayer is mostly paid outside the intent. | Peers with no off-chain agreement have no reason to submit our fee-0 jobs; liveness then rests on our own node. |
| **R76** | (owner) `blockchain.chain.chain_profile` = `public` \| `private`, **default `private`**. `blockchain.target.policy.pool_visibility` defaults from it. A private-chain intent is served **only** to peers of class `private` whose allowed chains include it, over mTLS; it is never exported to an `open` peer and never promoted (never_public). A node rejects a private-chain intent (by label **or** by its own chain profile) arriving from an `open` peer. Visibility is signed in `hub.sig` and only gets stricter. | Owner; §05 §5.4.5 rule 1: the default must be derived, not a flag someone remembers. Default `private` follows §05 §5.0 / §10 l.408 and fails closed; §06 §06.0.2 says `public` — overruled. | An operator who forgets to set `public` on Gnosis gets a bus that only private peers see: a liveness loss, never a leak. Existing databases need the upgrade step of §10.1. |
| **R77** | (owner) **Families on the bus in v1: EVM (`evm`, and `hedera` which runs the same Solidity on HSCS), Cosmos, Sui, Aptos, TON, Solana. Soroban is out.** Criterion: our contract computes a meta-tx digest and keeps a per-subject sequential nonce that a peer can read. Non-EVM op kind limited to `pay` in v1. Evidence §4.1. | Owner's criterion. Without a readable per-subject nonce a peer cannot run the consumption check of R80. | Soroban partners relay through Odoo outbox only. |
| **R78** | (owner) `intent_id` **is** the digest the contract emits in `MetaTransactionExecuted.digest`: EIP-712 `_hashTypedDataV4(hashStruct(m))` on EVM (`smartcontracts/src/common/MetaTxLib.sol`), the family digest otherwise (§4.4). It equals `blockchain.metatx.digest_hash` / `blockchain.signed.op.digest_hash`. Dedup is by `intent_id`. | §05 §5.2. UD §22.8 point 2 ("dedup by digest, not intent_id") assumed a sender-chosen id; with id = digest the two are one value. | — |
| **R79** | (owner) Acceptance policy is **authoritative in Odoo** (`blockchain.target.policy`), fetched by the node through `blockchain.mesh.peer.mesh_config`. `node.toml` `[[mesh.policy]]` / `[[mesh.peers]]` are used **only when `[odoo]` is absent** (standalone node, §3.3). With `[odoo]` present the mesh stays closed until the first successful fetch (fail closed). | Owner; UD §22.4 (one table, not two); §06 §06.3.3 (same concept). | Odoo down at node start ⇒ no mesh until it comes back; submit/indexer unaffected. |
| **R80** | **Consumption check before every bump and every resend, and after every reverted receipt/status** (fix of `submit.rs` `track()`/receipt handling and `adapter.rs` `step_once`/`follow()`): if the subject nonce moved past the intent's nonce, never bump or resend the meta-tx, report `consumed` instead of `reverted`/`dead`; on EVM free the outer nonce with a gap-filler (R18). A failed consumption read **fails closed**: no bump this round, retry next round. Odoo gets a non-terminal `chain_state = 'consumed'`; a job is never `dead`/`failed` because someone else landed it. `_mark_executed` sets `landed_elsewhere`. One per-chain in-flight digest set prevents our node from holding two live outer txs for one intent. | UD §22.8 point 1: bumping a tx that must revert pays twice. Today `track()` bumps blindly, a lost race reports `reverted` (business `failed`, `_fail_dependents`), and Odoo only learns at finality. | One `eth_call` per stuck tx per `stuck_after_secs` (60 s) and per reverted receipt. |
| **R81** | Wire spec string **`bamboo-intent/1.2`**. JSON on the wire. `hub.sig` covers a fixed binary message (§4.5) that includes `body_hash` = SHA-256 of the canonical JSON of the family body. The paper drafts 1.0/1.1 (§05 §5.2) were never implemented by any node and are void: receivers reject `1.0`/`1.1` and any other major with `UNSUPPORTED_SPEC`. | 1.1's `hub_sig_payload` used `address(relayer_id)` and a lottery `beacon`; R72/R74 change both, which §05's own rule makes a breaking change. `body_hash` stops forwarders swapping signature, `sig_kind` or native params (review H1). | — |
| **R82** | Numbers: `MAX_HOPS = 4`, `cursor_overlap = 200`, `publish_lag_ms = 500` (from UD §22.2, §05 §5.1.2 — **arbitrary**, UD §22.10.1); `exclusive_ms = 10 000` (**arbitrary**; replaces §05's 3 s, which assumed push gossip); `post_exclusive_jitter_ms = 2000`, `max_valid_for_secs = 3600`, `private_window_secs = 120`, `poll_ms = 1000`, page 200 rows / 1 MiB, handshake timeout 5 s, connection age 300 s (**arbitrary**). All are config. | Docs where they exist; otherwise the smallest values that cover one pull hop + simulate + one 5 s block. | Re-tune after a real multi-site run. |
| **R83** | (owner) Test topology: N `bamboo-node` processes from one binary with different configs + one anvil + one fake Odoo (axum, as `tests/e2e.rs` already does), plus one Odoo-side suite. Callback subject registry and ban-list sharing are out of v1. | UD §21.3 point 3: two processes of one binary catch wire-format errors; the vectors catch the rest. | Spec-reading errors of a second implementation are only caught by the vectors (§4.6). |
| **R84** | **The submitter normalizes the fields `canon()` zeroes** before building any meta-tx it did not get from Odoo: `MODE_RESTRICT_FEE_RECIPIENT` off ⇒ `feeRecipient := chains.fee_recipient` (our cold wallet) or `0` (contract pays `msg.sender`); `MODE_RESTRICT_RELAYER` off ⇒ `relayer := 0`. Wire values of unbound fields are never submitted. Applies to the gateway today (S0) and to mesh work. | `ERC20MetaTx.sol` l.87 pays `m.feeRecipient` whenever it is non-zero, but the digest zeroes it when unbound (`MetaTxLib.canon`). Without this, a client or forwarder takes the fee while we pay gas. `intent_id` is unchanged. | — |
| **R85** | **Private-visibility rows are served only by their origin** (stored `source != 'peer'`). Every private recipient must be admitted by the origin directly. | Review H5: otherwise a correct private peer re-serves to peers *it* trusts, outside the origin's allowlist (owner ruling 7: "allowlisted private peers"). | Private liveness depends on the origin being up. |
| **R86** | **`may_submit` requires `token_of(intent)` to be a registered token** (Odoo `node_config.tokens` of an active chain, or `[[chains]] tokens` standalone); Odoo forbids `submit` on `contract = '*'`. `token_of` = `contract` on EVM/Hedera/Cosmos; on Sui/Aptos/TON/Solana, where `contract` is the payer's own account, it is the token named in the payload or body, and the node checks that `contract` is that payer's account derived from it (§4.4). The policy `contract` column holds `token_of`. Fee checks use the **effective** fee as `FeePolicy.compute` (NONE ⇒ 0, PERCENT ⇒ `value × fee / 10^6`, FIXED ⇒ `fee`). | Review H4: otherwise a peer feeds attacker-deployed token clones with worthless fees that simulate fine (gas drain), and a NONE-mode intent with a huge `fee` field passes `min_fee`. Gateway and Odoo paths already gate on registered tokens (`gateway.rs` `chain_of`). | Partners must register their tokens in our Odoo before we submit for them. |

---

## 3. Roles and configuration

### 3.1 Shapes this round supports

Vocabulary of UD §21.4 / §23.3: a **module** is switched on in `[modules]`; a **shape** is a set of modules.

| Shape | Modules | Notes |
|---|---|---|
| Full node | `submit`, `indexer`, `gateway`, `mesh` | Our deployment: Odoo outbox + gateway + bus. |
| Mesh relayer | `submit`, `mesh` (no `[odoo]`) | Standalone partner node (§3.3). `indexer` is refused without `[odoo]`. |
| Forwarder | `mesh` only | Policy rows `support = forward_only`; no keys needed for a chain that is only forwarded. |

The `pool` module of UD §23.3 is not a separate switch: the store **is** the mesh-facing queue (UD §21.4 point 2 calls
it "pool"), and it exists iff `mesh` is on.

### 3.2 `node.toml` changes

`[odoo]` becomes optional. Validation (`config.rs` `Config::validate`):

- `[odoo]` absent ⇒ `modules.indexer` must be false (rules of §3.3).
- `modules.mesh = true` ⇒ `[mesh]` required.
- A `[[chains]]` entry needs a key only if `modules.submit` (today it always needs one).

```toml
[modules]
mesh = true                       # new; default false

[[chains]]
family = "evm"
evm_chain_number = 100
# ... existing keys ...
profile = "public"                # new; standalone only. Default "private" (R76). With [odoo] Odoo's chain_profile wins.
fee_recipient = "0x…"             # new, optional, EVM/Hedera. Cold wallet: R84 normalization target, published in
                                  # /v1/mesh/policy, used by fee_recipient_allow = "self_or_zero" (UD §21.5).
                                  # Never a lane key. Unset ⇒ R84 writes 0 (fee goes to the submitting lane).
tokens = ["0x…"]                  # new; standalone only (R86). With [odoo] the token list comes from node_config.

[mesh]
bind = "0.0.0.0:8550"             # mTLS only; there is no plaintext mode
cert = "/etc/bamboo/mesh.crt"     # self-signed X.509 (PEM) holding the Ed25519 key below
key = { file = "/etc/bamboo/mesh.key" }   # PKCS#8 PEM (48-byte Ed25519 PrivateKeyInfo), SecretSource like [keys]
store = "/var/lib/bamboo/mesh.sqlite"
poll_ms = 1000
max_hops = 4
cursor_overlap = 200
publish_lag_ms = 500
exclusive_ms = 10000
post_exclusive_jitter_ms = 2000
max_valid_for_secs = 3600
page_max = 200
page_max_bytes = 1048576
retention_secs = 86400
max_rows = 200000
peer_rps = 10                     # requests/s a peer may make to us (token bucket, burst = 2 × rps)
peer_intents_per_sec = 50         # new intents/s we ingest from one peer
max_conns = 64                    # concurrent inbound TLS connections
handshake_timeout_ms = 5000
max_conn_age_secs = 300
clock_skew_secs = 30

# Standalone only (no [odoo]); ignored with a warning when [odoo] is present (R79).
[[mesh.peers]]
name = "partner-a"
url = "https://a.example.net:8550"
spki_sha256 = "9f…64 hex"
class = "open"                    # open | private
chains = ["evm:100"]              # private peers: chains they may receive (required, non-empty).
                                  # open peers: optional filter; empty = every public chain.

[[mesh.policy]]
chain = "evm:100"
contract = "0x…"                  # canonical address of the family, or "*" (never "*" with submit = true, R86)
selector = "*"                    # EVM: "0x" + 8 hex, "0x" (empty data) or "*"; other families: "pay" or "*"
support = "full"                  # none | forward_only | full
submit = true
pool_visibility = "open"          # open | private | none
min_fee = "0"                     # uint256 decimal, smallest token unit, compared with the EFFECTIVE fee (R86)
fee_recipient_allow = "any"       # any | self_or_zero — only meaningful when the intent binds feeRecipient
```

Key generation, documented in `bamboo-node/README.md` (no new crate for it):

```bash
openssl genpkey -algorithm ed25519 -out mesh.key
openssl req -new -x509 -key mesh.key -out mesh.crt -days 3650 -subj "/CN=bamboo-node"
# peer_id = SPKI pin to give to partners:
openssl x509 -in mesh.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r
```

Also printed by `bamboo-node mesh-id --config node.toml` (new subcommand next to `addresses`, `main.rs`).

### 3.3 Standalone mode (no `[odoo]`)

`Config.odoo: Option<OdooCfg>`; the paths that need Odoo today take `Option<Odoo>`:

| Path | Today | Standalone |
|---|---|---|
| `Submitter::start` (`submit.rs` l.80–91) | `node_config_ref` → journal, in-flight, `plan` | `journal_max` and in-flight from the store only (§8.6); token list from `[[chains]] tokens` |
| `poll_outbox` | `relay_poll`/`relay_claim` | not called |
| `lane_runner` / `recover_lane` (`adapter.rs` l.161, l.225) | Odoo jobs + `node_config` | mesh channel only; recovery from store rows |
| outcome reports | `relay_report` | store only |
| admin refresh (`admin.rs` `read`) | `relay_stats` | readiness = RPC head + store open; job metrics omitted |
| `mesh_config` | Odoo | `[[mesh.peers]]`, `[[mesh.policy]]`, `[[chains]] profile` |

Adapters that read tokens from `node_config` take the toml list instead. Standalone nodes run no indexer, so their
outcomes come from the submit path only (receipts + consumption checks).

### 3.4 Dependencies (`bamboo-node/Cargo.toml`)

| Crate | Status | Use |
|---|---|---|
| `rusqlite` (features `bundled`) | **new** | store (R71) |
| `rustls = { version = "0.23", default-features = false, features = ["ring", "std", "logging", "tls12"] }` | in `Cargo.lock` (via `reqwest` `rustls-tls`, ring provider); direct dep | mTLS. **No default features**: the defaults pull `aws-lc-rs` (C/cmake) and, with two providers compiled in, `ServerConfig::builder()` panics. Always build with `builder_with_provider(rustls::crypto::ring::default_provider().into())`. |
| `tokio-rustls = { version = "0.26", default-features = false, features = ["ring"] }` | in lock; direct dep | TLS accept loop |
| `hyper-util` 0.1, `rustls-webpki` 0.103 | in lock; direct deps | serving axum over TLS (`TowerToHyperService`); SPKI extraction (`webpki::EndEntityCert::try_from(&der)` → `subject_public_key_info()`, which re-wraps the outer SEQUENCE) |
| `ed25519-dalek`, `sha2` | direct already | `hub.sig`, `peer_id`. The PEM key is parsed by hand: base64 body = fixed prefix `302e020100300506032b657004220420` ‖ 32-byte seed (no `pkcs8` feature needed) |

No `axum-server`, no `rcgen`, no `x509-parser`.

---

## 4. Envelope `bamboo-intent/1.2`

### 4.1 Family qualification (R77)

| Family | Digest (contract) | Per-subject nonce (contract) | Readable by a peer | Qualifies |
|---|---|---|---|---|
| EVM | `ERC20MetaTx.executeMetaTransaction`: `_hashTypedDataV4(m.hashStruct())`, emitted in `MetaTransactionExecuted.digest` (`smartcontracts/src/metatx/ERC20MetaTx.sol` l.62–103) | `_metaNonce[from][batch]`, must equal `m.nonce`, `+1` after execution (same file l.26, l.80, l.102) | `metaNonce(from, batch)` view (l.44) | **yes** |
| Hedera | `HederaMetaToken is MetaToken` — same `ERC20MetaTx` (`smartcontracts/src/hedera/HederaMetaToken.sol` l.15, `MetaToken is ERC20MetaTx`; R63) | same | same, via the JSON-RPC relay | **yes** (envelope family `hedera`, EVM body) |
| Cosmos | `sha256(payload)` (`chains/cosmos/metaop/src/lib.rs` l.119), emitted as `digest` attribute | `NONCES: Map<(&Addr, lane), u64>`, `op.nonce == next` (`chains/cosmos/token/src/lib.rs` l.81, l.194–197) | `QueryMsg::Nonce { owner, lane }` (l.239) | **yes** |
| Sui | `personal_digest(bcs(MetaOp))` (`chains/sui/sources/meta.move` l.322) | `Account<T>.lanes: Table<lane, u64>`, `next == nonce` (l.104, l.285–287) | `lane_nonce<T>(account, lane)` (l.484) | **yes** |
| Aptos | `sha3_256(bcs(MetaOp))` (`chains/aptos/sources/meta.move` l.114) | `Account.lanes: Table<lane, Lane{next}>` (l.110, l.278–279) | `#[view] lane_nonce(owner, lane)` (l.666) | **yes** |
| TON | `MetaOp` cell digest checked and emitted in `MetaTransactionExecuted` (`chains/ton/contracts/jetton.tact` l.233) | jetton wallet `lanes: map<uint256, uint64>`, `next == m.nonce` (l.121, l.226–230; revoke: `next == nonce + 1`, l.229) | getter `get_lane_nonce(lane)` (l.359) | **yes** (`pay`; lanes rotate every `LANE_TTL` — a check after `valid_until` is meaningless, expiry decides, §8.5) |
| Solana | `sha256(MetaOp)` (`chains/solana/programs/bamboo/src/account.rs` l.197; `lib.rs` l.125) | `LanePda{next}` seeded `["lane", subject, lane]`, `lp.next == args.nonce` (account.rs l.159–161, l.202) | read the `LanePda` account | **yes** (`pay`; lane PDA prunable after `valid_until`) |
| Soroban | `op_digest` = sha256(XDR) emitted by the token (`chains/soroban/contracts/token/src/lib.rs` l.102) | **none in our contract**: replay protection is the host's `SorobanAddressCredentials` nonce (random, not sequential, R65); our contract only has a global one-shot `pay_ref` (l.203–206) | `ref_used(pay_ref)` only | **no** |

### 4.2 Wire encoding

- UTF-8 JSON object, at most 32 KiB per envelope (§05 §5.1.2 `MAX_BODY`).
- Receivers **ignore unknown top-level fields** (minor bump rule, §05 §5.2) and reject an unknown major (R81). The
  family body (`evm` / `op`) is covered by `body_hash`, so unknown fields inside it are hashed, not ignored.
- Integers that fit in `u64` (timestamps, `hop_count`): JSON numbers. `uint256` values: canonical decimal strings
  (no sign, no leading zero; exactly `metatx.rs` `uint()`).
- Bytes and hashes: `0x` + lowercase hex. `peer_id`, `pubkey`, `sig`: lowercase hex **without** `0x`.
- Addresses: the family's canonical form (`dms_blockchain/lib/addresses.py`, R61): lowercase `0x` 20 bytes on
  EVM/Hedera, bech32 on Cosmos, `0x` + 64 hex on Sui/Aptos, raw `wc:hex` on TON, base58 on Solana.
- `chain_key` = `family:network` exactly as `blockchain.chain.chain_key` and `ChainCfg::chain_key()` (`evm:100`,
  `hedera:296`, `cosmos:bamboo-1`, `sui:localnet`, `aptos:4`, `ton:-239`, `solana:<genesis base58>`). Not CAIP-2:
  the node and Odoo already key on `chain_key` (R61); CAIP-2 stays a display field in Odoo.
- **Canonical body JSON** (for `body_hash` only): the `evm` or `op` object serialized with object keys sorted
  bytewise, no whitespace, no floats (integers must fit `i64`), every string printable ASCII `0x20–0x7e` (all values
  are hex, decimal, base58, bech32 or enum words; anything else ⇒ `BAD_ENVELOPE`). Rust: `serde_json::to_vec` of a
  `Value` (default `BTreeMap`, no `preserve_order` feature). Python: `json.dumps(o, sort_keys=True,
  separators=(',', ':'))`. Vector cases pin the bytes.

### 4.3 Fields

```json
{
  "spec": "bamboo-intent/1.2",
  "intent_id": "0x9f3c…64 hex",
  "chain_key": "evm:100",
  "family": "evm",
  "contract": "0xf17…",
  "visibility": "open",
  "evm": {
    "domain": {"name": "Bamboo MetaToken", "version": "1"},
    "meta_tx": {"from": "0xa1…", "to": "0xb2…", "value": "100", "data": "0x…", "batch": "7412…",
                "nonce": "0", "validUntil": "1756500900", "mode": 32, "relayer": "0x00…00",
                "fee": "5000", "feeRecipient": "0x00…00"},
    "signature": "0x…",
    "sig_kind": "eoa"
  },
  "hub": {"id": "64 hex", "pubkey": "64 hex", "published_at": 1756500012, "sig": "128 hex"},
  "exclusive": {"relayer_id": "64 hex", "until": 1756500022},
  "hop_count": 0
}
```

| Field | Req | Meaning |
|---|---|---|
| `spec` | yes | `bamboo-intent/1.2` |
| `intent_id` | yes | R78; recomputed by every receiver (§4.4) |
| `chain_key`, `family` | yes | `family` must equal the prefix of `chain_key`; `soroban` ⇒ `FAMILY_NOT_SUPPORTED` |
| `contract` | yes | EVM: the token = EIP-712 `verifyingContract` (MetaTxLib header: no forwarder). Others: the contract that verifies the op. |
| `visibility` | yes | `open` \| `private`, as set by the origin; receivers apply the stricter of this and their own policy (§9) |
| `evm` | iff `family ∈ {evm, hedera}` | `meta_tx` = `WireMetaTx` (`bamboo-node/src/metatx.rs`, camelCase, 11 fields of `MetaTxLib.MetaTransaction`); `domain` = EIP-712 `name`/`version` of the token (R5: implementation name/version on clones); `sig_kind` `eoa` (65 bytes, low-s) or `erc1271` (contract wallet, no local recover). The origin writes **zeros** in unbound `relayer`/`feeRecipient` (R84). |
| `op` | iff other families | the `op` object of a `signed_op` relay job (`blockchain.relay.job._payload`): `op_kind` (`pay` in v1), `payload` (hex of the exact signed bytes), `signature`, `public_key`, `auth_kind`, `extra` (native params for building the tx). `from`, `valid_until`, lane, nonce and relayer are **not** taken from the clear JSON: receivers decode them from `payload` (§4.4). `contract` is lifted to the top level. |
| `hub.id` | yes | origin `peer_id` = SHA-256(SPKI DER) |
| `hub.pubkey` | yes | raw 32-byte Ed25519 key; receivers check `sha256(SPKI_ED25519_PREFIX ‖ pubkey) == hub.id`, with `SPKI_ED25519_PREFIX = 302a300506032b6570032100` |
| `hub.published_at` | yes | origin clock, unix seconds |
| `hub.sig` | yes | Ed25519 (RFC 8032, pure) over §4.5 |
| `exclusive` | no | absent = anyone admitted may submit now |
| `hop_count` | yes | not signed; incremented by each receiver (§5.4) |

Dropped from §05's 1.1: `tokenContract` (gone since UD §24, BẢN 4), `bus_seq` (moved to the page wrapper, it is a
property of the serving node), `published_at` at top level (now signed inside `hub`), `beacon`, `pow`, `sponsor`
(R75), `zether` (out), `hints` (a receiver re-simulates anyway; `hints` leak shape on public chains, §05 §5.4.5).

### 4.4 `intent_id` and decoded fields per family

| Family | `intent_id` = | Routing fields decoded from | Implementations that must agree |
|---|---|---|---|
| `evm`, `hedera` | `keccak256(0x1901 ‖ domainSeparator(name, version, chainId, contract) ‖ hashStruct(canon(m)))`; `chainId` = number in `chain_key` | `meta_tx` (all signed) | `MetaTxLib.hashStruct`, `metatx.rs` `digest()`, `lib/eip712.py` |
| `cosmos` | `sha256(payload)` | payload JSON (`MetaOp`) | `metaop/src/lib.rs`, `lib/fam_cosmos.py` |
| `sui` | `blake2b256([3,0,0] ‖ bcs(vector<u8>(payload)))` | `adapters/sui.rs` `MetaOp::decode` (l.136) | `meta.move` `op_digest`, `adapters/sui.rs` `personal_digest`, `lib/fam_sui.py` |
| `aptos` | `sha3_256(payload)` | `adapters/aptos.rs` `MetaOp::decode` (l.149) | `meta.move`, `lib/fam_aptos.py` `digest` |
| `ton` | representation hash of the `MetaOp` cell tree carried in `payload` (BOC) | `adapters/ton.rs` `boc_parse` + `parse_metaop` (l.486) | `jetton.tact`, `adapters/ton.rs`, `lib/fam_ton.py` |
| `solana` | `sha256(payload)` (337-byte `MetaOp`) | `adapters/solana.rs` `MetaOp::decode` (l.154) | `account.rs` `digest()`, `adapters/solana.rs`, `lib/fam_solana.py` `digest` |

New Rust module `bamboo-node/src/mesh/digest.rs`: `pub fn decode(env: &Envelope) -> Result<Decoded>` returning
`{intent_id, from, lane, nonce, valid_until, relayer, fee_effective, selector, token}` by calling the existing helpers
and decoders above (`metatx::digest`, the adapters' `MetaOp::decode`/`parse_metaop`, `sha2`/`sha3`). No new family
encoder. One new decoder: Cosmos has none in `adapters/cosmos.rs` (the contract parses the JSON), so `digest.rs` adds
a small `serde` struct for the Cosmos `MetaOp` JSON (`chains/cosmos/metaop/src/lib.rs` fields); it is on the T9 fuzz
list.

`token` (= `token_of`, R86) per family, with the account-derivation check that binds `contract` to it:

| Family | `contract` is | `token_of` | Check |
|---|---|---|---|
| EVM, Hedera, Cosmos | the token | `contract` | — |
| Sui | the payer's `Account<T>` (`fam_sui.py` l.167) | `extra.registry` (bound by `body_hash`) | `derive_account(registry, from) == contract` (same formula as `fam_sui.py` l.159) |
| Aptos | the payer's Account object (`fam_aptos.py` l.233) | `asset` from the payload | `account_of(from) == contract` (`adapters/aptos.rs` l.207) |
| TON | the payer's jetton wallet (`fam_ton.py` l.296–312) | `extra.jetton_master` (bound by `body_hash`) | `jetton_wallet_address(from, master, code) == contract` (`adapters/ton.rs` l.526; code hash from the token record in `node_config`) |
| Solana | the payer's SubjectAccount PDA (`fam_solana.py` l.185) | `asset` (payload field; `extra.asset` must equal it) | `account_of(program, from) == contract` (`fam_solana.py` l.176) |

A failed check makes the intent `may_submit = false` (held and served, never submitted); it is not a rejection.

L2 checks (§7.2) beyond the hash: EVM — `mode` known (`MODE_KNOWN_MASK`, fee nibble ≤ 2),
`MODE_RESTRICT_RELAYER` with `relayer == 0` ⇒ `RELAYER_BOUND_ZERO` (§05 §5.0, a dead intent), `sig_kind = eoa` ⇒
`ecrecover(intent_id, signature) == from` with low-s. Other families: decoded `network`/`contract` fields of the
payload must match `chain_key`/`contract`; signature checking is left to the submitter's simulation (as R61 does for
Odoo), because WebAuthn/passkey envelopes differ per family. Unsigned parts that could still be wrong (`erc1271`
signature, non-EVM `signature`/`public_key`/`auth_kind`/`extra`) are bound by the origin's `hub.sig` through
`body_hash`; only a malicious *origin* can get them wrong, and §6 deletes its row when simulation fails so an honest
copy can still be ingested.

### 4.5 `hub.sig` message

```
hub_msg =  "bamboo-hub/v1"                 13 bytes ASCII, domain tag
         ‖ u8(len(chain_key)) ‖ chain_key  ASCII
         ‖ intent_id                       32 bytes
         ‖ body_hash                       32 bytes = sha256(canonical body JSON, §4.2)
         ‖ hub.id                          32 bytes
         ‖ u64be(hub.published_at)
         ‖ u8(visibility)                  0 = open, 1 = private
         ‖ u8(has_exclusive)               0 | 1
         ‖ exclusive.relayer_id            32 bytes (zeros when absent)
         ‖ u64be(exclusive.until)          0 when absent
hub.sig = Ed25519_sign(origin_key, hub_msg)          64 bytes
```

What it buys (§05 §5.2, re-scoped by R74): a forwarder cannot change `exclusive.*`, cannot downgrade `private` to
`open`, cannot move `published_at`, cannot swap the signature, `sig_kind`, wire `relayer`/`feeRecipient` or native
params. It does **not** stop an admitted peer from re-originating someone else's intent under its own `hub` —
first-seen-wins dedup, the `exclusive_ms` clamp and failed-row deletion bound that (§11, T6).

### 4.6 Conformance vectors

Ship `bamboo-node/tests/vectors/mesh-envelope-v1.2.json` and a byte-identical copy at
`dms_blockchain/tests/data/mesh-envelope-v1.2.json` (CI guard: `cmp` of the two files in the blockchain workflow,
R52). Generated by `cargo test --test mesh_vectors -- --ignored regenerate`; checked by the non-ignored test.

```json
{"spec": "bamboo-intent/1.2",
 "hub_key_seed": "01…32 bytes hex",          // Ed25519 seed of the test origin; peer_id derived
 "now": 1800000000, "fee_recipient": "0x…",  // our cold wallet for R84 cases
 "tokens": {"evm:100": ["0x…"], "sui:localnet": ["0x…registry"], …},   // registered tokens per chain
 "cases": [{"name": "…", "envelope": {…}, "from_peer_class": "open", "chain_profile": "public",
            "expect": {"accept": true, "intent_id": "0x…", "body_hash": "0x…", "hub_msg": "0x…", "hub_sig": "…",
                       "selector": "0x…", "valid_until": 1800000300, "fee_effective": "5000",
                       "may_submit": true, "submit_meta_tx": {…}}}]}
```

`submit_meta_tx` is the struct the submitter would encode after R84 normalization. Required cases (accept unless a
code is given):

1. EVM open FIXED fee, `pay(bytes32)` data — intent_id equal to the `MetaTxLib` KAT in `smartcontracts/test`.
2. EVM open mode with garbage in `relayer` and `feeRecipient` ⇒ **same** `intent_id` as case 1;
   `submit_meta_tx.feeRecipient` = `fee_recipient`, `relayer` = 0 (R84).
3. EVM `MODE_RESTRICT_RELAYER` with a lane address (accepted; `may_submit` only for that lane's node).
4. EVM `MODE_RESTRICT_RELAYER`, `relayer = 0` ⇒ `RELAYER_BOUND_ZERO`.
5. EVM empty `data` ⇒ selector `"0x"`.
6. EVM `sig_kind = erc1271` (no local recover, accepted).
7. EVM high-s signature ⇒ `BAD_SIGNATURE`.
8. Hedera `hedera:296` (chain id 296 in the domain).
9–13. Cosmos, Sui, Aptos, TON, Solana `pay` ops whose payload/digest are the existing cross-language vectors
   (`chains/cosmos/tests`, `adapters/aptos.rs` `payload_and_digest_match_move_and_python`, `adapters/solana.rs`
   `payload_digest_and_addresses_match_python_and_the_program`, `adapters/sui.rs` tests,
   `chains/ton/vectors/ton-vectors.json`); expected decoded `from`/`lane`/`nonce`/`valid_until`/`token`, and
   `may_submit = true` **computed** from the file's `tokens` map and a full/submit policy on `token_of` (R86, N1).
   Each of 10–13 has a twin whose `contract` is another payer's account ⇒ `may_submit = false`.
14. Soroban op ⇒ `FAMILY_NOT_SUPPORTED`.
15. `spec = "bamboo-intent/1.1"` and `"bamboo-intent/2.0"` ⇒ `UNSUPPORTED_SPEC`.
16. Unknown extra top-level field ⇒ accepted, ignored.
17. `hop_count = 4` arriving ⇒ `HOP_LIMIT` (stored would be 5 > `MAX_HOPS`).
18. `validUntil = now + 3601` ⇒ `VALID_TOO_LONG`; `validUntil = now + 10` (inside skew) ⇒ `EXPIRED`.
19. `intent_id` off by one byte ⇒ `DIGEST_MISMATCH`.
20. `visibility` flipped `private` → `open` after signing ⇒ `BAD_HUB_SIG`.
21. `exclusive.until` changed after signing ⇒ `BAD_HUB_SIG`.
22. `hub.pubkey` not matching `hub.id` ⇒ `BAD_HUB_SIG`.
23. Private-visibility intent with `from_peer_class = open` ⇒ `PRIVATE_FROM_OPEN_PEER`.
24. `exclusive.until − published_at > exclusive_ms` ⇒ accepted, `exclusive` ignored (clamp, §8.2).
25. `open`-labelled intent of a `chain_profile = private` chain from an open peer ⇒ `PRIVATE_FROM_OPEN_PEER` (M9).
26. `sig_kind` flipped `eoa` → `erc1271`, or `signature` swapped, after signing ⇒ `BAD_HUB_SIG` (body_hash).
27. Non-EVM `extra` changed after signing ⇒ `BAD_HUB_SIG`.
28. `published_at = now − 3000`, `validUntil = now + 300` ⇒ accepted (catch-up, H2); `published_at = now + 60` ⇒
    `BAD_ENVELOPE`.
29. NONE-mode intent with `fee = 10^30`, policy `min_fee = 1` ⇒ accepted, `fee_effective = "0"`,
    `may_submit = false` (R86).
30. Unregistered contract with a `full`/`submit` policy ⇒ accepted, `may_submit = false` (R86).
31. Body string with a non-ASCII character ⇒ `BAD_ENVELOPE`.
32. Body whose object keys are deliberately **unsorted** on the wire ⇒ the expected `body_hash` is that of the sorted
    form. Fails loudly if `serde_json`'s `preserve_order` feature ever gets switched on by feature unification.

The Odoo copy is used by `dms_blockchain/tests/test_mesh_vectors.py` to check that Odoo's own digest functions
(`lib/eip712.py`, `lib/fam_*.py` `build_terms`/`digest`) produce the same `intent_id` for cases 1–13, and that
`json.dumps(sort_keys=True, separators=(',', ':'))` gives the same `body_hash` — Odoo is the third implementation of
the digest (R13).

---

## 5. Bus HTTP API

Served by the `mesh` module on `[mesh] bind`. **Every** route requires mTLS (§5.1). JSON responses,
`Content-Type: application/json`, no cookies, no redirects. Version prefix `/v1/mesh` follows the spec major.

### 5.1 Authentication and connection limits

- TLS 1.3 only. Server: `rustls::ServerConfig` (ring provider, §3.4) with a custom `ClientCertVerifier` that
  **requires** a client cert, accepts self-signed certs (no chain building), lets rustls verify the TLS 1.3
  `CertificateVerify` signature with the cert's own key (`verify_tls13_signature` with ring algorithms), then
  computes `peer_id = sha256(spki)` and fails the handshake unless `peer_id` is an **active** peer in the current
  snapshot (`Arc<RwLock<PeerTable>>`). Unknown peers never reach HTTP parsing.
- **Per request**: the accept loop stores `peer_id` in a request extension; a middleware looks it up in the *current*
  snapshot on every request and answers `403 PEER_SUSPENDED` when it is no longer active (a suspended peer cannot keep
  using a keep-alive connection).
- Accept loop: `tokio::sync::Semaphore` of `max_conns`; `tokio::time::timeout(handshake_timeout_ms,
  TlsAcceptor::accept)`; each connection is closed after `max_conn_age_secs` (graceful shutdown of the hyper
  connection).
- Client: one `reqwest::Client` per peer built with `use_preconfigured_tls(rustls::ClientConfig)`: our cert+key as
  client auth, a `ServerCertVerifier` that accepts only a leaf whose SPKI hash equals that peer row's pin (ignores
  names, dates, CA). `redirect(Policy::none())`, timeout 10 s.
- Peer rotation of a key = a new peer row with the new pin; the old row is suspended after cut-over.
- Handler plumbing: `tokio_rustls::TlsAcceptor` → `server::TlsStream::get_ref().1.peer_certificates()` → `hyper_util`
  auto connection with `TowerToHyperService` over the axum router.

### 5.2 Routes

#### `GET /v1/mesh/policy`

What this node accepts and how it serves, filtered for the caller (an `open` peer never sees a private chain).
Callers cache it 60 s.

```json
{"spec": ["bamboo-intent/1.2"], "peer_id": "64 hex", "pubkey": "64 hex", "store_id": "32 hex",
 "max_hops": 4, "cursor_overlap": 200, "publish_lag_ms": 500, "exclusive_ms": 10000, "page_max": 200,
 "chains": [{"chain_key": "evm:100", "submit": true, "fee_recipient": "0x…",
             "contracts": [{"contract": "0x…", "selector": "*", "min_fee": "0",
                            "fee_recipient_allow": "any"}]}]}
```

`chains[].contracts` lists only rows with `support = full`, `submit = true` and a registered contract (R86); it is what
an origin uses to build the round-robin set (§8.2). `mode_known_mask` / `fee_modes_supported` of §05 §5.2 are fixed
by the contract today (`0xF3`, NONE/PERCENT/FIXED) and are not repeated.

#### `GET /v1/mesh/intents?since=<seq>&limit=<n>`

- `since` default 0, `limit` ≤ `page_max` (200). Full envelopes only (no summary/by-id two-step: an admitted peer
  could ask for full anyway, and a second round trip per hop is not in R70's latency budget).
- Server returns rows with `seq > since`, `received_at ≤ now − publish_lag_ms`, non-terminal, `valid_until > now`,
  stored `hop_count < max_hops`, and `may_export(row, caller)` (§9). Ordered by `seq`. The page ends early when the
  next envelope would take the body past `page_max_bytes` (1 MiB); at least one item is always returned when one is
  due.

```json
{"store_id": "32 hex",
 "items": [{"seq": 9101, "envelope": {…}}],
 "next": 9101}
```

The served envelope is the stored one with `hop_count` = stored value. `next` = seq of the last item (or `since` when
empty). There is no `head` field (it would count rows the caller cannot see; §11 T7).

Client rule (§05 §5.1.2 fix 3): request `since = max(0, cursor − cursor_overlap)`, dedup by `intent_id`, set
`cursor = next`, persist it with the peer's `store_id` in `peer_cursor`. A `store_id` different from the stored one
resets the cursor to 0 (the peer's store was recreated, M5). With the single-writer SQLite store the lag and overlap
are not needed for correctness (R71); they stay in the protocol so a future multi-writer store, or another
implementation, can rely on them.

#### Gateway additions (existing `gateway` module, R54 auth unchanged)

- `POST /v1/metatx`: R84 normalization before simulation (S0); response gains `intent_id` and, when published,
  `exclusive` (202). A duplicate returns `200` with the stored state (idempotent).
- `GET /v1/intents/{intent_id}` → `{"intent_id", "state", "consumed_kind"?, "tx_hash"?, "updated_at"}` from the store
  (the result queue of UD §22.9a; kept `retention_secs`), **only for rows with `source = 'gateway'`**: rows from
  peers or the outbox (incl. private-chain intents) answer 404, the same as unknown or expired ids.

### 5.3 Errors

Body `{"error": "<CODE>", "detail": "<text>"}`.

| HTTP | Code | When |
|---|---|---|
| — | (TLS alert) | client cert missing, bad `CertificateVerify`, peer not admitted/active, handshake timeout |
| 400 | `BAD_REQUEST` | bad query (`since` not a u64, `limit` out of range) |
| 403 | `PEER_SUSPENDED` | the connection's peer was suspended after the handshake |
| 429 | `RATE_LIMITED` | caller over `peer_rps`; header `Retry-After: <s>` |
| 503 | `NOT_READY` | store not open, or `[odoo]` present and `mesh_config` never fetched (R79) |

Ingest outcome codes (local; metrics label `code`; also returned by the gateway for door-A intents as 4xx `error`):
`UNSUPPORTED_SPEC`, `BAD_ENVELOPE`, `FAMILY_NOT_SUPPORTED`, `UNKNOWN_CHAIN`, `EXPIRED`, `VALID_TOO_LONG`,
`HOP_LIMIT`, `DIGEST_MISMATCH`, `BAD_SIGNATURE`, `RELAYER_BOUND_ZERO`, `BAD_HUB_SIG`, `PRIVATE_FROM_OPEN_PEER`,
`UNSUPPORTED` (policy `support = none`), `STORE_FULL`, `RATE_LIMITED`. `DUPLICATE` is not a rejection (no-op).

### 5.4 Forwarding, hops, idempotency

- The origin stores `hop_count = 0`. A receiver stores `served hop_count + 1` and rejects `> max_hops` (`HOP_LIMIT`);
  a node never serves a row whose stored `hop_count ≥ max_hops`. "Forwarding" in a pull bus = holding the row and
  serving it; there is no other forward action. Private rows are not forwarded at all (R85).
- Idempotency: `intent.intent_id` is UNIQUE; ingest of a known id is a no-op whatever its hop/hub (first seen wins).
  All bus routes are GET and side-effect free except rate-limit counters.
- `hop_count` is unsigned and a malicious peer can reset it (§05 §5.1.0); dedup is the real loop breaker, hops only
  trim waste.
- Pull latency per hop ≤ `poll_ms + publish_lag_ms` (1.5 s); 4 hops ≤ 6 s.

---

## 6. Node-local store (SQLite)

File `[mesh] store`. Opened once at start with `PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;` — `FULL` because the store holds the outer-nonce journal for mesh work (§8.6) and volume
is low. One `rusqlite::Connection` behind `Arc<Mutex<_>>`; every call runs in `tokio::task::spawn_blocking`.
`# ponytail: one connection + mutex; a writer thread with a channel if contention shows in /metrics.`

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- schema_version = '1', store_id = 16 random bytes hex

CREATE TABLE intent (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,                      -- bus_seq
  intent_id      BLOB    NOT NULL UNIQUE CHECK (length(intent_id) = 32),
  chain_key      TEXT    NOT NULL,
  family         TEXT    NOT NULL,
  contract       TEXT    NOT NULL,
  selector       TEXT    NOT NULL,
  subject        TEXT    NOT NULL,                                       -- decoded from (§4.4)
  lane           TEXT    NOT NULL,                                       -- EVM batch (decimal) / op lane (hex)
  subject_nonce  TEXT    NOT NULL,                                       -- decimal
  valid_until    INTEGER NOT NULL,                                       -- unix s
  visibility     INTEGER NOT NULL CHECK (visibility IN (0, 1, 2)),       -- open, private, none (never served)
  source         TEXT    NOT NULL CHECK (source IN ('gateway', 'outbox', 'peer')),
  source_peer    BLOB,                                                   -- peer_id when source = 'peer'
  odoo_job_id    INTEGER,                                                -- source = 'outbox'
  hop_count      INTEGER NOT NULL,
  exclusive_until INTEGER,                                               -- NULL = none or clamped away
  exclusive_self INTEGER NOT NULL DEFAULT 0,
  may_submit     INTEGER NOT NULL DEFAULT 0,                             -- local policy said submit (§7.3)
  state          TEXT    NOT NULL CHECK (state IN ('pooled', 'submittable', 'submitting', 'broadcast',
                         'landed', 'consumed', 'failed', 'expired')),
  consumed_kind  TEXT    CHECK (consumed_kind IN ('landed_elsewhere', 'superseded', 'unknown')),
  from_block     INTEGER,                                                -- chain head when received (§8.5 getLogs)
  lane_label     TEXT,                                                   -- our signing lane (journal)
  outer_nonce    INTEGER,                                                -- journal: written BEFORE send
  tx_hash        TEXT,
  envelope       BLOB    NOT NULL,                                       -- JSON as created/received
  received_at    INTEGER NOT NULL,                                       -- unix ms
  updated_at     INTEGER NOT NULL,                                       -- unix ms
  last_error     TEXT
);
CREATE INDEX intent_serve   ON intent (seq) WHERE state NOT IN ('landed', 'consumed', 'failed', 'expired');
CREATE INDEX intent_sched   ON intent (state, exclusive_until);
CREATE INDEX intent_valid   ON intent (valid_until);
CREATE INDEX intent_journal ON intent (chain_key, lane_label, outer_nonce) WHERE outer_nonce IS NOT NULL;

CREATE TABLE peer_cursor (peer_id BLOB PRIMARY KEY, store_id TEXT NOT NULL, cursor INTEGER NOT NULL,
                          updated_at INTEGER NOT NULL);
```

Transitions are single `UPDATE … WHERE intent_id = ? AND state = ?` statements (CAS); a zero row count means
someone else moved it.

| From | Event | To | Who |
|---|---|---|---|
| — | accepted, `!may_submit` or waiting for another's `exclusive` | `pooled` | accept (§7) |
| — | accepted, may submit now | `submittable` | accept |
| `pooled` | `exclusive` expired + jitter, `may_submit` | `submittable` | scheduler |
| `submittable` | in-flight digest set admits it, lane channel `try_send` ok | `submitting` | scheduler |
| `submitting` | channel full/closed, breaker open, transient RPC/simulate error, journal write failed | `submittable` | scheduler / outcome sink |
| `submitting` | journal written (lane, outer_nonce, tx_hash), sent | `broadcast` | submit |
| `submitting` | `valid_until` passed before send | `expired` | submit |
| `submitting`, `broadcast` | simulation revert or reverted receipt **with** consumption | `consumed` (+ kind) | submit |
| `submitting` | simulation revert **without** consumption, gas over cap, `metaTxDigest` mismatch | `failed` | submit |
| `broadcast` | receipt success | `landed` | submit |
| `broadcast` | reverted receipt **without** consumption | `failed` | submit |
| `broadcast` | outer nonce gap-filled after `valid_until` | `expired` | submit (R18) |
| `pooled`, `submittable` | `valid_until < now − clock_skew_secs` | `expired` | janitor |
| `pooled` (`source = outbox`) | our Odoo path landed / consumed it | `landed` / `consumed` | Odoo-path outcome sink (by digest) |
| any non-terminal | the subject nonce is seen consumed while scheduling | `consumed` | scheduler |

A row that ends `failed` is **deleted** (not kept for retention), so a later honest copy of the same `intent_id`
from another source can still be ingested (a bad re-originated copy cannot censor the intent, review H1). In its
place a **tombstone** is kept until `valid_until + clock_skew_secs`:

```sql
CREATE TABLE tombstone (intent_id BLOB NOT NULL, body_hash BLOB NOT NULL, expires_at INTEGER NOT NULL,
                        PRIMARY KEY (intent_id, body_hash));
```

L1 skips an envelope whose `(intent_id, body_hash)` is tombstoned (no re-simulation every poll while it sits in a
peer's overlap window, review N3); a copy with a different `body_hash` — the honest one — is still evaluated. The
janitor deletes expired tombstones. The
UD §22.1 names map as: `pooled` = `POOLED`+`FORWARDING`; `submittable`/`submitting` = `SUBMITTABLE`/`SIMULATED`;
`broadcast`; `landed`; `consumed` + kind = `LANDED_ELSEWHERE` / `SUPERSEDED` / unknown; `failed` = `REJECTED` after
L4; `expired`. Rejected intents (L0–L3) are never written (§05 §5.5 point 4) and not cached: an honest copy that
arrives later is always evaluated.

Retention (janitor, every 60 s):

1. `pooled`/`submittable` with `valid_until < now − clock_skew_secs` ⇒ `expired`.
2. `submitting` rows older than 60 s with no `tx_hash` ⇒ `submittable` (lost hand-off). `broadcast` rows are left
   to the submit path (it owns the outer nonce, R18).
3. `DELETE` terminal rows with `updated_at < now − retention_secs` (24 h, UD §22.9a).
4. Row count ≥ `max_rows` ⇒ new ingests fail with `STORE_FULL` (metric), nothing is evicted.

`peer_cursor` rows of peers no longer in the table are deleted at the next config refresh.

---

## 7. Acceptance policy

### 7.1 Table shape

One row per `(chain, contract, selector)` (UD §22.4 merges §21.4's matrix and §06.3.3's `blockchain.target.policy`):

| Column | Type | Meaning |
|---|---|---|
| `chain_key` | text | |
| `contract` | text | `token_of` (§4.4: the token itself; never a per-payer account) as canonical address, or `*` |
| `selector` | text | EVM: first 4 bytes of `meta_tx.data` as `0x` + 8 hex, `0x` for empty data, or `*`; other families: `pay` or `*` (v1, M6) |
| `support` | enum | `none` ⇒ reject `UNSUPPORTED`; `forward_only` ⇒ hold and serve, never submit; `full` |
| `submit` | bool | this node submits for this row (requires `support = full`, a concrete registered contract, a lane for the chain) |
| `pool_visibility` | enum | `open` \| `private` \| `none` (hold, never serve) |
| `min_fee` | uint256 | floor compared with the **effective** fee (R86); non-EVM intents have fee 0, so `submit` on non-EVM needs `min_fee = 0` |
| `fee_recipient_allow` | enum | `any` \| `self_or_zero`; only consulted when the intent **binds** `feeRecipient` (`MODE_RESTRICT_FEE_RECIPIENT`), since unbound recipients are normalized (R84) |

Lookup order (most specific wins, no merging): `(contract, selector)`, `(contract, *)`, `(*, selector)`, `(*, *)`.
**No matching row ⇒ `forward_only` with `pool_visibility` derived from the chain profile** (owner-confirmed) — default
deny for submission (§06 §06.3.3), routing kept (UD §21.1). Every column is static data; nothing in the table calls
out (UD §21.4 "evaluable before simulation").

### 7.2 Evaluation order (no RPC before L4)

```
accept(env, source, peer?) -> Result<Row, Code>          // mesh/accept.rs, pure except store + clock
  L0  size ≤ 32 KiB, JSON object, spec major == 1 and minor ≥ 2, family supported, chain_key known
      (in [[chains]] or in any policy row), fields well-formed, body canonicalizable (§4.2)
                                                       → BAD_ENVELOPE / UNSUPPORTED_SPEC / FAMILY_NOT_SUPPORTED /
                                                         UNKNOWN_CHAIN
  L1  source == peer: hop = env.hop_count + 1 ≤ max_hops                            → HOP_LIMIT
      intent_id already a row in the store, or (intent_id, body_hash) tombstoned    → DUPLICATE (no-op)
      peer rate: token bucket peer_intents_per_sec                                  → RATE_LIMITED (the puller stops
                                                                                       the page there; the cursor
                                                                                       does not pass the item)
  L2  decode (§4.4): recompute intent_id, decode from/lane/nonce/valid_until/relayer → DIGEST_MISMATCH / BAD_ENVELOPE
      valid_until > now + clock_skew_secs                                           → EXPIRED
      valid_until ≤ now + max_valid_for_secs                                        → VALID_TOO_LONG
      EVM mode/relayer/sig checks (§4.4)                                            → RELAYER_BOUND_ZERO / BAD_SIGNATURE
      hub: sha256(prefix‖pubkey) == hub.id, Ed25519 verify(hub_msg incl. body_hash) → BAD_HUB_SIG
      hub.published_at ≤ now + clock_skew_secs (a past value only means an expired exclusive) → BAD_ENVELOPE
  L3  private = env.visibility == private OR chain_profile(chain_key) == private
      source == peer AND private AND peer.class == open                             → PRIVATE_FROM_OPEN_PEER
      policy = lookup(chain_key, token_of, selector); support == none               → UNSUPPORTED
      visibility = strictest(env.visibility, policy.pool_visibility, chain_profile) (§9)
      may_submit = support == full && submit && token_of ∈ registered tokens
                   && account-derivation check passes (R86, §4.4)
                   && we have a lane for chain_key && relayer_ok && fee_ok && source != outbox
        relayer_ok: relayer unbound (EVM RESTRICT bit off / non-EVM decoded relayer zero), or the decoded relayer
                    equals one of our lanes' canonical addresses (adapter.lanes()[i].address, R61 — not the
                    `pk:<hex>` log label)
        fee_ok:     EVM — fee_effective (FeePolicy.compute) ≥ min_fee && (feeRecipient unbound
                    || fee_recipient_allow == any || feeRecipient ∈ {0, fee_recipient}); others — min_fee == 0
  decide (§7.3) and INSERT (from_block = cached head of the chain, or NULL when the node has no RPC for it)
```

L4 (RPC) happens only on the submit path (§8.4): simulation, `metaTxDigest(m) == intent_id` on EVM, consumption
check. L5 (`debug_traceCall`) is not used.

### 7.3 Forward vs submit vs reject

| Outcome | Condition | Store |
|---|---|---|
| reject | any L0–L3 code | not written; counted |
| hold + serve | accepted, `!may_submit` | `pooled`, served if visibility ≠ none and §9 allows |
| hold, submit later | `may_submit` and a valid `exclusive` for another peer still running | `pooled`, `exclusive_until` set |
| submit now | `may_submit` and (no exclusive, or exclusive to self, or exclusive expired) | `submittable` |

Submit and serve are not exclusive: a `submittable`/`submitting`/`broadcast` row is still served (if visible), so the
network keeps the intent if this node dies (UD §21.4 algorithm: "still forward, but with `exclusive_until`").

---

## 8. Exclusivity, submit, cancel and dedup

### 8.1 Sources

| Source | Origin of envelope | Exclusive | Who submits |
|---|---|---|---|
| `gateway` (door A, `POST /v1/metatx`, EVM only) | this node signs `hub` | round-robin (§8.2) when bus-eligible | assignee, then anyone after `until` |
| `outbox` (Odoo job of an opted-in company, R73) | this node signs `hub` | **none** | this node via the Odoo outbox (unchanged path); peers immediately |
| `peer` | as received | as received (clamped) | per §7.3 |

Bus-eligible = `pool_visibility ≠ none` after §9 and not relayer-bound to one of our lanes. A gateway intent that is
not bus-eligible is still written to the store with `visibility = 2` (durable, R71) and submitted locally.

When outbox publication hits a `DUPLICATE` (the same digest already arrived from a peer, e.g. the payer's wallet also
posted it elsewhere), the existing row is flipped to `may_submit = 0, source = 'outbox', odoo_job_id = …`: the Odoo
path owns it from then on (review H6).

### 8.2 Assignment (origin only, R74)

```
eligible(chain_key, contract, selector, visibility) =
      sorted_by_peer_id( {self if local policy may_submit}            # contract below = token_of (§4.4)
                       ∪ {p ∈ active peers : p.policy (cached /v1/mesh/policy) lists (chain_key, contract|*, selector|*)
                                              with submit, and may_export(visibility, p)} )
assignee = eligible[rr[chain_key] % len]; rr[chain_key] += 1        # in memory; reset on restart is harmless
exclusive = {relayer_id: assignee, until: published_at + exclusive_ms/1000}   # omitted when eligible is empty
```

Receivers honor `exclusive` only if `hub.sig` verified and `0 < until − published_at ≤ exclusive_ms/1000` of the
**receiver's** config; otherwise they store `exclusive_until = NULL` (clamp, vector 24).

### 8.3 Scheduler (every 250 ms, `mesh/sched.rs`)

```
for row in pooled where may_submit and (exclusive_until IS NULL or now ≥ exclusive_until + jitter(row)):
    CAS pooled → submittable
for row in submittable (oldest first):
    guard = inflight[chain_key].try_acquire(intent_id) else continue   # §8.4, shared with the Odoo path
    CAS submittable → submitting; try_send Work{origin: Mesh(intent_id), guard, …} to the chain's lane channel
    send failed ⇒ CAS submitting → submittable (dropping the guard releases the digest)
jitter(row) = u16(first 2 bytes of sha256(intent_id ‖ self.peer_id)) mod post_exclusive_jitter_ms   # differs per node
```

`exclusive_self` rows go straight to `submittable`. EVM mesh work uses the same `mpsc::Sender<Work>` as the gateway
(lane 0 today, `main.rs`); non-EVM mesh work uses a new per-chain channel read by `lane_runner` after `relay_poll`
finds nothing.

### 8.4 Submit path changes (shared with the Odoo outbox path)

`bamboo-node/src/submit.rs`:

```rust
pub enum Origin { Odoo(i64), Mesh([u8; 32]), Gateway([u8; 32]) }   // Gateway = door A without mesh (no store)
pub struct MetaRef { pub token: Address, pub from: Address, pub batch: U256, pub nonce: U256, pub digest: B256 }
pub struct Work { pub origin: Origin, pub to: Address, pub data: Bytes, pub valid_until: u64,
                  pub meta: Option<MetaRef> }                      // None for `call` jobs
struct Sent { work: Option<Work>, hashes: Vec<B256>, gas: u64, fees: (u128, u128), at: Instant }
pub type Inflight = Arc<Mutex<HashSet<B256>>>;                     // one per chain, all lanes + mesh scheduler
```

`job_id: Option<i64>` is replaced by `origin`; `work_from_job` fills `meta` for `kind = metatx`. Outcome sink per
origin: `Odoo` ⇒ `relay_report` as today **and** CAS the store row with that digest (if any, `source = outbox`) to
the same outcome, so we stop serving an intent we landed (review L8); `Mesh` ⇒ store transition (§6 table); `Gateway`
⇒ log only. Transient errors, gas over `max_gas_per_tx`, expiry in the channel and the `retry` queue all produce an
outcome for every origin (today `requeue()`/`fail()` do nothing without a `job_id`, `submit.rs` l.247–259).

**In-flight digest set (G2).** Members: every EVM `Submitter` lane, the gateway, the mesh scheduler **and every
non-EVM `lane_runner`/`step_once`** (`adapter.rs` l.161, l.335) of the chain. Lifecycle is an RAII guard, so no exit
can leak a digest:

```rust
impl Inflight { pub fn try_acquire(&self, d: B256) -> Option<InflightGuard> }   // None = already in flight
impl Drop for InflightGuard { fn drop(&mut self) { /* remove d */ } }
```

- The guard travels inside `Work` / the lane's job and is moved into `Sent` when a tx is broadcast; it is dropped when
  `Sent` is removed (terminal receipt, consumption, gap-fill settled).
- Every exit that leaves no `Sent` behind drops it: transient simulate/fee error (`requeue`), simulate revert (`dead`
  or `consumed`), journal-write retry (the `retry` queue keeps the guard; a dropped retry drops it), breaker open,
  expiry, channel send failure.
- **Odoo path avoids churn**: `poll_outbox`/`step_once` read `job.digest` from the `relay_poll` payload
  (`blockchain_relay_job.py` `_payload`, present for `metatx` and `signed_op`) and skip a job whose digest is in
  flight **before** `relay_claim` — no claim, no `queued` report, no `attempt_count` growth. Only if the digest
  enters the set between poll and claim does the path report `queued` once ("in flight on another path").
- Restart rebuilds the set from tracked entries (§8.6).

**Normalization (R84).** For every origin except `Odoo` (Odoo builds `fee = 0`, `feeRecipient = 0` itself), the
meta-tx has `feeRecipient := chains.fee_recipient or 0` when `mode & MODE_RESTRICT_FEE_RECIPIENT == 0`, and
`relayer := 0` when `mode & MODE_RESTRICT_RELAYER == 0`. `metatx.rs` gets
`pub fn normalize(m: &mut MetaTransaction, fee_recipient: Option<Address>)`. It is called **once, where the
`Work`/`Job` is built from a gateway request or an envelope** (`gateway.rs` `post_metatx`, `mesh` work builder), not in
`submit.rs`, so Hedera mesh work — which runs through `lane_runner` → `adapters/hedera.rs` `build` from a synthesized
`Job` — gets it too (review N8).

`submit(w)` (L4), in order:

1. `valid_until ≤ now` ⇒ `expired`.
2. Mesh origin, first attempt: `eth_call token.metaTxDigest(m)` must equal `intent_id` ⇒ else `failed`
   (`DIGEST_MISMATCH`: the envelope's `domain` lied).
3. Simulate (existing). On `SimError::Revert`: if `meta` is set, read `metaNonce(from, batch)`; `> nonce` ⇒
   **consumed** (§8.5 classification), else `failed`/`dead` as today. A failed `metaNonce` read ⇒ transient (requeue).
4. Journal before send: Odoo `signed` (existing) **or** store `UPDATE intent SET lane_label, outer_nonce, tx_hash`
   (mesh). Journal write fails ⇒ do not send, do not consume the nonce (review I5 rule, unchanged).
5. Send; `broadcast`.

Receipt handling (`track()`, `submit.rs` l.280–292) — **reverted receipt** with `meta` set: read `metaNonce`; consumed ⇒
classify and report `consumed` (never `reverted`, which in Odoo sets business `failed` and fires
`_fail_dependents()` in `blockchain_subject_account.py` l.459); read failed ⇒ keep the entry and retry next round.

`track()` — the R80 fix for stuck txs. `chain.nonce_at(lane, latest)` is **new** in `chain.rs`
(`get_transaction_count(addr).latest()`; today only `pending_nonce()` exists). For each in-flight outer nonce `n`
whose newest hash has no receipt:

```
if any receipt among s.hashes:                       # an EARLIER hash of ours mined (today: missed, retried forever)
    settle from that receipt (reverted ⇒ consumption check above); remove; continue
if not stuck (elapsed < stuck_after_secs): continue
count = chain.nonce_at(lane, latest)        ; on RPC error: no bump this round, continue   (fail closed)
if count > n:                                         # outer nonce used by a tx we no longer track
    remove; if meta: classify (§8.5); continue
if s.work.meta is Some(m):
    v = metaNonce(m.from, m.batch)          ; on RPC error: no bump this round, continue   (fail closed)
    if v > m.nonce:                                   # consumed — before EVERY bump
        classify (§8.5); report consumed
        replace at n with the gap-filler (self-send, 21 000 gas) at bumped fees   # never the meta-tx again (R18)
        keep tracking n until the gap-filler mines; continue
existing logic: live ⇒ bump the meta-tx; expired ⇒ gap-filler + dead
```

At the fee cap the existing wait branch (`submit.rs` l.301–311) also applies to the gap-filler: a same-fee
replacement is rejected as underpriced, so the consumed meta-tx is simply left to mine and revert (cost ≈ 24–30 k gas).

`bamboo-node/src/adapter.rs` (non-EVM lane runner, and Hedera):

- `ChainAdapter` gains `async fn op_consumed(&self, job: &Job) -> Result<Option<bool>>` (default `Ok(None)`), taking
  the `Job` so Hedera (`metatx` jobs) is served too. `Some(true)` iff the lane nonce has moved past the op's nonce;
  `Ok(None)` (unknown ⇒ never stop on it) for every op kind whose replay guard is not the lane nonce (M6): v1 answers
  only for `pay` (Cosmos `QueryMsg::Nonce`, Sui `lane_nonce`, Aptos view `lane_nonce`, TON `get_lane_nonce`, Solana
  `LanePda.next`, absent ⇒ 0) and Hedera `metaNonce`. TON revoke would be `next > nonce + 1`; not needed in v1.
- `step_once`: on `SimError::Revert`, call `op_consumed`; `Some(true)` ⇒ report `consumed`, not `dead`.
- `follow()`: on `TxStatus::Reverted`, call `op_consumed`; `Some(true)` ⇒ `consumed`, not `reverted`. Before every
  resend (`sent.is_err()` branch) call `op_consumed`; `Some(true)` ⇒ report `consumed`, stop resending, keep following
  the tx until its status is terminal or `valid_until + EXPIRY_GRACE`. RPC error ⇒ no resend this round.
- `Built`/`Signed` carry `origin: Origin` instead of `job_id: i64`; reports go to the outcome sink.

### 8.5 Classification after consumption

| Family | How | Result |
|---|---|---|
| EVM/Hedera | `eth_getLogs` on `token`, topic0 `MetaTransactionExecuted`, topic1 `from`, topic3 `batch`, from the row's `from_block` (mesh) or the block at job claim (Odoo; kept in memory with the `Sent`) to `latest`; pick the log with `nonce == m.nonce` | `digest == intent_id` and `relayer` ∈ our lanes ⇒ `landed` (an earlier hash of ours); `digest == intent_id` otherwise ⇒ `landed_elsewhere`; different digest ⇒ `superseded`; no log yet (lagging RPC) ⇒ `unknown` |
| others | `unknown` in v1 (the adapter `events()` scan is per block range and belongs to the indexer) | Odoo resolves at finality via `_mark_executed` (§10.3) |

After `valid_until` the subject nonce of TON/Solana/Aptos lanes may be pruned and read as 0; consumption checks are
only made while `now ≤ valid_until + clock_skew_secs`, and expiry decides after that.

### 8.6 Restart

- EVM cold start (`nonce.rs` `plan`): **non-terminal** store rows (`submitting`/`broadcast`) with an `outer_nonce` for
  this lane are fed into `plan()` as `Inflight` entries keyed by `Origin::Mesh`; terminal rows (`landed`, `consumed`,
  `failed`, `expired`) contribute their `outer_nonce` only to `journal_max` (a `consumed` row whose gap-filler was
  unmined at the crash must not return to `submittable`; `plan()` gap-fills its nonce like any journaled nonce
  ≥ `pending`). Non-terminal rows follow exactly the rules of Odoo rows: `outer_nonce < pending` ⇒ tracked
  (no re-sign); otherwise ⇒ the nonce is gap-filled and the row goes back to `submittable` (re-signed later at a new
  nonce; if the original tx still lands, the re-signed one reverts and is classified `landed`). `journal_max = max(Odoo
  journal_max_nonce, store max(outer_nonce))`. Store rows `submitting` without `tx_hash` ⇒ `submittable`. This closes
  the R16 hole for mesh/gateway work.
- The in-flight digest set is rebuilt from tracked entries.
- Non-EVM: `recover_lane` also walks store rows of its lane (same rules as Odoo in-flight jobs).
- Puller cursors come from `peer_cursor`; served intents survive restart.

### 8.7 What is guaranteed

Hard (enforced by code or chain):

- **G1** — The contract executes an intent at most once: the per-subject nonce must equal `m.nonce` and is
  incremented on execution (§4.1). A payer never pays twice, whatever the relayers do.
- **G2** — Our node holds **at most one live outer tx per intent**: the per-chain in-flight digest set is shared by
  every Submitter lane, the gateway and the mesh scheduler; store CAS and Odoo `relay_claim` admit one `Work` per path.
  (A restart may re-sign an intent at a new nonce after its old nonce was gap-filled, §8.6; the old tx is then dead.)
- **G3** — After a node observes consumption (simulation revert, reverted receipt, or the pre-bump/pre-resend
  re-check) it never broadcasts, resends or bumps that meta-tx again; on EVM the outer nonce is released by a
  gap-filler only (R18). An unreadable nonce never leads to a bump (fail closed).
- **G4** — No outer nonce is abandoned (R18, unchanged), now also for mesh/gateway work (store journal, §8.6).
- **G5** — A private-chain intent is served only by its origin and only to private peers that origin admitted for
  that chain (§9, R85).
- **G6** — A job of ours is never reported `dead`/`reverted` because another relayer executed it; it becomes
  `consumed`, then `final` (indexer) or `dead` only if superseded (§10.3).
- **G7** — We never submit wire values of `relayer`/`feeRecipient` that the signer left unbound (R84).

Best effort (not enforceable; bounded):

- **B1** — During `exclusive`, only the assignee submits **if every admitted peer honors it**. A peer that ignores it
  is detectable after the fact (its outer tx lands or reverts inside another peer's window; metric
  `bamboo_mesh_exclusive_violations_total`) and is handled by suspending its peer row.
- **B2** — After `until`, several eligible peers may submit; jitter spreads them over `post_exclusive_jitter_ms`, but a
  chain with 5 s blocks will still see overlaps. Each loser pays one reverted outer tx: the token checks the nonce
  before the signature (`ERC20MetaTx` steps 1–4), about 24–30 k gas on EVM (§05 §5.4.2).
- **B3** — An `outbox` intent published after the private window can be submitted by a peer while our node also claims
  it from Odoo. Same bound as B2; the Odoo job becomes `consumed` → `final` (landed elsewhere), never `dead`.
- **B4** — A node does not learn that a peer landed an intent before it acts on it (no receipt gossip in v1); it learns
  when it simulates or re-checks. Cost: that one simulation.

"Never double broadcast" therefore holds per node (G2, G3), and holds network-wide only as B1.

---

## 9. Private profile rules

```
chain_visibility(chain) = private if chain_profile == 'private' else open
effective(row) = strictest(env.visibility, policy.pool_visibility, chain_visibility)   # none > private > open

may_export(row, peer) =
      row.visibility == open    and peer.active and (peer.chains empty or row.chain_key ∈ peer.chains)
                                and not (peer.class == open and chain_profile(row.chain_key) == private)
   or row.visibility == private and row.source != 'peer'                                # R85: origin only
                                and peer.active and peer.class == private and row.chain_key ∈ peer.chains
```

Rules:

1. `may_export` is the **only** function that decides what leaves the node; the list route and the `/policy` chain list
   both call it. One unit test per branch (incl. "private row received from a peer is never re-served"); one e2e
   (§13.3 E5).
2. Visibility is monotone: it can only get stricter at each hop, and the origin's choice is signed (§4.5).
3. `chain_profile = private` forces `pool_visibility ∈ {private, none}` (Odoo constraints on both the policy and the
   chain write, §10.2, and a node check when loading toml). There is no promote path, so never_public holds by
   construction.
4. A private-chain intent from an `open` peer — labelled private **or** belonging to a chain we hold as private — is
   rejected (`PRIVATE_FROM_OPEN_PEER`) and counted; the peer is misconfigured or leaking and the operator must see it.
5. Logs never contain `data`, `payload`, amounts or counterparties of a private intent: `tracing` fields are
   `intent_id`, `chain_key`, `state`, `code`, `peer` only.
6. A private peer is still a peer: private-class peers also receive open intents.

---

## 10. Odoo side (`dms_blockchain`, `dms_blockchain_payment`)

Service methods follow CLAUDE.md §6: public names, no `@api.private`, `check_service()` group gate then `sudo()`, no
`company_id` taken from the client. All are reachable as `POST /json/2/<model>/<method>` (the node uses `/json/2`, R6)
and `call_kw`. Split for delivery: **S1a** = §10.3 (needed by the R80 fix), **S1b** = §10.1, §10.2, §10.4, §10.5.

### 10.1 `blockchain.chain` — new field (S1b)

```python
chain_profile = fields.Selection([('public', 'Public'), ('private', 'Private / permissioned')],
                                 required=True, default='private', index=True, tracking=True,
                                 help='Private: intents of this chain only travel between private mesh peers and '
                                      'are never published to open peers (R76).')
```

`_node_config()` adds `'chain_profile': self.chain_profile`. `write()` re-checks the policy constraint of §10.2 when
`chain_profile` changes to `private` (a stored compute on the policy does not fire the policy's own constraint).

**Upgrade (L2).** `data/blockchain_chain_data.xml` is `noupdate="1"`, so editing it does not reach existing
databases, and every existing chain becomes `private` on upgrade. Ship a post-migration script
`dms_blockchain/migrations/19.0.1.1.0/post-migrate.py` that sets `chain_profile = 'public'` on chains whose
`is_dev_chain` is false and whose `family`/number is a known public network (Gnosis 100, Celo 42220, Hedera 295…),
and bump the manifest version. Liveness only: an unmigrated chain is private, never leaked.

### 10.2 `blockchain.target.policy` and `blockchain.mesh.peer` — new models (S1b)

```python
class BlockchainTargetPolicy(models.Model):
    _name = 'blockchain.target.policy'
    _description = 'Mesh acceptance policy: chain + contract + selector'
    _order = 'chain_id, contract_address, selector'

    chain_id = fields.Many2one('blockchain.chain', required=True, index=True, ondelete='cascade')
    contract_address = fields.Char(required=True, default='*', help="Canonical address of the family, or '*'.")
    selector = fields.Char(required=True, default='*',
                           help="EVM: 0x + 8 hex of the meta-tx data, '0x' for empty data, '*'. "
                                "Other families: 'pay' or '*' (v1).")
    support = fields.Selection([('none', 'Reject'), ('forward_only', 'Forward only'), ('full', 'Full')],
                               required=True, default='forward_only')
    submit = fields.Boolean()
    pool_visibility = fields.Selection([('open', 'Open'), ('private', 'Private'), ('none', 'Not served')],
                                       compute='_compute_pool_visibility', store=True, readonly=False,
                                       required=True)
    min_fee_base = fields.Char(required=True, default='0')
    fee_recipient_allow = fields.Selection([('any', 'Any'), ('self_or_zero', 'Our fee wallet or zero')],
                                           required=True, default='any')
    active = fields.Boolean(default=True)

    _uniq = models.Constraint('UNIQUE(chain_id, contract_address, selector)',
                              'One policy per chain, contract and selector.')
    _min_fee_uint = models.Constraint("CHECK(min_fee_base ~ '^(0|[1-9][0-9]{0,77})$')", 'min_fee is a uint256.')
    _submit_needs_full = models.Constraint("CHECK(NOT submit OR support = 'full')", 'Only a full row submits.')
    _submit_needs_contract = models.Constraint("CHECK(NOT submit OR contract_address <> '*')",
                                               'Submission is per registered token, never for any contract.')
```

- `_compute_pool_visibility`: keeps an existing value; only when unset, `private` if `chain_id.chain_profile ==
  'private'` else `open`.
- `@api.constrains`: private chain ⇒ `pool_visibility != 'open'` (R76); `contract_address != '*'` ⇒ canonical via
  `chain_id._canonical_address` (stored canonical); `submit` ⇒ the contract is an active `blockchain.token` of the
  chain (R86; for Sui/Aptos/TON/Solana the column holds `token_of` — registry, asset or jetton master — never a
  per-payer account, §4.4); selector format by family (EVM regex `^(0x[0-9a-f]{8}|0x|\*)$`; others `pay` or `*`).
- No `company_id`: like `blockchain.chain` and `blockchain.token`, it is platform configuration of the node. The risk
  columns of §06 §06.3.3 (`risk_class`, `daily_call_cap`, `quarantined`) are not added (no consumer in v1).

`blockchain.mesh.peer` replaces the `blockchain.intent.hub` of §05 §5.1.2 and is separate from the address-based
`blockchain.relayer` registry of §10 §10.4.5 (which stays unbuilt: v1 identifies peers by SPKI, not by EVM address):

```python
class BlockchainMeshPeer(models.Model):
    _name = 'blockchain.mesh.peer'
    _description = 'Mesh peer (mTLS, pinned key)'
    _inherit = ['mail.thread']

    name = fields.Char(required=True, tracking=True)
    url = fields.Char(required=True, tracking=True, help='https://host:port of its /v1/mesh API.')
    spki_sha256 = fields.Char(required=True, tracking=True, string='Key pin (SPKI SHA-256)')
    peer_class = fields.Selection([('open', 'Open'), ('private', 'Private')], required=True, default='open',
                                  tracking=True)
    chain_ids = fields.Many2many('blockchain.chain', string='Chains',
                                 help='Private peer: chains it may receive (required). Open peer: optional filter.')
    state = fields.Selection([('draft', 'Draft'), ('active', 'Active'), ('suspended', 'Suspended')],
                             default='draft', required=True, tracking=True, index=True)

    _pin_uniq = models.Constraint('UNIQUE(spki_sha256)', 'One row per peer key.')
    _pin_format = models.Constraint("CHECK(spki_sha256 ~ '^[0-9a-f]{64}$')", 'The pin is 64 lowercase hex.')
```

Constraints: `url` must parse as `https://host[:port]` with no userinfo, path, query or fragment (the node never dials
anything else, §11 T8); `peer_class = 'private'` ⇒ `chain_ids` not empty; an `open` peer may not list a private
chain. No private-IP check on `url`: private peers usually live in a VPC, and the URL is admin data, never taken from
the network. Per-peer counters live in the node's `/metrics` only (no Odoo counter fields, no `mesh_report` in v1).

Service method (group `relay_worker`), refreshed by the node every 60 s:

```python
@api.model
def mesh_config(self):
    """POST /json/2/blockchain.mesh.peer/mesh_config — peers, policies and chain profiles (R79).
    No arguments: everything is platform configuration."""
    check_service(self.env, 'relay_worker')
    return self.sudo()._mesh_config()
# returns {'peers': [{name, url, spki_sha256, peer_class, chains: [chain_key], state}],   # active only
#          'policies': [{chain_key, contract, selector, support, submit, pool_visibility, min_fee,
#                        fee_recipient_allow}],                                          # active only
#          'chains': [{chain_key, chain_profile}]}
```

### 10.3 Consumption and `landed_elsewhere` (S1a — ships with the R80 fix)

`blockchain.relay.job`:

```python
CHAIN_STATES += [('consumed', 'Consumed (nonce used elsewhere)')]
TRANSITIONS['nonce_leased'] |= {'consumed'}
TRANSITIONS['signed'] |= {'consumed'}
TRANSITIONS['broadcast'] |= {'consumed'}
# 'mined' is NOT extended: no path reports 'consumed' after a successful receipt (the lost-race revert happens in
# 'broadcast'), and a job our own tx executed must never become 'consumed' and then 'dead' by the expiry cron.
# From 'consumed' only the indexer (final) and the expiry cron (dead) move a job. A late report
# ('mined'/'reverted'/'consumed') for a consumed job is accepted as a no-op, not a UserError.

landed_elsewhere = fields.Boolean(readonly=True, copy=False,
                                  help='Executed on chain by a transaction this node did not send.')
```

- `_apply_report('consumed')`: sets `last_error = 'nonce consumed: <kind>'`, keeps `business_state = 'pending'`; does
  **not** touch `metatx_state`/`op_state`. `FAILED_STATES` in `blockchain_subject_account.py` (l.35) stays
  `('dead', 'reverted')`, so `_fail_dependents()` never fires for `consumed`.
- `_cron_expire`: also moves `consumed` jobs to `dead`/`failed` when `valid_until < now − _EXPIRY_GRACE − 3600` and no
  final event arrived (the subject nonce was spent by another digest: superseded). The extra hour covers finality lag;
  "`final` wins `dead`" (existing comment) still applies if a late event arrives.
- Server-only fields (L4, N4): `create` **always** sets `landed_elsewhere = False` and
  `mesh_published_datetime = False` explicitly in every `vals` (an explicit value beats a `default_*` context key,
  which `super().create()` would otherwise apply — also under `sudo()`, which the portal flows use); `write` strips
  both unless `self.env.su` (service methods run under `sudo()`). No context key is consulted. A pre-set
  `mesh_published_datetime` would silently block publication, so this matters for liveness too.

`blockchain.chain.event`: new `relayer_address = fields.Char()` filled by `chain_event_ingest` from the event's
`relayer` when present (EVM already sends it: `indexer.rs` l.49; other families send nothing in v1).

`_mark_executed(tx_hash, relayer=None)` on `blockchain.metatx` and `blockchain.signed.op`: for each job,
`landed_elsewhere = not ((relayer and relayer == job.signer_address) or (not relayer and tx_hash == job.tx_hash))`,
then `final`/`success` as today (also from `consumed`). A job that was never claimed is `landed_elsewhere = True`.

### 10.4 Company setting (R73, S1b)

`res.company` (in `dms_blockchain`, `depends` stays `base, mail`):

```python
blockchain_bus_scope = fields.Selection(
    [('restricted', 'Company relayer only'), ('open', 'Mesh after private window')],
    default='restricted', required=True,
    help='Restricted (default, R10): payments are pinned to the company relayer and never published. '
         'Open: payers sign without a relayer; a job still waiting after the private window is offered '
         'to admitted mesh peers, who learn payer, payee, amount and time.')
blockchain_bus_private_window_secs = fields.Integer(default=120)
```

Exposed in `res.config.settings` (related fields), editable by `group_blockchain_manager`.
`dms_blockchain_payment/models/payment_transaction.py` (l.47, `_chain_start`, which also serves the custodial
autopay path) passes `relayer_address = None` instead of `provider.chain_relayer_address` when
`company.blockchain_bus_scope == 'open'`. The mandate path (`blockchain_autopay.py` l.267) builds `call` jobs, which
never reach the bus.

### 10.5 Outbox publication (S1b)

```python
mesh_published_datetime = fields.Datetime(readonly=True, copy=False)     # on blockchain.relay.job

@api.model
def mesh_publish_claim(self, chain, limit=20):
    """POST /json/2/blockchain.relay.job/mesh_publish_claim — outbox jobs to publish on the bus (R73).
    `chain` = EIP-155 number or chain_key (same as `_by_number`). Picks `queued` jobs of companies with bus scope
    'open', older than their private window, not relayer-bound, not yet published; stamps mesh_published_datetime
    under FOR UPDATE SKIP LOCKED (same pattern as relay_claim).
    Returns [{'job': job._payload(), 'chain_profile': chain.chain_profile}]."""
```

Eligibility in `_mesh_publishable_domain(chain)` + a Python filter: `job_kind = 'metatx'` with
`mode_flags & MODE_RESTRICT_RELAYER == 0`, or `job_kind = 'signed_op'` with `op_kind = 'pay'` and no relayer bound in
the op (the implementer checks each `fam_*.build_terms` for where the relayer lives); `create_date + window ≤ now`;
chain `active`; chain family in R77.

### 10.6 ACL and record rules

`ir.model.access.csv`:

```
access_target_policy_viewer,target policy viewer,model_blockchain_target_policy,group_blockchain_viewer,1,0,0,0
access_target_policy_manager,target policy manager,model_blockchain_target_policy,group_blockchain_manager,1,1,1,1
access_mesh_peer_viewer,mesh peer viewer,model_blockchain_mesh_peer,group_blockchain_viewer,1,0,0,0
access_mesh_peer_manager,mesh peer manager,model_blockchain_mesh_peer,group_blockchain_manager,1,1,1,1
```

No record rules on the two new models (no `company_id`, platform data — as `blockchain.chain`). Service accounts get no
ACL rows (existing pattern). Multi-company effects stay where company data is: `rule_relay_job_company` already limits
the new job fields to the job's company; the company setting is per company by construction. Views: list/form for both
models under the Blockchain configuration menu; `chain_profile` on the chain form; the two job fields on the job form.

No new cron: the node pulls `mesh_publish_claim`; `_cron_expire` is extended.

---

## 11. Security

| # | Threat | Mitigation |
|---|---|---|
| T1 | **Spam / flood** | handshake gate (unknown peers never reach HTTP); handshake timeout and connection semaphore against unauthenticated TCP; per-peer `peer_rps` on requests and `peer_intents_per_sec` on ingest (in-process token buckets — correct here because the node is one process; §05 §5.5's Redis objection was about Odoo workers); page row and byte caps; 32 KiB envelope cap; `max_valid_for_secs`; `max_rows` + `STORE_FULL`; nothing persisted before L2 passes; suspension of the peer row |
| T2 | **Replay** of an executed intent | contract nonce (G1); `valid_until`; dedup by `intent_id` |
| T3 | **Peer impersonation** | TLS 1.3 client auth: the peer proves possession of the pinned key (`CertificateVerify`); pins are exact SPKI hashes, no CA, no name check |
| T4 | **MITM on the client side** | server cert pinned per peer row; no fallback to WebPKI |
| T5 | **Intent tampering** | `intent_id` recomputed (L2); every meta-tx field under the subject's signature; non-EVM routing fields decoded from the signed payload; unsigned parts bound by `body_hash` in `hub.sig`; `hop_count` unsigned but bounded |
| T6 | **Censorship / exclusivity hijack** (a peer serves a poisoned copy first, or re-originates someone's intent with `exclusive` to itself) | no cache of rejections (a bad copy never blocks a good one); forwarders cannot alter a copy (`body_hash`); a re-originated bad copy fails simulation, its row is deleted and its `(intent_id, body_hash)` tombstoned (no re-simulation loop; the honest body is still evaluated); receivers clamp `until − published_at ≤ exclusive_ms`; violations metric; admission revocable |
| T7 | **Leak of private intents** | `may_export` single gate (§9); origin-only serving (R85); signed, monotone visibility; private-chain intents from open peers rejected; open peers never see private chains in `/policy`; logs carry no payload. **Accepted side channel:** the global `seq` lets an open peer see gaps between served items and so count our hidden rows and their timing (no `head` field, but gaps remain) |
| T8 | **SSRF** | the node dials only URLs from peer rows (Odoo admin or `node.toml`), never a URL from an envelope or a peer response; https only, no redirects; no callbacks (UD §22.9b stays) |
| T9 | **Parser attacks** | envelope decoder, canonical-body serializer and the new Cosmos `MetaOp` JSON decoder are fuzz targets (proptest, as R54 did for the gateway decoder): arbitrary bytes never panic, every rejection has a code; family decoders already have `decoders_never_panic` tests |
| T10 | **Downgrade of spec** | only `1.x, x ≥ 2` accepted; no guessing (§05 §5.2) |
| T11 | **Clock games** | `published_at` in the future beyond skew rejected; a past `published_at` only expires `exclusive` early; the clamp uses the receiver's `exclusive_ms`; chronyd requirement of §06 §06.12.9 applies to mesh nodes |
| T12 | **Fee theft and gas drain** | R84 normalization (fee of unbound intents goes to our wallet); R86: submit only for registered tokens, effective-fee comparison; simulation before send; the token checks nonce before signature so race losers pay little (§05 §5.4.2); no allowance in the fee path, so the approve-withdraw grief of §05 §5.5 does not apply |
| T13 | **Compromised peer key** | suspend the row: takes effect at the next `mesh_config` refresh (≤ 60 s) for new handshakes **and** for every request on open connections (per-request check), and connections are recycled every `max_conn_age_secs`; rotate by adding a new row |
| T14 | **Compromised node** | it holds no user funds and no subject keys; lane keys hold gas only (UD §21.5); the mesh key can only sign `hub.sig` and authenticate TLS |

---

## 12. Observability

Added to the admin `/metrics` (R51; `admin.rs` `render()` gets a `MeshStats` snapshot of atomic counters). These are
the only mesh counters in v1 (no Odoo copy).

| Metric | Type | Labels |
|---|---|---|
| `bamboo_mesh_ingest_total` | counter | `chain`, `source` (gateway\|outbox\|peer), `result` (accepted\|duplicate\|`<CODE>`) |
| `bamboo_mesh_store_rows` | gauge | `state` |
| `bamboo_mesh_peer_up` | gauge | `peer` (name) — last pull succeeded |
| `bamboo_mesh_peer_last_pull_seconds` | gauge | `peer` |
| `bamboo_mesh_peer_cursor_resets_total` | counter | `peer` (store_id changed) |
| `bamboo_mesh_served_total` | counter | `peer`, `route` |
| `bamboo_mesh_rate_limited_total` | counter | `peer`, `direction` (in\|out) |
| `bamboo_mesh_outcome_total` | counter | `chain`, `outcome` (landed\|landed_elsewhere\|superseded\|consumed_unknown\|failed\|expired) |
| `bamboo_mesh_exclusive_violations_total` | counter | `peer` |
| `bamboo_mesh_private_from_open_total` | counter | `peer` |
| `bamboo_submit_bump_skipped_consumed_total` | counter | `chain`, `lane` (R80; also for the Odoo path) |
| `bamboo_submit_inflight_dup_total` | counter | `chain` (a path found the digest already in flight, G2) |

`/readyz` adds a reason when `[mesh]` is on and the store is not open, or `mesh_config` was never fetched.
Odoo `relay_stats` already counts jobs by state, so `consumed` appears in `bamboo_relay_jobs` without change.

---

## 13. Test plan

Heavy runs (cargo e2e, Odoo tests) are one at a time (owner rule, OOM cap).

### 13.1 Unit (`cargo test`, no network)

- `gateway.rs` (S0): garbage `feeRecipient`/`relayer` with bits off ⇒ the `Work` calldata decodes to normalized
  fields (our fee wallet / 0, relayer 0); bound fields untouched; digest unchanged.
- `mesh/envelope.rs`: decode/encode round trip; unknown fields ignored; canonical body bytes; every L0 code; proptest
  fuzz (T9).
- `mesh/digest.rs`: `intent_id` and decoded fields per family against the vectors.
- `mesh/hubsig.rs`: `hub_msg` bytes golden; sign/verify; pubkey↔id check; PEM seed parsing.
- `mesh/accept.rs`: table-driven over §7.2 (each code) and §7.3 (each outcome); policy lookup order; no-row default;
  H1 (poisoned copy first, then the honest copy is accepted), H2 (old `published_at` accepted), H4 (unregistered
  contract, NONE-mode huge fee), M7 (relayer bound to our lane's canonical address), M9 (open label on a private chain).
- `mesh/export.rs`: `may_export` all branches (§9), including R85 (private row from a peer never served).
- `mesh/store.rs`: schema, every §6 transition, failed-row deletion + `(intent_id, body_hash)` tombstone (same body skipped, different body evaluated), UNIQUE dedup, retention, `max_rows`, seq order,
  cursor + `store_id` reset (temp file).
- `mesh/sched.rs`: exclusivity wait, deterministic jitter, round-robin set from cached peer policies, send failure
  returns the row to `submittable`.
- `mesh/tls.rs`: pin verifier accepts only the pinned SPKI; client verifier rejects another key; handshake with an
  unknown client fails; suspended peer on an open connection gets 403 (in-process, loopback).
- `config.rs`: `[odoo]` optional rules, `[mesh]` validation, private chain with `pool_visibility = open` refused,
  `submit` with `contract = "*"` refused.
- `submit.rs` (fake chain): R80 — consumed before bump ⇒ gap-filler, no meta-tx resend, `consumed`; `metaNonce` RPC
  error ⇒ no bump; earlier hash mined ⇒ settled from that receipt; simulate revert + consumed ⇒ `consumed` not `dead`;
  **reverted receipt + consumed ⇒ `consumed` not `reverted`** (H3); C1 normalization for mesh work; H6 — the same
  digest from `poll_outbox` and the mesh channel ⇒ one signature; outcome for every origin on transient errors.
- `adapter.rs` (fake adapter + fake Odoo): `op_consumed = Some(true)` on resend ⇒ `consumed`, no resend, lane released
  after terminal status; `TxStatus::Reverted` + consumed ⇒ `consumed`; `op_consumed = None` for non-`pay` ops never
  stops a job.
- `nonce.rs`: `plan` with non-terminal store rows (below/above `pending`); terminal rows only raise `journal_max`.
- `Inflight` guard (N2): every exit path of `submit()`/`step_once` without a `Sent` releases the digest; an Odoo job
  whose digest is in flight is skipped before `relay_claim` (no claim, no report); a non-EVM lane and an EVM lane
  never both sign one digest.
- `mesh/digest.rs`: `token_of` and the account-derivation check per family (N1); Cosmos JSON decoder fuzzed (N9).
- `gateway.rs`: `GET /v1/intents/{id}` answers 404 for `peer`/`outbox` rows (N12).

### 13.2 Conformance

`tests/mesh_vectors.rs` runs all §4.6 cases through `accept()` and the normalizer; the Odoo copy is checked by
`dms_blockchain/tests/test_mesh_vectors.py`; CI `cmp`s the two files.

### 13.3 Multi-node e2e (`tests/e2e_mesh.rs`, `--ignored`, anvil + forge + fake Odoo)

Topology: one anvil, contracts deployed as in `tests/e2e.rs`; nodes A, B, C started as **separate processes** of the
built binary (`env!("CARGO_BIN_EXE_bamboo-node")`) with generated configs and temp SQLite files; self-signed Ed25519
certs generated by the test with `openssl` (skip with a clear message if absent). Fake Odoo (axum) serves
`mesh_config`, `relay_poll`/`claim`/`report`, `mesh_publish_claim`, `node_config`, records calls.
Each scenario asserts chain state (balances, `metaNonce`) and store/Odoo states.

| # | Scenario | Pass when |
|---|---|---|
| E1 | **Forward**: A (gateway, `forward_only` for the token) receives a meta-tx with garbage unbound `feeRecipient`; B (`full`, submit) pulls and lands it | one outer tx on chain, from B; the fee lands in **B's** configured fee wallet (R84); B's row `landed`; A's row stays `pooled` until `valid_until`, then `expired` (A never submits) |
| E2 | **Dedup**: A and C both serve the same intent to B (C pulled it from A) | B ingests once (`duplicate` counted), submits once |
| E3 | **Exclusivity expiry**: A assigns B; B is stopped; after `until + jitter` C submits | C lands it; no tx from anyone before `until` |
| E4 | **Landed elsewhere, cancel**: `anvil_setNextBlockBaseFeePerGas` above B's `maxFeePerGas` (B's `max_fee_cap_gwei` keeps headroom for a bump), so B's tx stays pending; C lands the same intent with a higher fee cap; `stuck_after_secs = 1`; B's `track()` re-checks before bump | B never re-sends the meta-tx, replaces its outer nonce with a gap-filler at bumped fees, row `consumed/landed_elsewhere`; B's lane nonce not abandoned |
| E5 | **Private never exported**: chain profile private; A has B as private peer and C as open peer; B also lists C as private | B receives and can land; C never receives the intent, neither from A nor re-served by B (R85); C never sees the chain in A's `/policy` |
| E6 | **Peer not admitted / suspended**: D with an unpinned key pulls A ⇒ handshake fails; B is suspended in fake Odoo while its keep-alive connection is open ⇒ B's next request gets 403 within one `mesh_config` refresh; an open peer that injects a private-chain intent is rejected and counted | as stated |
| E7 | **Restart durability**: kill B (SIGKILL) after it journaled `outer_nonce`/`tx_hash` and sent; restart | B resumes tracking (no re-sign, no second outer nonce), row ends `landed`; puller cursor resumes from `peer_cursor`; A's gateway intent survives A's restart |
| E8 | **Outbox publication (R73)**: fake Odoo returns a job from `mesh_publish_claim`; A publishes without `exclusive`; A's breaker is forced open so A cannot submit; B lands it | Odoo receives no `dead`/`reverted` for the job; indexer path (fake) can mark it final; B landed |
| E9 | **Restricted company**: fake Odoo returns nothing from `mesh_publish_claim` | nothing from A's outbox is ever served |
| E10 | **Catch-up**: C is down for 120 s while A accepts intents with `validUntil` 300 s; C starts | C ingests all of them (none rejected for age, H2) and the still-valid ones are submittable |
| E11 | **Store recreated**: A's SQLite file is deleted and A restarted | B detects the new `store_id`, resets its cursor, and ingests A's next intent |
| E12 | **Race lost on the Odoo path**: our node's tx for an Odoo job is mined and reverts because C landed first | fake Odoo receives `consumed`, never `reverted` (H3) |

Non-EVM multi-node e2e is not in v1 (each family needs its own localnet, several GB of RAM — R3D §D). Non-EVM
coverage = vectors + adapter unit tests with fakes; one ignored e2e per family can reuse `tests/e2e_<family>.rs`
later (§15).

### 13.4 Odoo (`dms_blockchain/tests/`)

S1a (`test_relay_consumed.py`):
- `relay_report('consumed')` from `nonce_leased`/`signed`/`broadcast` (and refused from `mined`); business state stays pending; metatx
  state untouched; `_fail_dependents` not called; late `mined`/`reverted` report on a consumed job is a no-op.
- `_mark_executed` with relayer ≠ signer ⇒ `landed_elsewhere`; equal ⇒ not; no relayer ⇒ tx-hash rule; unclaimed ⇒
  elsewhere; `consumed` → `final`.
- `_cron_expire` moves stale `consumed` to `dead` only after the extra hour.
- `landed_elsewhere` and `mesh_published_datetime` cannot be set by an operator `write`, nor by a `default_*`
  context key on `create` — also when the create runs under `sudo()` (N4).

S1b (`test_mesh.py`, `test_mesh_vectors.py`):
- `chain_profile` default `private`; `_node_config` carries it; post-migration sets known public chains to `public`;
  switching a chain to `private` with an `open` policy raises.
- `blockchain.target.policy`: default visibility from profile, kept on later profile changes; private chain refuses
  `open`; UNIQUE; selector format by family; `submit` requires `full`, a concrete contract and a registered token.
- `blockchain.mesh.peer`: pin format/unique; https-only URL; private peer needs chains; open peer refuses a private
  chain.
- `mesh_config`: AccessError outside `relay_worker`; returns only active peers/policies.
- `mesh_publish_claim`: restricted company ⇒ nothing; open company ⇒ only after window; relayer-bound job excluded;
  second call returns nothing (stamped); `call` jobs never returned; accepts a `chain_key` for non-EVM.
- Portal: open company ⇒ request built with `relayer = 0` and mode without `MODE_RESTRICT_RELAYER`.
- `test_mesh_vectors.py`: §4.6 cases 1–13 digests and `body_hash`.

---

## 14. Work breakdown

Ordered streams for one agent at a time. "Gate" = the heavy command of the stream; run it alone.

**S0 — Gateway fee-recipient/relayer binding fix** (live bug, independent of the mesh; R84)
- Files: `bamboo-node/src/metatx.rs` (`normalize()`), `src/gateway.rs` (`post_metatx`: normalize before simulate),
  `src/config.rs` (`[[chains]] fee_recipient`), `node.example.toml`, `tests/e2e.rs` (assert the fee of an open-mode
  intent with a foreign `feeRecipient` lands in our wallet / the lane).
- Tests: §13.1 `gateway.rs` cases; one e2e assertion.
- Gate: `cargo test` then `cargo test --test e2e -- --ignored`.
- Done: a client can no longer redirect the fee of an unbound intent; bound intents unchanged; existing tests green.

**S1a — Odoo: consumed state and landed_elsewhere** (§10.3)
- Files: `dms_blockchain/models/blockchain_relay_job.py`, `blockchain_metatx.py`, `blockchain_signed_op.py`,
  `blockchain_chain_event.py`, views for the two fields.
- Tests: §13.4 S1a.
- Gate: Odoo test run of `dms_blockchain`, `dms_blockchain_payment`.
- Done: suite green; existing blockchain tests green.

**S2 — R80 fix on the existing relayer** (no mesh code)
- Files: `bamboo-node/src/submit.rs` (`Origin`, `MetaRef`, `Sent.hashes`, `Inflight` set, `track()`, reverted-receipt
  and simulate-revert classification, outcomes for every origin), `src/chain.rs` (`nonce_at`), `src/abi.rs`
  (`metaNonce`, `metaTxDigest`, event filter if missing), `src/adapter.rs` (`op_consumed(&Job)`, `step_once`,
  `follow`, `Origin` in `Built`/`Signed`), `src/adapters/{cosmos,sui,aptos,ton,solana,hedera}.rs` (`op_consumed`),
  `src/gateway.rs` (`Origin::Gateway`), `src/main.rs` wiring, `tests/e2e.rs` adjust.
- Tests: §13.1 `submit.rs`/`adapter.rs` cases; single-node e2e "peer lands while we are pending" (anvil automine off,
  second EOA sends the same meta-tx) and "our tx reverts after a lost race ⇒ consumed".
- Gate: `cargo test` then `cargo test --test e2e -- --ignored`.
- Done: no `relay_report('dead'|'reverted')` for a consumed job in any test; `bamboo_submit_bump_skipped_consumed_total`
  > 0 in the e2e; R18 invariant tests unchanged. Depends on S1a.

**S3 — Envelope, decoding, hub signature, vectors** (pure library)
- Files: `src/mesh/mod.rs`, `envelope.rs`, `digest.rs`, `hubsig.rs`, `accept.rs` (L0–L3, store behind a trait),
  `export.rs`; `tests/mesh_vectors.rs`; `tests/vectors/mesh-envelope-v1.2.json`;
  `dms_blockchain/tests/data/mesh-envelope-v1.2.json` (copy); CI `cmp` step.
- Tests: §13.1 envelope/digest/hubsig/accept/export; §13.2 (Rust side).
- Gate: `cargo test --lib --test mesh_vectors`.
- Done: 32 vector cases pass in Rust.

**S1b — Odoo: chain profile, policy, peers, company scope, outbox publication** (§10.1, §10.2, §10.4, §10.5)
- Files: `dms_blockchain/models/blockchain_chain.py`, `blockchain_target_policy.py` (new), `blockchain_mesh_peer.py`
  (new), `res_company.py` (new), `res_config_settings.py` (new or extend), `blockchain_relay_job.py`
  (`mesh_publish_claim`), `migrations/19.0.1.1.0/post-migrate.py`, `__manifest__.py` version, `security/…`,
  `views/…`, `__init__.py`; `dms_blockchain_payment/models/payment_transaction.py`; `tests/test_mesh.py`,
  `tests/test_mesh_vectors.py`.
- Gate: Odoo test run of `dms_blockchain`, `dms_blockchain_payment`.
- Done: suite green including vectors; `pg_constraint` shows the new UNIQUE/CHECK constraints (CLAUDE.md §5.2).

**S4 — Store and configuration**
- Files: `Cargo.toml` (`rusqlite` bundled), `src/mesh/store.rs`, `src/config.rs` (`[odoo]` optional, `[mesh]`,
  `profile`, `tokens`, standalone tables), `src/odoo.rs` (`mesh_config`, `mesh_publish_claim`,
  `NodeConfig.chain_profile`), `src/main.rs` (`mesh-id`, `Option<Odoo>` per §3.3), `node.example.toml`.
- Tests: §13.1 store/config.
- Gate: `cargo test` (first build with bundled SQLite; expect one long compile).
- Done: store survives reopen with identical `seq`/`store_id`; config tests cover every validation rule; a node with
  no `[odoo]` starts with `submit` + `mesh`.

**S5 — mTLS transport and bus API**
- Files: `Cargo.toml` (direct `rustls`/`tokio-rustls` without default features, `hyper-util`, `rustls-webpki`),
  `src/mesh/tls.rs`, `src/mesh/server.rs` (routes §5.2, limits §5.1), `src/mesh/puller.rs` (cursor/overlap/
  store_id, policy cache), `src/admin.rs` (metrics §12), `src/main.rs` wiring (peer table refresh from Odoo or toml,
  fail closed).
- Tests: §13.1 tls; server route tests with an in-process TLS client; puller against an in-process server.
- Gate: `cargo test`. Check `Cargo.lock` gains no `aws-lc-rs`.
- Done: two in-process nodes exchange intents over mTLS; unknown key refused at handshake; suspended key refused per
  request.

**S6 — Pipeline integration**
- Files: `src/mesh/sched.rs` (assignment, scheduler, janitor), `src/gateway.rs` (store write, `intent_id`,
  `GET /v1/intents/{id}`), `src/submit.rs` (store journal, cold start with store rows, mesh outcome sink, Odoo-path
  sink CAS on outbox rows), `src/adapter.rs` (mesh channel in `lane_runner`, `recover_lane` with store rows),
  `src/main.rs` (outbox publisher task calling `mesh_publish_claim`), `src/nonce.rs` (plan input).
- Tests: §13.1 sched/nonce; unit tests of the outcome sinks.
- Gate: `cargo test`.
- Done: unit tests green; manual run of two nodes on anvil lands one gateway intent through the other.

**S7 — Multi-node e2e and docs in code**
- Files: `tests/e2e_mesh.rs` (E1–E12), `bamboo-node/README.md` (mesh section, key generation, R16 line updated),
  `node.example.toml` (`[mesh]` commented example).
- Gate: `cargo build --release` then `cargo test --test e2e_mesh -- --ignored` (spawns 3–4 node processes; nothing
  else running).
- Done: E1–E12 green twice in a row.

**S8 — Spec corrections** (after owner approval of this spec; text only — list in §15.1).

Order: **S0 → S1a → S2 → S3 → S1b → S4 → S5 → S6 → S7 → S8.** S0 and S1a+S2 deliver fixes to the running relayer
before any mesh code; S3 is a pure library and can be done any time after S0.

---

## 15. Open follow-ups

### 15.1 Doc corrections required by R70–R86 (listed, not made)

| File | Where | Edit |
|---|---|---|
| UD | §22.2 table, row **C. Mesh** | "Đường": `gossipsub v1.1 topic bamboo/intent/<caip2>/v1` → `HTTP pull bus GET /v1/mesh/intents giữa peer đã duyệt (R70)`; "Xác thực": `Chữ ký peer libp2p + peer score` → `mTLS, SPKI ghim theo dòng peer (R72)`; "Rate limit ở đâu": → `token bucket theo peer trong tiến trình (peer_rps, peer_intents_per_sec)`. Add a note: libp2p là transport thứ hai về sau, cùng envelope. |
| UD | §22.2 rule 3 | keep `MAX_HOPS = 4`; add "do nút nhận tăng khi lưu; nút không phục vụ dòng đã ở MAX_HOPS; intent private không được chuyển tiếp (R85)". |
| UD | §23.6 diagram | `[mesh]     libp2p gossipsub` → `[mesh]     HTTP pull bus, mTLS ghim SPKI (R70, R72)`; add line `[store]    SQLite: intent + bus_seq (R71)`; `[pool]     open / private` → `(pool = store của mesh, §21.4 mục 2)`. |
| UD | §23.3 table, module `mesh` | "ingest `gossip` hoặc `pull`" → "ingest `pull` (HTTP bus, R70)". |
| UD | §21.4 shapes table | "Pool thuần … Ingest gossip" → "pull"; "Private relayer … kéo từ private pool" unchanged. |
| UD | §22.6 `profitable()` | `intent.fee` → effective fee (R86); add R84 normalization of unbound `feeRecipient`. |
| §05 | §5.0 table rows "Intent bus", "Kênh mạng", "Soft-exclusivity lottery" | public: `Mesh libp2p, gossipsub v1.1` → `Bus HTTP liên bang, peer đã duyệt (R70)`; private: `1 hub nội bộ, không federation` → `peer private do origin duyệt, mTLS (R76, R85)`; lottery → `round-robin do origin ký (R74)`. |
| §05 | §5.1 boxed conclusion and §5.1.2 | mark libp2p as deferred (R70); routes table: remove `/claim`, `/receipt`, `/publish`, `/peers`, `/pending` summary mode; bus served by `bamboo-node`, not an Odoo controller (UD §23.8); point to this spec §5. |
| §05 | §5.2 envelope | replace 1.1 by `bamboo-intent/1.2` (this spec §4), state 1.0/1.1 void (R81). |
| §06 | §06.0.2 field definition | `default='public'` → `default='private'` (R76). |
| PD | §3.4 / R16 | `/v1/metatx` normalizes unbound fields (R84); with `[mesh]` on, intents are durable in the mesh store (R71). |
| `bamboo-node/README.md` | "Bất biến vận hành", R16 line | same as PD (done in S0/S7, code-adjacent doc). |

### 15.2 Interpretations (confirmed by the owner, 2026-10-05)

1. The origin is a member of its own round-robin (R74).
2. Own outbox jobs are published without `exclusive` (R74).
3. Only `queued` outbox jobs are published (R73, R74).
4. A missing policy row means forward only (§7.1).

### 15.3 Deferred work

- libp2p transport carrying the same envelope (R70).
- Zether on the bus: `W = 0`, single-flight per `from_schnorr`, push latency (§05 §5.1.1, §5.4.3).
- Soroban: a contract-level per-subject nonce (or accept the host nonce as equivalent) would qualify it (R77).
- Non-EVM op kinds other than `pay` (TON revoke `next > nonce + 1`, Solana mandate generation) on the bus and in
  `op_consumed`.
- Multi-hop private routing with an origin-signed recipient set (R85).
- Non-EVM door A (`POST /v1/ops`) and non-EVM multi-node e2e on one localnet (Cosmos `wasmd` is the lightest).
- Consumption classification for non-EVM before finality (adapter event lookup for one tx range).
- "done" hints on the bus so holders drop landed intents without an RPC (B4); `/receipt` and forward scoring
  (UD §21.4, §22.8 point 3) once rewards exist.
- Odoo-side peer counters (`mesh_report`) if operators want them outside Prometheus.
- Per-lane channels for gateway/mesh EVM work (today lane 0 only, `main.rs`).
- Tune R82 numbers after a multi-site run (UD §22.10.1).
- Callback subject registry (UD §22.10.4), ban-list sharing (§05 §5.5 tier 5).

### 15.4 Contradictions resolved in this spec

| Topic | Sources | Followed | Why |
|---|---|---|---|
| Transport | §05 §5.1 (libp2p chosen, bản 3), UD §22.2 C, §23.6 vs owner 2026-10-05 | owner: HTTP pull bus (R70) | ruling |
| `chain_profile` default | §05 §5.0, §10 l.408: `private`; §06 §06.0.2: `public` | `private` (R76) | fails closed; §05 §5.4.5 rule 1 |
| Private profile bus | §05 §5.0 "1 hub nội bộ, không federation" vs owner ruling 7 | allowlisted private peers over mTLS, served by the origin only (R85) | ruling |
| Claim | §05 §5.1.2 `/claim` signed by secp256k1 relayer address, lottery + `beacon` | origin-signed `exclusive`, `relayer_id` = 32-byte `peer_id`, no claim route (R74, R81) | ruling 5 |
| `/policy`, `/peers` | §05 §5.1.2: public, bootstrap multiaddr | mTLS-only, filtered per caller, no discovery | R72, §9 |
| Summary/full | §05 §5.1.2 summary default + `/get?ids=` | full pages only | admitted peers; one round trip per hop |
| Dedup key | UD §22.8 pt 2 "digest, not intent_id" vs §05 §5.2 "intent_id = digest" | one value (R78) | §05 §5.2 makes them equal |
| `bus_seq`, `published_at` in envelope | §05 §5.2 | `bus_seq` in page wrapper; `published_at` inside signed `hub` | seq is per serving node |
| `W` | §05 §5.4.4a, UD §22.5: 3 s | 10 s (R82) | 3 s assumed push gossip; pull adds up to `poll + lag` per hop |
| Promote window | UD §22.7 300 s | 120 s private window, own outbox only (R73) | UD §22.10.2: 300 s never opens for 300 s ERC-20 expiry |
| No-policy default | UD §22.4 (`none` ⇒ reject) vs §06 §06.3.3 (default deny) | no row ⇒ forward only; explicit `none` ⇒ reject | deny submission, keep routing (UD §21.1) |
| `profitable()` | UD §22.6 `intent.fee >= min_fee`, `feeRecipient` allow-list | effective fee; unbound recipients normalized (R84, R86) | the raw field is not what the contract pays |
| Node → Odoo channel | UD §21.2 / §06 §06.0.1 (Postgres outbox + result table) vs PD R6 (`/json/2` only) | R6 | already ruled; mesh adds no Postgres |
| Per-`from` rate limit in Redis | §05 §5.5 tier 1 | per-peer in-process buckets | single process (UD §23.1); no Redis (UD §23.7) |
| Gateway queue durability | PD R16 (in memory) | store-backed when `[mesh]` on (R71) | ruling 2 provides the store |
| Gateway fee recipient | PD §3.4 says the gateway fills `feeRecipient` for DEX legs; `/v1/metatx` passes it through | normalize on every non-Odoo path (R84) | live bug (S0) |
| Bus host | §05 §5.1.2 (Odoo controller `intent_bus.py`) | `bamboo-node` | UD §23.8: Odoo is control plane, no gossip/pool |
| Target policy shape | §06 §06.3.3 (company, risk columns) vs UD §22.4 (routing columns) | UD §22.4 columns, no company | one table; risk columns have no v1 consumer |
| Third-party relayer registry | §10 §10.4.5 `blockchain.relayer` by address | `blockchain.mesh.peer` by SPKI | R72 |

---

## 16. Review disposition

### 16.1 Review 1 (spec-review-1.md, verdict FIX-THEN-GO)

All findings were checked against the code at 3a789d2 before applying (ERC20MetaTx l.87; `submit.rs` l.280–292
reports `reverted`; `blockchain_subject_account.py` l.35/l.459; adapters' `MetaOp::decode`/`parse_metaop`;
`blockchain_chain_data.xml` `noupdate="1"`; lock has ring, not aws-lc-rs). None was found wrong.

| # | Finding | Disposition | Where |
|---|---|---|---|
| C1 | Unsigned `feeRecipient` lets a forwarder/client take the fee | fixed — R84 normalization; also live in the gateway ⇒ new stream S0 | §1.1, R84, §4.3, §8.4, §13, §14 S0 |
| H1 | Poisoned copy censors; unbound parts tamperable | fixed — no rejection cache; non-EVM fields decoded from payload; `body_hash` in `hub.sig`; failed rows deleted | §4.2–§4.5, §6, §7.2, T5/T6 |
| H2 | `published_at` window breaks catch-up | fixed — reject only future values | §7.2, T11, vector 28, E10 |
| H3 | Lost race reported `reverted` | fixed — consumption check on reverted receipt/status; `mined → consumed`; no `_fail_dependents` | R80, §8.4, §10.3, E12 |
| H4 | Gas drain on `*` contracts; raw fee compared | fixed — R86 registered tokens + effective fee; Odoo CHECK | R86, §7, §10.2 |
| H5 | Private intents travel past the origin's allowlist | fixed — R85 origin-only serving | R85, §9, E5 |
| H6 | G2 false: two outer txs for one intent | fixed — per-chain in-flight digest set; duplicate-on-publish flips the row; G2 reworded | §8.1, §8.3, §8.4, §8.7 |
| M1 | rustls default features pull aws-lc-rs; PEM parsing | fixed — no default features, ring provider explicit; fixed-prefix PKCS#8 parsing | §3.4 |
| M2 | Restart rules conflict with `plan()`; `nonce_at` missing | fixed — store rows go through `plan()` with Odoo rules; `nonce_at` declared new | §8.4, §8.6 |
| M3 | Incomplete state machine; RPC errors not fail-closed | fixed — transition table; fail-closed reads; late reports on `consumed` are no-ops | §6, §8.4, §10.3 |
| M4 | Suspended peer keeps its connection; no handshake timeout | fixed — per-request check, timeout, semaphore, connection age | §5.1, T1, T13, E6 |
| M5 | Recreated peer store leaves cursor ahead | fixed — `store_id` in meta, pages, policy; cursor reset | R71, §5.2, §6, E11 |
| M6 | `op_consumed` wrong for revoke/mandate ops | fixed — `None` except `pay`; non-EVM bus limited to `pay` | §1.2, R77, §7.1, §8.4 |
| M7 | Non-EVM `relayer_ok` compared to `pk:` labels | fixed — decoded relayer vs canonical lane address | §7.2 |
| M8 | Standalone mode under-specified | fixed — §3.3 (kept the shape: owner accepted the toml fallback) | §3.3 |
| M9 | `PRIVATE_FROM_OPEN_PEER` used the label only | fixed — label or own chain profile | R76, §7.2, vector 25 |
| M10 | E1/E4 impossible; missing tests | fixed — E1/E4 rewritten; unit tests per finding; E10–E12; Odoo `consumed` tests | §13 |
| L1 | Wrong references; `op_consumed(&Value)`; R72 rationale | fixed | §4.6, §10.4, §8.4, R72 |
| L2 | `noupdate` data ⇒ chains become private on upgrade | fixed — post-migration script | §10.1 |
| L3 | `seq`/`head` side channel | fixed — `head` dropped; gap channel accepted and stated | §5.2, T7 |
| L4 | Server-only job fields writable | fixed — stripped in `create`/`write` unless `env.su` (no context key) | §10.3 |
| L5 | `getLogs` needs a block; `mesh_publish_claim` arg name | fixed — `from_block` column; argument `chain` | §6, §8.5, §10.5 |
| L6 | Stored compute re-triggers; constraint skipped on chain write | fixed — compute keeps value; chain `write` check | §10.1, §10.2 |
| L7 | Unbounded page bytes | fixed — `page_max_bytes` 1 MiB | §3.2, §5.2 |
| L8 | Outbox row served after we landed it | fixed — Odoo-path sink CAS by digest | §6, §8.4 |
| O1 | Summary/by-id two-step | accepted — full pages only, by-id route dropped | §5.2 |
| O2 | `seen_rejected` | accepted — dropped | §6, §7.2 |
| O3 | `mesh_report` + Odoo peer counters | accepted — deferred, `/metrics` only | §10.2, §12, §15.3 |
| O4 | Split S1 | accepted — S1a (with R80 fix) / S1b | §10, §14 |

Totals: 25 findings fixed (C1, H1–H6, M1–M10, L1–L8), 4 over-engineering items accepted (O1–O4), 0 rejected.

### 16.2 Review 2 (spec-review-2.md, verdict FIX-THEN-GO)

Verified against the code before applying: `contract` is the payer's account in `fam_sui.py` l.167, `fam_aptos.py`
l.233, `fam_solana.py` l.185, `fam_ton.py` l.312, and the token in `fam_cosmos.py` l.92; the token lives in
`extra.registry` / `asset` / `extra.jetton_master`; `adapters/cosmos.rs` has no `MetaOp` decoder; `_payload` carries
`digest`; `relay_poll`/`step_once` line refs. None was found wrong.

| # | Finding | Disposition | Where |
|---|---|---|---|
| N1 | Registered-token gate never passes for Sui/Aptos/TON/Solana | fixed — `token_of` per family + account-derivation check; policy column holds `token_of`; vectors 10–13 compute `may_submit` | R86, §4.4, §4.6, §7.1, §7.2, §8.2, §10.2 |
| N2 | In-flight set lifecycle incomplete, non-EVM lanes missing, Odoo churn | fixed — RAII guard released on every exit without a `Sent`; non-EVM lanes are members; skip by `job.digest` before `relay_claim` | §8.3, §8.4, §13.1 |
| N3 | Deleting failed rows ⇒ re-simulate loop | fixed — `(intent_id, body_hash)` tombstone until `valid_until` | §6, §7.2, T6, §13.1 |
| N4 | Stripping `vals` does not stop `default_*` context keys | fixed — `create` forces both fields `False`; `write` strips unless `env.su` | §10.3, §13.4 |
| N5 | `mined → consumed` unneeded and risky | fixed — removed; S1a test refuses it | §10.3, §13.4 |
| N6 | Terminal rows must not be fed to `plan()` | fixed — non-terminal only; terminal rows raise `journal_max` | §8.6, §13.1 |
| N7 | Missing `broadcast` + revert without consumption row | fixed | §6 |
| N8 | R84 in `submit.rs` misses Hedera via the adapter | fixed — normalize where `Work`/`Job` is built from a request or envelope | §8.4 |
| N9 | Cosmos needs a new payload decoder | fixed — stated as new, fuzzed | §4.4, T9 |
| N10 | `body_hash` breaks silently if `preserve_order` is enabled | fixed — vector 32 with unsorted keys | §4.6 |
| N11 | E4 cannot produce a stuck tx | fixed — next base fee above B's `maxFeePerGas`, cap headroom kept | §13.3 |
| N12 | `GET /v1/intents/{id}` exposes peer/private rows | fixed — `source = 'gateway'` only, others 404 | §5.2, §13.1 |

Totals review 2: 12 fixed, 0 rejected.
