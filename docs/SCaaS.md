# SCaaS — SmartContract as a Service: System Specification

**Status:** normative, 2026-10-06. Owner of this file: the `scaas` repository (`scaas/docs/SCaaS.md`).
**Companion:** [`integration.md`](integration.md) — how an ERP or application integrates.
**Language of record:** English. Component specs under `docs/superpowers/specs/` are partly in Vietnamese; their
rulings are cited by id (`R9`, `RS2-6`, `R114` …) and remain authoritative for their detail.


**Contents:** [0 Precedence and glossary](#0-precedence-sources-and-glossary) ·
[1 Positioning](#1-positioning) · [2 Service model](#2-service-model) · [3 Architecture](#3-architecture) ·
[4 Token system](#4-token-system) · [5 Meta-transaction layer](#5-meta-transaction-layer) ·
[6 Relayer network](#6-relayer-network) · [7 Families](#7-families) · [8 Zether](#8-zether--confidential-amounts) ·
[9 Keys and signing](#9-keys-and-signing) · [10 Sealed-bid tender](#10-sealed-bid-tender-specified) ·
[11 Data protection](#11-data-protection) · [12 Node API](#12-node-api-surface) · [13 Operations](#13-operations) ·
[14 Interfaces](#14-canonical-interfaces) · [15 Roadmap and open questions](#15-roadmap-open-questions-recorded-contradictions)

Every item below carries one status tag:

| Tag | Meaning |
|---|---|
| **BUILT** | Code exists in this repository with tests. The text describes what the code does. |
| **SPECIFIED** (link) | A component spec with rulings exists; code does not, or only partly. The link is the authority for detail. |
| **PLANNED** | Specified only here (and possibly in research notes); no component spec, no code. The text is the contract a future spec must satisfy or explicitly amend. |

Where something is partly built, the tag names the built part and the rest separately.

---

## 0. Precedence, sources and glossary

### 0.1 Precedence

When two sources disagree, the higher one wins:

1. **Owner rulings** — recorded in the component specs as `(owner)` rulings and in the decision list of
   2026-10-06 (node independence, store backends, admin auth, transports, `scaas` naming, families, market
   neutrality). They override everything below, including code that has not caught up.
2. **This document** (`SCaaS.md`) and `integration.md`.
3. **Component specs** in `docs/superpowers/specs/` (payments design R1–R20, wallets addendum R21–R29, round 3
   R30–R67, Zether design RS2-*, Zether limits RS-NV64-*, DEX RS5-*, per-family net specs, relayer mesh R70–R86,
   node independence R87–R111, mesh gossip amendment A2 R112–R127, token wrappers v2 [TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) R129–R149). For a detail this document does not state,
   the component spec is normative.
4. **Code** — pinned behaviour (typehashes, KAT vectors, conformance vectors) is normative for byte formats; a
   difference between code and an owner ruling is a bug in the code, not in the ruling.
5. **Research** in `docs/superpowers/specs/blockchain-research/` (`00-CANON.md`, `_USER-DECISIONS.md`, notes 01–16):
   background and rationale only.

The owner's SRS drafts (`ai-enterprise-blockchain-architecture.md` v3.3, `ai-enterprise-blockchain-integration.md`
v2.5, outside this repo) are **reference material, never edited from here**. Where they differ from rulings or code
the difference is listed in §15.3.

Superseded positions that readers of older material will meet:

| Older position | Current position | Ruling |
|---|---|---|
| ERP-held outbox claimed by the relayer with `FOR UPDATE SKIP LOCKED`, node reports back over `/json/2` | ERP keeps its own outbox and **pushes** jobs to the node's job API; it polls `/v1/jobs` and `/v1/events`; the node never calls the ERP | R87, R97, R101 |
| Redis lease with fencing token for outer nonces | Node store journal (`lane.journal_max`, job rows) with owner lock + fencing epoch | R88, R111 |
| ERP is the configuration authority (chains, tokens, finality, policy) | The node store is the configuration authority; `node.toml` bootstraps it | R95, R96, R99 |
| libp2p gossip as the only mesh transport | libp2p gossipsub for the **open mesh** + HTTP/QUIC **pull bus** for admitted peers | R70, R112, R113 |
| "Six ecosystems" (EVM, Hedera, TON, Sui, Soroban, Cosmos) | Family taxonomy (§7): EVM incl. Hedera; Cosmos; Soroban (Stellar, Pi); Move (Aptos, Sui); TON; Solana | owner 2026-10-06 |
| `bamboo-*` names (`bamboo-node`, `bamboo-intent/1.2`, `bamboo.pay.lane`, `BAMBOO_*`) | `scaas-*` names everywhere (`scaas-node`, `scaas-intent/1.2`, `scaas.pay.lane`, `SCAAS_*`) | R115, NI header |
| Country-specific data-protection law named in the protocol | Market-neutral: data-protection regimes are handled generically (GDPR-class) | owner |

**Naming note.** The `scaas` rename has landed in code: node `scaas-node/`, env `SCAAS_*`, metrics
`scaas_*`, headers `X-Scaas-*`, EIP-712 domains `"SCaaS …"`, tags `scaas.*` / `SCAAS-ZETHER-*` / `scaas/zether/…`.
Clients still read the domain a deployed contract reports (`eip712Domain()`) rather than assuming a string.

### 0.2 Glossary

| Term | Definition |
|---|---|
| **Subject** | The party whose value moves or whose authority is exercised: a person, a company, an AI agent, a device. Subjects sign; nobody signs for them (§1.2). |
| **Intent** | A subject-signed, domain-separated authorization of exactly one operation on exactly one contract (a meta-transaction on EVM, a `MetaOp` elsewhere). It is valid until `validUntil` and executes at most once. |
| **Envelope** | The wire wrapper of an intent between nodes: `scaas-intent/1.2` JSON with family body, `intent_id`, origin signature `hub.sig`, optional `exclusive`, `hop_count` (MESH §4, R81, R115). |
| **`intent_id` / digest** | The 32-byte digest the contract computes and emits in `MetaTransactionExecuted.digest` (EVM: EIP-712 `_hashTypedDataV4`; other families §4.4 of MESH). Dedup key everywhere (R78). |
| **Relayer** | A process holding gas-paying keys that submits subject intents as outer transactions. It cannot alter an intent; it can only submit, delay or refuse it. |
| **Node** | `scaas-node`, the Rust process that runs relayer roles: gateway, job API, submit lanes, indexer, mesh, DEX venue, admin (§3, §6). |
| **Lane** | One gas-paying relayer account on one chain (derived from a mnemonic at a BIP-44 account index, or a raw key). Each lane has its own outer nonce/sequence; a stuck lane never blocks another (R30, R62). Also used for the subject-side 2D nonce space: a **subject lane** = `(from, batch)` on EVM, `(subject, lane)` elsewhere. |
| **Outer nonce** | The chain-level nonce/sequence of a relayer lane account. Journaled before broadcast (R18, R88). |
| **Family** | A group of chains that share one contract code base and one node adapter: `evm` (incl. `hedera`), `cosmos`, `soroban`, `move` (`aptos`, `sui`), `ton`, `solana` (§7). |
| **Chain** | One network, keyed by `chain_key = family:network` (`evm:100`, `hedera:296`, `sui:mainnet`, `aptos:1`, `ton:-239`, `solana:<genesis>`, `cosmos:<chain-id>`, `soroban:pubnet`). CAIP-2 is a display field only (R61, MESH §4.2). |
| **Profile** | `public` or `private` per chain; default `private` (fails closed). Private-chain intents never leave admitted private peers and never touch gossip (R76, R85, A2 §12). |
| **Namespace** | The node's tenant unit (`[a-z0-9-]{3,40}`; reserved `~gateway`, `~mesh`, `~dex`). Holds granted chains, token subset, machine keys, quotas. The node has no notion of "company" (R90). |
| **Store** | The node's durable state: jobs, job events, index ranges, configuration, key metadata, audit log, DEX book, mesh tables. SQLite, PostgreSQL or MySQL; one owner process per store (R88, R111). |
| **Job** | A unit of submission work in the store (`metatx`, `call`, `signed_op`, or `tombstone`), identified by `uid` and by its idempotency tuple (R89, R91). |
| **Outbox** | The client-side table where a business transaction records "this must go on chain", committed atomically with the business change. In Odoo: `blockchain.relay.job`. The client pushes outbox rows to the node (R101). |
| **Feed** | A cursor-paged change log served by the node: `/v1/jobs` (job state changes) and `/v1/events` (finalized chain ranges, balances, DEX items) (R93, R94). |
| **Anchor** | Write-out direction: publishing a commitment or settling value on chain (§2.1). |
| **Land** | Read-in direction: a finalized on-chain fact delivered to a system of record (§2.1). Nothing lands before the finality gate. |
| **Settlement** | Transfer of value whose on-chain execution is the completion of a business obligation (payment, trade, tender award). |
| **`entryRef` / `payId`** | 32-byte reference carried by a payment op and emitted in `PaymentSettled`; links an on-chain payment to a business document. Current rule: 32 random bytes (R9). `payId` is the SRS name of the same field. |
| **Finality gate** | The rule that decides when a block range is final: `depth` (n confirmations), `tag` (`finalized`), or `instant` (BFT families), plus a quorum of independent RPC endpoints returning the same hash (R11, §6.6). |
| **Consumed** | Job state: the subject nonce of the intent moved past the intent's nonce through a transaction this node did not land (or not yet attributed). Never a failure by itself (R80, S1a). |
| **UA** | Universal Account: `keccak256(encodedY)` of a confidential (ElGamal) public key, registered with proof of possession (§8.6). |
| **Mandate** | An on-chain spending authorization held by a subject's wallet contract (`MandateWallet`): delegate, per-payment and per-period caps, payees, expiry, revocation (R25). |

---

## 1. Positioning

### 1.1 What SCaaS is

SCaaS is a **foundational infrastructure service for write authority and value**, used by ERPs, portals, mobile
apps and AI agents the way they use a database or object storage. It is made of:

- **immutable contracts** per network family (§4, §5, §7, §8, §10), deployed as EIP-1167 clones from an open factory
  on EVM and as equivalent modules/programs elsewhere;
- **`scaas-node`**, a relayer and indexer that pays gas for subject-signed intents, journals every submission,
  waits for finality and serves finalized facts back (§3, §6);
- **client-side signers** (`clientkeys`: passkey, 24-word seed vault; extension wallets) so that the subject signs
  on its own device (§9);
- **`zether-prover`** for confidential amounts (§8);
- a **console/dApp** (`app/`, PLANNED) for wallets, payments, DEX, Zether and node administration.

SCaaS does not depend on any ERP. Odoo (addons `dms_blockchain*` in the `bamboo-dms` repository) is one client
(R87).

### 1.2 Authority model: SCaaS vs IaaS vs BaaS

The difference is **who signs a valuable write**.

| Criterion | IaaS (AWS EC2, Google Compute Engine) — the app issues JWTs, the server signs | BaaS (Supabase) — Supabase Auth issues JWTs, the server signs; Postgres RLS | SCaaS — the client signs every valuable create/update |
|---|---|---|---|
| Who signs a write | The application server; the client holds a server-signed JWT and the server writes on its behalf | Supabase Auth signs the JWT; PostgREST/Postgres executes; RLS reads `auth.uid()` | **The subject**: its device signs each operation with a passkey (WebAuthn P-256) or a wallet key. The relayer pays gas and holds no subject key |
| Trust root | The operator, the cloud provider (IAM, hypervisor), anyone holding the JWT signing key | Supabase (operator) + the project owner holding the JWT secret / `service_role` key | The subject's authenticator/secure element + chain consensus + immutable contract code |
| Who can forge a subject's write | Anyone with the JWT signing key, direct DB write access or a compromised server/IAM — indistinguishable from the subject | Anyone with the JWT secret (mints any `uid`) or the `service_role` key (bypasses RLS) | **Nobody without the subject's private key.** An operator or relayer can only refuse or delay (censorship/liveness); countered by other relayers or by the subject (or payee) submitting itself |
| Non-repudiation | None: the server writes the log and can write any line | None (same reason) | Per operation: a domain-separated signature with nonce and expiry, publicly verifiable forever |
| Audit trail | App logs / CloudTrail held by the operator | Postgres/Supabase logs held by the operator | Append-only distributed ledger; the ERP is a read-in replica (land) |
| Authorization enforcement | App code (an endpoint is easy to miss) | RLS (centralized, but `service_role` and policy bugs bypass it) | Immutable contract code checks signature, nonce, expiry and limits on **every** call; no admin key above it |
| Revocation / rotation | Easy: short TTL, deny lists, rotate server keys | Easy: rotate JWT secret, revoke refresh tokens | Harder: on-chain key rotation in a smart account; several passkeys or guardians for device loss (§9.4) |
| Write latency and cost | Milliseconds; compute/DB cost | Milliseconds; plan-based | Chain finality (seconds to minutes); gas per write, sponsored by a relayer (§5.9, §6.9) |
| Reads | Served by the server | PostgREST + RLS | **Unsigned**: through the node feeds, an indexer or the ERP, with ordinary JWT/session auth. Only valuable writes go through client signatures |
| Privacy | Data inside the operator's infrastructure | Same | Public ledger: both parties' identities are visible by design; amounts and balances can be hidden with Zether (§8) |
| Typical failure | Leaked JWT signing key / IAM = every user impersonated | Leaked JWT secret / `service_role` = every user impersonated | Leaked key of **one** subject = only that subject, bounded by its mandate limits; lost relayer = delay, never loss |

Design consequences (normative):

1. **Scope of client signatures.** Every valuable create/update — transfer, payment, DEX order, tender bid,
   granting or changing authority, registering a key — carries the subject's signature. The server never holds a
   key to sign for a subject. The single exception is a custodial or delegated wallet that the subject or its
   organization **explicitly** entrusted, with limits and an approval log (R24, R25, R50).
2. **Passkeys** (WebAuthn, P-256) sign `authenticatorData ‖ SHA-256(clientDataJSON)` whose `challenge` is the typed
   digest of the operation (EIP-712 on EVM, the family digest elsewhere). Verifiers check `type`, `challenge`,
   `rpIdHash`, `origin`, UP and UV flags and low-`s` (R31, §9.3).
3. **UX.** One biometric/PIN per signature; related operations are batched under one signature over a Merkle root
   of their digests (R31).
4. **Anti-lock.** Subject signatures use **contract-level lanes and nonces**, never the subject's account sequence,
   so a stuck operation on one contract never blocks the subject elsewhere (R30, §5.5).
5. **Reads, reports and workflow** keep using JWT/session like IaaS/BaaS. SCaaS is the layer for write authority and
   value; it does not replace the application database.

### 1.3 What SCaaS is not

| Not | Why |
|---|---|
| A custodian | Relayer lanes hold gas only; the DEX holds no balances between transactions; subject funds stay in subject-controlled accounts or wallet contracts (MESH T14, §4.2, §10) |
| A mixer | Identities of both parties are always visible; only amounts and balances can be hidden (§8.1) |
| A database replacement | Business data stays in the client's system of record; only commitments, settlements and the minimum identity linkage go on chain (§2.2) |
| An upgradeable platform | No proxy upgrade on any contract that holds value; new behaviour = new version + voluntary migration (§4.3) |
| A token gatekeeper | The factory is open; provenance replaces allowlists (§4.3). Controlled tokens are a separate, explicit class (§4.5) |
| A single-ERP product | Odoo is one client; any ERP integrates through the same job API (R87, `integration.md`) |
| A market maker or profit-seeking relayer market | Relayer economics are cost recovery between parties with aligned interests; fee = 0 is the B2B default (§6.9) |

### 1.4 Deployment profiles

| Profile | Chains | Mesh | Typical relayers | Data exposure |
|---|---|---|---|---|
| **Public** | Public networks (Gnosis, Celo, Hedera, Cosmos chains, Sui, Aptos, TON, Solana, Stellar, Pi) — `profile = public` | Open mesh (gossip, opt-in per chain/policy/job) + pull bus for partners | Issuer, distributors, partners, third-party open relayers | Ledger public; private windows and bus scope control what is offered to peers (R73, A2 §8.4) |
| **Private / PoA** | A permissioned chain (reference: chain 9000, Nethermind, Clique, 1 signer, Prague, base fee 0) — `profile = private` (default) | No gossip, ever; pull bus only to admitted private peers, served by the origin only, over PQ-protected carriers | The operator's own nodes; admitted private peers | Chain-local; intents never leave the admitted set (R76, R85, A2 §12) |
| **Consortium** | A permissioned or public chain shared by members | Pull bus between admitted members (SPKI-pinned mTLS or QUIC), optionally gossip for public chains | Each member runs a node | Per-company `bus_scope`: `restricted` (default) / `open` (admitted peers) / `public` (also open mesh) |

Status: public and private profiles **SPECIFIED** ([relayer mesh](superpowers/specs/2026-10-05-relayer-mesh-design.md)
R76, [gossip amendment](superpowers/specs/2026-10-06-mesh-gossip-amendment.md) §12); the single-node relayer that
serves all three profiles without a mesh is **BUILT**.

---

## 2. Service model

### 2.1 Dual loop: write out (anchor/settle), read in (land)

```
  WRITE OUT (anchor / settle)                                     READ IN (land)
  subject signs ─► client outbox ─► node job API ─► simulate ─►   chain RPC ─► finality gate (depth|tag|instant
  journal ─► broadcast ─► chain                                     + RPC quorum) ─► normalized events ─►
                                                                    feed /v1/events ─► client applies ─► ERP book
```

| | Write out | Read in |
|---|---|---|
| Initiator | User, agent, workflow, ERP action | Node indexer |
| Pipeline | Client outbox → push (`POST /v1/jobs`) → accept checks → lease → simulate → journal (`signed`) → broadcast → follow | `final_head` → quorum hash → `getLogs`/family scan → normalized events → `feed_item(range)` → client sync |
| Controls | Idempotency key, namespace grants, registered tokens, R84/R100 normalization, simulation gate, gas breakers | Finality mode + RPC quorum, contiguous ranges, dedup by `(chain, tx_hash, log_index)` |
| Hard rule | No broadcast without a committed journal entry (F5/I5, R88) | **No business booking before the finality gate** (PD §5 guarantee 1, R11) |

Three properties distinguish a contract call from an ordinary API call:

1. **Two-phase result.** An HTTP 200, a `tx_hash` or a mined receipt is not the result. The result is the finalized
   event (`PaymentSettled`, `MetaTransactionExecuted`, …) delivered on `/v1/events`.
2. **Permanent publication.** Calldata is public forever. Only data that passes §2.2 may be put in a payload.
3. **No in-place rollback.** Reversal is a new compensating transaction (refund, burn, counter-transfer).

### 2.2 The four-condition test for putting a commitment on chain

Data may be anchored on chain only if **all four** hold (SRS integration §1.3, kept; market-neutral):

1. **Commitment only.** No plaintext amounts outside value transfers, account numbers, tax ids or party names.
   Business documents are referenced by an unlinkable value: payment `entryRef` = 32 random bytes (R9); other
   anchored records = `keccak256(salt ‖ payload)` with a per-record salt.
2. **Separable, destroyable salt.** Each salt is 256-bit CSPRNG output, stored off-chain in the client's secret
   store, keyed by the record. Deleting the salt makes the on-chain value permanently unlinkable (crypto-shredding,
   §11.2).
3. **Corporate anchor address.** Commitments are published from one address per legal entity, never from per-
   counterparty addresses that would reveal a relationship graph.
4. **Batching for high-frequency streams.** Delivery proofs, decision logs and similar streams are committed as a
   periodic Merkle root (hourly/daily), hiding business cadence.

Value transfers (payments, trades) necessarily show sender, receiver and amount on public chains; that is the
transparent mode. Hiding amounts uses Zether (§8). Hiding the relationship itself is out of scope by design (§1.3,
"not a mixer").

Status: rule **SPECIFIED** here; `entryRef` randomness **BUILT** (R9); salted anchoring and Merkle batching
**PLANNED** (HANDOFF GA 2.2 #11).

### 2.3 Two-phase saga vs one-transaction atomic settlement

| | Two-phase saga (client-led) | One-tx atomic settlement (SCaaS-led) |
|---|---|---|
| Use | Bridging to off-chain systems: bank rails, payment gateways, physical delivery, approvals | Token payments, DEX trades, mandates, tender deposits/refunds, loyalty |
| Mechanism | Client state machine with compensation steps; on-chain step is one leg | Contract atomicity: all legs in one transaction or none |
| Failure | Can stall between phases; needs timeout + compensation jobs | **Fee collected ⇔ operation completed**; any failure reverts everything, nonce not consumed (§5.7) |
| Latency | Bound by the slowest party (seconds to days) | One inclusion + finality |
| Risk control | Maker-checker, compensations | `validUntil`, lane nonces, mandate caps, price limits signed by the subject |

Rule: when every leg is on chain, use one-tx settlement. When a leg is off chain, the on-chain leg is anchored
**after** the off-chain leg is irrevocable, or the saga must have a funded on-chain compensation path.

Status: atomic settlement **BUILT** for payments (`pay` op), DEX (`OrderBookDex.settle`, legacy `MetaTxDex`),
mandates (`MandateWallet.payUnderMandate`); generic saga orchestration **PLANNED** (client-side).

---

## 3. Architecture

### 3.1 Components

| Component | Path | Role | Status |
|---|---|---|---|
| EVM contracts | `smartcontracts/evm/` (Foundry; `src/{common,metatx,factory,dex,wallet,account,registry,zether,hedera,chains}`) | Meta-tx tokens, open factory, DEX, mandate wallet, subject (passkey) account, Zether, account registry; profiles `private9000` (Prague), `zether` (Prague), `gnosis`, `celo` (Cancun) | **BUILT** |
| Hedera contracts | `smartcontracts/evm/src/hedera/` | `HederaMetaToken` (HIP-632 `isAuthorizedRaw` for ED25519 accounts) on HSCS | **BUILT** |
| Cosmos contracts | `smartcontracts/cosmos/` (CosmWasm workspace) | `scaas-token` (CW20 + meta-op), `scaas-mandate`, `scaas-dex`, shared `scaas-metaop` | **BUILT** |
| Soroban contracts | `smartcontracts/soroban/` | SEP-41 token + `pay`, mandate, DEX; native auth as meta-tx (Stellar and Pi) | **BUILT** |
| Move contracts | `smartcontracts/move/{aptos,sui}/` | Package `scaas`: `meta` (per-subject Account + lanes), mandate, DEX | **BUILT** |
| TON contracts | `smartcontracts/ton/` (Tact) | Jetton master/wallet with pubkey + lanes (`SignedTransfer`), mandate, escrow DEX | **BUILT** |
| Solana program | `smartcontracts/solana/` (Anchor) | Program `scaas`: SubjectAccount PDA, `LanePda`, mandate, DEX | **BUILT** |
| Build/test scripts | `smartcontracts/scripts/{build,test,deploy,devnet}.sh <family>`; `scripts/capped` | One entry point per family; heavy runs capped at 4 GB, one at a time | **BUILT** |
| `scaas-node` | `scaas-node/` | Rust relayer: gateway, submit lanes, indexer, drift, DEX venue, admin; mesh envelope library | **BUILT** (Odoo-pulled job source); store/job API/admin auth **SPECIFIED** ([NI](superpowers/specs/2026-10-06-node-independence-design.md)); mesh transports **SPECIFIED** ([MESH](superpowers/specs/2026-10-05-relayer-mesh-design.md), [A2](superpowers/specs/2026-10-06-mesh-gossip-amendment.md)) |
| Node store | (in `scaas-node`) | Jobs, feeds, config authority, credentials, audit, DEX book, mesh tables; SQLite/PostgreSQL/MySQL | **SPECIFIED** (NI §4, A1/R111) |
| `zether-prover` | `zether-prover/` (Rust, `cdylib`+`rlib`, WASM) | Keygen (EIP-2333 paths), ElGamal, Σ + Bulletproofs (n=64), disclosure openings, BSGS, `zether-cli`, `zether-read-balance` | **BUILT** (unaudited) |
| `clientkeys` | `clientkeys/` (ESM, `@noble`/`@scure`) | Passkey signer, 24-word seed vault, Zether conf keys and balance cache; bundle vendored into `dms_blockchain_bridge/static/lib/clientkeys` | **BUILT** (EVM-centric; Soroban/Aptos/Solana signers queued) |
| `app/` | `scaas/app/` (React + Vite) | Console and dApp: contracts, wallets, DEX book, Zether, node admin (built-in login or OIDC) | **PLANNED** (requirements NI §7.7, A2 §13.2) |
| Odoo client | `bamboo-dms/dms_blockchain`, `dms_blockchain_payment`, `dms_blockchain_bridge`, `dms_blockchain_dex` | One ERP client: outbox, payment provider `chain`, portal facade, DEX accounting | **BUILT** (pull model); push client **SPECIFIED** (NI §10) |
| CI | `.github/workflows/ci.yml` (`scaas-ci`) | forge test (pinned OZ v5.2.0, forge-std v1.16.2), `private9000` build, cargo clippy `-D warnings`, cargo test, EVM e2e on anvil | **BUILT**; CI for prover, clientkeys and non-EVM e2e **PLANNED** |

### 3.2 Node roles (one binary, modules switched in config)

| Role | What it does | Listener | Status |
|---|---|---|---|
| **gateway** (door A) | Public intake of signed meta-txs and DEX orders from anyone; normalize (R84), simulate, enqueue | `[modules] gateway_bind` (default `127.0.0.1:8547`), auth `none` (loopback only) / `bearer` / `hmac` (R54) | **BUILT**; durable, journaled door A **SPECIFIED** (NI §9.1) |
| **job API** | Machine clients push jobs, cancel, read feeds, push watch lists and token subsets | `[api] bind` (default `127.0.0.1:8547` in NI, which collides with the gateway default — §15.3), HMAC per key (R92) | **SPECIFIED** (NI §5) |
| **submit** | Per-chain lanes: lease → simulate → journal → sign → broadcast → follow → replace/gap-fill; consumption checks | — | **BUILT** |
| **indexer** | Finality gate + RPC quorum → normalized events → (today) Odoo `chain_event_ingest`, (target) `feed_item(range)`; drift A/C | — | **BUILT** (Odoo sink); feed **SPECIFIED** (NI §6) |
| **dex venue** | Price-time order book per market (limit, IOC, FOK, partial fills), settle jobs, final-event watcher | gateway `/v1/dex/*` | **BUILT** (book persisted in Odoo); store-backed **SPECIFIED** (R105) |
| **mesh** | Envelope `scaas-intent/1.2`, acceptance policy, store, exclusivity, pull bus, gossip, hints, announces, DEX book replication | `[mesh] bind` (HTTPS mTLS), `[gossip] listen` (QUIC/TCP) | Envelope/digest/accept/hubsig/export library **BUILT** (S3, 43 vectors); transports and pipeline **SPECIFIED** |
| **admin** | `/healthz`, `/readyz`, `/metrics` (open); `/v1/admin/*` (roles) | `[modules] admin_bind` (default `127.0.0.1:9108`) | health/metrics **BUILT** (R51); admin API **SPECIFIED** (NI §7) |

Shapes: full node (all roles), mesh relayer (submit + mesh), forwarder (mesh only) — MESH §3.1 as amended by NI
(every shape is ERP-free).

### 3.3 Target topology

```
                         OIDC IdP (optional)                       Prometheus
                                │ JWT                                   │ scrape
 app/ (React+Vite) ── login/session/JWT ──► admin API ─────────────┐   │
 automation ───────── admin key scaas_ak1. ─► admin API            │   ▼
 host shell ───────── scaas-node admin …  (CLI writes the store)   │  /healthz /readyz /metrics
                                                                    │
 ERP (Odoo, SAP, …)                                                 │        scaas-node
   outbox ─ push cron ── HMAC key ─► POST /v1/jobs, cancel, PUT /v1/watch, /v1/tokens
   sync cron ─────────── HMAC key ─► GET /v1/jobs?cursor=   GET /v1/events?cursor=
                                                                    │   ┌──────────────────────────┐
 wallets / partners / agents ─► gateway POST /v1/metatx, /v1/dex/* ─┼──►│ accept → store (job,     │
                                                                    │   │ job_event, feed_item,    │
 admitted peers ── HTTPS mTLS (X25519MLKEM768) /v1/mesh/* ─────────┼──►│ chain, token, lane,      │
               └── QUIC /scaas/bus/1.2 ────────────────────────────┤   │ namespace, keys, audit,  │
 open mesh ─────── libp2p gossipsub over QUIC (PQ) or TCP+Noise ────┘   │ dex_*, intent, gossip_*) │
                                                                        └─────┬───────────┬────────┘
                                          lanes (submit / lane_runner)        │           │ indexer
                                                                              ▼           ▲
                                         EVM · Hedera · Cosmos · Soroban · Aptos · Sui · TON · Solana RPC
```

Today (BUILT) the node instead pulls work from Odoo (`relay_poll`/`relay_claim`/`relay_report` over `/json/2`) and
writes indexed ranges to Odoo (`chain_event_ingest`). The transition is a per-chain flag `node_transport ∈
pull|push`, a transitional binary running both paths, and one-step removal of the pull path (R104, stream P9).

### 3.4 Data flows

**F1 — Client payment (push model, SPECIFIED; pull model BUILT):** client builds typed data (`pay(entryRef)` op,
server-chosen `validUntil`) → subject signs on device → client verifies the signature, writes outbox row in the
business transaction → push cron `POST /v1/jobs` (idempotent) → node accept (digest recomputed, token registered,
normalization) → lane leases, simulates, journals `signed`, broadcasts → receipt `mined` → indexer range final →
feed `range` with `PaymentSettled(entryRef)` → client books the payment.

**F2 — Door A (BUILT):** anyone posts `{chain, token, m, signature}` to `/v1/metatx` → breaker → normalize →
simulate → `metaTxDigest` → lane queue → same submit path.

**F3 — DEX (BUILT):** maker/taker orders signed over the DEX domain → `/v1/dex/orders` → venue book → match →
settle job (`call`) → `OrderBookDex.settle` → `OrderFilled`/`Matched` → watcher → accounting mirror.

**F4 — Mesh (SPECIFIED):** origin wraps a bus-eligible intent in `scaas-intent/1.2`, signs `hub.sig`, optionally
assigns `exclusive` → peers pull (bus) or receive (gossip) → `accept()` L0–L3 → store → scheduler → job in `~mesh` →
submit. Landed hints trigger consumption reads (R122).

**F5 — Confidential payment (BUILT on dev chains only):** prover builds statement + Σ + two Bulletproofs bound to
the envelope → meta-tx with `OP_ZTRANSFER` → `ZetherToken` verifies → `ConfidentialTransfer(entryRef)` → disclosure
via `ITransferDisclosure` for reconciliation.

### 3.5 Trust boundaries

| Boundary | Crossing | Control |
|---|---|---|
| Subject device ↔ everything | Signatures only; keys never leave (seed, passkey, Zether `x`) | R31, R32, R33 |
| Client ↔ node job API | HMAC per key, namespace-scoped, idempotent | R91, R92, R109 |
| Operator ↔ node admin | Built-in users (Argon2id), admin keys, optional OIDC; roles; audit | R106–R110 |
| Anyone ↔ gateway | Optional bearer/HMAC; body cap 64 KiB; concurrency 32; simulate before queue; reverse proxy rate limit (HANDOFF O5) | R54 |
| Node ↔ peers | Bus: SPKI-pinned mTLS or QUIC, admission per request; gossip: scoring, rate limits, validation | R72, R113, R118, R119 |
| Node ↔ chain | Simulation gate, finality gate + RPC quorum, breakers | R11, R55 |
| Contract ↔ caller | Signature, lane nonce, expiry, mode, fee cap, contract-only allowance | §4.4, §5 |
| Node ↔ secrets | Toml/keystores only; the store holds no secret | R92, R95 |

The node is trusted for **liveness and for the truth of the event feed it serves** (a compromised node can lie on
`/v1/events`; NI T7). It is never trusted with subject funds or subject keys. A second independent event source is
deferred (NI §18.3).

---

## 4. Token system

### 4.1 Hierarchy

```
IERC20
 └── IERC20MetaTx                         base: every token is gasless (§5)
      ├── IERC20Payment                   public payment: payWithFee, PaymentSettled(entryRef)
      │    ├── MetaToken v1 (kind META)   tier 1 standalone / tier 2 single-underlying wrapper   BUILT
      │    │    └── HederaMetaToken       + HIP-632 ED25519 signatures, HTS association          BUILT
      │    └── MetaTokenBase v2           + mtxTransfer/…WithFee/mtxPay/mtxBatch (§5.8)          BUILT (TW2 T1–T6)
      │         ├── NoUnderlyingToken     (kind META_NONE)   tier 1
      │         └── SingleUnderlyingToken (kind META_SINGLE) tier 2, rate (num/den), reserve
      │              └── MultiUnderlyingToken (kind META_MULTI) tier 3, 2–8 underlyings, guardian
      │         (+ Hedera children of each v2 tier: HederaNo/Single/MultiUnderlyingToken)         BUILT
      ├── IZetherToken + ITransferDisclosure
      │    └── ZetherToken v1 (kind ZETHER, dev chains only)                                    BUILT (unaudited)
      └── IRegulatedToken                 controlled class (court orders, CBDC)                SPECIFIED (AS §3)
```

Zether is a **child** of the meta-tx layer, not a parallel branch: every confidential token is relayable through
the same envelope (owner decision, canon). Non-EVM families implement the same roles natively (§7).

### 4.2 Three tiers

| Tier | Contract | `underlying` | Supply rule | Invariant | Status |
|---|---|---|---|---|---|
| 1 Standalone (loyalty, internal units, access tokens) | v1 `MetaToken`; v2 `NoUnderlyingToken` (`META_NONE`) | `address(0)` | `initialSupply` minted to `creator` at init; `mint(to, v)` by `minter` only (`minter = 0` ⇒ fixed supply); v2 adds holder `burn` and one-way `renounceMinter` (R141) | `Σ balances == totalSupply` | v1 and v2 **BUILT** ([TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md)) |
| 2 Single-underlying wrapper | v1 `MetaToken`; v2 `SingleUnderlyingToken` (`META_SINGLE`) | ERC-20 address | Only via `wrap(amount)` (mints `⌊received·num/den⌋` of the **measured** delta) / `unwrap(wrapped, recipient)` (pays `⌊w·den/num⌋`, burns `⌈out·num/den⌉`); v1 is the 1:1 case | v1: `underlying.balanceOf(this) ≥ totalSupply`; v2: `Σ⌊reserve·num/den⌋ ≥ totalSupply` with internal `reserve` (R134) | v1 **BUILT** at 1:1; v2 with rates **BUILT** (R133, R135) |
| 3 Multi-underlying (any-of) | v2 `MultiUnderlyingToken is SingleUnderlyingToken` (`META_MULTI`) | 2–8 ERC-20s, fixed at creation | `wrap(u, amount)` on one chosen leg at that leg's rate; `unwrap(u, wrapped, recipient)` into one chosen leg, bounded by `reserve_u`; guardian may only `disableWrap(u)` (one-way; unwrap stays open) | `Σ_i⌊reserve_i·num_i/den_i⌋ ≥ totalSupply` (pooled; no per-leg invariant) | **BUILT** (R136, v2) |

**Conversion rates (v2, R133/R135).** `(num, den)` per underlying, `uint96`, wrapped raw units per underlying raw
unit; every output rounds in the contract's favour; zero outputs revert. The issuer chooses at creation: **fixed**
(default, no setter) or **adjustable** by a `rateAdmin` (has code; should be a multisig/timelock) through a timelock
(default 7 days, [2, 30] days), ≤ `maxRateStepBps` per step (default 1 %, ≤ 10 %), **executed only by the
`rateAdmin`** within a 7-day window; one pending change per token, and while it is pending **wrap is paused on every
leg** (unwrap stays open, with `minOut`); execution requires real balances `≥` reserves on every leg and the
invariant afterwards; balances never rebase; the admin can renounce, not transfer. Multi-underlying legs may be
adjustable too (default off, R147). Residual risk, stated plainly: a per-leg change still shifts value between
holders who exit through different legs (an off-market leg is an arbitrage from the next transaction on); the
guards remove the front-run and the third-party same-transaction drain, not that shift. Fixed rates, or a
multisig/timelocked `rateAdmin` that only re-pegs toward market, are recommended ([TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §8.5). **Gasless unwrap**
(R148): meta-tx op `unwrap(address underlying, address recipient, uint256 minOut)` (`value` = wrapped units, fee in
wrapped units before the burn; burn and reserve debit before the underlying transfer, exact-amount check) and
`mtxUnwrap`/`mtxUnwrapWithFee`; gasless wrap
via EIP-2612/Permit2 is PLANNED (R149). Decimals are display only (issuer's choice; human rate = `num/den × 10^(D − d_i)`). A multi-underlying token
concentrates on its weakest underlying during a depeg (good legs drain first); `disableWrap` stops inflow, not exits
([TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §8.4).

`initData`: v1 `abi.encode(string name, string symbol, uint8 decimals, uint256 initialSupply, address minter)` (tier
2 ignores `decimals`); v2 per kind in [TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §4, §5.1, §8.1. Fee-on-transfer underlyings are measured on the way in
and must transfer exactly on the way out; rebasing underlyings are unsupported (a negative rebase stops wrap, exits
stay first-come); Zether refuses fee-on-transfer underlyings (`UnsupportedUnderlying`, RS2-15). Weighted baskets
(proportional redemption) are not planned (research §1.7.6).

### 4.3 Open factory and EIP-1167 clones (BUILT)

- **No proxy upgrades anywhere** (no UUPS, Transparent, Beacon or Diamond). Each implementation version is deployed
  once; every token is a 45-byte EIP-1167 clone (`363d3d373d3d3d363d73<impl>5af43d82803e903d91602b57fd5bf3`) that
  `DELEGATECALL`s it with its own storage. A clone costs ~45 000 gas instead of ~2.5 M.
- **Versions live in the factory**: `registerImplementation(kind, version, impl)` (registrar only, append-only,
  version 0 forbidden), `deprecate` marks but never blocks, `createUnregistered` deploys an off-catalogue
  implementation with `version() == 0` (visibly). A bug in v1 is permanent for v1 tokens; the remedy is voluntary
  migration (unwrap v1, wrap v2).
- **Provenance instead of gatekeeping**: anyone creates tokens; `getWrapper(creator, underlying)` is keyed by the
  pair, so two creators wrapping the same asset get two valid addresses; `factory()`, `creator()`, `underlying()`,
  `verifier()`, `implementation()`, `version()`, `isDeployedHere(token)` are public and immutable.
- **Atomic init**: CREATE2 salt = `keccak256(abi.encode(msg.sender, salt))` (nobody can take another creator's
  address); `initialize` runs in the same call and requires `msg.sender == FACTORY`; implementations lock themselves
  in the constructor (T9, T10).
- **Zether gate**: `zetherEnabled` default `false`; enabling and creating Zether tokens revert outside chain ids
  31337/1337 (`ZetherSafety`, RS2-1).
- **Factory v2** (R130, [TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §9, **BUILT**: `src/factory/OpenFactoryV2.sol`): a new deployment (v1's enum cannot
  decode new kinds); `IOpenFactoryV2.TokenKind` appends `META_NONE`, `META_SINGLE`, `META_MULTI` (`IOpenFactory.sol`
  stays frozen with v1 so the deployed v1 factory remains source-verifiable); `createTiered(kind, version, underlyings[], initData,
  salt)` / `createTieredUnregistered`; registration checks the implementation's `tokenKind()`; every underlying is
  indexed for provenance. v1 tokens stay on factory v1. The only token-level powers in v2 are creation-time and
  public: an adjustable-rate `rateAdmin` and the multi-underlying `guardian` (R142).
- **Registrar** is an EOA by default (deployer); it must become a multisig before mainnet (HANDOFF O2). Its only
  powers are `registerImplementation`, `deprecate`, `setZetherEnabled`.

EIP-712 domains: name per implementation (`"SCaaS MetaToken"`, `"SCaaS ZetherToken"`, `"SCaaS MandateWallet"`,
`"SCaaS SubjectAccount"`, `"SCaaS OrderBookDex"`), version `"1"` (`"2"` for the v2 tiers, R131), `chainId`,
`verifyingContract` = the clone itself. All clones share the name; replay safety comes from `verifyingContract`
(R5). Clients read `eip712Domain()` (ERC-5267).

### 4.4 Allowance lockdown invariant (BUILT, R26)

Owner ruling (supersedes R4 and the SRS "EOA caller" form): **an `approve`/allowance spender must be a contract,
and only a contract may call `transferFrom`. An EOA is never a spender.** Enforced in the token code of every
family:

| Case | `code.length` | Treated as |
|---|---|---|
| Plain EOA | 0 | EOA |
| EOA with an EIP-7702 delegation (`0xef0100 ‖ addr`, 23 bytes) | 23 | **EOA** (its private key still signs anything) |
| Contract during its constructor | 0 | **EOA** (cannot be approved or spend allowance from its own constructor) |
| Deployed contract | > 0, not a designator | contract |

- EVM `ERC20MetaTx`: `approve` reverts `SpenderNotContract(spender)`; `transferFrom` reverts
  `CallerNotContract(caller)` **before** the allowance check. No `permit`, no `increaseAllowance`: there is no second
  door. A subject grants an allowance through the meta-tx op `approve(address spender, uint256)` (value 0, `to ==
  spender`, spender a contract) — used by `OrderBookDex`.
- Soroban `approve` → `require_contract(spender)`; Cosmos `IncreaseAllowance` only for contract spenders and
  `TransferFrom` only from contracts; Move/TON/Solana have no allowance on the hot path (balances live in the
  subject's account object/wallet/PDA, moved only by subject-signed ops).
- Hedera HTS allowances at protocol level cannot be restricted; HTS tokens are used only through a tier-2 wrapper
  (R63).
- **Agents never sign allowances.** Spending authority is expressed as exact-amount, expiring meta-tx signatures or
  as an on-chain mandate (§4.7).

### 4.5 Permissionless vs controlled tokens

| | Permissionless (uncontrolled) | Controlled / regulated |
|---|---|---|
| Contract | `MetaToken`, `ZetherToken` clones | `IRegulatedToken` implementations (separate kind in the factory catalogue) |
| Admin powers | None: no owner, pause, blacklist, freeze, confiscation, arbitrary mint (v2 exceptions, chosen at creation and public: an adjustable-rate `rateAdmin` and the multi-underlying `guardian`, R142) | Freeze, unfreeze, forced transfer, court-ordered burn — **only** with a ruling reference and a multisig quorum |
| Use | Loyalty, internal units, B2B settlement tokens, wrapped stablecoins | Central-bank digital currency, licensed stablecoins, digital securities and bonds, real-world-asset claims |
| Guarantee | "Your key, your funds": neither the issuer nor the factory can touch balances | Due-process intervention, permanently evidenced on chain |
| Status | **BUILT** | **SPECIFIED** ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §3) |

**Controlled-token rules (normative for the future implementation):**

1. Every intervention takes `bytes32 courtRulingId` = `keccak256` of the authority's canonical ruling identifier
   (the document stays off chain) and emits an indexed event.
2. The intervention role is a contract (`ECDSA_MULTISIG` / Safe), never an EOA; default quorum 3-of-5 with seats for
   the issuer's legal/compliance function, finance, internal audit or custodian bank, and the supervising authority.
3. Freezing blocks outgoing transfers and meta-tx execution from the account; incoming credits remain possible
   (funds are never lost by the act of freezing).
4. `judicialForceTransfer` and `courtOrderBurn` respect the reserve invariant of a wrapper (a burn of wrapped units
   releases the corresponding underlying to the designated recipient).
5. `pause` (if offered) is bounded: `MAX_PAUSE = 7 days`, after which redeem/withdraw reopen automatically; exits
   are never blocked indefinitely (canon §1.10).
6. Zether-side: a confidential balance can be frozen (stuck) but not seized on public chains; seizure is only
   available on a private chain by a validator-witnessed forced transfer (canon §1.10.3).
7. Compliance gate for transfers of securities: `checkTransferCompliant(from, to, amount)` consults the account
   registry (accredited/KYC flags, holding limits); failures revert with a reason code.

Proposed interface: §14.6.

### 4.6 Vesting and streaming funds (SPECIFIED, [AS](superpowers/specs/2026-10-06-asset-suite-design.md) §4)

`VestingVault`: a single contract holding many streams; deposits through the meta-tx `approve` op to the vault
(contract spender, §4.4) or by direct transfer.

- Stream: `{token, sender, recipient, totalAmount, startTime, cliffTime, stopTime, amountWithdrawn, revocable}`.
- Vested amount at `t`: `0` if `t < cliffTime`; `totalAmount` if `t ≥ stopTime`; otherwise
  `totalAmount × (t − startTime) / (stopTime − startTime)` (integer floor).
- `withdrawVested(streamId, amount)` by the recipient — callable as a meta-tx (gasless for the recipient).
- `revoke(streamId)` (sender, only if `revocable`): pays out the vested part to the recipient and returns the
  unvested part to the sender in one transaction.
- Uses: streaming payroll, equity incentive vesting (e.g. 12-month cliff, 48-month linear), milestone grants
  released by an approver signature.
- Invariant: `token.balanceOf(vault) ≥ Σ_streams (totalAmount − amountWithdrawn)` for vault-held streams.

Proposed interface: §14.8.

### 4.7 Mandates (BUILT)

`MandateWallet` (one per payer, owner = the payer's EOA; R25, R29): the wallet holds the funds, implements ERC-1271
for its owner, and stores per-token mandates `{delegate, expiry, periodSeconds, periodStart, maxPerPayment,
maxPerPeriod, spentInPeriod}` plus allowed payees. `payUnderMandate(token, payee, amount, entryRef, validUntil,
sig)` checks not revoked, not expired, payee allowed, per-payment cap, per-period cap, `entryRef` unused and the
delegate's EIP-712 signature (`PayUnderMandate(address token,address payee,uint256 amount,bytes32 entryRef,uint256
validUntil)`), then pays through `payWithFee(FeeMode.NONE)` — no allowance. Kill switch: `revoke(token)` by the owner
or `revokeWithSig` by the delegate (platform revokes immediately through a relayer). Equivalent mandates exist on
Cosmos, Soroban, Sui, Aptos, TON and Solana.

### 4.8 Equity and bonds on a managed DEX (SPECIFIED, [AS](superpowers/specs/2026-10-06-asset-suite-design.md) §5–§8)

- Securities are controlled tokens (§4.5) with transfer compliance; bonds add a coupon schedule
  (`couponDates[]`, `couponRatePpm`, `maturity`) paid by a `CouponPayer` contract funded by the issuer, and principal
  redemption at maturity by burn-for-payout.
- A **managed DEX** is an `OrderBookDex` deployment whose markets list only compliant pairs and whose settlement calls
  the token's compliance check for both parties before any transfer; the operator of the venue is the licensed party
  (the `OrderBookDex.admin`, a multisig). The existing DEX already provides signed limit orders, price-time priority
  off chain, partial fills, IOC/FOK, `filled[orderHash]` and per-market fees capped at 1 % (§10 of
  [DEX](superpowers/specs/2026-10-03-dex-design.md)).

### 4.9 Open Asset Tokenization Suite (SPECIFIED as a product, [AS](superpowers/specs/2026-10-06-asset-suite-design.md); primitives BUILT)

A configuration wizard (in `app/` and any ERP) on top of `IOpenFactory`. Templates:

| Template | Factory call | Parameters | Status of primitive |
|---|---|---|---|
| Loyalty / rewards | `createMetaToken(1, 0, initData, salt)` | name, symbol, decimals, `minter` = issuer's mint contract or treasury multisig, fee 0 | **BUILT** |
| Internal 1:1 money | `createMetaToken(1, underlying, …)` | underlying stablecoin; wrap/unwrap through the clone | **BUILT** |
| Wrapper with a rate | `createTiered(META_SINGLE, …)` | underlying, `num/den`, fixed or adjustable (admin, delay, step) | **SPECIFIED** (TW2) |
| Confidential money | `createZetherToken(1, underlying, verifier, initData, salt)` | `registry`, `shieldScale`, `maxDecryptableShielded ≤ 2^54`, `confidentialFee`, auditor key | **BUILT** (dev chains only) |
| Multi-underlying money (e.g. xDAI/USDC/USDT) | `createTiered(META_MULTI, …)` | 2–8 underlyings, per-leg rates, guardian | **SPECIFIED** (TW2) |
| Vesting / streaming | `VestingVault` | cliff, duration, interval, revocability | **SPECIFIED** ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §4) |
| Controlled / security / bond | `IRegulatedToken` kind | quorum members, compliance registry, coupon schedule | **SPECIFIED** ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §3, §7) |
| Non-fungible in-app assets (ERC-721/1155 with meta-tx) | new kinds | — | **PLANNED** |

Provenance metadata published for every asset: `creator`, `underlying`, `version`, `implementation`, creation block
(issuance timestamp), and for wrappers the live reserve `underlying.balanceOf(token)` — readable by anyone for free.

---

## 5. Meta-transaction layer

### 5.1 Native mixin, no forwarder (BUILT)

Meta-transaction logic is embedded in every token (`ERC20MetaTx`), not in a forwarder. The subject signs EIP-712
typed data whose `verifyingContract` **is the token**. There is no ERC-2771 trusted forwarder (no `_msgSender()`
suffix, no 63/64 gas rule, no return bomb), and no ERC-4337 bundler/paymaster dependency for token operations.
Smart-contract wallets (ERC-1271, `AuthScheme 7`) are first-class signers.

### 5.2 `MetaTransaction` and the pinned typehash (BUILT)

```solidity
struct MetaTransaction {
    address from;          // signer; balance affected
    address to;            // recipient / op target on this token
    uint256 value;         // amount (0 for pure logic ops)
    bytes   data;          // op: empty = transfer; pay(bytes32); trade(...); approve(...); Zether ops
    uint256 batch;         // nonce dimension 1: the subject lane
    uint256 nonce;         // nonce dimension 2: sequence inside the lane
    uint256 validUntil;    // unix seconds
    uint32  mode;          // constraint flags + fee mode (§5.3)
    address relayer;       // bound relayer when MODE_RESTRICT_RELAYER
    uint256 fee;           // ppm (PERCENT) | absolute units (FIXED) | 0 (NONE)
    address feeRecipient;  // bound fee recipient when MODE_RESTRICT_FEE_RECIPIENT
}

bytes32 constant METATX_TYPEHASH = keccak256(
  "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,"
  "uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");

hashStruct(m) = keccak256(abi.encode(METATX_TYPEHASH, m.from, m.to, m.value, keccak256(m.data), m.batch, m.nonce,
                                     m.validUntil, m.mode, canonRelayer, m.fee, canonFeeRecipient))
digest        = keccak256(0x1901 ‖ domainSeparator(name, "1", chainId, token) ‖ hashStruct(m))
```

`data` is always hashed (`keccak256(m.data)`) — encoding dynamic bytes directly would break injectivity. The
typehash is pinned by `test_metaTxTypehashIsPinned`; the digest is cross-checked by one KAT
(`smartcontracts/evm/test/vectors/metatx_kat.json`, key `0xA11CE`) in Solidity, Rust (node), Python (Odoo
`lib/eip712.py`) and the wallet's own typed-data hashing (PD §6).

### 5.3 `mode` bitmask, canonical zeroing, R84 normalization (BUILT)

```
bit  31 ........................ 8 | 7  6  5  4 | 3  2  1  0
     reserved (must be 0)           | FEE MODE   | FLAGS
```

| Name | Value | Kind | Meaning |
|---|---|---|---|
| `MODE_OPEN` | `0x00` | — | No constraints, no fee |
| `MODE_RESTRICT_RELAYER` | `0x01` | flag | Only `msg.sender == m.relayer` may execute |
| `MODE_RESTRICT_FEE_RECIPIENT` | `0x02` | flag | The fee must go to `m.feeRecipient` |
| bits 2–3 | `0x04`, `0x08` | flags | Reserved, must be 0 |
| `MODE_FEE_NONE` | `0x00` | enum (bits 4–7) | No fee |
| `MODE_FEE_PERCENT` | `0x10` | enum | `fee` in ppm of `value` |
| `MODE_FEE_FIXED` | `0x20` | enum | `fee` in token units |
| `MODE_FLAGS_MASK` / `MODE_FEE_MASK` / `MODE_KNOWN_MASK` | `0x0F` / `0xF0` / `0xF3` | masks | `supportedModes()` returns `0xF3` |

Fee mode is an **enumerated nibble**, not flags: `mode & MODE_FEE_PERCENT` is a bug; use `feeModeOf(mode)` (values
0/1/2, otherwise `ModeFeeInvalid`). Unknown bits ⇒ `ModeUnknownBits` (`MetaTxUnknownMode`).

**Canonical zeroing:** when `MODE_RESTRICT_RELAYER` is off, `relayer` is hashed as `address(0)`; when
`MODE_RESTRICT_FEE_RECIPIENT` is off, `feeRecipient` is hashed as `address(0)` (`MetaTxLib.canon`). The struct keeps
both fields (removing them would change the typehash). Identical rule in contract, node, Odoo and client SDKs.

**R84/R100 normalization (submitter side):** because unbound fields are not signed but `ERC20MetaTx` pays a non-zero
`m.feeRecipient`, every submitter rewrites unbound fields before building the outer transaction: unbound
`feeRecipient := chains.fee_recipient` (the operator's cold wallet) or `0` (then the fee goes to `msg.sender`, the
lane); unbound `relayer := 0`. Wire values of unbound fields are never submitted. `intent_id` is unchanged. BUILT in
the gateway (stream S0); all origins SPECIFIED (R100).

### 5.4 Two branches: generic meta-tx vs token-specific fast path

| Branch | Entry | Use | Status |
|---|---|---|---|
| Generic | `executeMetaTransaction(m, signature)` with an op in `m.data` | Every subject-signed token operation; composable ops | **BUILT** |
| Payment op | `data = pay(bytes32 entryRef)` (exactly 36 bytes, `to ≠ 0`) through the generic path | Invoice/order payment with a reconciliation reference; emits `PaymentSettled(from, to, amount, feeAmount, feeRecipient, entryRef)` | **BUILT** (R2) |
| Direct payment | `payWithFee(to, amount, feeMode, fee, feeRecipient, entryRef)` — `msg.sender` pays gas; fee charged on top | Contract wallets (MandateWallet), self-submitted payments | **BUILT** |
| Named entry points (v2) | `mtxTransfer`, `mtxTransferWithFee`, `executeMetaTransactionWithFee`, `mtxPay(…, payId, …)`, `mtxUnwrap`, `mtxUnwrapWithFee` — build the same struct, same digest (§5.8) | Typed ABI for wallets/explorers; on-chain pay lane | **BUILT** (R138, R139; `mtxUnwrapWithFee` is decoded in the token's `fallback`, ABI `IMetaTokenV2UnwrapWithFee`) |
| Batch (v2) | `mtxBatch(MetaTransaction[], bytes[])`, atomic | Saves the 21 000 intrinsic gas per item after the first (TW2 §10.3, L3) | **BUILT** (R140); node batching **SPECIFIED** (TW2 §7.5) |
| Zether ops | `OP_ZTRANSFER`, `OP_ZBURN` inside the envelope (§8.8) | Confidential transfer/burn | **BUILT** (dev chains) |

Op table of `MetaToken` (`_checkOp` at step 6 must not fail later at step 8):

| `data` | Length | Checked at step 6 | Executed at step 8 |
|---|---|---|---|
| empty | 0 | balance (already) | `transfer(from → to, value)` |
| `pay(bytes32 entryRef)` | 36 | `to ≠ 0` (`PayToZero`) | transfer + `PaymentSettled` with the real fee |
| `trade(address counterToken, uint256 minCounterValue, address counterparty)` | 100 | `MODE_RESTRICT_RELAYER` set **and** `to == msg.sender` (`TradeLegNotRestricted`) | transfer `from → msg.sender` (the settlement contract) |
| `approve(address spender, uint256 amount)` | 68 | `value == 0`, `to == spender`, spender is a contract | set allowance |
| `unwrap(address underlying, address recipient, uint256 minOut)` (v2 wrapper tiers, BUILT, R148) | 100 | leg known, `to == recipient ∉ {0, token}`, `minOut ≤ out ≤ reserve`, `out > 0` | burn `⌈out·q⌉`, debit reserve, then transfer `out` of the underlying (exact amount); only this transfer may revert after step 7, and it reverts the whole tx |
| other | — | `MetaTxUnknownOp(bytes4)`; `< 4` bytes ⇒ `MetaTxUnknownOp(0)` | — |

### 5.5 2D nonces and batch lanes (BUILT)

Storage `_metaNonce[from][batch]`; an intent is valid iff `m.nonce == metaNonce(from, batch)`; execution increments
it. Independent lanes remove head-of-line blocking between agents and between business flows of the same subject.

| Lane derivation | Rule | Status |
|---|---|---|
| Payment request | `batch = keccak256("scaas.pay.lane" ‖ entryRef)`, `nonce = 0` ⇒ each request is payable at most once and the client can build typed data without reading the chain; v2 `mtxPay` derives the same lane on chain (`payLane(payId)`) | **BUILT** (R9); on-chain derivation **SPECIFIED** (R139) |
| Agent × purpose | `batch = uint256(keccak256(agentId ‖ purpose))` (e.g. procurement settlement, logistics milestones, payout distribution, treasury rebalance), sequential nonce inside | **SPECIFIED** here (client convention) |
| Non-EVM | `(subject, lane: bytes32) → nonce: u64` in the subject's account object/wallet/PDA (§7) | **BUILT** |

`cancelMetaNonce(batch)` (direct call by the subject) increments `metaNonce[msg.sender][batch]` and invalidates every
pending intent on that lane, including ones circulating on the mesh, without a dummy transfer. First use of a lane
costs ≈ +17 k gas (new storage slot). Anti-lock test per family is mandatory: X stuck on contract 1 never blocks Y on
contract 2 (R62).

### 5.6 Cheap-first execution pipeline (BUILT; the SRS "8 steps" are steps 1–8 below, step 9 is the nonce increment and event)

`executeMetaTransaction` (not payable), reentrancy guard in transient storage
(`keccak256("scaas.metatx.reentrancy.v1")`; v2: `…reentrancy.v2`):

| Step | Check / action | Cost class | Error |
|---|---|---|---|
| 1 | `MODE_RESTRICT_RELAYER` ⇒ `msg.sender == m.relayer` | no SLOAD | `MetaTxUnauthorizedRelayer` |
| 2 | `block.timestamp ≤ m.validUntil` | no SLOAD | `MetaTxExpired` |
| 3 | `validateMode(m.mode)` | no SLOAD | `MetaTxUnknownMode` |
| 4 | `m.nonce == metaNonce(from, batch)` | 1 SLOAD | `MetaTxBadNonce(expected, got)` |
| 5 | Signature over the digest: EOA ⇒ `ECDSA.tryRecover` (65 bytes, low-s); contract ⇒ ERC-1271 `isValidSignature` staticcall (50 000 gas; 400 000 for `SubjectAccount` clones, which verify P-256 in Solidity when no precompile) | ecrecover / call | `MetaTxBadSignature` |
| 6 | Fee computation (`feeRecipient = 0` ⇒ `msg.sender`), `FeePolicy.compute` + `validateRecipient`, balance ≥ value + fee, `_checkOp` | SLOADs | `MetaTxInsufficientForFee`, `FeeExceedsCap`, op errors |
| 7 | Transfer the fee | SSTORE | — |
| 8 | `_executeOp` | SSTORE | — |
| 9 | `nonce++`, emit `MetaTransactionExecuted(from, relayer, batch, nonce, digest, feeRecipient, fee)` | SSTORE | — |

Invariant: **fee collected ⇔ operation completed.** No `try/catch` around the op; any failure reverts everything,
fee not charged, nonce not consumed. Because the nonce check (step 4) precedes the signature (step 5), a relayer that
loses a race pays only ~24–30 k gas.

Measured gas (Foundry `MetaTxGas.t.sol`, EVM Prague, reported in SRS §4.6; envelope overhead also in canon §C7.6):

| Scenario | Execution gas | Full tx gas |
|---|---|---|
| Warm lane, `MODE_OPEN`, no fee | 35 241 | 58 702 |
| New lane (nonce 0 → 1), no fee | 52 341 | 75 802 |
| Warm, `FIXED` fee | 43 565 | 67 362 |
| Warm, `PERCENT` fee | 43 511 | 67 260 |
| Warm, `FIXED` + restricted relayer + fee recipient | 43 763 | 67 560 |
| ERC-1271 signature (basic verifier) | 54 530 | — |
| `cancelMetaNonce` | 27 579 | — |
| Baseline ERC-20 `transfer` | 20 081 | 41 181 |

Envelope overhead ≈ 17.5 k gas; collecting a fee ≈ +8.3 k gas.

### 5.7 FeePolicy (BUILT)

- `enum FeeMode { NONE, PERCENT, FIXED }`; `PPM_DENOMINATOR = 1 000 000`; `MAX_FEE_PPM = 10 000` (1 %) — a protocol
  constant protecting signers, not a governance parameter.
- `compute(PERCENT, amount, fee)`: `fee ≤ MAX_FEE_PPM`, result `amount × fee / 10^6`. `compute(FIXED, amount, fee)`:
  `fee ≤ amount × MAX_FEE_PPM / 10^6` (FIXED is also capped at 1 % of `value` for public tokens). Over the cap ⇒
  `FeeExceedsCap(feeAmount, cap)`.
- `validateRecipient`: non-NONE needs a non-zero recipient (`FeeRecipientRequired`).
- **Fee never to the payee** (owner, R132; v2, **BUILT**): for the transfer and `pay` ops and `payWithFee`, a non-zero
  fee whose resolved recipient equals `to` reverts `FeeRecipientIsPayee` (bound or relayer-default). v1 lacks the check.
- `requireConfidentialSafe`: `PERCENT` on any confidential op ⇒ `PercentFeeForbiddenOnConfidential` (a percentage
  fee would reveal the hidden amount). Zether outer fees are `NONE` or `FIXED`, and `FIXED` there is **not** capped at
  1 % because the amount is hidden (RS2-6).
- DEX fees are separate: per-market maker/taker ppm ≤ 10 000, bounded by the order's signed `maxFeePpm`.

### 5.8 Named meta-tx functions (BUILT, [TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §7; node batching SPECIFIED)

Owner ruling (R138–R140): thin entry points in the v2 `MetaTokenBase` (every tier) that build a `MetaTransaction`
and run the same nine steps. **No second typehash**: the earlier proposal here (`PAY_TYPEHASH`, `batchMtxPay` with a
partial-success bitmap) is withdrawn.

| Function | Struct built | Mode shape (else `MtxModeShape`) |
|---|---|---|
| `mtxTransfer(from, to, amount, batch, nonce, validUntil, mode, relayer, sig)` | `data = ""`, `fee = 0`, `feeRecipient = 0` | only `MODE_RESTRICT_RELAYER` may be set |
| `mtxTransferWithFee(…, mode, relayer, fee, feeRecipient, sig)` | `data = ""` | fee `PERCENT`/`FIXED`, `MODE_RESTRICT_FEE_RECIPIENT` set, `feeRecipient ≠ 0` |
| `executeMetaTransactionWithFee(m, sig)` | `m` (any op) | fee mode ≠ `NONE` (recipient bound or relayer-default) |
| `mtxPay(from, to, amount, payId, validUntil, mode, relayer, fee, feeRecipient, sig)` | `data = pay(payId)`, `batch = payLane(payId)`, `nonce = 0` | any valid mode |
| `mtxUnwrap(from, underlying, wrapped, recipient, minOut, batch, nonce, validUntil, mode, relayer, sig)` / `mtxUnwrapWithFee(…, fee, feeRecipient, sig)` | `to = recipient`, `value = wrapped`, `data = unwrap(underlying, recipient, minOut)` | as `mtxTransfer` / `mtxTransferWithFee` |
| `mtxBatch(MetaTransaction[] ms, bytes[] sigs)` | each item | per item; atomic (one failure reverts all); the node never batches unwrap items |

`payId` is the R9 `entryRef`; `payLane(p) = uint256(keccak256("scaas.pay.lane" ‖ p))`, the lane clients already
derive. A named call and `executeMetaTransaction` with the same struct have the **same digest, events and nonce**: a
signature works on either path and is consumed once; KATs stay valid. The names add a typed ABI, shape guards and
the on-chain pay lane, and save only calldata (R2's ≈ 4 k gas figure assumed a shorter typehash and does not apply).
The node batches per `(chain_key, token)` only items bound to its own lane (flush at 50 items or 3 s; SPECIFIED,
TW2 T7). Measured (`test/v2/MetaTxGasV2.t.sol`, clones, warm lane): `mtxTransfer` ≈ 660 gas and `mtxPay` ≈ 140 gas
below the generic path, `mtxTransferWithFee` ≈ 200 below, `executeMetaTransactionWithFee` ≈ 85 above (dispatch + shape
check); the v2 generic path is ≈ 2.2–3.9 k below v1 on every row. `mtxUnwrapWithFee` has 13 parameters, more than the
non-via-IR ABI decoder holds: the token decodes it in `fallback` (same selector and ABI; interface
`IMetaTokenV2UnwrapWithFee`), and Solidity callers build its calldata by hand.

### 5.9 Payer flexibility

| Model | How | Who pays gas | Status |
|---|---|---|---|
| Sponsored (company relayer) | Subject signs with `MODE_FEE_NONE` + `MODE_RESTRICT_RELAYER` = company lane | Company (OPEX) | **BUILT** (portal default, R10) |
| Fee in token | `MODE_FEE_PERCENT`/`FIXED`, fee ≤ 1 % to `feeRecipient` | Relayer, reimbursed in token | **BUILT** |
| **Payee self-relay / direct settlement** | Payer signs offline (`fee = 0`, relayer unbound or bound to the payee); hands the signature to the payee by QR, NFC, message or file; the payee's wallet submits it, paying gas itself; `PaymentSettled` identical. The signature is an expiring electronic cheque (`validUntil`) | Payee | **BUILT** on contract level (any `msg.sender` may submit an unbound intent); QR/EIP-681 tooling and user `cancelMetaNonce` UI **PLANNED** (HANDOFF #14) |
| **Receiver pays the fee** | Payer signs `pay` of `N`; payee co-signs a fee authorization (`fee`, `feeRecipient`) from its own balance; relayer submits both in one transaction (payer sends `N`, payee receives `N`, pays `fee`) | Relayer, reimbursed by payee | **SPECIFIED** ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §B2: `mtxPayReceiverFee`, payee co-signs `ReceiverFee` over the payer digest; R192–R193) |
| Gas sponsorship policy | Node policy: e.g. "inbound to wallet W, value ≥ X ⇒ accept with fee 0, book gas to account Y" | Sponsor (contract outside the chain) | **SPECIFIED** ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §B1, R189–R191); on-chain `SponsorshipPool` PLANNED-later (§B3) |
| `fee = 0` B2B | Company relayer, `MODE_FEE_NONE`; gas is OPEX | Company | **BUILT** |
| Enterprise inbound gateway | Partners post signed intents to the company's gateway (`POST /v1/metatx`); the company relays with its lanes | Company | **BUILT** (EVM door A) |

Per-family equivalents (subject never pays, relayer lane submits): Hedera — same Solidity on HSCS, no payer-account
sponsorship of subject transactions (R63); Cosmos — relayer lane sends `Relay{payload, auth}`, feegrant only as a
seam for subject-sent deposits, authz never (R66); Soroban — native authorization entries, relayer is source and may
fee-bump other lanes (R65); Sui — relayer lane PTB, sponsored transactions only for subject-sent deposits (R64);
Aptos — relayer lane sequence-number tx, fee-payer/orderless only as a seam for passkey/keyless subjects (RS11);
TON — relayer W5 lane sends `SignedOp` to the payer's jetton wallet, subject W5 gasless not used (R67); Solana —
relayer lane is fee payer, subject signature checked through the Ed25519/Secp256r1 precompile instruction (RS12).

---

## 6. Relayer network

### 6.1 Node invariants (normative)

| # | Invariant | Mechanism | Status |
|---|---|---|---|
| N1 | The node never holds subject funds or subject keys. Lane keys hold gas only. | No allowance to relayers; meta-tx moves only `from → to` as signed | **BUILT** |
| N2 | No broadcast without a committed journal entry (`signed` with lane, outer nonce, tx hash). | Journal-before-send; failure ⇒ retry, nonce not spent (F5/I5) | **BUILT** (journal in Odoo); in store **SPECIFIED** (R88) |
| N3 | No outer nonce is ever abandoned. | Replacement up to the fee cap; expired job ⇒ 0-value self-send gap-filler at that nonce (R18) | **BUILT** |
| N4 | At most one live outer transaction per intent per node. | Per-chain in-flight digest set shared by every lane, gateway and mesh (G2); durable `job_live_digest` UNIQUE index (R89) | set **BUILT**; index **SPECIFIED** |
| N5 | After observing consumption, never bump, resend or re-sign that intent. | Consumption read before every bump/resend and after every reverted receipt; fails closed (R80, G3) | **BUILT** (S2) |
| N6 | A job is never `dead`/`reverted` because someone else landed it. | `consumed` state, then `final` by the indexer or `dead` only if superseded after `valid_until + grace + 1 h` (G6, S1a) | **BUILT** |
| N7 | Wire values of unbound `relayer`/`feeRecipient` are never submitted. | R84 normalization on every origin (R100) | **BUILT** for gateway; all origins **SPECIFIED** |
| N8 | Nothing is booked before finality. | Indexer delivers only final, quorum-agreed, contiguous ranges | **BUILT** |
| N9 | Circuit breakers never block indexing, tracking of signed txs, rescues or gap-fillers. | Breakers gate new work only (R55) | **BUILT** |
| N10 | One owner process per store. | Backend lock + fencing epoch checked in every journal transaction (A1.1) | **SPECIFIED** |

### 6.2 Job lifecycle

**Node job states** (store, NI §4; mirrors Odoo `TRANSITIONS`/`LATE_NOOP`; shared vector `tests/api/transitions.json`):

```
            accept                lease (CAS, lane_hint)         journal (before send)
  (none) ─────────► queued ───────────────────────► leased ─────────────────────► signed ──► broadcast ──► mined
     │ cancel-by-     │  ▲  transient / restart       │                              │  ▲        │           │
     │ origin, no job │  └──────────────────────────── ┘                              │  └ replace┘           │ late receipt
     ▼                │ cancel (never published)                                     │                       ▼
  cancelled ◄─────────┤                                                              ├──► reverted ◄─────────┘
  (tombstone)         │ published + cancel ⇒ stays queued, hold = 1, 409 TOO_LATE    │
                      ├──► dead (expiry before submit, bad payload)                  ├──► dead (expired + gap-filled)
                      │                                                              │
                      └────────────── leased/signed/broadcast ──► consumed ◄─────────┘ (R80 classification)
```

| From | To | Who |
|---|---|---|
| — | `queued` | job API accept, gateway, mesh scheduler, DEX venue |
| — | `cancelled` (kind `tombstone`) | cancel by origin with no job (R98) |
| `queued` (`hold = 0`, past `lease_hold_after_start_secs` = 15 s) | `leased` (lane, `claim_block`, `attempt_count + 1`) | lane scheduler |
| `queued`, `leased` (never published) | `cancelled` | cancel |
| `queued` (published) | `queued` + `hold = 1` | cancel ⇒ `409 TOO_LATE, published: true` |
| `queued`, `leased` | `dead` | expiry before submit; bad payload |
| `leased` | `queued` | transient simulate/fee/RPC error; restart before signing; in flight on another path |
| `leased` | `signed` (+ `outer_nonce`, `tx_hash`, signer; `lane.journal_max` bumped) | **journal, before send** |
| `leased`, `signed`, `broadcast` | `consumed` | R80 |
| `signed`, `broadcast` | `broadcast`, `mined`, `reverted`, `queued` (gap-filled at cold start), `dead` | submit / follow |
| `mined` | `reverted` | late receipt |
| `consumed` | (late `mined`/`reverted`/`consumed` = no-op) | `LATE_NOOP` |

`final` is **not** a node job state: finality is a property of the event feed. A client marks its own job final
when a final `MetaTransactionExecuted(digest)` arrives on `/v1/events` (so a job is also final when someone else
executed it — MODE_OPEN, payee self-relay, mesh peer). Node `cancelled` is reported to Odoo as `dead` with
`error = 'cancelled'`. Terminal rows are purged after 30 d **and** `valid_until < now − 86 400`, so a purged
idempotency key can never be re-accepted.

Status: Odoo-side state machine incl. `consumed` **BUILT** (`dms_blockchain`); node store state machine
**SPECIFIED** (NI §4).

**Consumption classification** (MESH §8.5): EVM/Hedera read `MetaTransactionExecuted` logs for `(token, from,
batch)` from the claim block, pick `nonce == m.nonce`: same digest and relayer ∈ our lanes ⇒ `landed`; same digest,
other relayer ⇒ `landed_elsewhere`; other digest ⇒ `superseded`; no log yet ⇒ `unknown`. Other families report
`unknown` in v1 and resolve at finality. Consumption checks only run while `now ≤ valid_until + clock_skew`
(TON/Solana/Aptos lane nonces may be pruned after expiry). Status **BUILT**.

### 6.3 Nonce journal and restart (`plan()`)

- **Cold start** (`nonce.rs::plan`, BUILT): `next = max(getTransactionCount(pending), journal_max + 1)`. Every
  journaled nonce in `[pending, journal_max]` whose tx is no longer in the mempool is gap-filled (0-value self-send,
  21 000 gas) and its job returns to `queued` (the subject nonce prevents double execution). Jobs `nonce_leased`
  without a tx hash ⇒ `queued`; jobs `signed`/`broadcast` with a hash ⇒ tracked, **never re-signed**.
- **Target** (SPECIFIED, NI §9.2): inputs from the store; `journal_max` = monotonic `lane.journal_max`, bumped in the
  same transaction as `leased → signed`; never an aggregate over purgeable rows. Nonces are `BIGINT` (i64); adapters
  refuse values above `i64::MAX`.
- **Replacement:** stuck after `stuck_after_secs` (default 60) ⇒ same nonce, `maxFee`/`priority` × 1.25 (≥ +1 wei),
  repeated up to `max_fee_cap_gwei` (default 500); at the cap, wait (a same-fee replacement is rejected as
  underpriced).
- **Generic lanes** (non-EVM): one transaction in flight per lane, status poll 500 ms, backoff 1 s → 60 s, expiry
  grace 30 s; Sui additionally journals the last signed tx bytes to `params.lane_journal` and re-sends them on start
  so a gas coin is never equivocated. Solana lanes use a per-lane durable nonce account.
- **Same lane keys in two stores** (forbidden; SPECIFIED NI §9.4): on sequence families, `nonce_at(latest) >
  journal_max + 1 + tracked` ⇒ the lane refuses to lease, `/readyz` reason, metric `scaas_lane_foreign_nonce_total`.

### 6.4 Gas circuit breakers (R55, BUILT)

Per lane, in memory, sampled every 15 s; open breakers stop **new** work only.

| Breaker | Rule | Defaults |
|---|---|---|
| `base_fee_spike` (EVM) | current base fee > `spike_ratio` × 1 h trailing mean, with ≥ 4 samples and fee > `spike_min_base_fee_gwei` | ratio 3.0 (0 disables), min 1 gwei |
| `gas_budget` | gas spent in the fixed hour window ≥ `gas_budget_per_hour` (smallest gas unit) | warn at 90 % |
| `balance_floor` | lane balance < `min_relayer_balance` | warn below 120 % of the floor |
| structural | simulated gas > `max_gas_per_tx` ⇒ job `dead` | 3 000 000 |

Metric `scaas_breaker_open{chain,lane,breaker}`; manual reset
`POST /v1/admin/chains/{key}/breaker/reset` (operator, SPECIFIED).

### 6.5 Simulation gate (BUILT)

Mandatory before signing: EVM `eth_estimateGas` from the lane address (gas used = estimate + 20 %); non-EVM
`ChainAdapter::build` = build + family simulation (`simulateTransaction`, `sui_dryRun`/dev-inspect, Cosmos
`tx/simulate`, Aptos simulate, TON emulation, Solana `simulateTransaction`). Outcomes:

| Simulation result | Job outcome |
|---|---|
| ok | journal + send |
| revert with data, subject nonce consumed | `consumed` (R80) |
| revert with data, not consumed | `dead` with decoded error (`MetaTxBadNonce`, `MetaTxExpired`, …) |
| transport error, timeout, unreadable nonce | `queued` (retry), never `dead` (review P7) |
| gas > `max_gas_per_tx` | `dead` |

SLO W3B-02 requires **0 %** of broadcast transactions to revert for a reason simulation could have caught (§13.1).

### 6.6 Finality gates per family (BUILT)

`finality = {mode, depth, quorum}` per chain; `rpc_urls.len() ≥ quorum` or the node refuses to start; the indexer
advances only when ≥ `quorum` endpoints return the same hash at the candidate head; ranges ≤ 1 000 blocks
(`MAX_SPAN`); `/readyz` fails when `final_head − indexed > max_index_lag` (default 100).

| Family | Mode | Final head | Height unit | Notes |
|---|---|---|---|---|
| EVM private (chain 9000, Clique 1 signer) | `depth`, 1 | `latest − 1` | block | Reorg-free by construction |
| EVM public (Gnosis) | `tag` `finalized`, quorum ≥ 2 | `eth_getBlockByNumber('finalized')` | block | ~160–240 s; quorum 2 required before `active` |
| EVM L2 (Celo OP Stack) | `l1_batch` | L1-finalized batch | block | **PLANNED** (HANDOFF #13); until then `tag` |
| Hedera | `instant` | latest record file via JSON-RPC relay | block | aBFT |
| Cosmos | `instant` | latest committed block (`/status`) | height | CometBFT |
| Soroban (Stellar, Pi) | `instant` | `getLatestLedger` | ledger | SCP closed ledger |
| Sui | `instant` | latest certified checkpoint (quorum on digest) | checkpoint | |
| Aptos | `instant` | committed `block_height` (bounded by indexer progress) | block | AptosBFT |
| TON | `depth`, 0 | `masterchainInfo.last` | masterchain seqno | |
| Solana | `tag` `finalized` | `getSlot(finalized)`, min slot over quorum | slot | ~12.8 s TowerBFT |

Soft finality (booking small amounts before hard finality under an exposure cap) is **PLANNED** and never applies to
payment-bound flows (canon §C10.9).

Chain enablement (owner step O4, PLANNED as tooling): a chain moves `draft → active` only after (1) a working
simulation path, (2) 7 days of measured finality depth on the real network, (3) ≥ 2 independent RPC endpoints for
the quorum.

### 6.7 Mesh

Two transports, one pipeline (R112): the **pull bus** for admitted peers and **libp2p gossipsub** for the open
mesh. Same envelope, same `accept()`, same store, same dedup, same scheduler.

| Aspect | Pull bus (admitted peers) | Open mesh (gossip) |
|---|---|---|
| Admission | Peer row with SPKI SHA-256 pin, class `open`/`private`, allowed chains; checked at handshake **and** per request (R72) | gossipsub v1.1 scoring, graylist/ban, per-source/origin/`from` buckets (R119); Kademlia `/scaas/kad/1.0.0` discovery, toml bootstrap (R120) |
| Carriers | HTTPS mTLS (`/v1/mesh/policy`, `/v1/mesh/intents?since=`) or QUIC `/scaas/bus/1.2`; never TCP+Noise (`TRANSPORT_NOT_PQ`) | QUIC (default) or TCP+Noise+yamux |
| Catch-up | Cursor with `store_id`, overlap 200, page ≤ 200 rows / 1 MiB | `/scaas/sync/1` anti-entropy (R125) |
| Private data | Only private-class peers, only from the origin (R85) | Never (A2 §12) |
| Topics | — | `/scaas/intent/1.2/<chain_key>`, `/scaas/hint/1/<chain_key>`, `/scaas/dex/1/<chain_key>/<dex>/<base>/<quote>`, `/scaas/announce/1` |

**Envelope** `scaas-intent/1.2` (BUILT as library, `src/mesh/`, 43 conformance cases): `spec`, `intent_id`,
`chain_key`, `family`, `contract`, `visibility`, family body (`evm` with domain, 11-field `meta_tx`, signature,
`sig_kind` `eoa|erc1271`; or `op` with exact signed `payload`), `hub{id, pubkey, published_at, sig}`,
`exclusive{relayer_id, until}?`, `hop_count`. `hub.sig` = Ed25519 over the fixed binary `hub_msg` with domain tag
`scaas-hub/v1`, covering `chain_key`, `intent_id`, `body_hash` = SHA-256 of canonical body JSON, `hub.id`,
`published_at`, visibility, exclusive. Receivers recompute `intent_id`, reject unknown majors and 1.0/1.1
(`UNSUPPORTED_SPEC`), cap 32 KiB, `MAX_HOPS = 4`, `max_valid_for_secs = 3600`, clock skew 30 s.

**Acceptance** (MESH §7, BUILT library): L0 shape → L1 hop/dedup/tombstone/rate → L2 digest, expiry, EVM
mode/relayer/low-s, `hub.sig` → L3 private isolation, policy lookup `(contract, selector) > (contract, *) > (*,
selector) > (*, *)`, no row ⇒ `forward_only`; `may_submit` requires `support = full`, `submit`, a **registered token**
(R86), a lane, relayer and effective-fee checks. RPC only on the submit path.

**Families on the mesh v1** (R77): EVM, Hedera, Cosmos, Sui, Aptos, TON, Solana; **Soroban is out** (replay
protection is the host's random auth nonce, not a peer-readable per-subject nonce). Non-EVM op kind: `pay` only.

**Exclusivity** (R74, R121): the origin assigns `exclusive.relayer_id` round-robin over eligible submitters (itself
included); `until = published_at + exclusive_ms` (bus clamp 10 000 ms; gossip default per chain 7 000 ms). Gossip
peers are eligible only with an announce advertising `submit` **and** admin trust or ≥ 3 chain-attributed landings
in 7 days; 3 misses in 1 h ⇒ excluded 1 h. After `until`, any eligible node submits after a deterministic jitter
(`sha256(intent_id ‖ peer_id)` mod 2 000 ms). Exclusivity is a courtesy, not a lock: losers pay one reverted outer
tx (~24–30 k gas) because the token checks the nonce before the signature.

**Private scope:** `chain_profile` default `private`; private-chain or private-visibility rows leave the node only
through `may_export` on the bus, only to admitted private peers allowed for that chain, only from the origin, only
on PQ carriers. `may_gossip` requires `visibility = open`, `profile = public`, `chain.gossip = 1` and an origin of
`gateway` (policy `gossip`) or `job` with `bus_scope = public`; a row pulled from a bus peer is never introduced to
the open mesh.

**Bus scope per job** (R99, A2 §8.4): `restricted` (default; company relayer only, never published), `open`
(admitted bus peers after `private_window_secs`, default 120 s), `public` (also the open mesh). Own outbox jobs are
published without `exclusive`.

**Landed hints** (R122): the lander publishes `scaas-hint/1`; receivers only use it to trigger the R80 consumption
read — a hint never changes state. False hints cost score.

**Announces** (R123): `scaas-announce/1`, signed, strictly increasing `version`, `expires_at ≤ issued_at + 24 h`,
re-published every 10 min; carries the open-peer policy view, chains, lanes with proof of possession
(`secp256k1_sign(keccak256("scaas-lane-pop/1" ‖ chain_key ‖ peer_id))`), DEX homes, endpoints. URLs in announces are
never dialed.

**DEX book gossip** (R124): home-node model — only the node that proves the order's `relayer` matches and settles;
others hold read-only replicas merged by `home_seq` (last-writer-wins) joined with chain facts (`filled = max`,
`closed = or`).

Status: mesh library **BUILT**; bus, gossip, hints, announces, DEX replication **SPECIFIED**
([MESH](superpowers/specs/2026-10-05-relayer-mesh-design.md) rev 3, [A2](superpowers/specs/2026-10-06-mesh-gossip-amendment.md)
rev 1, unreviewed).

### 6.8 Transports and post-quantum key exchange (SPECIFIED, R113–R116)

| Carrier | Default | Key exchange | Carries |
|---|---|---|---|
| libp2p QUIC (`/ip4/…/udp/4001/quic-v1`) | on | **X25519MLKEM768 only** (codepoint `0x11EC`), rustls provider `aws-lc-rs` | gossip, sync, Kademlia, bus `/scaas/bus/1.2` |
| libp2p TCP + Noise XX + yamux | on | X25519 (classical) | open-mesh gossip, sync of public data, identify, ping, Kademlia — **never** bus or private data |
| HTTPS mTLS bus (`[mesh] bind`, default `0.0.0.0:8550`) | on | **X25519MLKEM768 only** | bus `/v1/mesh/*` |

- One process-wide rustls `CryptoProvider` (`aws-lc-rs` + `prefer-post-quantum`), installed once and passed to every
  builder; exactly one provider in use (`cargo tree` check). This reverses MESH §3.4's `ring` choice (R114).
- **One node identity** (R116): Ed25519 seed in `[identity] key`; the same key is the `hub.sig` key, the self-signed
  TLS certificate key, and the libp2p identity. `peer_id = SHA-256(SPKI DER)`; libp2p `PeerId` derived from the same
  public key. Distinct signing contexts: `scaas-hub/v1`, `scaas-announce/ed25519/1`, `scaas-hint/ed25519/1`,
  `scaas-dexbook/ed25519/1`, `scaas-dexhead/ed25519/1`, TLS `CertificateVerify`, `libp2p-tls-handshake:`,
  `noise-libp2p-static-key:`.
- **Limit (stated):** PQ protects recorded traffic against harvest-now-decrypt-later only; authentication remains
  Ed25519. Upgrade seam: announce `pq_pubkey` (ML-DSA-65) and hybrid domain tags `scaas-*/ed25519+mldsa65/1`.

Status: **SPECIFIED** (A2); today the node has no TLS server, QUIC, Noise or libp2p (only an outbound rustls client).

### 6.9 Economics

**Break-even of a fee-earning relayer** (SRS §5.2, kept as an order-of-magnitude argument): a meta-tx on Gnosis costs
≈ $0.00015 of gas; at a 10× markup the margin is ≈ $0.0015 per tx; a relayer with SLA RPC, a small VPS and gas float
costs ≈ $45–70 per month ⇒ break-even ≈ $60 / $0.0015 = **40 000 tx per month**. Most enterprises do not reach this
early.

Consequences (normative):

1. Relayers are run by parties with aligned business interest (issuer, distributors, partners, the payee), not by a
   fee market. The only in-protocol reward is the intent's own `fee`/`feeRecipient` (R75): no sponsorship pool, no
   forwarder pay, no stake. (The opt-in `SponsorshipPool` of [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §B3 is an application contract, not a mesh reward;
   R75 unchanged, R194.)
2. **B2B default `fee = 0`** (`MODE_FEE_NONE` + `MODE_RESTRICT_RELAYER` to the company relayer, R10): gas is an
   operating expense of the company relayer, booked per transaction (§13.2). `MODE_FEE_NONE` is also the cheapest mode
   (≈ 8 300 gas less than a fee-taking meta-tx).
3. Payee-side relaying (§5.9) removes relayer dependence entirely for incoming payments.
4. Sponsorship policy (gas subsidy for qualifying inbound payments, e.g. "inbound to wallet W ≥ X currency units ⇒
   fee 0, booked to account Y") is a node policy row, never a contract feature. Status **SPECIFIED** ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §B1).
5. Metric W3B-06 (relayer fee spread) may be negative by design.

---

## 7. Families

Common model (R30, R3D §D.0): the subject only **signs** a domain-separated payload; each contract keeps its own
lane/nonce space; a relayer lane submits from its own account and pays native gas. Native sponsorship features are
used only so that a **relayer** pays, never so that the subject's account sequence orders anything. Every family ships
the same three roles: token with `pay` + meta-op, mandate, DEX — plus a multi-key subject account where the chain
needs one.

**`MetaOp` v1** (non-EVM; family encoding, every field mandatory): `domain = "scaas.metaop.v1"` ‖ `network` ‖ `contract` ‖ `op` (`pay | trade | mandate_pay |
revoke`) ‖ `from` ‖ `to` ‖ `amount` ‖ `payRef` (32) ‖ `lane` (32) ‖ `nonce` (u64) ‖ `validUntil` (u64 seconds) ‖
`relayer` (optional) ‖ `extra` (hash of op-specific parameters). No relayer fee field on non-EVM (fee NONE, R10/R75).

Summary:

| Family | Chains | Meta-tx mechanism | Subject signature | Lane key (relayer) | Mesh v1 | Status |
|---|---|---|---|---|---|---|
| EVM | Gnosis (100), Celo (42220), private chain 9000, anvil 31337 | Contract-level EIP-712 (`ERC20MetaTx`) | ECDSA secp256k1 (EOA) / ERC-1271 (SubjectAccount: P-256 WebAuthn, secp256k1) | secp256k1 `m/44'/60'/0'/0/i` | yes | **BUILT** |
| Hedera | 295 / 296 / 297 / 298 | Same Solidity on HSCS via JSON-RPC relay | ECDSA (alias) or ED25519 via HIP-632 `isAuthorizedRaw` | secp256k1 `m/44'/3030'/0'/0/i` | yes (family `hedera`) | **BUILT** |
| Cosmos | CosmWasm chains (`cosmos:<chain-id>`) | Contract-level `Relay{payload, auth}` | ADR-036 secp256k1 (Keplr/Leap `signArbitrary`) / WebAuthn P-256 | secp256k1 `m/44'/118'/0'/0/i` | yes | **BUILT** |
| Soroban | Stellar (`pubnet`, `testnet`, `standalone`), Pi Network (`pi-mainnet`, `pi-testnet`) | Native Soroban authorization (`SorobanAddressCredentials`, random nonce + ledger expiry) | ed25519 (Freighter `signAuthEntry`) / custom account `__check_auth` with `secp256r1_verify` | ed25519 `m/44'/148'/i'`; Pi `m/44'/314159'/i'` (`coin_type` override) | **no** (R77) | **BUILT** |
| Move — Aptos | 1 / 2 / 4 | Contract-level, per-owner `Account` object with lanes | ed25519 (Wallet Standard `signMessage`) / WebAuthn P-256 (pure-Move verifier) | ed25519 `m/44'/637'/i'/0'/0'` | yes | **BUILT** |
| Move — Sui | mainnet / testnet / devnet / localnet | Contract-level, shared `Account<T>` per subject with lanes | ed25519 / secp256k1 / secp256r1 / passkey (`signPersonalMessage`) | ed25519 `m/44'/784'/i'/0'/0'` | yes | **BUILT** |
| TON | -239 / -3 | Custom jetton wallet verifies `SignedOp` | TON Connect `signData` (cell) / passkey | ed25519 `m/44'/607'/i'` (W5R1 lane wallets) | yes (`pay`) | **BUILT** |
| Solana | `solana:<genesis hash>` | Program-level, SubjectAccount PDA + `LanePda` | raw ed25519 / off-chain message / passkey, verified via precompile instruction | ed25519 `m/44'/501'/i'/0'` | yes (`pay`) | **BUILT** |

Lane keys come from one 24-word BIP-39 mnemonic (`[keys] mnemonic`: env, 0600 file, or Web3 Secret Storage v3
keystore) or a raw `private_key` (one lane); `scaas-node addresses` prints every lane address to fund (R60).

### 7.1 EVM

- **Gnosis Chain (100):** recommended public chain for B2B; native gas xDAI (stable-value); finality `tag
  finalized` (~160–240 s), quorum ≥ 2 independent RPCs; profile `gnosis` (Cancun, EIP-2537 measured live). Seeded
  `draft` until O4.
- **Celo (42220, OP-Stack L2):** native fee abstraction **CIP-64** (transaction type `0x7b`, `feeCurrency`) lets a
  sender pay gas in an allowed ERC-20; SCaaS does not depend on it (relayers pay CELO) but clients using CIP-64 must
  add ≈ 50 000 intrinsic gas for the fee currency. Finality mode `l1_batch` is **PLANNED**; profile `celo` (Cancun).
- **Private chain 9000:** Nethermind 1.39, Clique PoA, one signer, 5 s blocks, base fee 0 (gas free), Prague
  (Fusaka + BPO2) after the 2026-08-31 chainspec fix — profile `private9000` = `prague`; finality `depth 1, quorum
  1`. Not on the Zether dev allowlist (RS2-1, owner question Z3).
- **Deployment:** `smartcontracts/scripts/deploy.sh evm <rpc>` runs `script/Deploy.s.sol` (OpenFactory, registrar,
  SubjectAccountFactory, MetaToken v1 registered as `META v1`, MetaTxDex, OrderBookDex, optional demo token) and
  writes `deployments/<chainid>.json`. Zether and the registry are not in the deploy script (dev chains only).
- **Passkey:** OZ 5.2 `P256.verify` (RIP-7212 precompile `0x100` when present, Solidity fallback ~200–330 k gas);
  `has_p256_precompile` is probed per chain.

### 7.2 Hedera

- HSCS runs EVM bytecode; the relayer is the EVM adapter pointed at a JSON-RPC relay; lanes are ECDSA accounts with
  EVM aliases (coin 3030) that must exist and be funded.
- `HederaMetaToken`: 64-byte signatures from an account without code are verified through HIP-632
  `isAuthorizedRaw` (HAS precompile `0x16a`, 100 k gas) — ED25519 Hedera accounts sign meta-txs natively.
  `associateUnderlying()` associates the HTS underlying (`0x167`). `HederaMandateWallet` adds `executeAsOwnerRaw`.
- **Payer-account sponsorship of subject transactions is not used** (it orders operations by the subject's account,
  R30). **HTS** tokens are used only behind a tier-2 wrapper (protocol-level HTS allowances cannot be restricted to
  contracts). **HCS** (consensus topics as an audit log) and **scheduled transactions** (multi-signature collection
  over time) are **PLANNED** — candidates for anchoring (§2.2) and for R4 approvals respectively.
- Finality: `instant` (aBFT record file).

### 7.3 Cosmos (CosmWasm)

- Contracts: `scaas-token` (minimal CW20 + `Pay{to, amount, pay_ref}` + `Relay{payload, auth}` with ops `pay`,
  `trade`, `revoke`; `QueryMsg::Nonce{owner, lane}`), `scaas-mandate` (CW20 `Receive`, `PayUnderMandate`, `Revoke`,
  `Withdraw`), `scaas-dex` (`SetMarket`, `Settle{maker, taker}`, fill-or-kill); `scaas-metaop` library.
- Signed payload: JSON `MetaOp` with sorted keys, `deny_unknown_fields`; ADR-036 sign doc built from a fixed byte
  template with `chain_id: ""`; the domain lives in the payload (`network == env.block.chain_id`, `contract ==
  env.contract.address`); address = bech32(ripemd160(sha256(pk))) must equal `from`.
- **feegrant** is only a seam for subject-sent deposits; **authz is never used** (a relayer grantee would be an EOA
  spender, R26). ICS-29 relayer fees for IBC are out of scope.
- Relayer: lane account sends `MsgExecuteContract`, account sequence per lane, one tx in flight; finality
  `instant` (CometBFT). Deploy tooling for Cosmos is **PLANNED** (`deploy.sh` exits 2).

### 7.4 Soroban (Stellar and Pi Network)

- Meta-tx = **native Soroban authorization**: the subject signs `HashIdPreimage::SorobanAuthorization` (network id +
  contract + function + args, random `i64` nonce, ledger expiry); the relayer lane is the transaction source and
  pays; `fee_bump_lane = i` lets one lane fee-bump (CAP-15) every lane's transaction. No second verifier is written.
- Contracts: token (SEP-41 + `pay(from, to, amount, pay_ref, valid_until)`, one-shot `pay_ref`, `approve` only to
  contract spenders), custom account (P-256 WebAuthn + ed25519 keys, Merkle batching; guardian recovery is a stub),
  mandate, DEX (`settle(maker, taker, maker_fill)` with two `require_auth_for_args`).
- Op digest (for indexing and the job API): `sha256(XDR(Vec[Symbol("scaas_metaop_v1"), network_id, contract,
  Symbol(fn), Vec(args)]))`.
- The subject `G…` account must exist on the ledger. Pi Network = the Soroban family with network passphrase "Pi
  Testnet"/"Pi Network" and SLIP-44 314159 (owner to confirm passphrases at deploy).
- **Not on the mesh v1** (R77): replay protection is the host's random auth nonce; there is no peer-readable
  per-subject sequential nonce. Soroban jobs go through the job API only.
- Finality: `instant` (SCP closed ledger).

### 7.5 Move — Aptos and Sui

**Aptos** (package `scaas`, `upgrade_policy = compatible`): one `Account` object per owner (derived from Root
`b"scaas.root"`) holding primary fungible-asset stores for every asset; `MetaOp{domain, chain_id, contract, asset,
op, from, to, amount: u128, pay_ref, lane, nonce: u64, valid_until: u64, relayer, extra}`, digest
`sha3_256(bcs(MetaOp))`; `package entry relay_pay(lane, owner, asset, …)` prevents other modules from wrapping
relayed entries (`check_entry_visibility.sh`); key management with up to 8 keys and 8 origins, guardian recovery
after 172 800 s; pure-Move P-256 verifier (unaudited). Native **fee-payer (AIP-39) and orderless transactions** are
kept as a seam for passkey/keyless subjects only; the relayer lane uses sequence-number transactions and pays.
Finality: committed block (AptosBFT), cursor bounded by the Indexer API's processed version.

**Sui** (package `scaas`): shared `Account<T>` per (subject, coin type) registered in `Registry<T>` (a second
`open` is refused, so nobody can create a decoy account); subject signs `signPersonalMessage(BCS(MetaOp))`, Move
recomputes `blake2b256([3,0,0] ‖ bcs(vector<u8>))` and verifies ed25519 / secp256k1 (SHA-256) / secp256r1 /
passkey. Relayer lane sends a **PTB** calling `meta::relay_pay<T>`; each lane has its own gas coin and one tx in
flight; the node journals the last signed tx bytes to disk (`lane_journal`) so a gas coin is never equivocated.
**Sponsored transactions** (dual signature) are used only for subject-sent deposits (seam). DEX `settle<A,B>` is
atomic; several settles batch in one PTB. Finality: certified checkpoint.

### 7.6 TON

- Jetton (TEP-74) rewritten in **Tact** with a custom jetton wallet holding the owner's pubkey, an optional
  passkey and `lanes: map<uint256, uint64>` (rotated every `LANE_TTL` = 30 days). `BindKey` proves the pubkey from
  the owner's W5R1/V4R2/V3R2 wallet `stateInit` (no subject transaction needed).
- Subject signs with TON Connect `signData` (type `cell`); the wallet rebuilds the exact envelope (prefix
  `0x75569022`, app domain, timestamp, address) around the `MetaOp` cell tree and checks `CHKSIGNU`; the app domain is
  checked off-chain against the chain's configured domain (R10-3).
- Relayer: lane **W5** wallet (seqno per lane) sends `SignedOp` (opcode `0x5b0a1d01`) as an internal message with
  TON attached (`attach_nanoton`, default 0.15 TON). **W5 gasless extensions and Highload wallets of the subject are
  not used** (subject seqno would be a lock, R30); a Highload-v3 relayer wallet is a possible future lane type
  (PLANNED).
- DEX: actor model has no cross-contract atomicity ⇒ **escrow**: leg A waits in the DEX for leg B; expiry ⇒
  permissionless `Refund`.
- Finality: masterchain block (`depth 0`). Open item: report the payer jetton-wallet tx hash with `mined`
  (TODO #8).

### 7.7 Solana

- Anchor program `scaas`: SubjectAccount PDA owns the token accounts; `LanePda{next}` seeded `["lane", subject,
  lane]` (prunable after `valid_until`); `MetaOp` fixed 337 bytes, digest `sha256(MetaOp)`; the subject signs
  `"<domain>:" ‖ hex(sha256(MetaOp))` as raw ed25519, Solana off-chain message (`\xffsolana offchain`) or passkey;
  the program verifies by inspecting the Ed25519/Secp256r1 precompile instruction in the same transaction.
- Native fee payer is the relayer lane; recent-blockhash expiry (~60–90 s) is why the subject never signs the
  transaction itself (queued jobs and resting DEX orders live much longer). Each **lane** owns a **durable nonce
  account** (created on first use), so lane transactions do not expire while queued.
- Priority fees: transaction v1 header with `max_priority_lamports` total, explicit compute-unit and loaded-data
  limits (`max_cu`, `max_loaded_bytes`).
- Finality: commitment `finalized`; indexing via standard JSON-RPC (`getSignaturesForAddress` + `getTransaction`),
  no proprietary APIs. The public test program id is refused on public clusters.
- clientkeys has no Solana signer yet (PLANNED).

### 7.8 Event normalization (all families, BUILT)

Every adapter emits `{event, contract, block_number, block_hash, tx_hash, log_index, from, to, amount, fee,
fee_recipient, entry_ref | digest}` with family-canonical addresses (EVM lowercase `0x`, bech32, `0x`+64, `G…/C…`
strkeys, raw `wc:hex`, base58). Events: `PaymentSettled`, `MetaTransactionExecuted`, and on EVM `Transfer` to
watched receiving wallets (drift A). Heights: block / height / ledger / checkpoint / masterchain seqno / slot.

---

## 8. Zether — confidential amounts

**Status: BUILT, UNAUDITED — NOT FOR PRODUCTION FUNDS.** `ZetherToken`, `ZetherMetaTx`, `ZetherVerifierBn254`,
`ZetherVerifierBls12381`, `UniversalAccountRegistry` and `zether-prover` exist with tests; every Zether contract and
the registry refuse to deploy or initialize outside chain ids 31337/1337, and `OpenFactory.zetherEnabled` defaults
to `false`. Spec: [Zether design](superpowers/specs/2026-10-03-zether-design.md) (byte-exact),
[limits](superpowers/specs/2026-10-05-zether-limits.md). Owner gates: Z1 independent cryptographic audit, Z3 whether
chain 9000 counts as dev, Z4 curve choice, Z5 gas optimization before public chains.

### 8.1 Philosophy: identity visible, amounts hidden

| | Mixer | SCaaS Zether |
|---|---|---|
| Transaction graph | broken | fully visible (ring size **2**: sender and receiver only) |
| Identities | hidden | visible (accounts link to verifiable organizational identity) |
| Amounts and balances | fixed pool denominations | ElGamal-encrypted |
| Relayer fee | hidden in the pool | public scalar |
| Travel-rule / audit | incompatible | compatible: disclosure by sender, receiver or auditor (§8.9) |

### 8.2 Cryptography

Lifted ElGamal on G1: key `x ∈ [1, r)`, `Y = [x]G`; balance `(C, D) = ([b]G + [ρ]Y, [ρ]G)`; homomorphic add/sub on
ciphertexts; decryption `[b]G = C − [x]D` then discrete log by client-side BSGS. Proofs: one Σ-protocol (sender
knows `x`, the three ciphertexts encrypt the same `v` with the same `s`, the remaining balance relation) plus
**exactly two Bulletproof range statements** — `v ∈ [0, 2^{n_v})` and `b' = b − fee − v ∈ [0, 2^{n_b})` — in **one**
Fiat-Shamir transcript (`init = keccak256("SCAAS-ZETHER-TRANSCRIPT-V1")`, statement absorbed first: strong
Fiat-Shamir). NUMS generators computed in the verifier constructor and stored with SSTORE2 (130 points: `h`, `U`,
`G_0..63`, `H_0..63`).

| | bn254 (alt_bn128) | BLS12-381 G1 |
|---|---|---|
| Point encoding | 64 B (EIP-196) | 128 B (EIP-2537, 16-byte zero pads) |
| Precompiles | `0x06` add, `0x07` mul | `0x0b` G1ADD, `0x0c` G1MSM (subgroup check), `0x10` map |
| Security | ~100 bit | ~117–126 bit |
| Chains | any EVM since Byzantium | Prague (EIP-2537) |
| `proofSystemId` | `keccak256("scaas/zether/sigma-bullets/bn254/n64-n64/v1")` | `keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v1")` |

Both curves are supported; the token creator chooses the verifier. BLS12-381 buys security, **not** gas (measured:
it is more expensive; the earlier "45–60 % cheaper" claim is wrong).

### 8.3 Constants (current values; supersede the SRS)

| Constant | Value | Where |
|---|---|---|
| `n_v` (value range bits) | **64** (was 32; RS-NV64-1) | verifier `NV = 64` |
| `n_b` (balance range bits) | **64** | verifier `NB = 64`; the SRS rule `n_b − n_v ≥ 24` is relaxed (safety from `MAX_TOTAL_SHIELDED` and `r > 2^253`) |
| `MAX_TOTAL_SHIELDED` | **2^54** | hard cap of per-token `maxDecryptableShielded` |
| Single transfer maximum | `< 2^64` (in practice bounded by the sender's balance ≤ 2^54) — one transaction for any amount, so large payments are no longer split and their size is not revealed by the number of transactions | |
| `confidentialFee` | `< 2^64` and `< maxDecryptableShielded` | set at `initialize` |
| Decryption (BSGS) | **no `DECRYPT_BOUND` constant**: client-configured `table_bits ∈ [18, 27]`, `bound_bits ≤ 54`; defaults mobile/WASM 22/44, desktop 24–26/54; WASM caps at 2^24 entries (2^26 with `allowLargeTable`) | `zether-prover` `BsgsParams` |
| Balance cache | `{ua, token, accSeq, balance}` in the device vault, verified by `[b]G == C − [x]D` before use, updated on rollOver (BSGS only on `pending`) and own debits; never on chain or on a server | clientkeys `sealBalanceCache` |
| `shieldScale` | raw underlying units per shielded unit (e.g. a 6-decimal stablecoin kept to 2 decimals: `10^4`) | `fund(amount)` pulls `amount × shieldScale` |
| Ring size | 2 | |

Native CLI `zether-read-balance` reads balances above the device bound (table up to 2^27).

### 8.4 Gas (measured, execution gas, chain 31337, n_v = 64)

| Operation | bn254 | BLS12-381 |
|---|---|---|
| `verifyTransfer` (auditor off / on) | 2 700 151 / 2 728 409 | 2 928 567 / 2 971 201 |
| `transferConfidential` direct (auditor, inner fee) | 3 286 339 | 3 919 760 |
| `transferConfidential` in envelope (+ outer fee) | 3 357 045 | 3 975 916 |
| `burn` | 1 396 358 | 1 521 169 |
| `fund` (first / warm) | 191 360 / 28 591 | 247 307 / 36 832 |
| `rollOverPublic` (work / no-op) | 115 234 / 2 305 | 166 414 / 2 295 |
| `rollOverSigned` | 133 557 | 197 503 |
| `register` SELF_SCHNORR | 102 659 | 83 440 |

The canon kill criterion (2.5 M per transfer) is exceeded; accepted by the owner for v1 in exchange for one
transaction per payment of any size. Optimizations (single randomized MSM for Σ, `bytes32[2]` points, disclosure
bundle out of storage) are open (Z5).

### 8.5 Account state, `acc`/`pending`, rollOver

Per `(UA, token)`: `acc` (source of every proof), `pending` (all credits: fund, incoming transfers, inner fees),
`accSeq` (in the statement; `require(accSeq == provedAccSeq)`), `pendingSeq`, `lastRolledPendingSeq`, `sendCounter`
(in the statement; +1 per successful debit), `mode`, `modeNonce`.

`rollOver`: `acc += pending; pending = 0; accSeq += 1`, only when `pendingSeq > lastRolledPendingSeq` (otherwise a
silent no-op — anti-DoS). Two modes (`enum RollOverMode { PUBLIC, OWNER_ONLY }`, `setRollOverMode` signed):

- `PUBLIC` (default; retail, loyalty, low-risk): anyone may call `rollOverPublic(UA)` / `rollOverBatch(UA[])`.
- `OWNER_ONLY` (treasury, B2B high value): only `rollOverSigned(UA, expectedPendingSeq, validUntilBlock, sig)`;
  requires `lastRolledPendingSeq < expectedPendingSeq ≤ pendingSeq` (RS2-17, RS2-19) so a dust credit cannot kill
  the owner's rollOver and a no-op signature cannot be replayed to force one.

### 8.6 Universal Account registry (BUILT, dev chains)

`UA = keccak256(encodedY)` (64 or 128 bytes ⇒ curve; one UA per (curve, network, account) — never per token; the
same person has distinct UAs on two curves, never merged). `register(encodedY, authScheme, authData, popSignature,
linkEVM)`:

- point valid, not identity, in the subgroup; UA not yet registered (`AccountAlreadyRegistered`);
- **proof of possession** (anti-rogue-key): `c = keccak256(abi.encodePacked(registry, encodedY, msg.sender))`;
  `popSignature = abi.encode(schnorrPop, authPop)` — a Schnorr signature by `x` over `c` **and** a proof of the
  authorization key over `c`. Because `c` binds `msg.sender`, registration is not relayable by third parties: the
  subject calls from its own EOA or smart account;
- `linkEVM` ⇒ `links[msg.sender] = UA`, `link_eth[UA] = msg.sender` (`EVMAlreadyLinked` if already linked);
- no key rotation, no relinking: a new key is a new UA (RS2-9).

Eight account kinds (`enum AuthScheme`, values 0–4 frozen), six verifier paths:

| # | Scheme | `authData` | Authorization on transfer/burn/rollOverSigned | Use |
|---|---|---|---|---|
| 0 | `SELF_SCHNORR` | `0x` | the ZK proof itself (or Schnorr by `x`) | single holder |
| 1 | `ECDSA_MULTISIG` | `abi.encode(address[] ownersSorted, uint256 threshold)`, `0 < t ≤ n` | `abi.encode(bytes[] sigs)` sorted by signer, raw digest, low-s | boards, finance approvers |
| 2 | `FROST_BN254` | `abi.encode(bytes groupKey64, uint256 t, uint256 n)` | one Schnorr by the group key | t-of-n agents / MPC |
| 3 | `MUSIG2_BN254` | `abi.encode(bytes aggKey64, uint256 n)` | one Schnorr by the aggregate key | n-of-n |
| 4 | `BLS_BN254` | `abi.encode(bytes g2PubKey128)` | BLS min-sig, pairing `0x08` | private chains; **forbidden on a bn254 Zether key** |
| 5 | `BLS_12381` | `abi.encode(bytes g2PubKey256)` | BLS min-sig, EIP-2537 | public chains; **forbidden on a BLS12-381 Zether key** |
| 6 | `PQ_COMMITMENT` | `abi.encode(bytes32 pqCommitmentHash)` | as 0 on chain; PQ verification off chain; commitment kept for future rotation | PQ readiness |
| 7 | `SMART_ACCOUNT_1271` | `abi.encode(address account)` (must have code) | `isValidSignature(digest, sig)` | Safe, SubjectAccount (passkeys) |

FROST and MuSig2 share one Schnorr verification path (`z·G == R + c·P`, O(1) gas regardless of signer count). BLS on
the same curve as the ElGamal key is rejected because publishing `[x]G2` makes DDH decidable on G1. BLS keys at
infinity are rejected (RS2-18). Authorization digest `keccak256("SCAAS-ZETHER-AUTH-V1" ‖ keccak256(statement))`:
every transfer and burn needs **both** the proof (knowledge of `x`) **and** the scheme signature, so a leaked `x`
of a non-`SELF_SCHNORR` account is a read-only breach (`survivesEncKeyLeak`).

### 8.7 Fees on confidential operations

Inner fee: public scalar `fee` in the statement, `C_acc − [fee]G`, credited to the `beneficiary` UA's `pending`;
fixed per token (`confidentialFee`). Outer fee: paid from the token's **public** ERC-20 balance (wrap/unwrap 1:1);
`NONE` or `FIXED` only (`PERCENT` forbidden; FIXED not capped at 1 %).

### 8.8 Replay protection and envelope binding

1. **Envelope:** 2D nonce, `validUntil`, EIP-712 signature (domain `("SCaaS ZetherToken", "1", chainId, token)`).
2. **State:** `accSeq` and `sendCounter` in the statement, compared with storage before verification.
3. **Binding:** `envelopeBinding = keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENVELOPE-V1"), chainid, token,
   from, to, value, batch, nonce, validUntil, mode, canonRelayer, fee, canonFeeRecipient))` is part of the statement
   (`ZTX_V1_RELAYED`); direct calls use `ZTX_V1_DIRECT` with binding 0. Stripping a proof out of its envelope, moving
   it to another envelope, token or chain, or replaying it after execution all change the transcript and revert.

Envelope ops: `OP_ZTRANSFER = bytes4(keccak256("zetherTransfer(bytes,bytes,bytes,bytes32)"))`, `OP_ZBURN =
bytes4(keccak256("zetherBurn(bytes,uint256,address,bytes32,bytes,bytes)"))`, with `m.to = 0`, `m.value = 0`.
Direct calls: `transferConfidential(payload, proof, authSig, beneficiary) returns (bytes32 entryRef)` and
`burn(payload, amount, recipient, beneficiary, proof, authSig)` (no outer fee). `entryRef =
keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENTRY-V1"), chainid, token, fromUA, sendCounter))`.

### 8.9 Disclosure (`ITransferDisclosure`, BUILT)

The token stores per `entryRef` the bundle `Y_to ‖ C_out ‖ D_out ‖ C_aud` (256 B, ≈ +200 k gas, RS2-15). Three
openings, all kept:

| Kind | Opening | Check |
|---|---|---|
| `SENDER_S` | `abi.encode(uint256 s)` | `[s]G == D_out` and `[amount]G + [s]Y_to == C_out` |
| `RECEIVER_X` | `abi.encode(A1, A2, z)` (Chaum-Pedersen) | `log_G(Y_to) == log_{D_out}(C_out − [amount]G)` |
| `AUDITOR` | as `RECEIVER_X` with the token's immutable auditor key and `C_aud` | same |

Challenge `e = hashToScalar(keccak256("SCAAS-ZETHER-DISCLOSE-V1" ‖ chainid ‖ token ‖ entryRef ‖ be32(amount) ‖
kind ‖ A1 ‖ A2))`; `amount < 2^64`, `z < r`, `e ≠ 0`. `verifyTransferAmount` is a free view; `attestTransferAmount`
emits `AmountAttested(entryRef, amount, kind, attestedBy, timestamp)`; `transferCiphertext(entryRef)` returns the
ciphertext and recipient key. The auditor reads exactly the per-transfer `C_aud`, never anyone's `acc`/`pending`.
Disclosure is irrevocable once handed over. Sender randomness `s` is derived deterministically (HKDF over the seed,
chain, token, from UA and the **on-chain** `sendCounter`); reusing a counter would reuse ElGamal randomness.

### 8.10 Keys

Confidential key `x` is derived from the same 24-word seed on a separate path (R33): BLS12-381 EIP-2333
`m/12381/<coin>/<account>/7`; bn254 EIP-2333-style with salt `"SCAAS-ZETHER-BN254-v1"` on `m/254/<coin>/<account>/7`;
`<use> = 8` reserved for viewing/disclosure keys. `x` never equals a signing scalar of the same seed, never leaves
the device (clientkeys `sealConfKey`).

### 8.11 Families

Zether is EVM-only in v1 (BN254 or BLS12-381 precompiles). Non-EVM families: feasibility notes only. Zether intents
are not carried on the mesh (`W = 0` and single-flight per sender need their own design).

### 8.12 Post-quantum Zether on private/PoA chains (PLANNED)

Goal: confidential balances whose confidentiality survives a quantum adversary, on private/PoA chains where gas is
free and validators are known (lattice ciphertexts and proofs are far too large for public-chain gas).

- **Encryption:** lattice-based additively homomorphic scheme — BFV or BGV (RLWE), plaintext modulus chosen so that
  `2^54` balances plus fee/value sums never wrap; parameter set targeting ≥ 128-bit post-quantum security (e.g. ring
  dimension 4096–8192); ciphertexts stored off the EVM state (content-addressed blobs) with a commitment on chain.
- **Validity:** lattice range and well-formedness proofs (or, as an interim, attestation by a validator quorum on the
  private chain, recorded on chain) replacing Bulletproofs; transcript and envelope binding identical to §8.8.
- **Identity/authorization:** `PQ_COMMITMENT` accounts (§8.6) rotate to ML-DSA keys; envelope signatures move to
  hybrid domain tags (`…/ed25519+mldsa65/1`-style) as in §6.8.
- **Disclosure:** the same three roles (sender, receiver, auditor) with lattice openings.
- **Scope:** private/PoA profile only; no gossip; deployment gated like v1 (dev allowlist until audited).

Queued after the current mesh and node streams (owner order: EVM, Cosmos, Hedera, Soroban, TON, Sui, Aptos, Solana,
then mesh round 4, then PQ Zether). A component spec is required before code.

---

## 9. Keys and signing

### 9.1 Two custody axes

| Axis | Key | Purpose | Custody | Status |
|---|---|---|---|---|
| `auth_custody` | secp256k1 / ed25519 / P-256 signing keys | Authorizes spending (EIP-712, MetaOp, WebAuthn) | Subject device (passkey, seed vault), wallet extension, or — for entrusted custodial/delegated wallets — a KMS/HSM (FIPS 140-3 Level 3) behind the custody adapter | device **BUILT**; KMS/HSM adapters **PLANNED** (O6) |
| `conf_custody` | Zether `x` (bn254 / BLS12-381) | Decrypts balances, builds proofs | Subject device (seed path `…/7`); for organizations a threshold-MPC or enclave key oracle with a narrow interface `zk_mul_by_x(points, ctx)`, `zk_nonce_commit`, `zk_response` — commercial HSMs do not support these curves | device **BUILT**; key oracle **PLANNED** |

Leaking one axis does not compromise the other: a leaked signing key cannot read balances; a leaked `x` cannot move
funds (except `SELF_SCHNORR` accounts). Relayer lane keys are a third, unrelated class (gas only, §9.6). The node
never needs `x`.

### 9.2 `SigningPolicyService` (PLANNED as a service; rules SPECIFIED)

All signing that is not done by a human on a device — custodial wallets, delegated mandates, AI agents — passes a
policy check **co-located with the signer** (not in the ERP), with an idempotency key per request. No short-lived
session keys are issued to agents; agents use the same custody path as users, bounded by policy.

Checks before any signature:

1. Destination contract ∈ allowlist (token, mandate wallet, DEX).
2. Operation ∈ allowed ops/selectors (`pay(bytes32)`, `payUnderMandate`, `executeMetaTransaction` with an allowed
   op; never `approve` to an EOA — impossible anyway by §4.4).
3. Amount ≤ per-call cap; cumulative ≤ hourly and daily caps (velocity, in the signer's own store).
4. `validUntil − now ≤ 300 s`.
5. Risk class routing: R1 (no value), R2 (small value), R3 (above the R2 threshold, treasury or B2B outflow) ⇒
   maker-checker, R4 (governance/keys) ⇒ quorum of ≥ 2 approvers distinct from the requester. Rescue/exit operations
   are never throttled.

Today the Odoo client applies checks 1–4 in-process before calling the dev-only `env:` custody adapter (R50); the
mandate path enforces caps on chain (§4.7).

### 9.3 Passkeys (BUILT)

- WebAuthn P-256 assertion `{authenticatorData, clientDataJSON, r, s}`; `challenge = base64url(operation digest)`.
- Verifier checks: `type == "webauthn.get"`, challenge, `rpIdHash`, `origin` (stored per key as `keccak(origin)` on
  EVM), UP and UV flags, low-`s` (clients convert DER to `(r, s)` and normalize `s := n − s` when `s > n/2`), then
  P-256 over `sha256(authenticatorData ‖ sha256(clientDataJSON))`.
- Batch: one assertion over a Merkle root of digests; leaf `keccak256(keccak256(0x00 ‖ digest))` (second-preimage
  safe); each operation carries `(keyIndex, proof, sig)`.
- Per family: EVM/Hedera `SubjectAccount` (ERC-1271; P-256 via precompile `0x100` or Solidity); Sui
  `secp256r1_verify`/passkey; Soroban `secp256r1_verify` (CAP-51) in a custom account; Cosmos `secp256r1_verify`
  (cosmwasm-std 2.1+); Aptos pure-Move P-256; Solana Secp256r1 precompile; TON passkey auth kind in the jetton
  wallet.
- `clientkeys/src/passkey-signer.js`: `creationOptions` (PRF enabled by default), `requestOptions`, `derToRS`,
  `encodeAssertion = abi.encode(authenticatorData, clientDataJSON, r, s)`, `merkleBatch`, `accountSignature =
  abi.encode(keyIndex, bytes32[] proof, sig)`.

### 9.4 Subject accounts, guardians, recovery, backup (BUILT; backup toggle PLANNED)

`SubjectAccount` (EVM; equivalents per family): multiple authorized keys (`P256_WEBAUTHN(x, y, rpIdHash,
originHash)`, `SECP256K1(address)`), never zero keys (`LastKey`); `addKey`/`removeKey`/`rotateKey`/`setGuardian`
only through `executeAsOwner` signed by an existing key (own nonce, `OwnerCall(bytes data,uint256 nonce,uint256
validUntil)`); guardian `initiateRecovery(newKey)` → anyone `completeRecovery` after `RECOVERY_DELAY = 2 days`
(adds a key, removes none); the owner can `cancelRecovery`. Deployed by `SubjectAccountFactory` (CREATE2, salt =
`keccak256(abi.encode(firstKey, guardian))`, idempotent) — the client enqueues the deploy job before the first
payment.

Seed and passkey back each other up: the seed-derived key is the natural recovery key when a passkey is lost and
vice versa.

**Backup-key toggle (PLANNED):** a per-account setting `backup_mode ∈ {passkey_prf (default), seed_verified,
guardian_only, device_bound}`. `device_bound` (no backup) is refused for any value-bearing flow (estimated loss
3–8 %/year vs 0.05–0.2 % with PRF backup, canon §C15.1); switching modes is an owner call on the account; clients
show the mode and the recovery delay.

### 9.5 Seed vault (BUILT)

- 24-word BIP-39 generated on the device (import accepts 12–24 valid words); shown once; verification by re-entering
  3 random words (`SeedBackup` states `fresh → revealed → challenged → verified → taken`).
- Storage: AES-256-GCM with a 32-byte data key wrapped by the passkey **PRF** when available, else by a PIN/passphrase
  through scrypt (`N = 2^17, r = 8, p = 1` in the code); `needsRewrap`/`rewrapPin`; buffers wiped after use within JS
  limits. Mnemonic and keys never leave the device.
- Derivation (`clientkeys` `NETWORKS`): EVM `m/44'/60'/0'/0/i`; Cosmos `m/44'/118'/0'/0/i`; Hedera ECDSA
  `m/44'/3030'/0'/0/i`, Hedera ED25519 `m/44'/3030'/0'/0'/i'`; Sui `m/44'/784'/i'/0'/0'`; Stellar `m/44'/148'/i'`
  (Pi: coin 314159); TON `m/44'/607'/i'`; Aptos `m/44'/637'/i'/0'/0'`. Solana `m/44'/501'/i'/0'` **PLANNED** in
  clientkeys. TON keys from these paths are importable into TON wallets as "BIP-39/Ledger path", not as native TON
  mnemonics.
- Zether conf keys from the same seed on separate paths (§8.10).

### 9.6 Relayer lane keys (BUILT; KMS seam)

- One mnemonic (24 words, BIP-39 checksum, optional BIP-39 passphrase) for every lane without its own key; per-chain
  `lanes = [account indexes]`; paths per family as in §7; `coin_type` override per chain.
- Sources (`SecretSource`): `{env}`, `{file}` (refused unless mode 0600/0400), `{keystore, passphrase_env}` (Web3 Secret
  Storage v3: scrypt + AES-128-CTR + keccak MAC; `scaas-node keystore new --kind mnemonic|secp256k1|ed25519` checks
  the secret before writing, the kind is an operator label and is not stored). Secrets are never logged; start-up prints only addresses.
- `Signer` trait (`curve()`, `public_key()`, `sign(msg)` → 65-byte low-s `r‖s‖v` or 64-byte ed25519) with
  `LocalSigner`; **KMS/HSM signers are a seam** (O7; required on public chains for production).
- Lanes hold gas only; funding from treasury and balance monitoring (`scaas_relayer_balance{chain,lane}`) are
  operator duties (O8); automatic refill is PLANNED (HANDOFF GA 2.2 #3).
- Node identity key (Ed25519, `[identity] key`) is separate from lane keys (secp256k1 is not a TLS signature scheme).

### 9.7 Threshold and aggregate signatures

| Scheme | Where | Property | Status |
|---|---|---|---|
| ECDSA N-of-M (`MultiSig.requireQuorum`) | registry scheme 1, controlled-token quorums | sorted signers, raw digest, low-s; gas grows with M | **BUILT** |
| FROST t-of-n (Schnorr, bn254) | registry scheme 2 | one Schnorr verification on chain (O(1)); default for agent clusters; no single node holds the key | on-chain verification **BUILT**; off-chain FROST signer/DKG **PLANNED** |
| MuSig2 n-of-n | registry scheme 3 | as FROST, all signers required; nonce reuse leaks the key ⇒ hard anti-replay counters | verification **BUILT**; signer **PLANNED** |
| BLS aggregation (BN254 on private chains, BLS12-381 via EIP-2537) | registry schemes 4/5; `Bls12381.verifyMinSig`, RFC 9380 hash-to-curve (KAT tested) | many signers, one pairing check; never on the same curve as a Zether key | **BUILT** |
| Smart-account policies (Safe, SubjectAccount) | scheme 7 | arbitrary policy via ERC-1271 | **BUILT** |

---

## 10. Sealed-bid tender (SPECIFIED)

Component spec: [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §A (R180–R188), authoritative for detail; no code. Where it differs from the text below (deposit
and commitment in one token `pay` intent, permissionless reveal/withdraw, cancel until `commitDeadline`,
`minBidders`, no `awardDeadline`, per-bid payout routing) the spec wins. Sources: SRS architecture §10 and §9.7, research synthesis "mechanism 8", canon §C22.6, settlement
note §15.12.1. Detail added here (timing, deposits, penalties, events, meta-tx paths) is new and normative.

### 10.1 Problem

On a public ledger an open bid is visible to competitors in the mempool and in blocks (bid sniping, collusion). The
tender separates the **commitment** (hidden, bonded) from the **revelation** (after the deadline), and returns every
honest loser's deposit without anyone's approval.

### 10.2 Roles and parameters

| Item | Definition |
|---|---|
| Buyer | Creates the tender; may be a multisig or a `SubjectAccount` |
| Bidder | Any account allowed by the tender's eligibility rule (open, or allowlisted UAs / addresses set at creation) |
| `depositToken` | A META token (tier 1/2); deposits are public amounts. Zether deposits are out of scope for v1 |
| `minDeposit` | Bid bond per bidder, same for all bidders, in `depositToken` units |
| `commitDeadline` | End of phase 1 (unix seconds) |
| `revealDeadline` | End of phase 2; `revealDeadline − commitDeadline ≥ minRevealWindow` (default 24 h; never below 1 h) |
| `awardDeadline` | End of the buyer's award window; default `revealDeadline + 7 days` |
| `rule` | `LOWEST_PRICE` (procurement) or `HIGHEST_PRICE` (sale); ties broken by earliest commitment block, then lowest `bidder` address |
| `slashSink` | Where forfeited deposits go: the tender's `projectFund` address fixed at creation (never the buyer's EOA by default) |
| `performanceBondPolicy` | `RETURN_ON_AWARD` or `HOLD_UNTIL_RELEASE` (winner's deposit becomes a performance bond released by a buyer signature or after `bondReleaseTime`) |

### 10.3 Phases

```
 createTender ──► OPEN_FOR_BIDS ──(commitDeadline)──► REVEAL_PHASE ──(revealDeadline)──► AWARDABLE
                     │ submitBidCommitment              │ revealBid                         │ settleTender (buyer or
                     │ (deposit locked)                 │ (hash checked)                    │ anyone after awardDeadline)
                     │                                  │                                   ▼
                     └── cancelTender (buyer, only before the first commitment) ──► CANCELLED      SETTLED
                                                                                     (all deposits withdrawable)
```

1. **Commit** (`now ≤ commitDeadline`): bidder computes `commitment = keccak256(abi.encode(tenderId, price, salt,
   bidder, chainId, tenderContract))` with a 256-bit random `salt` kept off chain; calls `submitBidCommitment(tenderId,
   commitment)` which pulls exactly `minDeposit` (via the meta-tx `approve` op to the tender contract — a contract
   spender — or via a `pay`-style op into the tender). One live commitment per bidder; a bidder may **replace** its
   commitment before the deadline (deposit unchanged) but never withdraw it in this phase.
2. **Reveal** (`commitDeadline < now ≤ revealDeadline`): `revealBid(tenderId, price, salt)`; the contract recomputes
   the commitment; mismatch reverts. Revealed prices become public.
3. **Award** (`now > revealDeadline`): `settleTender(tenderId)` selects the winner deterministically by `rule` among
   revealed bids (optionally only bids within a buyer-declared `[minPrice, maxPrice]` set at creation); emits
   `TenderSettled`. If the buyer does not settle by `awardDeadline`, anyone may call it (the result is
   deterministic). With zero revealed bids the tender settles with `winner = address(0)`.
4. **Withdraw** (`SETTLED` or `CANCELLED`): `withdrawDeposit(tenderId)` (pull payment).

### 10.4 Invariants

- **I1 — 100 % refund:** every bidder that revealed a valid bid and did not win can withdraw exactly `minDeposit` at
  any time after settlement, without the buyer's consent; every bidder of a cancelled tender can withdraw exactly
  `minDeposit`. No fee, no deduction, no expiry on the claim.
- **I2 — conservation:** `depositToken.balanceOf(tender) ≥ Σ unwithdrawn deposits + Σ held performance bonds`.
- **I3 — hiding:** until `revealDeadline` nobody (including the buyer) can learn a price from chain data;
  commitments are bound to `tenderId`, bidder, chain and contract, so they cannot be copied to another tender.
- **I4 — determinism:** the winner is a pure function of the revealed set and `rule`.
- **I5 — one outcome:** `settleTender` succeeds once; afterwards state is immutable.

### 10.5 Griefing penalties

| Behaviour | Penalty |
|---|---|
| Commits but does not reveal by `revealDeadline` (probing, blocking) | Deposit forfeited to `slashSink` (`DepositSlashed`) |
| Reveals a price outside the declared `[minPrice, maxPrice]` | Treated as not revealed (forfeit) — declared at creation so bidders know the rule |
| Winner fails to sign the contract/PO within the award terms (off-chain obligation) | Under `HOLD_UNTIL_RELEASE`, the buyer may claim the bond after `bondClaimTime` with a signed reason; otherwise the bond returns at `bondReleaseTime` |
| Buyer never settles | Anyone settles after `awardDeadline` (no buyer veto over refunds) |
| Spam commitments | Bounded by `minDeposit` and optional eligibility allowlist |

### 10.6 Meta-transactions and privacy

All bidder calls are relayable: commit, reveal and withdraw are ops of the tender contract with its own EIP-712
domain and the subject's lane/nonce space (R30), so bidders never need gas. To avoid revealing a bidder's identity at
commit time where that matters, a bidder may commit from a fresh `SubjectAccount`; identity is still disclosed at
reveal (SCaaS is not anonymous, §1.3). Confidential bids (encrypted prices opened by an auditor key, Zether deposits)
are a later extension.

### 10.7 Interface

See §14.7. Events: `TenderCreated`, `BidSubmitted`, `BidRevealed`, `TenderSettled`, `DepositRefunded`,
`DepositSlashed`, `TenderCancelled`, `BondReleased`, `BondClaimed`.

---

## 11. Data protection

### 11.1 Principles (market-neutral)

SCaaS takes no position on any one country's law. Deployments map these technical controls to their applicable
data-protection regime (GDPR-class regimes: lawful basis, minimization, erasure, retention, cross-border transfer,
processor agreements):

1. **No personal data on chain.** On chain: addresses, amounts (or ciphertexts), random `entryRef`s, digests,
   commitments. Never names, document numbers, tax ids, order numbers or free text (T18). A CI guard on calldata types
   (allow `address`, `bool`, `uint*`, `int*`, `bytes32`, `bytes32[]`; deny `string`/`bytes` except declared proof and
   signature fields) is **PLANNED**.
2. **Linkage off chain.** The mapping address ↔ party lives in the client's system of record (e.g. `res.partner` +
   approved wallet records) and can be erased there.
3. **Minimized node state.** The node store holds payloads (payer, payee, amounts) only as long as needed
   (`job_retention_secs` 30 d for terminal jobs, feeds 7 d); backups encrypted, file mode 0600 / DB grants (NI T5).
4. **Logs carry no payloads** (MESH §9 rule 5; NI §15).
5. **Private chains and private bus scope** for data that must not reach third parties (§1.4).

### 11.2 Crypto-shredding with ephemeral salts (SPECIFIED, [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §C; tooling not built)

For anchored records (§2.2) that may contain or derive from personal data:

- `salt = CSPRNG(32 bytes)` per record; `commitment = keccak256(salt ‖ canonical(payload))`; only `commitment` goes on
  chain (or into a Merkle root).
- The salt is stored in the client's secret store keyed by record id (never in the node store, never on chain).
- **Erasure request:** delete the salt (and the off-chain mapping). Without it, the commitment is computationally
  unlinkable (2^256 preimage space); the on-chain value becomes random data.
- **Retention conflicts:** records under a legal retention duty (anti-money-laundering, accounting) are refused for
  erasure until `retain_until`, with the legal basis returned; surplus personal data is deleted for real; on-chain
  pseudonyms are handled by shredding the off-chain mapping and decryption material.
- **Erasure API (client side):** `erase_subject(party_id, reason)` → `{erased: […], refused: [{model, id,
  legal_basis}]}`, requires a compliance role, writes an erasure log containing only a hash of the subject id.
- Payment `entryRef`s are already unlinkable by construction (random, R9) — no salt needed; erasing the client's
  request record removes the link.
- Zether: erasing the off-chain mapping UA ↔ party; the confidential amounts stay encrypted; disclosure proofs
  already handed to a counterparty or auditor cannot be revoked (state this to data subjects).

### 11.3 Disclosure for reconciliation and audit

- Transparent tokens: amounts are public; reconciliation uses `entryRef`.
- Zether tokens: the receiver or sender produces an `ITransferDisclosure` opening for the counterparty's
  reconciliation or for an auditor (§8.9); the token's auditor key reads every `C_aud` of that token. An independent,
  deterministic open-source verifier CLI for openings is **PLANNED** (for courts and auditors).

### 11.4 Land gate (CI phase gate, PLANNED as tooling)

Read-in of chain data into an analytical store (beyond the operational booking a payment requires) is gated: phase 1
blocks blockchain-vocabulary tables from analytical publication in CI; phase 2 opens after the deployment's privacy
impact assessment is signed by its compliance and security owners (HANDOFF O9).

---

## 12. Node API surface

All JSON, no cookies, no redirects. Errors are `{"error": "<CODE>", "detail": "<text ≤ 300 chars>"}`. Detail:
[NI §5–§7](superpowers/specs/2026-10-06-node-independence-design.md), [MESH §5](superpowers/specs/2026-10-05-relayer-mesh-design.md),
[A2 §5, §13](superpowers/specs/2026-10-06-mesh-gossip-amendment.md). Client usage: `integration.md`.

### 12.1 Listeners and authentication

| Listener | Bind (config) | Credential | Never accepts |
|---|---|---|---|
| gateway | `[modules] gateway_bind` | `none` (loopback only) / `bearer` / `hmac` single shared secret ≥ 16 bytes (R54) | — |
| job API | `[api] bind` (`127.0.0.1:8547`) | HMAC per machine key: `X-Scaas-Key`, `X-Scaas-Timestamp` (±300 s), `X-Scaas-Nonce` (`[A-Za-z0-9_-]{1,64}`, single use until ts + 300 s), `X-Scaas-Signature = hex(HMAC-SHA256(secret, ts "." nonce "." METHOD " " path?query "\n" body))` (R92) | admin sessions, admin keys, OIDC tokens (R109) |
| admin | `[modules] admin_bind` (`127.0.0.1:9108`) | open: `/healthz`, `/readyz`, `/metrics`, `/v1/admin/login`, `/v1/admin/auth-modes`; otherwise `Authorization: Bearer` with prefix `scaas_s1.` (session), `scaas_ak1.` (admin key) or a JWT (OIDC) (R106) | machine HMAC keys (R109) |
| mesh bus | `[mesh] bind` (`0.0.0.0:8550`) and QUIC `/scaas/bus/1.2` | TLS 1.3 / QUIC client cert, SPKI pin of an active peer row; X25519MLKEM768 only | unpinned keys, TCP+Noise |
| gossip | `[gossip] listen` | libp2p Ed25519 identity, scoring | non-Ed25519 PeerIds |

Machine key secret = `HMAC-SHA256(master_key, "scaas-api-key/1" ‖ 0x00 ‖ key_id ‖ 0x00 ‖ u32be(generation))`;
the store keeps no secret (R92). Non-loopback job/admin binds need TLS in front. Body caps: gateway 64 KiB, job API
1 MiB.

### 12.2 Roles (R107)

`viewer ⊂ operator ⊂ admin`, plus `key_custodian` (not implied by `admin`). Every admin credential carries roles;
creating credentials needs `key_custodian`, and a caller can grant only roles it holds. OIDC maps a per-issuer claim
(`role` for ABP, `realm_access.roles` for Keycloak; `scope` only for machine tokens).

| Capability | viewer | operator | admin | key_custodian |
|---|---|---|---|---|
| Read info, chains, lanes, tokens, namespaces, jobs (no payloads), audit, peers, policy, markets | ✓ | ✓ | ✓ | — |
| Pause/resume a chain, reset a breaker, cancel a job, suspend a peer, pause a market, ban a gossip peer | — | ✓ | ✓ | — |
| Change chain parameters, `fee_recipient`, tokens, lanes, namespaces, policy, peers, markets, gossip switches | — | — | ✓ | — |
| Create/rotate/revoke machine keys, admin keys, admin users | — | — | — | ✓ (roles ⊆ caller's) |

### 12.3 Route summary

| Route | Listener | Auth / role | Status |
|---|---|---|---|
| `POST /v1/metatx` `{chain, token, m, signature}` → `202 {"status":"queued"}` (target adds `intent_id`) | gateway | R54 | **BUILT** |
| `GET /v1/intents/{intent_id}` (gateway-origin rows only) | gateway | R54 | **SPECIFIED** |
| `POST /v1/dex/orders`, `GET /v1/dex/orders?maker=`, `POST /v1/dex/cancel`, `POST /v1/dex/cancel-all`, `GET /v1/dex/markets`, `GET /v1/dex/depth` (levels ≤ 200), `GET /v1/dex/trades`, `GET /v1/dex/ticker` | gateway | R54 | **BUILT** |
| `GET /v1/dex/depth?scope=network`, `GET /v1/dex/homes` | gateway | R54 | **SPECIFIED** (A2 §11.5) |
| `GET /v1/info` | job API | read | **SPECIFIED** |
| `POST /v1/jobs` (≤ 50 per batch) | job API | submit | **SPECIFIED** |
| `GET /v1/jobs/{uid}` | job API | read | **SPECIFIED** |
| `POST /v1/jobs/{uid}/cancel`, `POST /v1/jobs/cancel {origin}` | job API | submit | **SPECIFIED** |
| `GET /v1/jobs?cursor=&limit=&wait=` | job API | read | **SPECIFIED** |
| `GET /v1/events?cursor=&limit=&wait=` | job API | read | **SPECIFIED** |
| `GET/PUT /v1/watch/{chain_key}`, `GET/PUT /v1/tokens/{chain_key}` | job API | read / submit | **SPECIFIED** |
| `GET /healthz`, `GET /readyz`, `GET /metrics` | admin | open | **BUILT** |
| `POST /v1/admin/login`, `/session/refresh`, `/logout`, `GET /v1/admin/me`, `GET /v1/admin/auth-modes` | admin | — / any | **SPECIFIED** |
| `GET /v1/admin/info`, `GET /v1/admin/chains[/{key}]`, `GET …/lanes`, `GET /v1/admin/jobs`, `GET /v1/admin/audit` | admin | viewer | **SPECIFIED** |
| `PATCH /v1/admin/chains/{key}`, `PUT …/fee_recipient`, `POST/DELETE …/tokens`, `PUT …/lanes` (`409 LANE_BUSY`) | admin | admin | **SPECIFIED** |
| `PUT /v1/admin/chains/{key}/state`, `POST …/breaker/reset`, `POST /v1/admin/jobs/{uid}/cancel` | admin | operator | **SPECIFIED** |
| `GET/POST/PATCH /v1/admin/namespaces[/{name}]` | admin | viewer / admin | **SPECIFIED** |
| `GET/POST/PATCH/DELETE /v1/admin/users`, `/admin-keys`, `/keys` (`…/rotate`) | admin | viewer / key_custodian | **SPECIFIED** |
| `GET/POST/PATCH/DELETE /v1/admin/mesh/peers`, `/mesh/policy`; `PUT …/peers/{id}/state` | admin | viewer / admin / operator | **SPECIFIED** |
| `GET/POST/PATCH /v1/admin/dex/markets`, `PUT …/{id}/state` | admin | viewer / admin / operator | **SPECIFIED** |
| `GET /v1/admin/gossip[/peers|/announces]`, `PUT/DELETE …/peers/{id}/ban`, `GET/PUT/DELETE …/trusted` | admin | viewer / operator / admin | **SPECIFIED** (A2) |
| `GET /v1/mesh/policy`, `GET /v1/mesh/intents?since=&limit=` | mesh bus | pinned peer | **SPECIFIED** |
| `/scaas/sync/1` (`intents`, `announces`, `book`), `/scaas/bus/1.2` (`policy`, `intents`) | libp2p | peer | **SPECIFIED** |

### 12.4 Host CLI (R108)

Writes credential rows and the audit log directly (no owner lock needed; never touches jobs):

```
scaas-node --config node.toml                                   # run
scaas-node addresses --config node.toml                         # print lane addresses (BUILT)
scaas-node keystore new --kind mnemonic|secp256k1|ed25519 --out DIR --name FILE   # BUILT
scaas-node mesh-id --config node.toml                           # peer_id, PeerId, SPKI pin
scaas-node admin create NAME --role admin --role key_custodian  # password from stdin, twice
scaas-node admin passwd NAME | admin disable NAME
scaas-node admin key create --role operator --label ci          # prints scaas_ak1.… once
scaas-node key create --namespace odoo-prod --scopes "submit read"   # machine key
scaas-node store init                                           # once per new node: creates the store (0600)
scaas-node store restored                                       # mandatory after any restore: restore_epoch + 1
```

Status: `addresses`, `keystore new`, `store init`, `store restored` **BUILT**; the rest **SPECIFIED**. The node never
creates its store at start: a missing store file (unmounted volume, typo'd `[store] url`) refuses to start.

### 12.5 Admin authentication details (SPECIFIED, R106/R106a)

- Built-in users: Argon2id PHC (`m = 19 MiB, t = 2, p = 1`), passwords 12–256 bytes; login rate limit 5/min per
  name, 20/min per source; lockout after 10 failures for 900 s; uniform `401` with a dummy hash for unknown names.
  Session token `scaas_s1.<b64url(json{sub, ep, roles, iat, exp, auth_time})>.<b64url(HMAC)>`, key derived from
  `master_key` with label `scaas-admin-session/1`; TTL 900 s, refresh until `auth_time + 43 200 s`; `session_epoch`
  bump revokes all sessions of a user.
- Admin API keys: `scaas_ak1.<key_id>.<b64url(32 random bytes)>`, only SHA-256 stored, expiry, hot revoke.
- OIDC: exact issuer allowlist (several allowed), discovery with exact issuer echo, JWKS cached by `(iss, kid)`,
  RS256 (n ≥ 2048) / ES256 / EdDSA per issuer, `aud` must contain the node audience (never one of the app's
  `client_ids`), `exp` and `iat` required, 60 s skew, lifetime ≤ 3 600 s, `none`/`HS*`/`jku`/`x5u`/`jwk`/`x5c`/`crit`
  rejected, no redirects, unknown `iss` never fetches. App: Authorization Code + PKCE S256, tokens in memory only.
- CORS on the admin listener only: exact origins, no credentials, methods `GET POST PATCH PUT DELETE`.
- Audit: every mutation, login and CLI action appends a hash-chained `audit_log` row (`row_hash =
  sha256(prev_hash ‖ canonical row)`) in the same transaction; head exported as `scaas_audit_head_info{hash}`.

---

## 13. Operations

### 13.1 SLOs and telemetry W3B-01 … W3B-06

| Id | Indicator | Definition | Target | On breach | Status |
|---|---|---|---|---|---|
| W3B-01 | Meta-tx success rate | intents finalized (incl. `landed_elsewhere`) ÷ intents broadcast, 30 d | ≥ 99.5 % | fail over RPC, check lane balances, page operator | metric inputs **BUILT** (`scaas_relay_jobs{state}`); SLO **PLANNED** |
| W3B-02 | Simulation zero-revert | broadcast transactions that reverted for a reason simulation would have caught ÷ broadcast; lost races (`consumed`) excluded | **0.00 %** (any occurrence is an incident); research guard: revert rate ≤ 0.5 % per 7 d including races | stop the chain's new work (breaker), investigate contract/simulation drift | gate **BUILT**; metric **PLANNED** |
| W3B-03 | Gas budget adherence | gas spent ÷ approved budget per lane and window | ≤ 100 % (warn 90 %) | breaker `gas_budget` stops new work; notify finance owner | **BUILT** (R55) |
| W3B-04 | Finality latency | broadcast → final range delivered, p95 | ≤ chain hard finality + 60 s (Gnosis ≤ 240 s + 60 s; chain 9000 ≤ 15 s) | alert; check RPC quorum and indexer lag | lag gauge **BUILT** (`scaas_indexer_lag_blocks`); histogram **PLANNED** |
| W3B-05 | Zether proof latency | client proof time + on-chain verification | to be set after measurement on target devices | optimize prover/verifier | **PLANNED** |
| W3B-06 | Relayer fee spread | fees earned − gas paid, per chain per month | may be negative (fee = 0 B2B) | monthly OPEX review | **PLANNED** |

Additional operational SLOs (research §06.8): jobs final without manual intervention ≥ 99.5 %/month; outer-nonce gap
age = 0 for 99.9 % of the time; signed-but-orphaned transactions = 0.

**Metrics (BUILT, prefix `scaas_`):** `relay_jobs{chain,state}`, `payment_requests_attention{chain}`,
`indexer_lag_blocks{chain}`, `relayer_balance{chain,lane}`, `breaker_open{chain,lane,breaker}`,
`drift_alerts{chain}`, `submit_bump_skipped_consumed_total`. SPECIFIED additions: job API, feed, store owner,
admin, audit, OIDC, lane-foreign-nonce (NI §15), mesh (MESH §12) and gossip/TLS (A2 §13.3) metrics.

**Trace contract (PLANNED; OpenTelemetry):** every submission span carries `chain_key`, `lane` (address),
`tx_hash`, `gas_used`, `effective_gas_price`, `entry_ref`, `mode`, `batch`/`nonce`, `finality_depth`, `job_uid`,
`namespace`. No payload data.

**Readiness** (`/readyz`, BUILT): per chain ≥ quorum RPCs answer within 3 s, indexer lag ≤ `max_index_lag`, upstream
reachable; snapshot refreshed every 10 s; 503 with reasons. SPECIFIED additions: store open and owned, lane used
outside this store, issuer failed closed, no gossip peer for 5 min (informational).

### 13.2 FinOps

- **Unit cost:** gas of every finalized job is converted to the deployment's reporting currency at the transaction
  time and allocated to the business document (`entryRef` → invoice/order). PLANNED (HANDOFF GA 2.2 #10).
- **Budgets:** per lane `gas_budget_per_hour`; per namespace `max_live_jobs`; sponsorship budgets per policy row
  (SPECIFIED, [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §B1).
- **Float:** each lane holds gas float for ~50 transactions; refill from treasury when below 30 % of target; the
  `balance_floor` breaker stops a lane at the floor. Auto-refill is PLANNED; today an operator refills (O8).
- **Indicative fixed costs** (research canon §C19, not re-estimated for all families): infrastructure ≈ $480–830 per
  month in year 1; minimum configuration ≈ $620 per month; third-party audit of all contract families is the largest
  one-off cost (O1).
- **Break-even** of independent relayers: §6.9.

### 13.3 RACI

R = responsible, A = accountable, C = consulted, I = informed.

| Decision / task | Contract engineering | Security (CISO) | Legal & compliance | Finance (CFO) | Node operator |
|---|---|---|---|---|---|
| Implement and test contracts | R | C | I | I | I |
| Register a new implementation version in the factory | C | A (after independent audit) | C | I | R (registrar multisig signer) |
| Enable a chain (`draft → active`) | C | A | A | I | R |
| Open read-in of chain data to analytics (land gate phase 2) | I | C | A | I | R |
| Set gas and sponsorship budgets | C | I | I | A | R |
| Emergency pause of a chain / breaker override | C | A | I | C | R |
| Lane key, KMS/HSM and MPC custody | C | A | I | I | R |
| Admin credentials and machine keys (key_custodian) | I | A | I | I | R |
| Controlled-token interventions (court orders) | I | C | A | C | R (submits the quorum transaction) |
| Curve / confidentiality horizon for a Zether token | C | A | C | C | I |
| Store restore and re-push acknowledgement | I | C | I | I | A/R |

Human approval is mandatory (never delegated to an agent) for: opening the land gate, the confidentiality horizon,
credit/gas budgets per agent, registering a new factory implementation, controlled-token interventions.

### 13.4 Incident response runbook

| T | Action | Owner |
|---|---|---|
| T+0 | P1 alert (W3B breach, wrapper reserve below supply, foreign nonce on a lane, audit-chain mismatch) | on-call |
| T+1 min | Preserve evidence: node logs, `/metrics` snapshot, store backup, `audit_log` head | on-call |
| T+5 min | `PUT /v1/admin/chains/{key}/state paused` (stops new submissions; indexing continues) or `halted` (also stops indexing, for chain faults); pause DEX markets | operator |
| T+10 min | Rotate affected credentials: machine keys (`generation + 1`), admin keys, `master_key` if the store or host is suspect; drain and replace lane keys (move gas to new lanes) | key_custodian |
| T+15 min | Declare or dismiss a security breach | CISO |
| T+30 min | Legal review of notification duties under the applicable data-protection regime | legal |
| T+60 min | Root cause; decide resume / wind-down of the affected token or chain | CISO + engineering |
| T+24 h | Post-mortem | all |

Contract-level response is limited by design: permissionless tokens have **no pause**. Containment is off-chain
(stop relaying, pause markets) plus user communication; a controlled token may use its bounded pause (§4.5).

### 13.5 Disaster recovery

| Component | RPO | RTO | Mechanism |
|---|---|---|---|
| Node store | 0 for committed journal (SQLite `synchronous = FULL`; PG/MySQL durable commit); backups ≤ 5 min | 30 min | Restore on another host, then **mandatory** `scaas-node store restored` (bumps `restore_epoch`); clients halt sync until an operator acknowledges; re-push is an operator action (R110). Re-revoke keys revoked after the backup or rotate `master_key` (T19) |
| Lane state | — | minutes | Cold start `plan()`: gap-fill journaled nonces, track signed txs, requeue the rest; never re-sign a tracked tx |
| Private chain | 0 | 60 min | Validator snapshots every 6 h + archive node; quarterly restore drill |
| Client outbox | per ERP database policy | per ERP | The outbox is the client's source of truth for "must go on chain" |
| Subject keys | — | — | Passkey PRF backup, seed, guardians (§9.4); the operator holds none |
| Signer / KMS | — | 30 min | Shamir-split or KMS-native backup of lane mnemonics |

No hot failover for one (company, chain) in v1 (R97); two nodes may serve one company only on different chains.

### 13.6 Circuit breakers and emergency procedures

- Automatic breakers: §6.4. They stop new work, never rescues, gap-fillers, tracking or indexing (N9).
- **Stuck outer transaction:** automatic replacement at ×1.25 every `stuck_after_secs` up to the fee cap; at the cap
  the operator may raise `max_fee_cap_gwei` (hot) or wait; never abandon the nonce.
- **Foreign nonce on a lane** (key used elsewhere): the lane stops leasing; operator verifies no second store or wallet
  uses the key, then retires the lane.
- **Store fencing lost:** the node stops leasing/journaling immediately (`NOT_OWNER`), re-takes the lock with a new
  epoch, replays `plan()`.
- **RPC disagreement:** quorum not met ⇒ indexer holds, `/readyz` red; add or replace endpoints (toml, restart).
- **Wrapper reserve mismatch:** stop relaying for the token, notify holders; no admin key exists to "fix" a
  permissionless token — migration to a new version is the remedy.
- **Lost race / consumed jobs:** not incidents; they resolve to `final` (landed elsewhere) or `dead` (superseded) by the
  normal rules.

---

## 14. Canonical interfaces

Built interfaces are quoted from `smartcontracts/evm/src` (Solidity 0.8.28, OpenZeppelin 5.2). Proposed
interfaces are normative targets for future versions; they must keep the built conventions (custom errors, EIP-712
domains on the contract itself, lane nonces, contract-only allowances, no proxy upgrades).

### 14.1 `IOpenFactory` — BUILT (`src/common/IOpenFactory.sol`, `src/factory/OpenFactory.sol`)

```solidity
interface IOpenFactory {
    enum TokenKind { META, ZETHER }   // future kinds (REGULATED, MIGRATION) append; values never reused
                                      // factory v2 (TW2, BUILT): IOpenFactoryV2.TokenKind adds META_NONE = 2,
                                      // META_SINGLE = 3, META_MULTI = 4; this file stays frozen with v1

    event ImplementationRegistered(TokenKind indexed kind, uint64 indexed version, address indexed implementation, address registrar);
    event ImplementationDeprecated(TokenKind indexed kind, uint64 indexed version, string reason);
    event TokenDeployed(address indexed token, address indexed creator, address indexed underlying,
                        TokenKind kind, uint64 version, address implementation, address verifier);

    error VersionAlreadyRegistered(TokenKind kind, uint64 version, address existing);
    error VersionUnknown(TokenKind kind, uint64 version);
    error VersionKindMismatch(TokenKind expected, TokenKind got);
    error ImplementationNotAContract(address implementation);
    error VerifierUnsupportedOnThisChain(address verifier, string curveName);
    error VerifierRequiredForZether();
    error SaltAlreadyUsed(address existing);

    function registerImplementation(TokenKind kind, uint64 version, address implementation) external; // registrar
    function deprecate(TokenKind kind, uint64 version, string calldata reason) external;             // registrar
    function implementationOf(TokenKind kind, uint64 version) external view returns (address);
    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool);
    function latestVersion(TokenKind kind) external view returns (uint64);

    function createMetaToken(uint64 version, address underlying, bytes calldata initData, bytes32 salt) external returns (address);
    function createZetherToken(uint64 version, address underlying, address verifier, bytes calldata initData, bytes32 salt) external returns (address);
    function createUnregistered(TokenKind kind, address implementation, address underlying, address verifier,
                                bytes calldata initData, bytes32 salt) external returns (address);   // version() == 0

    function predictAddress(address implementation, address creator, bytes32 salt) external view returns (address);
    function isDeployedHere(address token) external view returns (bool);
    function creatorOf(address token) external view returns (address);
    function versionOf(address token) external view returns (TokenKind kind, uint64 version);
    function getWrapper(address creator, address underlying) external view returns (address);       // first one
    function getWrapperCount(address creator, address underlying) external view returns (uint256);
    function getWrapperAt(address creator, address underlying, uint256 index) external view returns (address);
    function deployCountFor(address underlying) external view returns (uint256);
    function deployedFor(address underlying, uint256 index) external view returns (address);
}
// OpenFactory only: address public immutable registrar; bool public zetherEnabled;
//   event ZetherEnabled(bool enabled); error NotRegistrar(); error ZetherDisabled();
//   function setZetherEnabled(bool on) external;   // on ⇒ dev chain only
// IFactoryToken: function initialize(address creator, address underlying, address verifier, uint64 version, bytes calldata initData) external;
```

Differences from the SRS draft: adds `isDeprecated`, `getWrapperCount/At`, `deployedFor`, the events/errors above
and `setZetherEnabled`; `predictAddress` is per `(implementation, creator, salt)`.

**Factory v2 — BUILT** (`src/common/IOpenFactoryV2.sol`, `src/factory/OpenFactoryV2.sol`; [TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §9; a new deployment, all functions above kept):

```solidity
function createTiered(TokenKind kind, uint64 version, address[] calldata underlyings,
                      bytes calldata initData, bytes32 salt) external returns (address token);
function createTieredUnregistered(TokenKind kind, address implementation, address[] calldata underlyings,
                                  bytes calldata initData, bytes32 salt) external returns (address token); // version 0
event TieredTokenDeployed(address indexed token, address indexed creator, TokenKind kind, uint64 version,
                          address implementation, address[] underlyings);
error UnderlyingCountInvalid(uint256 n);          // META_NONE 0, META_SINGLE 1, META_MULTI 2..8
// registerImplementation checks impl.tokenKind() (VersionKindMismatch) and impl.factory() == this for the new kinds
interface IFactoryTokenV2 {
    function tokenKind() external pure returns (TokenKind);
    function initialize(address creator, address[] calldata underlyings, uint64 version, bytes calldata initData) external;
}
```

### 14.2 `IERC20MetaTx` and `IERC20Payment` — BUILT (`src/metatx/`)

```solidity
interface IERC20MetaTx is IERC20 {
    event MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch,
                                  uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
    // no MetaNonceCancelled event in the built code (the SRS draft has one; PLANNED for v2: indexers then see
    // lane cancellations without reading storage)
    error MetaTxExpired(uint256 validUntil, uint256 nowTs);
    error MetaTxBadNonce(uint256 expected, uint256 got);
    error MetaTxBadSignature();
    error MetaTxUnauthorizedRelayer(address allowed, address caller);
    error MetaTxUnknownMode(uint32 mode);
    error MetaTxInsufficientForFee(uint256 needed, uint256 available);
    error SpenderNotContract(address spender);   // R26
    error CallerNotContract(address caller);     // R26

    function metaNonce(address from, uint256 batch) external view returns (uint256);
    function metaTxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bool success);
    function supportedModes() external view returns (uint32);   // 0xF3
    function cancelMetaNonce(uint256 batch) external;
}

interface IERC20Payment is IERC20MetaTx {
    event PaymentSettled(address indexed from, address indexed to, uint256 amount, uint256 feeAmount,
                         address feeRecipient, bytes32 indexed entryRef);
    function payWithFee(address to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient,
                        bytes32 entryRef) external returns (bool);   // msg.sender pays; fee on top of amount
}
```

`MetaToken` adds: `OP_PAY = bytes4(keccak256("pay(bytes32)"))`, `OP_TRADE =
bytes4(keccak256("trade(address,uint256,address)"))`, `OP_APPROVE = bytes4(keccak256("approve(address,uint256)"))`;
`mint`, `wrap`, `unwrap`; provenance getters; errors `MetaTxUnknownOp(bytes4)`, `PayToZero`,
`TradeLegNotRestricted`, `WrapperHasNoMint`, `NotMinter`, `NotAWrapper`, `ApproveCarriesValue`,
`ApproveSpenderMismatch`.

**v2 additions — BUILT** (`src/metatx/{MetaTxCore,MetaTokenBase,IMetaTokenV2,NoUnderlyingToken,SingleUnderlyingToken,MultiUnderlyingToken}.sol`, `src/hedera/HederaTokensV2.sol`; [TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §3, §5–§8, §10.2): domain `("SCaaS MetaToken", "2", chainId, clone)`, same
`MetaTransaction` typehash.

```solidity
// MetaTxCore / MetaTokenBase (all tiers)
event MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce);
error FeeRecipientIsPayee();  error MtxModeShape(uint32 mode);  error MtxBatchEmpty();  error MtxBatchLengthMismatch();
error UnwrapRecipientMismatch();
function mtxTransfer(address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
                     uint32 mode, address relayer, bytes calldata signature) external returns (bool);
function mtxTransferWithFee(address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
                            uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature)
    external returns (bool);
function executeMetaTransactionWithFee(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external returns (bool);
function mtxPay(address from, address to, uint256 amount, bytes32 payId, uint256 validUntil, uint32 mode,
                address relayer, uint256 fee, address feeRecipient, bytes calldata signature) external returns (bool);
function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures) external returns (bool);
function payLane(bytes32 payId) external view returns (uint256);
function mtxUnwrap(address from, address underlying, uint256 wrapped, address recipient, uint256 minOut, uint256 batch,
                   uint256 nonce, uint256 validUntil, uint32 mode, address relayer, bytes calldata signature)
    external returns (bool);
function mtxUnwrapWithFee(address from, address underlying, uint256 wrapped, address recipient, uint256 minOut,
                          uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer, uint256 fee,
                          address feeRecipient, bytes calldata signature) external returns (bool);
// op OP_UNWRAP = bytes4(keccak256("unwrap(address,address,uint256)")) on wrapper tiers; MetaTxUnknownOp on NoUnderlyingToken
// NoUnderlyingToken
function mint(address to, uint256 amount) external;  function burn(uint256 amount) external;  function renounceMinter() external;
// SingleUnderlyingToken (MultiUnderlyingToken overrides the single-asset ABI to revert UnderlyingRequired)
function wrap(uint256 amount) external returns (uint256 minted);
function unwrap(uint256 wrapped, address recipient) external returns (uint256 out);                   // minOut = 0 (v1 ABI)
function unwrap(uint256 wrapped, address recipient, uint256 minOut) external returns (uint256 out);
function addReserve(address underlying, uint256 amount) external;
function proposeRate(address underlying, uint96 num, uint96 den) external;   // rateAdmin; one pending per token; RateFixed if fixed
function cancelRate() external;                                              // rateAdmin
function executeRate() external;                                             // rateAdmin only, eta ≤ now ≤ eta + 7 days
function renounceRateAdmin() external;
function underlyings() external view returns (address[] memory);
function legOf(address u) external view returns (uint96 num, uint96 den, uint256 reserve, uint8 decimals, bool wrapEnabled);
function collateralValue() external view returns (uint256);                  // Σ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply
// MultiUnderlyingToken
function wrap(address underlying, uint256 amount) external returns (uint256 minted);
function unwrap(address underlying, uint256 wrapped, address recipient, uint256 minOut)
    external returns (uint256 out, uint256 burned);
function disableWrap(address underlying, bytes32 reason) external;           // guardian, one-way
function renounceGuardian() external;
// errors: WrapPausedForRateChange(address), UnwrapBelowMin(uint256 out, uint256 minOut), UnwrapRecipientInvalid(address)
```

Events `Wrapped`, `Unwrapped`, `ReserveAdded`, `RateChangeProposed`, `RateChangeCancelled`, `RateChanged`,
`RateAdminRenounced`, `MinterRenounced`, `WrapDisabled`, `GuardianRenounced` and the error list: [TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §10.2.

### 14.3 `IZetherToken` — BUILT (`src/zether/IZetherToken.sol`)

```solidity
interface IZetherToken is IERC20MetaTx {
    struct AccountState { bytes accC; bytes accD; bytes pendingC; bytes pendingD; uint64 accSeq; uint64 pendingSeq;
                          uint64 sendCounter; uint64 modeNonce; ZetherTypes.RollOverMode mode; }
    event Funded(ZetherTypes.UA indexed account, uint256 amount);
    event ConfidentialTransfer(ZetherTypes.UA indexed from, ZetherTypes.UA indexed to, ZetherTypes.UA indexed beneficiary,
                               uint256 fee, uint256 sendCounter, bytes32 entryRef);
    event Burned(ZetherTypes.UA indexed account, uint256 amount, address indexed recipient);
    event RolledOver(ZetherTypes.UA indexed account, uint256 accSeq);
    event RollOverModeChanged(ZetherTypes.UA indexed account, ZetherTypes.RollOverMode mode);

    function maxDecryptableShielded() external view returns (uint256);   // ≤ 2^54
    function shieldScale() external view returns (uint256);
    function confidentialFee() external view returns (uint256);
    function auditorKey() external view returns (bytes memory);
    function totalShielded() external view returns (uint256);
    function registered(ZetherTypes.UA account) external view returns (bool);
    function accountState(ZetherTypes.UA account) external view returns (AccountState memory);
    function sendCounter(ZetherTypes.UA account) external view returns (uint256);

    function rollOverPublic(ZetherTypes.UA account) external;
    function rollOverBatch(ZetherTypes.UA[] calldata accounts) external;
    function rollOverSigned(ZetherTypes.UA account, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig) external;
    function setRollOverMode(ZetherTypes.UA account, ZetherTypes.RollOverMode mode, uint64 validUntilBlock, bytes calldata sig) external;

    function fund(bytes calldata encodedY, uint256 amount) external;
    function transferConfidential(bytes calldata payload, bytes calldata proof, bytes calldata authSig,
                                  ZetherTypes.UA beneficiary) external returns (bytes32 entryRef);
    function burn(bytes calldata payload, uint256 amount, address recipient, ZetherTypes.UA beneficiary,
                  bytes calldata proof, bytes calldata authSig) external;
    function wrap(uint256 amount) external;
    function unwrap(uint256 amount, address recipient) external;

    function transferStatement(bytes calldata payload, ZetherTypes.UA beneficiary, bytes32 envelopeBinding) external view returns (bytes memory);
    function burnStatement(bytes calldata payload, uint256 amount, address recipient, ZetherTypes.UA beneficiary,
                           bytes32 envelopeBinding) external view returns (bytes memory);
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);

    function verifier() external view returns (IZetherVerifier);
    function registry() external view returns (address);
    function underlying() external view returns (address);
    // provenance: factory(), creator(), implementation(), version()
}
```

Differences from the SRS draft (RS2-2, RS2-14, limits): direct `transferConfidential` has 4 parameters and no outer
fee (the outer fee lives only in the envelope); `burn` carries `recipient`, `beneficiary`, `authSig`; registration
lives in the registry, not the token (`Registered` event removed); `RolledOver` carries `accSeq` (no epoch).

### 14.4 `ITransferDisclosure` — BUILT (implemented by `ZetherToken`)

```solidity
interface ITransferDisclosure {
    enum OpeningKind { SENDER_S, RECEIVER_X, AUDITOR }
    event AmountAttested(bytes32 indexed entryRef, uint256 amount, OpeningKind kind, address indexed attestedBy, uint256 timestamp);
    error UnknownEntry(bytes32 entryRef);
    error OpeningMalformed();
    function verifyTransferAmount(bytes32 entryRef, uint256 amount, OpeningKind kind, bytes calldata opening) external view returns (bool);
    function attestTransferAmount(bytes32 entryRef, uint256 amount, OpeningKind kind, bytes calldata opening) external returns (bool);
    function transferCiphertext(bytes32 entryRef) external view returns (bytes memory encodedCiphertext, bytes memory encodedYTo);
}
```

### 14.5 `IUniversalAccountRegistry` — BUILT (`src/registry/`, dev chains only)

```solidity
interface IUniversalAccountRegistry {
    struct AccountConfig { bool registered; AuthScheme scheme; address linkedEVMAddress; bytes authData; }
    event AccountRegistered(ZetherTypes.UA indexed ua, AuthScheme indexed scheme, address indexed linkedEVM, bytes authData);
    error AccountAlreadyRegistered(ZetherTypes.UA ua);
    error InvalidProofOfPossession();
    error UnauthorizedScheme(AuthScheme scheme);
    error EVMAlreadyLinked(address evmAddress);
    error InvalidPublicKey();
    error InvalidAuthData();
    error Unauthorized(ZetherTypes.UA ua);

    function register(bytes calldata encodedY, AuthScheme authScheme, bytes calldata authData,
                      bytes calldata popSignature, bool linkEVM) external returns (ZetherTypes.UA ua);
    function accounts(ZetherTypes.UA ua) external view returns (bool registered, AuthScheme scheme,
                                                                address linkedEVMAddress, bytes memory authData);
    function links(address evmAddress) external view returns (ZetherTypes.UA);
    function link_eth(ZetherTypes.UA ua) external view returns (address);
    function isRegistered(ZetherTypes.UA ua) external view returns (bool);
    function keyLengthOf(ZetherTypes.UA ua) external view returns (uint256);                       // 64 | 128 | 0
    function popChallenge(bytes calldata encodedY, address account) external view returns (bytes32); // keccak256(abi.encodePacked(registry, encodedY, account))
    function requireAuthorized(ZetherTypes.UA ua, bytes32 digest, bytes calldata sig, bool zkCovered) external view;
}
enum AuthScheme { SELF_SCHNORR, ECDSA_MULTISIG, FROST_BN254, MUSIG2_BN254, BLS_BN254, BLS_12381, PQ_COMMITMENT, SMART_ACCOUNT_1271 }
```

`EVMLinkUpdated` from the SRS draft is not built (no relinking, RS2-9). Proposed extension (PLANNED) for identity
sync with regulated tokens: `attributes(UA) → (uint64 flags, uint64 validUntil, address attester)` with flag bits
`KYC_DONE = 1`, `ACCREDITED = 2`, `SANCTIONS_CLEAR = 4`, set by an attester multisig, read by `IRegulatedToken`
compliance checks; the registry itself stays free of personal data.

### 14.6 `IRegulatedToken` — SPECIFIED ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §3.3 supersedes this proposal)

```solidity
interface IRegulatedToken is IERC20Payment {
    event AccountFrozen(address indexed account, bytes32 indexed courtRulingId, address indexed authority);
    event AccountUnfrozen(address indexed account, bytes32 indexed courtRulingId, address indexed authority);
    event JudicialTransferExecuted(address indexed from, address indexed to, uint256 amount, bytes32 indexed courtRulingId);
    event CourtOrderedBurn(address indexed account, uint256 amount, bytes32 indexed courtRulingId);
    event Paused(bytes32 indexed reasonRef, uint64 until);       // until ≤ now + 7 days
    event Unpaused();
    error AccountIsFrozen(address account);
    error NotAuthority(address caller);
    error RulingRequired();
    error PauseTooLong(uint64 until);
    error TransferNotCompliant(address from, address to, uint8 reason);

    function authority() external view returns (address);          // multisig contract (≥ 3-of-5); never an EOA
    function complianceRegistry() external view returns (address); // optional (securities)
    function isFrozen(address account) external view returns (bool);
    function checkTransferCompliant(address from, address to, uint256 amount) external view returns (bool ok, uint8 reason);

    function freezeAccount(address account, bytes32 courtRulingId) external;                                 // authority
    function unfreezeAccount(address account, bytes32 courtRulingId) external;                               // authority
    function judicialForceTransfer(address from, address to, uint256 amount, bytes32 courtRulingId) external returns (bool);
    function courtOrderBurn(address account, uint256 amount, bytes32 courtRulingId) external returns (bool);
    function pause(bytes32 reasonRef, uint64 until) external;       // authority; exits reopen automatically at `until`
    function unpause() external;
}
```

Rules: §4.5. Meta-tx execution from a frozen `from` reverts at step 6 (`AccountIsFrozen`); credits to frozen
accounts succeed. `courtRulingId == 0` ⇒ `RulingRequired`.

### 14.7 `ISealedBidTender` — SPECIFIED (superseded by [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §A.3; sketch kept for history)

```solidity
interface ISealedBidTender {
    enum TenderState { NONE, OPEN_FOR_BIDS, REVEAL_PHASE, AWARDABLE, SETTLED, CANCELLED }
    enum Rule { LOWEST_PRICE, HIGHEST_PRICE }
    enum BondPolicy { RETURN_ON_AWARD, HOLD_UNTIL_RELEASE }
    struct TenderConfig {
        address buyer; address depositToken; uint256 minDeposit;
        uint64 commitDeadline; uint64 revealDeadline; uint64 awardDeadline;
        Rule rule; uint256 minPrice; uint256 maxPrice;           // 0/0 = no bounds
        BondPolicy bondPolicy; uint64 bondReleaseTime; address slashSink;
        bytes32 eligibilityRoot;                                 // 0 = open; else Merkle root of allowed bidders
        bytes32 documentRef;                                     // hash of the tender documents (off chain)
    }
    event TenderCreated(uint256 indexed tenderId, address indexed buyer, bytes32 documentRef, TenderConfig config);
    event BidSubmitted(uint256 indexed tenderId, address indexed bidder, bytes32 commitment);
    event BidRevealed(uint256 indexed tenderId, address indexed bidder, uint256 price);
    event TenderSettled(uint256 indexed tenderId, address indexed winner, uint256 winningPrice);
    event TenderCancelled(uint256 indexed tenderId);
    event DepositRefunded(uint256 indexed tenderId, address indexed bidder, uint256 amount);
    event DepositSlashed(uint256 indexed tenderId, address indexed bidder, uint256 amount);
    event BondReleased(uint256 indexed tenderId, address indexed winner, uint256 amount);
    event BondClaimed(uint256 indexed tenderId, bytes32 reasonRef, uint256 amount);
    error WrongPhase(TenderState state);
    error NotEligible(address bidder);
    error CommitmentMismatch();
    error AlreadyWithdrawn();

    function createTender(TenderConfig calldata c) external returns (uint256 tenderId);
    function cancelTender(uint256 tenderId) external;                      // buyer, before the first commitment
    function submitBidCommitment(uint256 tenderId, bytes32 commitment, bytes32[] calldata eligibilityProof) external;
    function revealBid(uint256 tenderId, uint256 price, bytes32 salt) external;
    function settleTender(uint256 tenderId) external;                      // buyer; anyone after awardDeadline
    function withdrawDeposit(uint256 tenderId) external;                   // losers, all bidders of a cancelled tender
    function releaseBond(uint256 tenderId) external;                       // buyer signature or after bondReleaseTime
    function claimBond(uint256 tenderId, bytes32 reasonRef) external;      // buyer, HOLD_UNTIL_RELEASE only
    function commitmentOf(uint256 tenderId, uint256 price, bytes32 salt, address bidder) external view returns (bytes32);
    function state(uint256 tenderId) external view returns (TenderState);
    // meta-tx: every bidder function also available through the contract's EIP-712 op envelope with lane nonces
}
// commitment = keccak256(abi.encode(tenderId, price, salt, bidder, block.chainid, address(this)))
```

Differences from the SRS draft: no `payable` (token deposits, not native coin), explicit `createTender`, phase state
`AWARDABLE`, eligibility proof, bond handling, slashing event, and a commitment bound to tender, chain and contract.

### 14.8 `IVestingVault` — SPECIFIED ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §4.2 supersedes this proposal)

```solidity
interface IVestingVault {
    struct Stream { address token; address sender; address recipient; uint256 totalAmount;
                    uint64 startTime; uint64 cliffTime; uint64 stopTime; uint256 amountWithdrawn; bool revocable; bool revoked; }
    event StreamCreated(uint256 indexed streamId, address indexed sender, address indexed recipient, address token,
                        uint256 totalAmount, uint64 startTime, uint64 cliffTime, uint64 stopTime, bool revocable);
    event TokensWithdrawn(uint256 indexed streamId, address indexed recipient, uint256 amount);
    event StreamRevoked(uint256 indexed streamId, uint256 vestedPaid, uint256 unvestedReturned);
    function createStream(address token, address recipient, uint256 amount, uint64 startTime, uint64 cliffTime,
                          uint64 stopTime, bool revocable) external returns (uint256 streamId);
    function withdrawVested(uint256 streamId, uint256 amount) external returns (bool);   // recipient; meta-tx capable
    function revoke(uint256 streamId) external;                                           // sender, if revocable
    function vestedAmount(uint256 streamId, uint64 at) external view returns (uint256);
    function balanceOfStream(uint256 streamId) external view returns (uint256 withdrawable);
}
```

### 14.9 Other built interfaces (reference)

| Contract | Key entry points |
|---|---|
| `MandateWallet` | `setMandate(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry)`, `setPayee`, `revoke`, `payUnderMandate(token, payee, amount, entryRef, validUntil, sig)`, `revokeWithSig`, `executeAsOwner`, `isValidSignature`; typehashes `PayUnderMandate(address token,address payee,uint256 amount,bytes32 entryRef,uint256 validUntil)`, `RevokeMandate(address token,uint256 validUntil)` |
| `SubjectAccount` / `SubjectAccountFactory` | `initialize(firstKey, guardian)`, `isValidSignature`, `executeAsOwner(data, nonce, validUntil, signature)`, `addKey`/`removeKey`/`rotateKey`/`setGuardian`/`execute` (self), `initiateRecovery`/`completeRecovery`/`cancelRecovery`; factory `predict`, `deploy` (idempotent) |
| `OrderBookDex` | `settle(Match[]) returns (bool[])` (atomic per pair; none ⇒ `NothingSettled`), `cancel(CancelReq[])`, `invalidateNonces(maker, newMin, sig)`, `checkOrder`, `setMarket` (admin); `Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,uint256 nonce,uint256 expiry,uint32 maxFeePpm,uint8 flags,address relayer,uint8 feeMode,uint256 fee,address feeToken,address feeRecipient)` |
| `MetaTxDex` (legacy) | `settle(Leg a, Leg b)`: two `trade` meta-tx legs, fill-or-kill, no allowance, no route in the gateway |
| `IZetherVerifier` | `proofSystemId`, `curveName`, `isSupportedOnThisChain`, `verifyTransfer(statement, proof)`, `verifyBurn`, `generators`, point ops |

---

## 15. Roadmap, open questions, recorded contradictions

### 15.1 Roadmap

Order of streams per `TODO.md` and NI §17 / A2 §17 (one heavy stream at a time):

| # | Stream | Content | Depends on | Status |
|---|---|---|---|---|
| 0 | Review | Owner review of NI (R87–R111) and §18.2; independent review; deferred full test runs after the repo split | — | open |
| 1 | S3 / S3′ | Envelope library, digests per family, `hub.sig`, conformance vectors; renames to `scaas-intent/1.2`; gossip message builders + `scaas-gossip-v1.json` | — | envelope **BUILT** (43 cases); gossip vectors open |
| 2 | P1 | Node store v2 on SQLite + config authority; `[identity]`, `[transport]`, `[gossip]` config parsing | S3 | **SPECIFIED** |
| 3 | P2 | Job API, HMAC machine keys, built-in admin users, admin keys, CLI | P1 | **SPECIFIED** |
| 4 | P3 | Submit and lanes from the store (safety-critical); gateway journaled in `~gateway` | P2 | **SPECIFIED** |
| 5 | P4 | Indexer and `/v1/events`, watch lists, token subsets | P3 | **SPECIFIED** |
| 6 | P5 | Odoo push/sync client | P4 | **SPECIFIED** |
| 7 | P6 | Push e2e, cutover rehearsal and runbook; owner cutover per chain (testnet first) | P5 | **SPECIFIED** |
| 8 | P2b | OIDC mode, full admin routes, audit export, CORS (JWT verification on `aws-lc-rs`) | P6 | **SPECIFIED** |
| 9 | P1b | PostgreSQL and MySQL backends | P2b | **SPECIFIED** |
| 10 | P7 | DEX book in the store | P1b | **SPECIFIED** |
| 11 | S1b′ | Company bus scope (`restricted`/`open`/`public`) delivered per job | P5 | **SPECIFIED** |
| 12 | S5′ | HTTPS mTLS bus, process-wide `aws-lc-rs` + X25519MLKEM768 | P1 | **SPECIFIED** |
| 13 | S6′ | Mesh pipeline over job rows; `may_gossip` hooks | S5′ | **SPECIFIED** |
| 14 | G1 | libp2p core: QUIC + TCP/Noise, Kademlia, gossipsub + scoring, sync, bus over QUIC | S6′ | **SPECIFIED** |
| 15 | G2 | Announces, exclusivity over gossip, landed hints | G1 | **SPECIFIED** |
| 16 | G3 | DEX book gossip (home model) | G2, P7 | **SPECIFIED** |
| 17 | S7″ | Multi-node e2e (MESH E1–E12 on both bus carriers + E-G1…E-G10) | G3 | **SPECIFIED** |
| 18 | P9 | Remove the pull path (`odoo.rs`, `[odoo]`, legacy Odoo service methods) after ≥ 14 days all-push | S7″ or calendar | **SPECIFIED** |
| 19 | S8″ | Spec corrections across older specs | P9 | **SPECIFIED** |
| 20 | Rename | `scaas` names in code, metrics, env, headers and on-chain tags | owner plan | **BUILT** (code); older component specs still cite old names |
| 21 | app | React + Vite console/dApp (EVM + meta-tx families first; passkey/seed vault, extension wallets, dev key; OIDC only for node admin) | node APIs | **PLANNED** |
| 22 | Queued | TON payer tx hash on `mined`; backup-key toggle, device-bound vault, Sui `fam_sui.verify`, Soroban/Aptos/Solana signers in clientkeys; Zether portal balance cache | — | **PLANNED** |
| 23 | Product features | receiver-pays, sponsorship policy, KeyPool auto-refill, outbound treasury payouts, anchoring (Merkle/HCS), crypto-shredding tooling, W3B SLOs/OTel/FinOps, controlled tokens, tender, vesting, managed DEX, asset suite wizard, Celo `l1_batch`, Hedera HCS/scheduled tx | — | **PLANNED**; controlled tokens, vesting, managed DEX, asset suite **SPECIFIED** ([AS](superpowers/specs/2026-10-06-asset-suite-design.md)); receiver-pays, sponsorship policy, tender, crypto-shredding **SPECIFIED** ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md)) |
| 24 | Post-quantum Zether | BFV/BGV confidential balances on private/PoA chains | mesh round 4 | **PLANNED** |
| 25 | TW2 T1–T8 | Token wrappers v2: `MetaTxCore` + named functions, three tiers, rates, multi-underlying (adjustable legs, admin-only execute, all-leg wrap pause), gasless unwrap op with `minOut`, factory v2, Hedera children, invariant suite, node/Odoo fields ([TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §15) | owner review of TW2 | contracts T1–T6 **BUILT** (EVM + Hedera); T7 node/Odoo/SDK **SPECIFIED** |
| — | Owner/operator steps | O1 audit of every contract family; O2 registrar multisig; O3 real deployments; O4 7-day finality evidence + ≥ 2 RPCs; O5 reverse-proxy rate limits; O6/O7 KMS/HSM custody and lane signers; O8 lane funding; O9 land-gate decision; O10 subject-account onboarding; Z1–Z6 Zether gates | — | open |

### 15.2 Open questions for the owner

1. **Interpretations of NI §18.2** still to confirm: Odoo namespace `allow_call = true`; paused chain accepts and
   holds jobs; several companies may share a namespace (default one per database); status latency ≤ ~10 s live,
   ≤ 1 min idle; cancel of a published job reports "already sent".
2. **`bus_scope = public`** as a separate opt-in (A2 §19 q1; this document assumes separate).
3. **Relayer-unbound DEX orders** in network books (settle-claim rule, A2 §11.6) or keep home-bound only.
4. **Assignment trust on the open mesh:** `assign_min_landed = 3` in 7 days, or admin trust only.
5. **QUIC PQ-only:** accept that classical-only third-party nodes join only over TCP+Noise.
6. **Chain 9000 as a Zether dev chain** (Z3) and the **curve** policy for production Zether tokens (Z4).
7. **Receiver-pays** two-signature op design and whether it belongs in v2 of `MetaToken`.
8. **Controlled tokens**: quorum composition defaults and whether `IRegulatedToken` is a factory kind or a separate
    factory.
9. **Tender** parameters (minimum reveal window, slash sink default, bond policy default).
10. **Soroban on the mesh**: accept the host auth nonce as the consumption signal (would qualify Soroban) or keep it
    job-API only.
11. **Second event source** to bound a compromised node's ability to fake `/v1/events` (NI §18.3).

### 15.3 Contradictions between the SRS drafts and rulings/code (resolved here in favour of rulings/code)

| Topic | SRS says | Current position | Source |
|---|---|---|---|
| Job source | ERP outbox claimed with `FOR UPDATE SKIP LOCKED`, updates over `/json/2` | ERP pushes to the node job API and polls feeds | R87, R97, R101 |
| Nonce store | Redis Lua lease + fencing generation | Node store journal + owner lock + fencing epoch | R88, R111, UD §23.7 |
| Config authority | `blockchain.chain`/`blockchain.token` in the ERP | Node store; toml bootstraps | R95 |
| Mesh transport | libp2p gossipsub only, topic `/metatx/v1`, validate with `metaTxDigest` + simulation before gossip | Gossip (open mesh) + pull bus (admitted); per-chain topics `/scaas/intent/1.2/<chain_key>`; bounded freshness read, simulation on submit only | R112, R117, R118 |
| Private profile | Mesh off, single internal hub, round robin | Admitted private peers over a PQ bus, origin-only serving | R76, R85, R113 |
| Ecosystems | Six ecosystems | Family taxonomy; Soroban = Stellar + Pi; Move = Aptos + Sui; Solana added; Soroban not on the mesh v1 | owner, R77 |
| EOA approve lockdown | Block EOA **callers** of `approve` (`msg.sender == tx.origin && extcodesize == 0`) | Block EOA **spenders** and EOA callers of `transferFrom`; EIP-7702 designators are EOAs | R26 |
| Fast path | `mtxPay(sender, …, payId, …)` and `batchMtxPay` exist with their own typehash | v1: `pay(bytes32 entryRef)` op and `payWithFee`; v2: named `mtxPay`/`mtxBatch` as thin entry points over the one pinned typehash (BUILT) | R2, R138–R140 |
| Tier 3 | Weighted basket (`depositBasket`/`redeemBasket`, all legs at once) | Any-of multi-underlying: wrap/unwrap one chosen leg, pooled reserve, guardian disables wrap only | R136 |
| Fee recipient | Relayer or any address | Never the payee (`FeeRecipientIsPayee`, v2) | R132 |
| `payId` derivation | `keccak256(companyId ‖ moveId ‖ amount ‖ ephemeralSalt)` | `entryRef` = 32 random bytes; lane = `keccak256("scaas.pay.lane" ‖ entryRef)`; `payId` of the v2 `mtxPay` **is** `entryRef` and v2 derives the lane on chain (`payLane`) | R9, R139 |
| Event name | `Payment(sender, recipient, amount, fee, feeRecipient, payId)` | `PaymentSettled(from, to, amount, feeAmount, feeRecipient, entryRef)` | code |
| `cancelMetaNonce` event | `MetaNonceCancelled` emitted | No event in the built code | code |
| Pipeline | 8 steps | 9 steps (nonce++ and emit separate; `_checkOp` at step 6) | code |
| Zether `n_v` | 32 | 64 | RS-NV64-1 |
| `DECRYPT_BOUND` | constant 2^40 | Client-configured BSGS (`bound_bits ≤ 54`) + device balance cache | RS-NV64-2 |
| Large transfers | Auto-split above 2^32 − 1 units | One transaction up to the balance (≤ 2^54) | Zether limits D1 |
| `shieldScale` | Number of decimals kept (e.g. "2") | Raw units per shielded unit (e.g. `10^4`) | RS2-3 |
| Zether gas | ~1.905 M per transfer; BLS cheaper | 3.29 M (bn254) / 3.92 M (BLS) measured; BLS more expensive | Zether design §15 |
| `IZetherToken` | 6-parameter `transferConfidential` with outer fee; `Registered` event in the token | 4 parameters, no outer fee on direct calls; registration in the registry | RS2-14 |
| Registry PoP challenge | `keccak256(registry ‖ encodedY ‖ msg.sender)` | Same, plus a second proof for the authorization key (`authPop`) | Zether design §11.2 |
| Hedera sponsorship | Payer-account sponsoring | Not used (subject sequence lock); same Solidity on HSCS, HIP-632 for ED25519 | R63 |
| Cosmos | `x/feegrant` + `x/authz` | feegrant only as a seam, authz never | R66 |
| TON | W5 gasless extensions for the subject | Relayer W5 lanes; custom jetton wallet verifies `SignedOp` | R67 |
| Sui | Sponsored transactions as the gas mechanism | Relayer lane PTB; sponsorship only for subject deposits | R64 |
| Inbound API | `POST /api/v1/blockchain/{ecosystem}/{network}/inbound-{tx_type}` with raw native transactions | Gateway `POST /v1/metatx` (EVM) + job API `POST /v1/jobs` (all families, signed payloads, never subject-signed native transactions) | R30, R87 |
| Celo finality | `l1_batch` | PLANNED; `tag` until built | config |
| Data protection | Names one country's regulation (e.g. a national personal-data decree) | Market-neutral; generic GDPR-class controls | owner |
| Example amounts | Local-currency examples, local caps | Neutral units | owner |
| FIPS | "FIPS 140-2 moved to historical on 2026-09-21" | Use FIPS 140-3 Level 3 language | canon §C15.1 |
| Precedence | Compiled code > canon > SRS | Owner rulings > SCaaS.md > component specs > code (byte formats) > research | owner |
| Redis/KeyPool (V3 addendum in research) | Multi-wallet KeyPool canonical; Redis lease optional | Lanes per chain from one mnemonic; least-in-flight/oldest-first by lane scheduler; no Redis | R60, R62, UD §23.7 |

Contradictions inside this repository found while writing (to fix in their files, not here):

| File | Says | Code / ruling |
|---|---|---|
| `smartcontracts/evm/README.md` | "mode bitmask removed, wildcard `relayer == 0`" | `MetaTxLib` keeps the bitmask (`0xF3`) |
| `smartcontracts/evm/README.md` | "Zether is still interface only" | `ZetherToken`, verifiers, registry built (dev chains) |
| `smartcontracts/evm/README.md`, `src/chains/private9000/README.md` | chain 9000 profile `berlin`, no BLS precompiles | `foundry.toml` `private9000 = prague` after the 2026-08-31 chainspec fix |
| round-3 design R32 | seed vault scrypt `N = 2^15` | `clientkeys` uses `N = 2^17` |
| round-3 design §B.1 `Family` enum | six families | adapters for eight (`evm`, `hedera`, `cosmos`, `soroban`, `sui`, `ton`, `solana`, `aptos`) |
| MESH §3.4 | `ring` provider, no `aws-lc-rs` | reversed by R114 |
| NI §3 / §7.1 | job API `[api] bind` default `127.0.0.1:8547` | the built gateway's default `gateway_bind` is also `127.0.0.1:8547`; one default must change when both listeners run |
