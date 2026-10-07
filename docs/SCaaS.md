# SCaaS — SmartContract as a Service: System Specification

**Status:** normative, 2026-10-07 (aligned with the component specs listed in §0.1, including every 2026-10-07 review
fold and the owner rulings of that day: chain id 7622, `PqzToken` implements `IERC20MetaTx`, every value-holding program
immutable at deploy). Owner of this file: the `scaas` repository (`scaas/docs/SCaaS.md`).
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
   neutrality) and 2026-10-07 (private chain id 7622; `PqzToken` implements `IERC20MetaTx`, PQZ R284; Aptos, Sui,
   Solana and Cosmos programs immutable at deploy, R3D CR-R3-11 / NI R348). They override everything below,
   including code that has not caught up.
2. **This document** (`SCaaS.md`) and `integration.md`.
3. **Component specs** in `docs/superpowers/specs/` (register below). For a detail this document does not state,
   the component spec is normative.
4. **Code** — pinned behaviour (typehashes, KAT vectors, conformance vectors) is normative for byte formats; a
   difference between code and an owner ruling is a bug in the code, not in the ruling.
5. **Research** in `docs/superpowers/specs/blockchain-research/` (`00-CANON.md`, `_USER-DECISIONS.md`, notes 01–16):
   background and rationale only.

**Component spec register** (short names used throughout this document):

| Short | Spec | Rev | Rulings | Status |
|---|---|---|---|---|
| PD | [payments design](superpowers/specs/2026-10-03-blockchain-payments-design.md) | 1.1 | R1–R20, CR-PD-1…6 | BUILT (pull model); fixes PAY-FIX1…7 SPECIFIED |
| ADW | [wallets addendum](superpowers/specs/2026-10-03-blockchain-payments-addendum-wallets.md) | 1.1 | R21–R29, CR-ADW-1…4 | BUILT; fixes ADW-FIX1…4 SPECIFIED |
| R3D | [round 3](superpowers/specs/2026-10-03-blockchain-round3-design.md) | 1.2 | R30–R67, CR-R3-1…11 | BUILT; fixes R3-FIX1…15 SPECIFIED |
| WSF | [wallet signing formats](superpowers/specs/blockchain-research/round3-wallet-signing-formats.md) (research note) | 1.1 | CR-WSF-1…2 | fixes WSF-FIX1…2 SPECIFIED |
| INFRA | [infrastructure-service positioning](superpowers/specs/2026-10-03-blockchain-infrastructure-service.md) | 1.2 | — (follows §1 here; CR-R3-11) | positioning text |
| ZD | [Zether design](superpowers/specs/2026-10-03-zether-design.md) rev 1.1, [limits](superpowers/specs/2026-10-05-zether-limits.md) rev 1.1, [ConsenSys `MAX` note](superpowers/specs/2026-10-05-zether-consensys-max.md) rev 1.1 | 1.1 | RS2-1…26, RS-NV64-* | BUILT (dev chains, unaudited); fixes ZF-FIX1…3 SPECIFIED |
| DEX | [DEX design](superpowers/specs/2026-10-03-dex-design.md) | 1.1 | RS5-1…20 | BUILT (EVM); fixes DX-FIX1…5 SPECIFIED |
| net-hedera | [Hedera](superpowers/specs/2026-10-03-net-hedera.md) | 1.2 | R6-1…11 | BUILT; NET-HEDERA-FIX1…3 SPECIFIED |
| net-sui | [Sui](superpowers/specs/2026-10-03-net-sui.md) | 1.1 | RS7-1…14 | BUILT; NET-SUI-FIX1…4 SPECIFIED |
| net-soroban | [Soroban](superpowers/specs/2026-10-03-net-soroban.md) | 1.1 | R8-1…15 | BUILT; NET-SOROBAN-FIX1…2 SPECIFIED |
| net-cosmos | [Cosmos](superpowers/specs/2026-10-03-net-cosmos.md) | 1.1 | R9-1…8 | BUILT; NET-COSMOS-FIX1…3 SPECIFIED |
| net-ton | [TON](superpowers/specs/2026-10-03-net-ton.md) | 1.1 | R10-1…17 | BUILT; review verdict **BLOCK** (C1) until NET-TON-FIX1; NET-TON-FIX1…4 SPECIFIED |
| net-aptos | [Aptos](superpowers/specs/2026-10-04-net-aptos.md) | 1.1 | RS11-1…26 | BUILT; NET-APTOS-FIX1…3 SPECIFIED |
| net-solana | [Solana](superpowers/specs/2026-10-04-net-solana.md) | 1.1 | RS12-1…25 | BUILT; NET-SOLANA-FIX1…3 SPECIFIED |
| MESH | [relayer mesh](superpowers/specs/2026-10-05-relayer-mesh-design.md) | 3 | R70–R86 | library BUILT; transports SPECIFIED |
| NI | [node independence](superpowers/specs/2026-10-06-node-independence-design.md) (single normative place for node routes, tables, config) | 3.7 | R87–R111, R320–R328, R340–R349 | store P1 BUILT; rest SPECIFIED; node fixes NR1–NR5 SPECIFIED |
| A2 | [mesh gossip amendment](superpowers/specs/2026-10-06-mesh-gossip-amendment.md) | 2.1 | R112–R128 | SPECIFIED |
| TW2 | [token wrappers v2](superpowers/specs/2026-10-06-token-wrappers-v2.md) | 1.2 | R129–R149 | contracts T1–T6, T8 **BUILT**; T7 SPECIFIED |
| APP | [app (console + dApp)](superpowers/specs/2026-10-06-scaas-app-design.md) | 1.2 | R150–R179 | SPECIFIED |
| TSS (B) | [tender, sponsorship, shredding](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) | 1.3 | R180–R199 | SPECIFIED |
| AS (A) | [asset suite](superpowers/specs/2026-10-06-asset-suite-design.md) | 1.1 | R200–R217 | SPECIFIED |
| OPS (C) | [operations](superpowers/specs/2026-10-06-operations-design.md) | 1.2 | R230–R247 | SPECIFIED (some metrics BUILT) |
| S4F (D) | [signers follow-ups](superpowers/specs/2026-10-06-signers-followups.md) | 1.1 | R250–R269 | SPECIFIED |
| PQZ (E) | [post-quantum Zether](superpowers/specs/2026-10-06-pq-zether-design.md) | 1.4 | R270–R289 (R284 rewritten in rev 1.4) | SPECIFIED |
| UA (F) | [Universal Account](superpowers/specs/2026-10-06-universal-account-design.md) | 1.4 | R290–R318, R330–R331 | SPECIFIED |

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
| Aptos/Sui/Solana packages upgradeable (`compatible`, "multisig in production", net-* RS11-13) | **Immutable at deploy** on every family (Aptos `immutable`, Sui `make_immutable`, Solana authority `None`, Cosmos `--no-admin`); deploy-script gate; node holds an upgradeable chain `halted` | CR-R3-11, NI R348 |
| `PqzToken` has no meta-tx envelope (PQZ rev ≤ 1.3) | `PqzToken` is ERC-20 + `IERC20MetaTx` exactly like `ZetherToken`, plus the v3 `UAMetaTransaction` path | PQZ R284 (rev 1.4) |
| Finality = RPC quorum on one block hash | Quorum over the **normalized event set** of each range, every family; `quorum = 1` is single-provider trust | CR-PD-2, CR-R3-2 |
| Pay-once per request is unconditional | Pay-once holds under the lane-horizon rule `H = 30 d` (issuers and every signing client) | CR-PD-4, RS7-11, RS11-24, RS12-24 |
| `allow_call` lets a namespace send any `call` | `allow_call` is necessary, not sufficient: node-side target/selector table | CR-PD-1 |
| Gas breaker meters successful fees only | Breaker meters every billed outcome (`fee + value_out + deposits`); attempt cap; per-subject grief score | NI R340–R342 |

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
| **Namespace** | The node's tenant unit (`[a-z0-9-]{3,40}`; reserved `~gateway`, `~mesh`, `~dex`). Holds granted chains, token subset, external-client API keys, quotas. The node has no notion of "company" (R90). |
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
| **UA** | Universal Account: an account identifier derived from key data, like an EOA generalised to every signature scheme — the native address for a chain's native accounts (never registered), else `keccak256(keccak256(kind_tag) ‖ key_data)` (32 bytes, kind-tagged, top 96 bits non-zero), registered per chain with a proof of possession that binds chain (`chain_key` and `chain_uid`, the genesis hash, R330), registry, UA and `authRef` (not the caller, so registration is relayable) ([UA](superpowers/specs/2026-10-06-universal-account-design.md) rev 1.4, R290–R295, R330; summary §9.8). Today's built registry is the Zether-only `keccak256(encodedY)` form (§8.6), superseded by UA. |
| **Mandate** | An on-chain spending authorization held by a subject's wallet contract (`MandateWallet`): delegate, per-payment and per-period caps, payees, expiry, revocation (R25). |

---

## 1. Positioning

### 1.1 What SCaaS is

**SCaaS means the smart contracts themselves are the API services that run the business services** (owner).
Payments, mandates, tokens and wrappers, the DEX, tenders, vesting, distributions and confidential transfers are
contract functions (§4, §5, §7, §8, §10): code per network family that is immutable from the moment it is deployed
(owner, R3D CR-R3-11), deployed as EIP-1167 clones from an open factory on EVM and as equivalent modules/programs
elsewhere, that checks the subject's signature, nonce, expiry and
limits on every call. ERPs, portals, mobile apps and AI agents call them the way they call any API. The contracts
are the product; everything else is a way to reach them:

- **`scaas-node`**: infrastructure, not the product. **Anyone can run it**; it doubles as a relayer: it submits
  subject-signed intents and pays their gas, journals every submission, indexes, waits for finality and serves
  finalized facts back (§3, §6). How a node operates is up to whoever runs it: each operator sets its own
  acceptance, fee, sponsorship, denylist, gossip and peer policies and its own SLOs and monitoring. Operators are
  independent, and the protocol guarantees (contract rules, signatures, nonces) do not depend on any of them; the
  defaults and the `scaas/ops` bundle are recommendations ([OPS](superpowers/specs/2026-10-06-operations-design.md)
  R247);
- **client-side signers** (`clientkeys`: passkey, 24-word seed vault; extension wallets) so that the subject signs
  on its own device (§9);
- **`zether-prover`** for confidential amounts (§8);
- a **console/dApp** (`app/`, SPECIFIED, [APP](superpowers/specs/2026-10-06-scaas-app-design.md)) for wallets,
  payments, DEX, Zether and node administration.

SCaaS does not depend on any ERP. Odoo (addons `dms_blockchain*` in the `bamboo-dms` repository) is one client
(R87).

### 1.2 Authority model: SCaaS vs IaaS vs BaaS

The difference is **who signs a valuable write**. In IaaS and BaaS the service is the operator's server; in SCaaS
the service is the contract, and a node only carries signed writes to it and reads facts back.

| Criterion | IaaS (AWS EC2, Google Compute Engine) — the app issues JWTs, the server signs | BaaS (Supabase) — Supabase Auth issues JWTs, the server signs; Postgres RLS | SCaaS — the client signs every valuable create/update |
|---|---|---|---|
| Who signs a write | The application server; the client holds a server-signed JWT and the server writes on its behalf | Supabase Auth signs the JWT; PostgREST/Postgres executes; RLS reads `auth.uid()` | **The subject**: its device signs each operation with a passkey (WebAuthn P-256) or a wallet key. The relayer pays gas and holds no subject key |
| Trust root | The operator, the cloud provider (IAM, hypervisor), anyone holding the JWT signing key | Supabase (operator) + the project owner holding the JWT secret / `service_role` key | The subject's authenticator/secure element + chain consensus + contract code that is immutable at deploy on every family (no upgrade key in the trust root; CR-R3-11) |
| Who can forge a subject's write | Anyone with the JWT signing key, direct DB write access or a compromised server/IAM — indistinguishable from the subject | Anyone with the JWT secret (mints any `uid`) or the `service_role` key (bypasses RLS) | **Nobody without the subject's private key.** An operator or relayer can only refuse or delay (censorship/liveness); countered by other relayers or by the subject (or payee) submitting itself |
| Non-repudiation | None: the server writes the log and can write any line | None (same reason) | Per operation: a domain-separated signature with nonce and expiry, publicly verifiable forever |
| Audit trail | App logs / CloudTrail held by the operator | Postgres/Supabase logs held by the operator | Append-only distributed ledger; the ERP is a read-in replica (land) **through its node** (see "Land") |
| Authorization enforcement | App code (an endpoint is easy to miss) | RLS (centralized, but `service_role` and policy bugs bypass it) | Immutable contract code checks signature, nonce, expiry and limits on **every** call; **no admin can move a subject's funds**, except the bounded, creation-time powers listed below this table |
| Revocation / rotation | Easy: short TTL, deny lists, rotate server keys | Easy: rotate JWT secret, revoke refresh tokens | Harder: on-chain key rotation in a smart account; several passkeys or guardians for device loss (§9.4) |
| Write latency and cost | Milliseconds; compute/DB cost | Milliseconds; plan-based | Chain finality (seconds to minutes); gas per write, sponsored by a relayer (§5.9, §6.9) |
| Reads | Served by the server | PostgREST + RLS | **Unsigned**: through the node feeds, an indexer or the ERP, with ordinary JWT/session auth. Only valuable writes go through client signatures |
| Land (booking into the ERP) | — | — | The ERP trusts **its own node** and, through it, the **RPC quorum**: an event is booked only when ≥ `quorum` independent providers return the same event set for a final range (CR-PD-2, CR-R3-2); `quorum = 1` is single-provider trust; a compromised node can lie on `/v1/events` (§3.5, NI T7). "Verifiable without trusting a server" holds for **signatures**, not automatically for ERP bookings |
| Privacy | Data inside the operator's infrastructure | Same | Public ledger: both parties' identities are visible by design; amounts and balances can be hidden with Zether (§8) |
| Typical failure | Leaked JWT signing key / IAM = every user impersonated | Leaked JWT secret / `service_role` = every user impersonated | Leaked key of **one** subject = only that subject, bounded by its mandate limits; lost relayer = delay, never loss; no upgrade key exists to leak; a leaked admin key reaches only the bounded powers below, never subject balances |

**Admin-power exceptions** (the complete list; each is public, set at creation or bounded, and none moves a subject's
balance; [INFRA](superpowers/specs/2026-10-03-blockchain-infrastructure-service.md) rev 1.2):

| Power | Bound | Status |
|---|---|---|
| TW2 adjustable-rate `rateAdmin` and multi-underlying `guardian` (R142) | creation-time, timelocked/step-capped rate changes; guardian may only `disableWrap` (§4.2) | BUILT |
| `OrderBookDex.admin` `setMarket` | per-market fee ≤ 1 %, bounded by each order's signed `maxFeePpm` | BUILT |
| Soroban token admin `mint` | unlimited mint on that token (a supply power, not a balance power) | BUILT |
| TON DEX admin `WithdrawFees` | fees only; bounced payouts kept apart (R3D CR-R3-9, net-ton R10-17) | BUILT; fix NET-TON-FIX3 / R3-FIX13 SPECIFIED |
| Cosmos DEX `Sweep` | **removed** (R3D CR-R3-10): the DEX holds no balances between transactions | removal R3-FIX14 SPECIFIED |
| Solana program `Config.admin` | creates DEX markets only | BUILT |
| Controlled tokens' `issuer`/`compliance` | only for the regulated class, against a recorded order (§4.5, AS R200–R208) | SPECIFIED |

There is **no upgrade key** on any family (CR-R3-11, §1.3). Existing dev deployments of Aptos, Sui and Solana are still
upgradeable by one key; they are abandoned and redeployed immutable by stream R3-FIX15 (dev funds only).

Design consequences (normative):

1. **Scope of client signatures.** Every valuable create/update — transfer, payment, DEX order, tender bid,
   granting or changing authority, registering a key — carries the subject's signature. The server never holds a
   key to sign for a subject. The single exception is a custodial or delegated wallet that the subject or its
   organization **explicitly** entrusted, with limits and an approval log (R24, R25, R50). The node signs ERP-built
   `call` jobs (whose own signature lives in the calldata) only when selector and target are in its call table
   (CR-PD-1, §6.10).
2. **Passkeys** (WebAuthn, P-256) sign `authenticatorData ‖ SHA-256(clientDataJSON)` whose `challenge` is the typed
   digest of the operation (EIP-712 on EVM, the family digest elsewhere). Verifiers check `type`, `challenge`,
   `rpIdHash`, `origin` (exact), UP and UV flags and low-`s` with **one `clientDataJSON` grammar and one shared vector
   file for every family** (R31, R3D CR-R3-1, §9.3).
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
| An upgradeable platform | No proxy upgrade on any contract that holds value; **immutable at deploy on every family** (EVM clones; Aptos `upgrade_policy = "immutable"`; Sui `make_immutable` on the `UpgradeCap` in the deploy run; Solana upgrade authority `None` after `initialize`; Cosmos instantiated `--no-admin`; TON and Soroban as built). Each family's deploy script fails if the result is still upgradeable, and the node holds such a chain `halted` (`PROGRAM_UPGRADEABLE`). New behaviour = new version + voluntary migration (§4.3) (owner, CR-R3-11, NI R348; streams R3-FIX15, NR5) |
| A token gatekeeper | The factory is open; provenance replaces allowlists (§4.3). Controlled tokens are a separate, explicit class (§4.5) |
| A hosted node service | The node is infrastructure anyone can run; operators are independent, set their own policies and can only refuse or delay, never forge (§1.1, §1.2) |
| A single-ERP product | Odoo is one client; any ERP integrates through the same job API (R87, `integration.md`) |
| A market maker or profit-seeking relayer market | Relayer economics are cost recovery between parties with aligned interests; fee = 0 is the B2B default (§6.9) |

### 1.4 Deployment profiles

| Profile | Chains | Mesh | Typical relayers | Data exposure |
|---|---|---|---|---|
| **Public** | Public networks (Gnosis, Celo, Hedera, Cosmos chains, Sui, Aptos, TON, Solana, Stellar, Pi) — `profile = public` | Open mesh (gossip, opt-in per chain/policy/job) + pull bus for partners | Issuer, distributors, partners, third-party open relayers | Ledger public; private windows and bus scope control what is offered to peers (R73, A2 §8.4) |
| **Private / PoA** | A permissioned chain (reference: chain 7622, Nethermind, Clique, 1 signer, forks through Fusaka, base fee 0; §7.1) — `profile = private` (default) | No gossip, ever; pull bus only to admitted private peers, served by the origin only, over PQ-protected carriers | The operator's own nodes; admitted private peers | Chain-local; intents never leave the admitted set (R76, R85, A2 §12) |
| **Consortium** | A permissioned or public chain shared by members | Pull bus between admitted members (SPKI-pinned mTLS or QUIC), optionally gossip for public chains | Each member runs a node | Per-company `bus_scope`: `restricted` (default) / `open` (admitted peers) / `public` (also open mesh) |

Status: public and private profiles **SPECIFIED** ([relayer mesh](superpowers/specs/2026-10-05-relayer-mesh-design.md)
rev 3 R76, [gossip amendment](superpowers/specs/2026-10-06-mesh-gossip-amendment.md) rev 2.1 §12); the single-node relayer that
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
| Controls | Idempotency key, namespace grants, registered tokens, signed fields read from the payload (R344), R84/R100 normalization, `call` target table (CR-PD-1), value-out and deposit caps (R345, R346), simulation gate, gas breakers + grief score (R340–R342) | Finality mode + RPC quorum over the event set (CR-PD-2, CR-R3-2), contiguous ranges, dedup by `(chain, tx_hash, log_index)` |
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
| EVM contracts | `smartcontracts/evm/` (Foundry; `src/{common,metatx,factory,dex,wallet,account,registry,zether,hedera,chains}`) | Meta-tx tokens, open factory, DEX, mandate wallet, subject (passkey) account, Zether, account registry; profiles `private9000` (Prague; the private chain, now chain 7622, §7.1), `zether` (Prague), `gnosis`, `celo` (Cancun). UA registry + MetaToken v3 ([UA](superpowers/specs/2026-10-06-universal-account-design.md) F1/F2) and `PqzToken` ([PQZ](superpowers/specs/2026-10-06-pq-zether-design.md) E-S4) **SPECIFIED** | **BUILT** |
| Hedera contracts | `smartcontracts/evm/src/hedera/` | `HederaMetaToken` (HIP-632 `isAuthorizedRaw` for ED25519 accounts) on HSCS | **BUILT** |
| Cosmos contracts | `smartcontracts/cosmos/` (CosmWasm workspace) | `scaas-token` (CW20 + meta-op), `scaas-mandate`, `scaas-dex`, shared `scaas-metaop` | **BUILT** |
| Soroban contracts | `smartcontracts/soroban/` | SEP-41 token + `pay`, mandate, DEX; native auth as meta-tx (Stellar and Pi) | **BUILT** |
| Move contracts | `smartcontracts/move/{aptos,sui}/` | Package `scaas`: `meta` (per-subject Account + lanes), mandate, DEX | **BUILT** |
| TON contracts | `smartcontracts/ton/` (Tact) | Jetton master/wallet with pubkey + lanes (`SignedTransfer`), mandate, escrow DEX | **BUILT** |
| Solana program | `smartcontracts/solana/` (Anchor) | Program `scaas`: SubjectAccount PDA, `LanePda`, mandate, DEX | **BUILT** |
| Build/test scripts | `smartcontracts/scripts/{build,test,deploy,devnet}.sh <family>`; `scripts/capped` | One entry point per family; heavy runs capped at 4 GB, one at a time | **BUILT** |
| `scaas-node` | `scaas-node/` | Rust relayer: gateway, submit lanes, indexer, drift, DEX venue, admin; mesh envelope library | **BUILT** (Odoo-pulled job source); store/job API/admin auth/gateway additions **SPECIFIED** ([NI](superpowers/specs/2026-10-06-node-independence-design.md) rev 3.7); mesh transports **SPECIFIED** ([MESH](superpowers/specs/2026-10-05-relayer-mesh-design.md), [A2](superpowers/specs/2026-10-06-mesh-gossip-amendment.md)) |
| Node store | (in `scaas-node`) | Jobs, feeds, config authority, credentials, audit, DEX book, mesh tables; SQLite/PostgreSQL/MySQL | SQLite store P1 **BUILT**; the rest **SPECIFIED** (NI §4, A1/R111) |
| `zether-prover` | `zether-prover/` (Rust, `cdylib`+`rlib`, WASM) | Keygen (EIP-2333 paths), ElGamal, Σ + Bulletproofs (n=64), disclosure openings, BSGS, `zether-cli`, `zether-read-balance` | **BUILT** (unaudited); PQZ feature `pq`, `pqz-cli` **SPECIFIED** ([PQZ](superpowers/specs/2026-10-06-pq-zether-design.md) §11) |
| `clientkeys` | `clientkeys/` (ESM, `@noble`/`@scure`) | Passkey signer, 24-word seed vault, Zether conf keys and balance cache; bundle vendored into `dms_blockchain_bridge/static/lib/clientkeys` | **BUILT** (EVM-centric); vault v2, non-EVM signers, `fam/*` and `wallets/*` **SPECIFIED** ([S4F](superpowers/specs/2026-10-06-signers-followups.md)); `UAKey` **SPECIFIED** (UA F3) |
| `app/` | `scaas/app/` (React + Vite) | Console and dApp over all seven families: contracts, wallets, DEX book, Zether, node admin (built-in login or OIDC) | **SPECIFIED** ([APP](superpowers/specs/2026-10-06-scaas-app-design.md) rev 1.2; requirements NI §7.7, A2 §13.2) |
| Odoo client | `bamboo-dms/dms_blockchain`, `dms_blockchain_payment`, `dms_blockchain_bridge`, `dms_blockchain_dex` | One ERP client: outbox, payment provider `chain`, portal facade, DEX accounting | **BUILT** (pull model); push client **SPECIFIED** (NI §10) |
| CI | `.github/workflows/ci.yml` (`scaas-ci`) | forge test (pinned OZ v5.2.0, forge-std v1.16.2), `private9000` build, cargo clippy `-D warnings`, cargo test, EVM e2e on anvil | **BUILT**; CI for prover, clientkeys and non-EVM e2e **PLANNED** |

### 3.2 Node roles (one binary, modules switched in config)

| Role | What it does | Listener | Status |
|---|---|---|---|
| **gateway** (door A) | Public intake of signed meta-txs and DEX orders from anyone; normalize (R84), simulate, enqueue | `[modules] gateway_bind` (default `127.0.0.1:8547`), auth `none` (loopback only) / `bearer` / `hmac` (R54) | `/v1/metatx`, `/v1/dex/*` **BUILT**; durable, journaled door A, `/v1/gateway`, `/v1/ops`, `/v1/ua-metatx`, `/v1/ua/register`, error contract **SPECIFIED** (NI §5.5, §9.1) |
| **job API** | External server-side clients push jobs, cancel, read feeds, push watch lists and token subsets | `[api] bind` (default `127.0.0.1:8548`), HMAC per API key (R92) | **SPECIFIED** (NI §5) |
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
 automation ───────── OIDC client credentials ─► admin API         │   ▼
 host shell ───────── scaas-node admin …  (CLI writes the store)   │  /healthz /readyz /metrics
                                                                    │
 ERP (Odoo, SAP, …), server side                                    │        scaas-node
   outbox ─ push cron ── API key (HMAC) ─► POST /v1/jobs, cancel, PUT /v1/watch, /v1/tokens
   sync cron ─────────── API key (HMAC) ─► GET /v1/jobs?cursor=   GET /v1/events?cursor=
                                                                    │   ┌──────────────────────────┐
 wallets / app / partners / agents ─► gateway /v1/metatx, /v1/ops,  │   │                          │
                                       /v1/ua-*, /v1/dex/* ─────────┼──►│ accept → store (job,     │
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
Venue fixes (SPECIFIED, [DEX](superpowers/specs/2026-10-03-dex-design.md) rev 1.1 RS5-12…20; streams DX-FIX1…5): a
rounding-dust **maker** is skipped and removed from the book instead of stopping the match (RS5-12); `feeToken ∈ {0,
sellToken, buyToken}` and pair failures are attributed by evidence (`eth_call settleOne` revert reason), so one poisoned
maker blocks neither healthier makers nor recovery (RS5-13); ERC-1271 checks capped (RS5-14, §14.9); **non-EVM
settlement is relayer-bound** — Cosmos, Soroban and TON orders name the settling relayer and the contract checks the
sender (RS5-15; Soroban has no open form, R8-10); committed balance includes matched-but-unsettled fills (RS5-16);
on-chain `markets(key)` re-checked every poll (≤ 30 s) and a mismatching market stops serving (RS5-17); IOC matches a
single maker on Sui/Aptos/Solana (`ioc_single_maker`, required before N3, RS5-18); `min_nonce < 2^(w−1)` on
Sui/Aptos/Solana (RS5-19); a late `Matched` after recovery debits the restored order (RS5-20). The book moves to the
node store (NI R105) and relayer-bound jobs are lane-pinned (NI R102).

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
| Client ↔ node job API | HMAC per API key, namespace-scoped, idempotent; API keys only for external **server-side** clients, never in browser/mobile/desktop apps or extensions | R91, R92, R109 |
| Operator ↔ node admin | Built-in users (Argon2id) or optional OIDC; roles; audit. Config automation = OIDC client credentials or the host CLI | R106–R110 |
| Anyone ↔ gateway | Optional bearer/HMAC; body cap 64 KiB; concurrency 32; simulate before queue; reverse proxy rate limit (HANDOFF O5) | R54 |
| Node ↔ peers | Bus: SPKI-pinned mTLS or QUIC, admission per request; gossip: scoring, rate limits, validation | R72, R113, R118, R119 |
| Node ↔ chain | Simulation gate; finality gate = ≥ `quorum` independent endpoints agree on the final head **and on the normalized event set** of every range, else no ingest and `/readyz` red; `quorum = 1` is single-provider trust, reported at start and as `scaas_finality_quorum{chain}`; breakers | R11, CR-PD-2, CR-R3-2, R55, R340 |
| Contract ↔ caller | Signature, lane nonce, expiry, mode, fee cap, contract-only allowance | §4.4, §5 |
| Node ↔ secrets | Toml/keystores only; the store holds no secret | R92, R95 |

The node is trusted for **liveness and for the truth of the event feed it serves** (a compromised node can lie on
`/v1/events`; NI T7). It is never trusted with subject funds or subject keys. The event-set quorum bounds what one
dishonest RPC provider can inject (it sees pending payments through the node's own simulate calls, CR-PD-2); it does
not bound a compromised node. A second independent event source is deferred (NI §18.3). Status: event-set quorum
**SPECIFIED** (PAY-FIX3 EVM/Hedera, R3-FIX3 Sui/Solana/Soroban, R3-FIX4 Cosmos/TON, which today read one endpoint);
Aptos per-transaction agreement **BUILT**.

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
      │         (+ regulated child per tier: *_REG kinds 5–7, RegulatedControls)                  SPECIFIED (AS §3)
      │         (+ MetaToken v3 per tier: bytes32 UA ledger, UAMetaTransaction, §9.8)             SPECIFIED (UA F2)
      ├── IZetherToken + ITransferDisclosure
      │    └── ZetherToken v1 (kind ZETHER, dev chains only)                                    BUILT (unaudited)
      └── PqzToken (post-quantum class, never an upgrade of ZetherToken; + v3 UAMetaTransaction
           path; dev chains and the private chain 7622 only, §8.12)                            SPECIFIED (PQZ R284)
```

Zether is a **child** of the meta-tx layer, not a parallel branch: every confidential token is relayable through
the same envelope (owner decision, canon). This includes `PqzToken` (owner 2026-10-07, PQZ rev 1.4 R284: "PqzToken
must also follow `IERC20MetaTx`"). Non-EVM families implement the same roles natively (§7).

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
- **Same rule on every family** (CR-R3-11): a fix to an Aptos package, Sui package, Solana program, Cosmos contract,
  TON or Soroban contract is a new deployment at a new address plus voluntary migration by the owners of the
  balances; accounts on the old deployment keep working with the old code.

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
| Contract | `MetaToken`, `ZetherToken` clones | Regulated implementations, one per v2 tier: factory kinds `META_NONE_REG = 5`, `META_SINGLE_REG = 6`, `META_MULTI_REG = 7` (R200) |
| Admin powers | None: no owner, pause, blacklist, freeze, confiscation, arbitrary mint (v2 exceptions, chosen at creation and public: an adjustable-rate `rateAdmin` and the multi-underlying `guardian`, R142) | The `controls()` bits set at creation (`FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST`); bits can only be cleared later, never set; no power mints, changes a rate or touches the reserve (R201, R208) |
| Use | Loyalty, internal units, B2B settlement tokens, wrapped stablecoins | Central-bank digital currency, licensed stablecoins, digital securities and bonds, real-world-asset claims |
| Guarantee | "Your key, your funds": neither the issuer nor the factory can touch balances | Due-process intervention against a recorded order, permanently evidenced on chain; mandatory disclosure (`termsHash`) |
| Status | **BUILT** | **SPECIFIED** ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) rev 1.1 §3) |

**Controlled-token rules** (summary of AS R200–R208, R217; AS is normative):

1. Two creation-time roles, each a **contract** (multisig, default 3-of-5 with an external seat recommended):
   `issuer` executes (freeze, unfreeze, forced transfer, pause), `compliance` records and revokes orders. Neither is
   transferable; renouncing **relaxes** powers (R202).
2. A forced transfer needs a live compliance **order record** `{subject, beneficiary, maxAmount, freezeUntil}`
   (`orderId` = keccak256 of the authority's canonical order identifier, the document off chain), moves only from the
   frozen subject to the recorded beneficiary, cumulatively ≤ `maxAmount`. There is **no court-ordered burn**: a
   burn is a forced transfer to a beneficiary that burns or unwraps (R203).
3. A frozen account cannot send, be a meta-tx `from` or receive a relayer fee; it can still receive. Issuer-only
   freezes last ≤ 30 days (≤ 60 days per episode); longer ones need a compliance record (R204).
4. `pause(ref, until)`: `until ≤ now + 7 days`, no extension, 7-day cooldown; a fee-less unwrap, holder burn and forced
   transfer are never paused (R205).
5. Transfer eligibility through a separate `ComplianceRegistry` (address → flags, `validUntil`, attester; no personal
   data); only **receivers** are checked; the UA registry is not extended (R206). Checks run at pipeline step 6
   (R207).
6. Zether-side: a confidential balance can be frozen (stuck) but not seized on public chains (canon §1.10.3).

Interface: AS §3.3 (supersedes the earlier `IRegulatedToken` proposal, §14.6).

### 4.6 Vesting and streaming funds (SPECIFIED, [AS](superpowers/specs/2026-10-06-asset-suite-design.md) §4)

AS R209 replaces the earlier single-vault design: **one EIP-1167 `VestingGrant` clone per grant**, funded
counterfactually (the grantor transfers to the address `predictGrant(params)` returned, which reverts unless the
parameters pass every state-independent check; anyone then deploys it; init reverts only `Underfunded`).

- Schedules: linear with cliff and optional step `interval`, or ≤ 16 tranches, optionally gated per tranche by an
  `approver` (milestones). Revocable option: the grantor reclaims the unvested part.
- Claim: permissionless `release()` that pays only the beneficiary — gasless through any relayer, no signature, no
  nonce, no allowance.
- No owner, no upgrade; remainders go only to a creation-time `sweepTo`/grantor (R216).
- Uses: streaming payroll, equity incentive vesting (e.g. 12-month cliff, 48-month linear), milestone grants.

Interface: AS §4.2 (supersedes the `IVestingVault` proposal, §14.8).

### 4.7 Mandates (BUILT)

`MandateWallet` (one per payer, owner = the payer's EOA; R25, R29): the wallet holds the funds, implements ERC-1271
for its owner, and stores per-token mandates `{delegate, expiry, periodSeconds, periodStart, maxPerPayment,
maxPerPeriod, spentInPeriod}` plus allowed payees. `payUnderMandate(token, payee, amount, entryRef, validUntil,
sig)` checks not revoked, not expired, payee allowed, per-payment cap, per-period cap, `entryRef` unused and the
delegate's EIP-712 signature (`PayUnderMandate(address token,address payee,uint256 amount,bytes32 entryRef,uint256
validUntil)`), then pays through `payWithFee(FeeMode.NONE)` — no allowance. Kill switch: `revoke(token)` by the owner
or `revokeWithSig` by the delegate (platform revokes immediately through a relayer). Equivalent mandates exist on
Cosmos, Soroban, Sui, Aptos, TON and Solana.

- **Revocation epoch** (SPECIFIED, ADW CR-ADW-1, stream ADW-FIX1): `MandateWallet` keeps `epoch[token]`, bumped by
  every `setMandate` and revoke; the signed revoke becomes `RevokeMandate(address token,uint64 epoch,uint256
  validUntil)` and must match the current epoch, so a public revoke signature cannot be replayed against a mandate the
  owner re-established. Typehash change on dev deployments only; the built wallet has no epoch (EVM only: the Solana
  mandate binds a generation, and the Sui/Aptos/Cosmos mandates are one-shot).
- **Hedera ED25519 owners** pay from a `MandateWallet` only through `HederaMandateWallet.executeAsOwnerRaw`
  (ADW CR-ADW-2): ERC-1271 runs under STATICCALL, where HIP-632 `isAuthorizedRaw` halts, so a meta-tx with
  `from = wallet` works for ECDSA owners only. The raw call is relayed as a `call` job (call table, §6.10) or sent by
  the owner.

### 4.8 Equity and bonds on a managed DEX (SPECIFIED, [AS](superpowers/specs/2026-10-06-asset-suite-design.md) §5–§8)

- Securities are regulated tokens (§4.5). Coupons and dividends are **Merkle distributions** off a node-indexed,
  recomputable snapshot (one `Distribution` clone each, claims open ≥ 1 h after creation, `cancel` until then;
  R210, superseding the earlier `CouponPayer`). Bond redemption, fixed-price buybacks and splits are
  `ExchangeOffer`s (gasless `trade` leg, exact multiples; a split is a migration to a new token, balances never
  rebase; R211, R212).
- A **managed market** is a market on an `OrderBookDex` instance whose `admin` is the licensed venue operator's
  multisig and whose node policy has `managed = 1`: home-bound orders only, relayer fee `NONE` on regulated legs,
  eligibility of both parties checked at node intake, book not gossiped by default (R214); on chain the regulated
  token's own checks are the arbiter. The existing DEX already provides signed limit orders, price-time priority
  off chain, partial fills, IOC/FOK, `filled[orderHash]` and per-market fees capped at 1 % (§10 of
  [DEX](superpowers/specs/2026-10-03-dex-design.md)).

### 4.9 Open Asset Tokenization Suite (SPECIFIED as a product, [AS](superpowers/specs/2026-10-06-asset-suite-design.md); primitives BUILT)

A configuration wizard (in `app/` and any ERP) on top of `IOpenFactory`/`IOpenFactoryV2`. Templates are off-chain
presets (versioned JSON) mapping to one factory call plus optional action contracts (R213):

| Template | Factory call | Parameters | Status of primitive |
|---|---|---|---|
| Loyalty / rewards | `createMetaToken(1, 0, initData, salt)` | name, symbol, decimals, `minter` = issuer's mint contract or treasury multisig, fee 0 | **BUILT** |
| Internal 1:1 money | `createMetaToken(1, underlying, …)` | underlying stablecoin; wrap/unwrap through the clone | **BUILT** |
| Wrapper with a rate | `createTiered(META_SINGLE, …)` | underlying, `num/den`, fixed or adjustable (admin, delay, step) | **BUILT** (TW2) |
| Confidential money | `createZetherToken(1, underlying, verifier, initData, salt)` | `registry`, `shieldScale`, `maxDecryptableShielded ≤ 2^54`, `confidentialFee`, auditor key | **BUILT** (dev chains only) |
| Multi-underlying money (e.g. xDAI/USDC/USDT) | `createTiered(META_MULTI, …)` | 2–8 underlyings, per-leg rates, guardian | **BUILT** (TW2) |
| Vesting / streaming | `VestingGrant` clone per grant | cliff, duration, interval or tranches, approver, revocability | **SPECIFIED** ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §4) |
| Controlled / security / bond | `createTiered(META_*_REG, …)` + `Distribution` / `ExchangeOffer` | issuer and compliance contracts, `controls()` bits, `ComplianceRegistry` + `requiredFlags`, `termsHash` | **SPECIFIED** ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §3, §5–§7) |
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

**Lane horizon (protocol rule, PD CR-PD-4; amends R9).** "Each payment request is payable at most once" holds iff
(1) every signature issued on a pay lane has `validUntil ≤ t_first_issue + H`, `H = LANE_HORIZON = 30 d`, and (2) every
family that prunes lane state keeps an executed lane for ≥ `H` after the executed op's `validUntil` (TON two
`LANE_TTL` generations; Aptos and Solana `PRUNE_DELAY_S`; Sui `prune` after `valid_until + LANE_HORIZON_S`, RS7-11).
Obligations:

| Who | Obligation | Status |
|---|---|---|
| Issuer (ERP, app) | Sign one op per pay lane, or keep every op on that lane inside `H` of the first; terms signed beyond `H` get no pay-once guarantee | Odoo constants comply (BUILT) |
| Every signing client (connectors, `clientkeys`, app) | Refuse to sign an op with `valid_until > now + LANE_HORIZON_S` on a pruning family (Aptos RS11-24, Solana RS12-24, Sui RS7-11) | SPECIFIED (NET-APTOS-FIX3, NET-SOLANA-FIX3, NET-SUI-FIX2) |
| Contract | Sui `relay_pay` refuses `valid_until > now + LANE_HORIZON_S` on chain (RS7-11); Solana caps `valid_until` and order `expiry` at `MAX_TTL_S = 31 d` (RS12-21) | SPECIFIED (NET-SUI-FIX2, NET-SOLANA-FIX1) |
| Node | Refuses `max_valid_for_secs > LANE_HORIZON` on a pruning family; constants pinned equal in tests (TON `LANE_TTL`, Aptos/Solana `PRUNE_DELAY_S`, node `LANE_TTL_S`, Odoo `LANE_HORIZON_S`) | SPECIFIED (R3-FIX12) |

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
| Gas sponsorship policy | Node policy: e.g. "inbound to wallet W, value ≥ X ⇒ accept with fee 0, book gas to account Y" | Sponsor (contract outside the chain) | **SPECIFIED** ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) rev 1.3 §B1, R189–R191; budget and rate counts at accept, NI rev 3.6 §5.2); on-chain `SponsorshipPool` PLANNED-later (§B3) |
| `fee = 0` B2B | Company relayer, `MODE_FEE_NONE`; gas is OPEX | Company | **BUILT** |
| Enterprise inbound gateway | Partners post signed intents to the company's gateway (`POST /v1/metatx`); the company relays with its lanes | Company | **BUILT** (EVM door A); intake rules that stop Door A being a free gas faucet **SPECIFIED** (CR-PD-3, §6.10) |

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
| N11 | Every outer tx the lane pays for is metered, and a subject cannot make the node pay repeatedly. | Breaker meters `fee + value_out + deposits` of every included tx (failures too); one requeue after a billed failure; `max_attempts`; per-subject grief score (R340–R342, §6.4) | EVM metering **BUILT**; rest **SPECIFIED** (NR1) |
| N12 | Fields the signed payload carries are read from it, never from job JSON. | `contract`, `valid_until`, `from`, lane, nonce, relayer binding, value/forward floors from the decoded payload; a differing JSON copy ⇒ `422 BAD_PAYLOAD`; unsigned fields may only narrow (R344) | mesh decoders **BUILT**; job paths **SPECIFIED** (NR2) |
| N13 | No lane sends native value or funds deposits it cannot get back, beyond caps. | `chain.max_value_out` (R345), deposit rule (R346) | **SPECIFIED** (NR2) |
| N14 | Mesh and gateway intents are signature-checked before any chain call. | Per-family local verify, `BAD_SIGNATURE` counts against the peer (R343) | EVM `eoa` **BUILT**; rest **SPECIFIED** (NR3) |
| N15 | Adapter state needed across restarts lives in the store. | `outer_tx` signed bytes, object refs, durable-nonce value; no local journal (R347) | **SPECIFIED** (NR4) |
| N16 | The node serves no upgradeable program and holds each custody key in one family. | Upgradeability read at activation and start ⇒ `halted`, `PROGRAM_UPGRADEABLE` (R348); `Config::validate` refuses one public key in two families (R349) | **SPECIFIED** (NR5) |

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
| `queued`, `leased` | `dead` | expiry before submit; bad payload; `attempt_count > chain.max_attempts` (default 5) ⇒ `ATTEMPTS_EXHAUSTED` (R341) |
| `leased` | `queued` | transient simulate/fee/RPC error; restart before signing; in flight on another path; outcome **not included** (precheck/CheckTx/mempool reject, `BUSY`, dropped: nothing billed) |
| `broadcast` | `queued` once, then `reverted` | outcome **included and billed** (R341): at most one requeue per job, only where the family spec names the parameter the retry raises (gas or CU limit to its cap: Hedera, Aptos RS11-21, Solana RS12-22); otherwise, or the second time, `reverted` with the decoded reason (R80 checked first) |
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
  so a gas coin is never equivocated. Solana lanes use a per-lane durable nonce account. Target (NI R347, RS7-9,
  SPECIFIED NR4): every adapter-local state (Sui unresolved txs — all of them per lane, not the last one — Solana
  durable-nonce value, TON seqno generation) lives in the store's `outer_tx` row, written in the `leased → signed`
  transaction, so it moves with the owner lock on a restore elsewhere; no local-directory journal.
- **Same lane keys in two stores** (forbidden; SPECIFIED NI §9.4): on sequence families, `nonce_at(latest) >
  journal_max + 1 + tracked` ⇒ the lane refuses to lease, `/readyz` reason, metric `scaas_lane_foreign_nonce_total`.

### 6.4 Gas circuit breakers (R55, BUILT)

Per lane, in memory, sampled every 15 s; open breakers stop **new** work only.

| Breaker | Rule | Defaults |
|---|---|---|
| `base_fee_spike` (EVM) | current base fee > `spike_ratio` × 1 h trailing mean, with ≥ 4 samples and fee > `spike_min_base_fee_gwei` | ratio 3.0 (0 disables), min 1 gwei |
| `gas_budget` | gas spent in the fixed hour window ≥ `gas_budget_per_hour` (smallest gas unit) | warn at 90 % |
| `balance_floor` | lane balance < `min_relayer_balance` | warn below 120 % of the floor |
| structural | simulated gas > `max_gas_per_tx` ⇒ job `dead` | 3 000 000 (Zether chains ≥ 4 200 000, ZD §15; PQZ chain 16 000 000) |

Metric `scaas_breaker_open{chain,lane,breaker}`; manual reset
`POST /v1/admin/chains/{key}/breaker/reset` (operator, SPECIFIED).

**What the breaker meters (NI rev 3.7, SPECIFIED, stream NR1).** Today the EVM path meters every receipt; the non-EVM
runner meters `Mined` only, so a drain through failed, billed transactions passes under `gas_budget_per_hour` on every
non-EVM family. Target:

| Rule | Detail | Ruling |
|---|---|---|
| Cost of every included tx | `Breaker::spend(fee + value_out + deposits)` for mined, reverted and billed-failed txs of ours: `fee` as charged; `value_out` = native value moved out of the lane beyond fees, net of excess returned (TON forward and attach, EVM `value`); `deposits` = rent/storage the lane funded (Solana rent, Sui storage net of rebate, Aptos storage fee, Soroban rent). Adapter `tx_cost(tx_id) → TxCost`; stored on `outer_tx` | R340 |
| Billed-failure retry | not included ⇒ `queued`; included and billed ⇒ one requeue at most, then `reverted`; `chain.max_attempts` (hot, default 5) ⇒ `dead ATTEMPTS_EXHAUSTED`; each family spec keeps its code → class table | R341 |
| Grief score | table `subject_grief(chain_key, subject, day, billed_failures, cost)`; counts billed failures and `consumed` outcomes of jobs never published on the bus (TW2 §7.6 / AS §3.8 exemptions); ≥ 3 in 24 h ⇒ one live job per chain + re-simulation right before signing; ≥ 10 in 24 h or `cost ≥ chain.grief_cost_cap` ⇒ intake `429 SUBJECT_THROTTLED` until 24 h after the last count; namespace aggregate metric `scaas_grief_*` | R342 |
| Value out | `chain.max_value_out` (hot; TON default 0.05 TON above the fixed attach, every other family 0); above ⇒ `422 VALUE_OUT_TOO_HIGH` at intake and again at lease | R345 |
| Deposits | the lane funds rent/storage only if refunded to the lane (`rent_payer` + `prune`), for an account only a configured receiving wallet controls, or ≤ `chain.max_deposit_per_job`; a deposit a third party can reclaim (e.g. a Solana ATA its owner closes) ⇒ `422 DEPOSIT_NOT_ALLOWED`, re-checked before signing | R346 |

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

**Event-set quorum (SPECIFIED, PD CR-PD-2 / R3D CR-R3-2; supersedes R11's quorum on one block hash).** `final_head` =
the minimum height reported by ≥ `quorum` endpoints with the same block/ledger/checkpoint hash there (`tag` mode: min
`finalized`; `depth` mode: min `latest`); `events(from, to)` is read from ≥ `quorum` endpoints and must be the **same
normalized list** (the adapter's own output, so one comparison serves every family; EVM: sorted `(block_number,
block_hash, tx_hash, log_index, address, topics, data)`); disagreement ⇒ no ingest, warning, `/readyz` red. Per
family: EVM/Hedera `eth_getLogs` (PAY-FIX3); Aptos per-transaction agreement (**BUILT**); Sui event query per
checkpoint range, Solana per-signature transaction agreement, Soroban `getEvents` per ledger range (R3-FIX3); Cosmos
`status` + `block` + tx events and TON `masterchainInfo` + jetton-wallet transactions **honour the configured
quorum** (today one endpoint; R3-FIX4). Receipt proofs may replace the set comparison where providers serve them.

| Family | Mode | Final head | Height unit | Notes |
|---|---|---|---|---|
| EVM private (chain 7622, Clique 1 signer) | `depth`, 1 | `latest − 1` | block | Reorg-free by construction |
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

**Signature check before any chain call** (NI R343, SPECIFIED, stream NR3; before S5): today the decoders check
domain, network and contract only, and every EVM `erc1271` intent passes. Target: EVM `eoa` as today; `erc1271` by one
`eth_call isValidSignature` charged to a per-peer simulate budget; Hedera 64-byte ED25519 as `sig_kind =
"hedera_ed25519"` (key from the mirror node, cached; R6-11); Cosmos ADR-036 and passkey, Solana ed25519 locally; Aptos,
TON and Sui against the account's key (one cached state read each). Failure ⇒ `BAD_SIGNATURE`, never simulated,
counted against the publishing peer.

**Families on the mesh v1** (R77): EVM, Hedera, Cosmos, Sui, Aptos, TON, Solana; **Soroban is out** (replay
protection is the host's authorization nonce, `i64(sha256("scaas.soroban.nonce" ‖ entryRef ‖ validUntil)[0..8])`, a
per-entry value with no peer-readable per-subject sequence). Non-EVM op kind: `pay` only.

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
rev 2.1: review 1 and the owner answers folded in — `bus_scope = public` is a separate opt-in, DEX books carry
home-bound **and** relayer-unbound orders per market, exclusive-assignment trust is automatic after 3 verified
landings, QUIC offers only the PQ group, DEX homes auto-trusted (R128)). UA intents travel as `scaas-intent/1.3`
(`evm.ua_meta_tx` body only, same topic; 1.2 nodes ignore them; UA R316).

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

### 6.10 Intake rules for `call` jobs and Door A (SPECIFIED, PD rev 1.1 CR-PD-1, CR-PD-3)

**`call` target/selector table** (CR-PD-1 (c); streams PAY-FIX2 node, PAY-FIX1 Odoo). A `call` job carries calldata
the client built; a lane signs it as `msg.sender`. The node executes one only if its 4-byte selector is in the table
**and** the target meets the row's rule; **never** when the target is a registered token of the chain (any kind),
the token factory, or a contract in which a lane key holds a role; `call` jobs carry no native value. `allow_call`
on the namespace stays necessary and is no longer sufficient (NI R103 grants `call` per namespace, not per target).

| Selector | Target rule | Producer today |
|---|---|---|
| `SubjectAccountFactory.deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)` | the chain's account factory (`chain_contract.kind = account_factory`) | Odoo subject accounts |
| `SubjectAccount.executeAsOwner(bytes,uint256,uint256,bytes)` | runtime code = EIP-1167 clone of that factory's `IMPLEMENTATION` (checked at lease, cached) | Odoo subject accounts |
| `MandateWallet.payUnderMandate`, `revokeWithSig` (epoch-bound, CR-ADW-1), `executeAsOwner`; `HederaMandateWallet.executeAsOwnerRaw` (CR-ADW-2) | any address that is not a registered token (self-authenticating: the target checks the delegate/owner signature) | Odoo payment requests, auto-pay |
| `OrderBookDex.settle` / `cancel` / `invalidateNonces` | the chain's DEX | DEX venue, `dms_blockchain_dex` |
| `UniversalAccountRegistry.register` (UA `UARegistry.register` after F1) | `chain.ua_registry`, `~gateway` only (NI R320) | node gateway |

Refusal: NI push model `403 CALL_TARGET_REFUSED` at accept (next to the `allow_call` check, re-checked at lease);
legacy pull path `dead` with `CALL_TARGET_REFUSED` before simulation. A new call shape needs a table row (node
release). Why: one operator session (or a stolen one) could otherwise turn a lane that holds fee income, and on dev
deployments admin roles, into an arbitrary transaction. The NI text still has to fold this table (PD §15.4
amendment); this document is normative until it does. Client side: the outbox row is immutable (`integration.md`
§3.5).

**Door A is not a free gas faucet** (CR-PD-3; stream PAY-FIX4). At gateway intake: a `transfer`/`pay` op with
`value == 0` ⇒ `422 ZERO_VALUE`; the `~gateway` door applies its `min_fee` floor to the effective fee (TSS R189,
MESH §7), waived and budget-capped by a matching sponsor policy; `profile = private` keeps fee 0 (B2B default), while
`profile = public` refuses fee-0 Door A intents unless a sponsor policy matches; a per-`from` token bucket (default 60
per hour, in memory) sits on top of the reverse-proxy per-IP limit. Every door also applies R343–R346 (§6.1 N12–N14,
§6.4).

**Idempotent journal report on the pull path** (CR-PD-5, PAY-FIX5): a `signed` report repeated with the same
`(tx_hash, outer_nonce, signer)` succeeds unchanged; the node keeps the signed `(raw, hash, n)` and re-reports it
before anything else, and gives `n` to no other job meanwhile.

---

## 7. Families

Common model (R30, R3D §D.0): the subject only **signs** a domain-separated payload; each contract keeps its own
lane/nonce space; a relayer lane submits from its own account and pays native gas. Native sponsorship features are
used only so that a **relayer** pays, never so that the subject's account sequence orders anything. Every family ships
the same three roles: token with `pay` + meta-op, mandate, DEX — plus a multi-key subject account where the chain
needs one.

Cross-family rules from the 2026-10-07 reviews (each family spec's "fix" table is normative for detail):

- **Immutable at deploy** (CR-R3-11, §1.3): every family's deploy script ends with a gate that fails on an
  upgradeable result; the node re-checks at activation and start (NI R348).
- **Node rules** NI R340–R349 apply to every adapter (§6.1 N11–N16, §6.4): failed-fee/value/deposit metering, one
  billed retry, attempt cap, grief score, payload-sourced fields, value-out and deposit caps, journals in the store,
  one custody key per family. Each family spec keeps its own error code → class table and deposit list.
- **One WebAuthn grammar** (CR-R3-1): exact `clientDataJSON` grammar, exact origin match, UP and UV, low-`s`;
  `crossOrigin: true` and any `topOrigin` refused; shared vectors `smartcontracts/test/vectors/webauthn_kat.json` run in
  every family's suite (R3-FIX1, R3-FIX2).
- **Event-set quorum** on every family (§6.6).
- **Lane horizon** obligations on pruning families (§5.5).
- **Key lifecycle per family** (CR-R3-6; §9.4 table).

**`MetaOp` v1** (non-EVM; family encoding, every field mandatory): `domain = "scaas.metaop.v1"` ‖ `network` ‖ `contract` ‖ `op` (`pay | trade | mandate_pay |
revoke`) ‖ `from` ‖ `to` ‖ `amount` ‖ `payRef` (32) ‖ `lane` (32) ‖ `nonce` (u64) ‖ `validUntil` (u64 seconds) ‖
`relayer` (optional) ‖ `extra` (hash of op-specific parameters). No relayer fee field on non-EVM (fee NONE, R10/R75).

Summary:

| Family | Chains | Meta-tx mechanism | Subject signature | Lane key (relayer) | Mesh v1 | Status |
|---|---|---|---|---|---|---|
| EVM | Gnosis (100), Celo (42220), private chain 7622, anvil 31337 | Contract-level EIP-712 (`ERC20MetaTx`) | ECDSA secp256k1 (EOA) / ERC-1271 (SubjectAccount: P-256 WebAuthn, secp256k1) | secp256k1 `m/44'/60'/0'/0/i` | yes | **BUILT**; DX-FIX3, ZF-FIX1, ADW-FIX1 SPECIFIED |
| Hedera | 295 / 296 / 297 / 298 | Same Solidity on HSCS via JSON-RPC relay | ECDSA (alias) or ED25519 via HIP-632 `isAuthorizedRaw` | secp256k1 `m/44'/3030'/0'/0/i` | yes (family `hedera`) | **BUILT**; NET-HEDERA-FIX1…3 SPECIFIED |
| Cosmos | CosmWasm chains (`cosmos:<chain-id>`) | Contract-level `Relay{payload, auth}` | ADR-036 secp256k1 (Keplr/Leap `signArbitrary`) / WebAuthn P-256 | secp256k1 `m/44'/118'/0'/0/i` | yes | **BUILT**; R3-FIX1/4/9/14, NET-COSMOS-FIX1…3 SPECIFIED |
| Soroban | Stellar (`pubnet`, `testnet`, `standalone`), Pi Network (`pi-mainnet`, `pi-testnet`) | Native Soroban authorization (`SorobanAddressCredentials`, random nonce + ledger expiry) | ed25519 (Freighter `signAuthEntry`) / custom account `__check_auth` with `secp256r1_verify` | ed25519 `m/44'/148'/i'`; Pi `m/44'/314159'/i'` (`coin_type` override) | **no** (R77) | **BUILT**; R3-FIX5/8, NET-SOROBAN-FIX1…2 SPECIFIED |
| Move — Aptos | 1 / 2 / 4 | Contract-level, per-owner `Account` object with lanes | ed25519 (Wallet Standard `signMessage`) / WebAuthn P-256 (pure-Move verifier) | ed25519 `m/44'/637'/i'/0'/0'` | yes | **BUILT**; R3-FIX15, NET-APTOS-FIX1…3 SPECIFIED |
| Move — Sui | mainnet / testnet / devnet / localnet | Contract-level, shared `Account<T>` per subject with lanes | ed25519 / secp256k1 / secp256r1 / passkey (`signPersonalMessage`) | ed25519 `m/44'/784'/i'/0'/0'` | yes | **BUILT**; R3-FIX7/15, WSF-FIX2, NET-SUI-FIX1…4 SPECIFIED |
| TON | -239 / -3 | Custom jetton wallet verifies `SignedOp` | TON Connect `signData` (cell) / passkey | ed25519 `m/44'/607'/i'` (W5R1 lane wallets) | yes (`pay`) | **BUILT**; **BLOCK** for non-Odoo paths until NET-TON-FIX1; R3-FIX10/11/13, NET-TON-FIX1…4 SPECIFIED |
| Solana | `solana:<genesis hash>` | Program-level, SubjectAccount PDA + `LanePda` | raw ed25519 / off-chain message / passkey, verified via precompile instruction | ed25519 `m/44'/501'/i'/0'` | yes (`pay`) | **BUILT**; R3-FIX6/15, WSF-FIX1, NET-SOLANA-FIX1…3 SPECIFIED |

Lane keys come from one 24-word BIP-39 mnemonic (`[keys] mnemonic`: env, 0600 file, or Web3 Secret Storage v3
keystore) or a raw `private_key` (one lane); `scaas-node addresses` prints every lane address to fund (R60).

### 7.1 EVM

- **Gnosis Chain (100):** recommended public chain for B2B; native gas xDAI (stable-value); finality `tag
  finalized` (~160–240 s), quorum ≥ 2 independent RPCs; profile `gnosis` (Cancun, EIP-2537 measured live). Seeded
  `draft` until O4.
- **Celo (42220, OP-Stack L2):** native fee abstraction **CIP-64** (transaction type `0x7b`, `feeCurrency`) lets a
  sender pay gas in an allowed ERC-20; SCaaS does not depend on it (relayers pay CELO) but clients using CIP-64 must
  add ≈ 50 000 intrinsic gas for the fee currency. Finality mode `l1_batch` is **PLANNED**; profile `celo` (Cancun).
- **Private chain 7622:** Nethermind 1.39, Clique PoA, one signer, 5 s blocks, base fee 0 (gas free), forks live
  through Fusaka + BPO2 (incl. EIP-2537, EIP-7951 P-256 at `0x100`, EIP-7825 16,777,216 gas per-tx cap, EIP-7623,
  EIP-7934) after the 2026-08-31 chainspec fix; Solidity profile `private9000` = `prague`; finality `depth 1, quorum
  1`. Not on the classical Zether dev allowlist (RS2-1, owner question Z3); the only PQZ chain (§8.12). Nodes bind
  the profile to the genesis hash, not to the chain id alone (PQZ §11.3).
  Chain id formerly 9000 (collides with Evmos Testnet); owner decision 2026-10-07, migration pending (stream CHAINID).
  Component specs, code directories (`src/chains/private9000`) and the foundry profile still say 9000 until then.
- **Deployment:** `smartcontracts/scripts/deploy.sh evm <rpc>` runs `script/Deploy.s.sol` (OpenFactory, registrar,
  SubjectAccountFactory, MetaToken v1 registered as `META v1`, MetaTxDex, OrderBookDex, optional demo token) and
  writes `deployments/<chainid>.json`. Zether and the registry are not in the deploy script (dev chains only).
- **Passkey:** OZ 5.2 `P256.verify` (RIP-7212 precompile `0x100` when present, Solidity fallback ~200–330 k gas);
  `has_p256_precompile` is probed per chain.

### 7.2 Hedera

- HSCS runs EVM bytecode; the relayer is the EVM adapter pointed at a JSON-RPC relay; lanes are ECDSA accounts with
  EVM aliases (coin 3030) that must exist and be funded.
- `HederaMetaToken`: 64-byte signatures from an account without code are verified through HIP-632
  `isAuthorizedRaw` (HAS precompile `0x16a`, called with CALL; 100 k gas cap) — ED25519 Hedera accounts sign
  meta-txs natively, but only with a **raw signer** over the 32-byte EIP-712 digest: clientkeys seed
  (`m/44'/3030'/0'/0'/i'`) or an ECDSA-alias account; HashPack/WalletConnect `hedera_signMessage` (HIP-820 prefix)
  cannot be verified (WSF CR-WSF-2).
- **HTS underlying association is part of `initialize`**, with a fail-closed custom-fee check (TW2 R144 for v2,
  net-hedera R6-8 for v1, SPECIFIED, NET-HEDERA-FIX2: new v1 implementation, `deprecate(META, 1)` on Hedera). The
  built v1 permissionless `associateUnderlying()` (`0x167`) is **superseded** and removed by that stream. Wizards and
  wallets read every key of the HTS issuer and warn (R6-9).
- `HederaMandateWallet` adds `executeAsOwnerRaw`: the only way an ED25519 owner pays from its wallet (CR-ADW-2, §4.7).
- Node (SPECIFIED, NET-HEDERA-FIX1/3): Hedera status code → class table instead of unconditional requeue (R6-7, NI
  R341; `WRONG_NONCE` retried once); `tx_fee` on every receipt and `lane_balance` for the breaker (R6-10); mesh
  `sig_kind = "hedera_ed25519"` (R6-11).
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
  `instant` (CometBFT). Deploy tooling for Cosmos is **PLANNED** (`deploy.sh` exits 2); when it lands, contracts are
  instantiated `--no-admin` (CR-R3-11) with `instantiate2` and a salt containing the genesis hash, and the node
  refuses two chains with the same chain id (R9-4).
- Fixes (SPECIFIED): **passkey v2** — account `sha256("scaas.passkey.v2" ‖ pk65 ‖ rpIdHash ‖ sha256(origin))[..20]`,
  rpIdHash read from `authenticatorData`, origin through the shared grammar, UV and low-`s` checked; v1 passkey
  addresses (dev only) no longer accepted (CR-R3-1, R9-6; R3-FIX1, NET-COSMOS-FIX2); `extra` must be empty outside
  `trade` (R9-8); node reads `contract`/`valid_until` from the signed payload (R9-5) and resends a tx that dropped out
  of the mempool after `resubmit_after_blocks` (R9-7); head and events honour the quorum (R3-FIX4); the DEX loses
  `Sweep` (CR-R3-10) and gains a bound settler (DEX RS5-15, DX-FIX4); no key rotation or guardian yet (R3-FIX9). Under
  UA the passkey account becomes a 32-byte `webauthn-p256` UA shown only as a URN (UA R315).

### 7.4 Soroban (Stellar and Pi Network)

- Meta-tx = **native Soroban authorization**: the subject signs `HashIdPreimage::SorobanAuthorization` (network id +
  contract + function + args, `i64` nonce, ledger expiry); the relayer lane is the transaction source and pays;
  `fee_bump_lane = i` lets one lane fee-bump (CAP-15) every lane's transaction. No second verifier is written. The
  nonce is **deterministic**, not random: `nonce = i64(sha256("scaas.soroban.nonce" ‖ entryRef ‖
  validUntil_be64)[0..8])` (Odoo `fam_soroban.py`; net-soroban §1), so one payment request at one validity maps to
  one host nonce.
- Contracts: token (SEP-41 + `pay(from, to, amount, pay_ref, valid_until)`, `approve` only to contract spenders),
  custom account (P-256 WebAuthn + ed25519 keys, Merkle batching; guardian recovery is a stub), mandate, DEX
  (`settle(maker, taker, maker_fill)` with two `require_auth_for_args`).
- **`pay_ref` is one-shot per `(from, pay_ref)`**, not globally, and `pay` moves a positive amount
  (`Key::PayRef(from, pay_ref)`, `ref_used(from, pay_ref)`, `amount ≤ 0` ⇒ `NonPositiveAmount`; R8-9 = R3D CR-R3-3;
  SPECIFIED, NET-SOROBAN-FIX1 / R3-FIX5): with the built global key, a stranger's 0- or 1-unit `pay` with the victim's
  ref blocks the victim's signed payment. The mandate keeps its own `Key::Ref(pay_ref)` (only its delegate spends it).
  Booking already sums settlements per `entry_ref` and receiver, so a stranger's payment is only money in.
- **DEX relayer binding** (R8-10 = DEX RS5-15; SPECIFIED, DX-FIX4): `Order.relayer: Address` is mandatory — Soroban has
  **no open form** (unlike DEX RS5-15's "relayer 0 = open" elsewhere) — and `settle` calls
  `maker.relayer.require_auth()` and requires `maker.relayer == taker.relayer`; the built DEX lets a third party
  re-submit both auth entries with `maker_fill = 1`.
- Other fixes (SPECIFIED): TTL bumps on `pay_under_mandate`/`__check_auth` and adapter `RestoreFootprint` + retry
  (R8-11); `op_consumed` reads the host nonce key and `ref_used` (R8-12); `crossOrigin`/`topOrigin` refused (R8-13);
  `tx_fee` on SUCCESS and FAILED + `lane_balance` (R8-14); `valid_until`/`contract` from the signed invocation (R8-15);
  guardian + delayed recovery (R3-FIX8).
- Op digest (for indexing and the job API): `sha256(XDR(Vec[Symbol("scaas_metaop_v1"), network_id, contract,
  Symbol(fn), Vec(args)]))`.
- The subject `G…` account must exist on the ledger. Pi Network = the Soroban family with network passphrase "Pi
  Testnet"/"Pi Network" and SLIP-44 314159 (owner to confirm passphrases at deploy).
- **Not on the mesh v1** (R77): replay protection is the host's auth nonce (per entry, above); there is no
  peer-readable per-subject sequential nonce. Soroban jobs go through the job API only.
- Finality: `instant` (SCP closed ledger).

### 7.5 Move — Aptos and Sui

**Aptos** (package `scaas`; deployed as an object code deployment; **`upgrade_policy = "immutable"`** at deploy,
RS11-20 / CR-R3-11 — the built `Move.toml` still says `compatible` and dev deployments are redeployed by NET-APTOS-FIX2 /
R3-FIX15; the publish script reads `0x1::code::PackageRegistry` back and exits 1 unless immutable): one `Account` object per owner (derived from Root
`b"scaas.root"`) holding primary fungible-asset stores for every asset; `MetaOp{domain, chain_id, contract, asset,
op, from, to, amount: u128, pay_ref, lane, nonce: u64, valid_until: u64, relayer, extra}`, digest
`sha3_256(bcs(MetaOp))`; `package entry relay_pay(lane, owner, asset, …)` prevents other modules from wrapping
relayed entries (`check_entry_visibility.sh`); key management with up to 8 keys and 8 origins, guardian recovery
after 172 800 s; pure-Move P-256 verifier (unaudited). Native **fee-payer (AIP-39) and orderless transactions** are
kept as a seam for passkey/keyless subjects only; the relayer lane uses sequence-number transactions and pays.
Finality: committed block (AptosBFT), cursor bounded by the Indexer API's processed version.

Aptos fixes (SPECIFIED): error-class table — a committed out-of-gas is rebuilt **once** at `params.max_gas_amount`,
then `reverted`; every committed tx (failures too) feeds `tx_cost`; billed failures count toward the subject's grief
score (RS11-21, NI R340–R342); dispatchable fungible assets refused unless the token enables `features.dispatchable`,
and always on the not-yet-opened path (RS11-23); lazy ed25519 open requires the `application:` line and records it as
the first origin (RS11-22); mesh/gateway verify the ed25519 `fullMessage` locally (RS11-26). Streams NET-APTOS-FIX1…3.

**Residual risk — multisig wrap (Aptos, stated).** Relayed entries are `package entry`, so scripts and other
packages cannot wrap them, but the VM calls an entry function regardless of visibility when a
`0x1::multisig_account` executes a stored payload; a hash-only execution carries no payload, so the indexer gets no
hint. Bounded: the wrapper needs the subject's signature (relayer `0x0`), funds still reach the signed receiver, and
the consumed lane stops a replay on the same lane — the client only misses the settlement (the request expires with
attention). Mitigation if needed: hint by `fungible_asset_activities` per asset (net-aptos §6.6, L1).

**Sui** (package `scaas`): shared `Account<T>` per (subject, coin type) registered in `Registry<T>` (a second
`open` is refused, so nobody can create a decoy account); subject signs `signPersonalMessage(BCS(MetaOp))`, Move
recomputes `blake2b256([3,0,0] ‖ bcs(vector<u8>))` and verifies ed25519 / secp256k1 (SHA-256) / secp256r1 /
passkey. Relayer lane sends a **PTB** calling `meta::relay_pay<T>`; each lane has its own gas coin and one tx in
flight; the node journals the last signed tx bytes to disk (`lane_journal`) so a gas coin is never equivocated.
**Sponsored transactions** (dual signature) are used only for subject-sent deposits (seam). DEX `settle<A,B>` is
atomic; several settles batch in one PTB. Finality: certified checkpoint.

Sui rulings (SPECIFIED):

- **Immutable at deploy** (RS7-14, CR-R3-11): the deploy script publishes and calls
  `0x2::package::make_immutable(upgrade_cap)` in the same run; the gate requires the `UpgradeCap` to be deleted before
  `params.package` is recorded; the node re-checks `params.upgrade_cap` at activation and every start (`halted`,
  `PROGRAM_UPGRADEABLE`). `type_package = package`; every fix is a new package with new `Root`/`Registry<T>`/
  `Account<T>` ids, and owners move funds by signing `pay` from the old account (NET-SUI-FIX3).
- **`Keys` belong to the subject, not to a coin type** (CR-R3-5, R3-FIX7): one shared `Keys` object per subject (keys,
  origins, guardian, recovery, `key_nonce`, policy) created by the first `open`; every `Account<T>` stores its `Keys`
  id; DEX `cancel`/`invalidate_nonces` take the maker's `&Keys`. Fresh package publish.
- Lane table `{nonce, valid_until}`, `relay_pay` refuses `valid_until > now + LANE_HORIZON_S` (30 d) on chain;
  permissionless `prune` after `valid_until + LANE_HORIZON_S` with the storage rebate to the caller (the node collects it
  with its lanes, NI R346 (a)); replacing ops on one lane/nonce signed more than `LANE_HORIZON_S` apart is the
  client's obligation (RS7-11, §5.5). `forward` never returns a removed key (RS7-10). NET-SUI-FIX2.
- Lane journal = the set of every unresolved tx per lane, moved into the store's `outer_tx` (RS7-9, NI R347;
  NET-SUI-FIX1); mesh `sui_op` signature checked before dry-run (RS7-13).

**Wallet-key signatures on Sui and Solana** (WSF CR-WSF-1; streams WSF-FIX1, WSF-FIX2). These wallets put no
requesting origin into `signMessage`/`signPersonalMessage` bytes, so on-chain application binding is not possible.
Rules: (1) the signed bytes are **readable UTF-8 text the contract re-renders from the `MetaOp`** and compares byte for
byte (`SCaaS <op>` / `Amount: <decimal> <symbol>` / `To:` / `Network:` / `Valid until:` / `Ref:` / `Digest:`; decimals
and symbol from the on-chain token/config; Solana as OCMS v1 in the `\xffsolana offchain` envelope, Sui as a personal
message, not BCS) — no blind hex blobs; (2) portal/app flows offer the **passkey first** (origin and rpIdHash checked on
chain); (3) opt-in account policy bit `POLICY_PASSKEY_FOR_VALUE` (Solana `SubjectAccount.policy`, Sui `Keys.policy`)
makes value ops require a passkey, wallet keys then authorise key operations only. **Residual risk:** a user who
approves a readable "pay X to Y" message on a phishing page has authorised it, as with any wallet transaction.

### 7.6 TON

> **BLOCK (net-ton rev 1.1, review C1).** An unbounded forward-TON amount lets one signed `pay` send a lane's balance
> to an address the signer chooses. **No job API (NI P2, cutover P6), mesh (S5) or gateway path may reach a TON lane
> until the node half of NET-TON-FIX1 lands** (R10-12, NI R340/R344/R345). The built Odoo pull path is safe today:
> Odoo builds `extra = 0` and never sets `forward_nanoton`.

- Jetton (TEP-74) rewritten in **Tact** with a custom jetton wallet holding the owner's pubkey, an optional
  passkey and `lanes: map<uint256, uint64>` (rotated every `LANE_TTL` = 30 days). There is **no `BindKey` message**:
  the key binds lazily — a `SignedOp` carries the owner wallet's optional `stateInit`; the jetton wallet checks
  `hash(stateInit) == owner.hash` and reads the pubkey from the W5R1/V4R2/V3R2 data by code hash (R10-5; no subject
  transaction needed). `set_key` (passkey attach/detach) must carry a proof of possession of the attached key (UA
  R314; not yet in code).
- Subject signs with TON Connect `signData` (type `cell`); the wallet rebuilds the exact envelope (prefix
  `0x75569022`, app domain, timestamp, address) around the `MetaOp` cell tree and checks `CHKSIGNU`. **Domain binding**
  (R10-14, supersedes R10-3's Odoo-only check): the node refuses a `domain ∉ chain.ton_app_domains` at every door (job
  API, mesh, gateway) before any `build`, and new deployments pin it on chain (R10-14: `domainHash` in the wallet init
  data; R3D CR-R3-7 records a per-wallet `domains` set changed only by the owner's own wallet plus a timestamp bound —
  the two forms are reconciled in NET-TON-FIX3 / R3-FIX11, §15.3). `SignedOp` is an ordinary message anyone can relay,
  so the off-chain check alone never runs when a phishing page relays its own.
- Relayer: lane **W5** wallet (seqno per lane) sends `SignedOp` (opcode `0x5b0a1d01`) as an internal message with
  TON attached (`attach_nanoton`, default 0.15 TON). **W5 gasless extensions and Highload wallets of the subject are
  not used** (subject seqno would be a lock, R30); a Highload-v3 relayer wallet is a possible future lane type
  (PLANNED).
- **Forward TON is capped on every path** (R10-12, SPECIFIED): node `chain.max_value_out` (0.05 TON) at intake and at
  lease for the signed floor and any `extra.forward_nanoton` (unsigned, NI R344) ⇒ `422 VALUE_OUT_TOO_HIGH`; lane
  `value = max(attach, forward + 0.1 TON)`; forwarded value feeds the breaker (`value_out`, R340). Contract (new wallet
  code and master): `MAX_FORWARD_TON` (0.1 TON) ⇒ `E_VALUE`; DEX legs carry `excessTo` so a failed leg returns tokens
  to their owner and excess TON to the lane.
- Other fixes (SPECIFIED): `tx_id` = TEP-467 normalized message hash, with seqno lookup as fallback (R10-13); `build`
  simulates the balance and checks the passkey locally (R10-15); a revoke moves the lane to `nonce + 2`, so it runs
  exactly once (R10-16); a guardian and delayed passkey rotation (R3-FIX10; a TON passkey cannot rotate today).
  Streams NET-TON-FIX1…4.
- DEX: actor model has no cross-contract atomicity ⇒ **escrow**: leg A waits in the DEX for leg B; expiry ⇒
  permissionless `Refund`. The DEX keeps nothing that is not its own (R10-17, SPECIFIED): `cancel` of an unknown order
  returns the TON; bounced payouts and refunds go to a separate `bounced[master]`, never to `fees`, and the admin
  returns them through an evented `RefundBounced{master, to, amount}`; `WithdrawFees` withdraws fees only (R3D CR-R3-9
  states a per-owner `unclaimed` + `Claim`; R10-17 notes the bounce body is truncated to 256 bits, so it cannot carry
  the destination — reconciled in NET-TON-FIX3 / R3-FIX13, §15.3). Settlement relayer binding: DEX RS5-15, DX-FIX4.
- Finality: masterchain block (`depth 0`). The adapter reports the payer jetton-wallet tx hash with `mined`
  (**BUILT**; the former TODO #8 is done). Residual: a `final` from the indexer before the node's `mined` still flags
  `landed_elsewhere` (informational).

### 7.7 Solana

- Anchor program `scaas`: SubjectAccount PDA owns the token accounts; `LanePda{next}` seeded `["lane", subject,
  lane]` (prunable after `valid_until + PRUNE_DELAY_S`); `MetaOp` fixed **336 bytes** (`MetaOp::LEN`), digest
  `sha256(MetaOp)`; the subject signs `"<domain>:" ‖ hex(sha256(MetaOp))` as raw ed25519, Solana off-chain message
  (`\xffsolana offchain`) or passkey; the program verifies by inspecting the Ed25519/Secp256r1 precompile instruction
  in the same transaction. Wallet text becomes readable and rebuilt on chain under WSF CR-WSF-1 (§7.5).
- **Immutable at deploy** (RS12-19, CR-R3-11; SPECIFIED, NET-SOLANA-FIX1 / R3-FIX15): `deploy.sh` = deploy with a
  temporary authority → `initialize` → `solana program set-upgrade-authority --final` → check `ProgramData`
  `upgrade_authority_address == None` and `Config` exists, else exit 1. The node holds a chain whose program still has
  an authority `halted` (`PROGRAM_UPGRADEABLE`). The built deploy keeps an upgrade authority (dev only).
- **Signing network fixed at build time** (R3D CR-R3-4, R3-FIX6): the Solana runtime exposes no genesis hash, so
  `deploy.sh` reads `solana genesis-hash --url <cluster>` and builds with `SCAAS_NETWORK` = that hash; `initialize`
  loses its `network` argument; a program id already recorded for another genesis is refused. The chain profile's
  `chain_uid` (UA R330) is that genesis hash; the node keeps RS12-8 (RPC genesis == `chain_uid` == `Config.network`).
  Until R3-FIX6 lands: never reuse a program id across clusters.
- **Lane-funded rent** (RS12-20, NI R346): the destination ATA of `relay_pay`/`mandate_pay` must exist (the program no
  longer creates it); the node adds `create_idempotent` paid by the lane only for a configured receiving wallet, else
  `422 DEPOSIT_NOT_ALLOWED` — otherwise a recipient that closes its ATA for the rent drains the lane in a loop.
  `MAX_TTL_S = 31 d` caps `valid_until` and order `expiry` on chain (RS12-21); a CU exhaustion is rebuilt once at
  `max_cu`, then `reverted` (RS12-22); `crossOrigin`/`topOrigin` refused (RS12-23); connectors refuse ops beyond the
  lane horizon (RS12-24); mesh verifies ed25519 locally (RS12-25). The owner passkey id becomes the UA `webauthn-p256`
  id shown only as a URN (UA R315). Streams NET-SOLANA-FIX1…3.
- Native fee payer is the relayer lane; recent-blockhash expiry (~60–90 s) is why the subject never signs the
  transaction itself (queued jobs and resting DEX orders live much longer). Each **lane** owns a **durable nonce
  account** (created on first use), so lane transactions do not expire while queued.
- Priority fees: transaction v1 header with `max_priority_lamports` total, explicit compute-unit and loaded-data
  limits (`max_cu`, `max_loaded_bytes`).
- Finality: commitment `finalized`; indexing via standard JSON-RPC (`getSignaturesForAddress` + `getTransaction`),
  no proprietary APIs. The public test program id is refused on public clusters.
- clientkeys has no Solana signer yet; the seed and passkey signers are **SPECIFIED** (S4F R263–R267, `fam/*`).

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
the private chain 7622 counts as dev, Z4 curve choice, Z5 gas optimization before public chains. Post-quantum
confidential balances are a separate class: §8.12. Node note: the built default `max_gas_per_tx` (3,000,000) is
below a classical Zether transfer (3.36 M); a chain with Zether must set `max_gas_per_tx ≥ 4.2 M` (BLS envelope
3.98 M execution + intrinsic + calldata ≈ 4.10 M; ZD rev 1.1 §15).

Review fixes (ZD rev 1.1, SPECIFIED; streams ZF-FIX1…3): clientkeys and the node gateway accept a Zether token only if
its `verifier()` and `registry()` are the chain's pinned canonical addresses (the factory stays open for provenance,
RS2-20); `ZetherMetaTx` applies the `MetaToken` ERC-1271 cap — 400 k when `m.from.codehash` is the `SubjectAccount`
clone codehash, else 50 k — so a passkey `SubjectAccount` can sign envelopes (RS2-21); an outer fee recipient equal to
the token reverts `FeeWouldStick` (RS2-24); mandatory invariant/fuzz, off-subgroup and `D_out = O` tests (RS2-23); the
client balance-cache key includes the chain (`chainId:ua:token`, later `chain_uid`, RS2-25); the public
`schnorrSign` export takes no caller-chosen `k` (RS2-26). The built registry's PoP does not bind an authority: register
only from an account you alone control until UA F1 (RS2-22).

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
| Balance cache | `{ua, token, accSeq, balance}` in the device vault, verified by `[b]G == C − [x]D` before use, updated on rollOver (BSGS only on `pending`) and own debits; never on chain or on a server; key `chainId:ua:token` (RS2-25; built key `ua:token`) | clientkeys `sealBalanceCache` |
| `shieldScale` | raw underlying units per shielded unit (e.g. a 6-decimal stablecoin kept to 2 decimals: `10^4`) | `fund(amount)` pulls `amount × shieldScale` |
| Ring size | 2 | |

Native CLI `zether-read-balance` reads balances above the device bound (table up to 2^27).

Soundness of the balance relation holds for every balance `< r` (RS-NV64-1), so the canon rule "`2^n_b > total ×
1024`" is superseded; `n_b = 128` would add ≈ 1.06 M gas (≈ +32 %) per transfer and ≈ +76 % per burn and is not
planned. ConsenSys Zether's `MAX = 2^32 − 1` is a decryption bound, not a soundness bound; separate Zether "series"
are separate, non-fungible tokens ([MAX note](superpowers/specs/2026-10-05-zether-consensys-max.md) rev 1.1). BSGS
timings in the limits spec are estimates ([limits](superpowers/specs/2026-10-05-zether-limits.md) rev 1.1).

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

> **Superseded (SPECIFIED, [UA](superpowers/specs/2026-10-06-universal-account-design.md) rev 1.4, R290–R318, R330–R331;
> summary §9.8).** The registry below becomes the general, admin-free, monotonic `UARegistry` (kind-tagged 32-byte ids for
> every non-native kind; PoP binds chain (incl. `chain_uid`) + registry + UA + `authRef`, not `msg.sender`, so `register` is relayable;
> one key = one purpose). Zether UAs become `keccak256(keccak256("scaas.ua.zether-<curve>.v1") ‖ Y)` with an
> immutable `authRef` (0 = self, or a native/SIGNING UA that co-signs the PoP) replacing `AuthScheme` and
> `links`/`link_eth`. Scheme mapping (UA §12.2): `SELF_SCHNORR` → `authRef = 0`; `ECDSA_MULTISIG` → `msig` of EOA
> members; `FROST/MUSIG2_BN254` → `frost/musig2-bn254` UAs (group key checked on chain); `BLS_*` → `bls-*` UAs
> (cross-curve rule kept); `PQ_COMMITMENT` → retired (R313); `SMART_ACCOUNT_1271` → native contract id. Breaking,
> dev chains only (R312). This section describes the code as built until stream F1 lands.

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
| 6 | `PQ_COMMITMENT` | `abi.encode(bytes32 pqCommitmentHash)` | as 0 on chain; PQ verification off chain; commitment kept for future rotation | PQ readiness (retired by UA R313: PQ kinds are verified on chain) |
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

The token stores per `entryRef` the bundle `Y_to ‖ C_out ‖ D_out ‖ C_aud` (bn254 256 B ≈ +200 k gas; BLS12-381
512 B ≈ +375 k gas, estimate; RS2-15, ZD rev 1.1 §12). Three openings, all kept:

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
are not carried on the mesh (`W = 0` and single-flight per sender need their own design); neither are PQZ
envelopes (`metatx`/`ua_metatx` naming a PQZ token are never exported). PQZ: private chain only
(§8.12).

### 8.12 Post-quantum Zether on private/PoA chains (SPECIFIED, [PQZ](superpowers/specs/2026-10-06-pq-zether-design.md) rev 1.4)

Component spec E (R270–R289) is normative; nothing of it is built. **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
Summary:

| Item | PQZ (rev 1.4) |
|---|---|
| Class | `PqzToken`, a separate token class, never an upgrade of `ZetherToken`; same shape (identities visible, ring size 2, encrypted amounts and balances, public fee scalar, sender/receiver/auditor disclosure) (R270) |
| Encryption | additive module-LWE with BFV-style encoding ("MLWE-BFV-add"): `d = 64`, `k = 32` (LWE dimension 2048), `q = 2^42 − 215` (prime, `X^64 + 1` splits into 4 factors), `Δ = 2^26 − 1`, CBD(1) secrets, CBD(20) errors, plaintext = 16 base-16 digits; primal-uSVP β ≈ 476 (core-SVP 139 classical / 126 quantum; Kyber-512 is 406) (R271, R272) |
| Credit cap | `K_MAX = 1024` live units per account between refreshes; `fund` and fee credits go to a public `plainPending` integer, never to ciphertexts (R275) |
| Proofs | one LNP22 lattice proof per op through `pqz-core`, a LaZer fork whose arithmetic layers are rewritten (integer-only, constant-time C99, no GMP/MPFR/`malloc`/`abort`); `proofSystemId = keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v1")`; kill criterion: proof > 96 KB or p99 verify > 50 ms (R278) |
| Verification | native precompiles on the private chain only: `PQZ` at `0x…0F01`, `MLDSA65` at `0x…0F10`; the verify path never crashes the node; no Solidity verifier (R279, R280) |
| Gate | hard-coded allowlist (dev 31337/1337 and the private chain) **and** a constructor precompile self-test; `OpenFactory.pqzEnabled = false` by default; release gates G-LIC (licences/patents) and Z1 (audit) (R270) |
| Identity | UA kind `0x0142` `pqz-mlwe` (`d` = 16,384-byte public key), a Zether-family kind; `authRef` must be a PQ signing UA (`mldsa65`/`mldsa44`/`fndsa512`) or an `msig` whose non-PQ members' weight is below the threshold; `0`, native ids and classical-only kinds refused (R281, R282; UA R305) |
| Meta-transactions (owner 2026-10-07, R284 rewritten in rev 1.4, §7.11 there) | `PqzToken` is ERC-20 + **`IERC20MetaTx` exactly like `ZetherToken`**: public ERC-20 ledger, `wrap`/`unwrap` of the underlying 1:1 as **direct calls** (same surface as classical), R26 allowances, the unchanged `MetaTransaction` struct, typehash, `canon`, 2D nonce, `cancelMetaNonce`, `supportedModes() = 0xF3`, nine steps, `MetaTransactionExecuted`; domain `("SCaaS PqzToken", "1", chainId, token)`. **v3 path**: `uaExecute(UAMetaTransaction, auth)`, domain `("SCaaS PqzToken", "3", chainId, token, salt = chainUid)`, so a PQ UA (an `mldsa65` fee UA) pays the outer fee and the whole path is post-quantum; one nonce map for both paths. Envelope ops: `m.to = 0`, `m.value = 0`, `m.data` byte-identical to the direct calldata of `pqzTransfer`, `pqzBurn` (burn and refresh), `fund(bytes32,uint256)` (from the signer's public balance), `rollOver`; `data` empty = plain public transfer. Outer fee `NONE`/`FIXED` only on PQZ ops (`PERCENT` refused), checked before any statement build and taken after the proof verifies. `envelopeBinding` is a statement header field (0 for a direct call), so proof and PQ `authSig` cover exactly one envelope. **Gasless exit = the envelope `burn`**, which pays the underlying straight to `recipient`; no envelope `unwrap` op, no `pay`, no `mtxBatch`/`uaBatch` (an op is ≈ 3 M gas, ≈ 80 KB). Authority split: the envelope signer controls only its public balance and its nonces; confidential value needs the PQ `authSig` and the proof. Not on the mesh, as classical Zether |
| Decryption | direct rounding, exact, microseconds; no BSGS, no cache needed (R285) |
| Limits and sizes | `MAX_TOTAL_SHIELDED = 2^62`, amounts `< 2^64` (R286); ciphertext 16,512 B, public key 16,384 B, transfer proof ≈ 30–50 KB (estimate); statement 83,008 B (transfer) / 49,984 B (burn) with the 576-byte header incl. `envelopeBinding`; a transfer ≈ 77 KB calldata (≈ 81 KB in a v3 envelope), ≈ 2.8 M gas direct and ≈ 2.82 M in a v1 envelope while p99 verify ≲ 9.7 ms (§4.4, §9.4 there) |
| Keys | seed by UA §8.1's PQ rule `HKDF-SHA256(BIP-39 seed, "scaas.ua.pq.v1", kind_tag ‖ account ‖ i)`, derived in the app's key worker, sealed as a 32-byte leaf (R282) |
| Provers | native x86-64/aarch64, then the browser/mobile WASM prover in the app's Zether worker (E-S6), fallback a loopback-only `pqz-cli serve` run by the user (R287, §11.5 there) |
| Node | chain profile flag `pqz` bound to the genesis hash (RPC genesis == profile == `registry.chainUid()` == each token's `chainUid`), probe `has_pqz_precompile`; **envelope ops travel as ordinary `metatx` (v1) and `ua_metatx` (v3) jobs** on a token row with `kind = pqz`; job kind `pqz_call` stays for **direct open calls** only (`pqzTransfer`, `pqzBurn`, `rollOver`; direct `fund` is never a node job); every PQZ job is pre-simulated on a follower and never batched; `max_gas_per_tx = 16,000,000` on the private chain; 1 MiB body limit on job submissions to the `pqz` profile only (§11.3 there; NI amendment pending; operator recommendations, OPS R247) |
| Odoo / ERPs | no new model: PQZ envelopes are pushed as ordinary `metatx`/`ua_metatx` jobs (`m.data` opaque), the outer fee booked from `MetaTransactionExecuted`/`UAMetaTransactionExecuted` like any token (§11.4 there; `integration.md` §3.1) |
| Migration | classical `ZetherToken.burn` then `PqzToken.fund`; the amount is public once (R289) |

Per family: v1 on the private EVM chain only (Nethermind precompile); other private EVM chains later through a
co-processor seam; public chains never without an owner ruling (PQZ §14). Streams E-S0 … E-S9 and the G-LIC gate
(PQZ §16).

---

## 9. Keys and signing

> **Account identity, key kinds and one key = one purpose:** [UA](superpowers/specs/2026-10-06-universal-account-design.md)
> rev 1.4 (SPECIFIED), summarized in §9.8. Signers, vault v2 and the backup switch:
> [S4F](superpowers/specs/2026-10-06-signers-followups.md) rev 1.1 (SPECIFIED).

### 9.1 Two custody axes

| Axis | Key | Purpose | Custody | Status |
|---|---|---|---|---|
| `auth_custody` | secp256k1 / ed25519 / P-256 signing keys | Authorizes spending (EIP-712, MetaOp, WebAuthn) | Subject device (passkey, seed vault), wallet extension, or — for entrusted custodial/delegated wallets — a KMS/HSM (FIPS 140-3 Level 3) behind the custody adapter | device **BUILT**; KMS/HSM adapters **PLANNED** (O6) |
| `conf_custody` | Zether `x` (bn254 / BLS12-381); PQZ 32-byte leaf (§8.12) | Decrypts balances, builds proofs | Subject device (seed path `…/7`; PQZ leaf sealed in the key worker); for organizations a threshold-MPC or enclave key oracle with a narrow interface `zk_mul_by_x(points, ctx)`, `zk_nonce_commit`, `zk_response` — commercial HSMs do not support these curves | device **BUILT**; key oracle **PLANNED** |

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
- **One rule and one grammar for every family** (R3D CR-R3-1, SPECIFIED; streams R3-FIX1, R3-FIX2), in order:
  `authenticatorData` ≥ 37 bytes; `rpIdHash` equals the stored one; UP **and** UV; `clientDataJSON` matches exactly
  `{"type":"webauthn.get","challenge":"<b64url(digest)>","origin":"<origin>"` followed by `}` (end), or by
  `,"crossOrigin":false` and then `}` (end) or `,` (the EVM `_clientDataOk` grammar); the origin equals a stored origin
  **exactly** (no prefix match; the built TON check accepts `https://a.example.evil`); `s ≤ n/2`; then P-256. Shared
  vectors `smartcontracts/test/vectors/webauthn_kat.json` (Safari L2 and Chrome/Firefox L3 accept shapes; rejects:
  `crossOrigin:true`, `topOrigin`, a member before `crossOrigin`, whitespace, a suffixed origin, wrong rpIdHash, UV
  unset, high-s, another digest) run in every family's suite. Built gaps: Cosmos checks neither rpIdHash, origin nor
  UV; Sui, Soroban, TON and Solana do not refuse `crossOrigin: true`.
- **Documented limitation** (ADW L3): `SubjectAccount.isValidSignature` accepts any digest signed by any of its keys —
  ERC-1271 digests are not account-wrapped (ERC-7739 class). SCaaS digests bind `from`/`verifyingContract`, so none of
  ours replay across accounts; a third-party protocol that trusts the same key on two accounts is exposed. Wrapping is
  rejected for now (it would change every 1271 digest, KAT, clientkeys and Odoo builder).
- Batch: one assertion over a Merkle root of digests; leaf `keccak256(keccak256(0x00 ‖ digest))` (second-preimage
  safe); each operation carries `(keyIndex, proof, sig)`.
- Per family: EVM/Hedera `SubjectAccount` (ERC-1271; P-256 via precompile `0x100` or Solidity); Sui
  `secp256r1_verify`/passkey; Soroban `secp256r1_verify` (CAP-51) in a custom account; Cosmos `secp256r1_verify`
  (cosmwasm-std 2.1+); Aptos pure-Move P-256; Solana Secp256r1 precompile; TON passkey auth kind in the jetton
  wallet.
- `clientkeys/src/passkey-signer.js`: `creationOptions` (PRF enabled by default), `requestOptions`, `derToRS`,
  `encodeAssertion = abi.encode(authenticatorData, clientDataJSON, r, s)`, `merkleBatch`, `accountSignature =
  abi.encode(keyIndex, bytes32[] proof, sig)`.

### 9.4 Subject accounts, guardians, recovery, backup (BUILT; backup switch SPECIFIED, [S4F](superpowers/specs/2026-10-06-signers-followups.md))

`SubjectAccount` (EVM; equivalents per family): multiple authorized keys (`P256_WEBAUTHN(x, y, rpIdHash,
originHash)`, `SECP256K1(address)`), never zero keys (`LastKey`); `addKey`/`removeKey`/`rotateKey`/`setGuardian`
only through `executeAsOwner` signed by an existing key (own nonce, `OwnerCall(bytes data,uint256 nonce,uint256
validUntil)`); guardian `initiateRecovery(newKey)` → anyone `completeRecovery` after `RECOVERY_DELAY = 2 days`
(adds a key, removes none); the owner can `cancelRecovery`. Deployed by `SubjectAccountFactory` (CREATE2, salt =
`keccak256(abi.encode(firstKey, guardian))`, idempotent) — the client enqueues the deploy job before the first
payment. Under UA it is **option (b)**, kept byte-identical: the optional native smart account for users who need a
stable address across key rotation, guardian recovery or third-party compatibility (UA R307); its `SECP256K1` keys
come from the role path `m/7622'/0'/<account>'/2'/<i>'`, never the EOA path (UA R300, S4F R269).

Seed and passkey back each other up: the seed-derived key is the natural recovery key when a passkey is lost and
vice versa. New `SECP256K1` keys that Odoo or clientkeys register on a subject account use the role path, never the
subject's EOA key; registering a key whose address equals the subject's `payer_address` on the same account is refused
(ADW CR-ADW-3, ADW-FIX3; existing dev keys stay until rotated).

**Key lifecycle per family** (R3D CR-R3-6; gaps are streams):

| Family | Rotation | Guardian / recovery | Gap |
|---|---|---|---|
| EVM | `SubjectAccount` add/remove/rotate via `executeAsOwner` | guardian + `RECOVERY_DELAY` | — |
| Hedera | native account key update (no `SubjectAccount`, R6-2) | native | — (stated) |
| Aptos | account keys + origins | guardian + `RECOVERY_DELAY` | — |
| Sui | per `Account<T>` today → per subject `Keys` (CR-R3-5) | guardian per `Account<T>` today | R3-FIX7 |
| Soroban | account-authorised add/remove | **seam only** (R8-2) | R3-FIX8 |
| Cosmos | **none** (passkey address = hash of key + rp + origin) | **none** | R3-FIX9 (passkey account contract: design + impl) |
| TON | wallet key follows the owner's wallet; **a passkey cannot rotate** | **none** | R3-FIX10 (guardian + delayed passkey rotation) |
| Solana | KeyOp add/remove/policy | `start_recovery` / `finish_recovery` | — |

A plain EOA never rotates. Merkle batching of several digests under one passkey assertion exists today on EVM and
Soroban only; Sui, Aptos, Cosmos, TON and Solana verify one digest per assertion (INFRA review M2).

**Backup switch (SPECIFIED, S4F R250–R254; replaces the earlier per-account mode list):** one boolean deployment
switch "backup key required", default **OFF** (app `policy.requireBackupKey`, Odoo
`dms_blockchain.require_backup_key`). An account has a backup iff it holds ≥ 2 distinct active keys (one passkey on
two origins counts once), or exactly one and an independent guardian; an `msig` UA iff `Σweights − max(weight) ≥
threshold`. With the switch ON, clients and issuers (never contracts or node intake) refuse value operations from an
account without backup; key operations stay open; **exits are never blocked** — single-key derived UAs and other
unsatisfiable kinds may only move their balance out. BE/BS flags drive non-blocking warnings.

### 9.5 Seed vault (BUILT)

- 24-word BIP-39 generated on the device (import accepts 12–24 valid words); shown once; verification by re-entering
  3 random words (`SeedBackup` states `fresh → revealed → challenged → verified → taken`).
- Storage: AES-256-GCM with a 32-byte data key wrapped by the passkey **PRF** when available, else by a PIN/passphrase
  through scrypt (`N = 2^17, r = 8, p = 1`, 128 MiB; code and S4F R259 agree, superseding round-3 R32's `2^15`);
  `needsRewrap`/`rewrapPin`; buffers wiped after use within JS limits. Mnemonic and keys never leave the device. Vault
  v2 (SPECIFIED, S4F R255–R258): an outer AES-256-GCM layer under a per-origin non-extractable WebCrypto device key in
  IndexedDB; recovery after device loss is the recovery phrase.
- Derivation (`clientkeys` `NETWORKS`): EVM `m/44'/60'/0'/0/i`; Cosmos `m/44'/118'/0'/0/i`; Hedera ECDSA
  `m/44'/3030'/0'/0/i`, Hedera ED25519 `m/44'/3030'/0'/0'/i'`; Sui `m/44'/784'/i'/0'/0'`; Stellar `m/44'/148'/i'`
  (Pi: coin 314159); TON `m/44'/607'/i'`; Aptos `m/44'/637'/i'/0'/0'`. Solana `m/44'/501'/i'/0'` **SPECIFIED** ([S4F](superpowers/specs/2026-10-06-signers-followups.md) R263) in
  clientkeys. These native paths serve native accounts only (EVM `m/44'/60'/0'/0/i` is the EOA only); every derived
  UA kind and every account-role key comes from the UA tree (§9.8). TON keys from these paths are importable into
  TON wallets as "BIP-39/Ledger path", not as native TON mnemonics.
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
- **One custody key per family** (NI R349, SPECIFIED, NR5): a key the node holds (lane key, mandate delegate,
  custody adapter key) signs in exactly one family; `Config::validate` refuses the same public key in two families and
  imported keys carry a family tag. Hedera ED25519, Stellar and the TON mandate delegate all sign raw 32-byte digests
  with ed25519, so one key across two families would make a compromised signer a cross-chain oracle. Portal
  connectors follow the same rule.

### 9.7 Threshold and aggregate signatures

| Scheme | Where | Property | Status |
|---|---|---|---|
| ECDSA N-of-M (`MultiSig.requireQuorum`) | registry scheme 1, controlled-token quorums; UA: the EOA-member path of `msig` (`0x0120`, weighted threshold, ≤ 16 members, one level) | sorted signers, raw digest, low-s; gas grows with M | **BUILT**; `msig` **SPECIFIED** |
| FROST t-of-n | registry scheme 2 (bn254); UA kinds `frost-secp256k1` `0x0111` (RFC 9591) and `frost-bn254` `0x0113` | one signature verification on chain (O(1)); UA registration checks every DKG proof of knowledge and `Y = Σ C_i0` on chain; share distribution and party distinctness are attestation-only (UA §4.3) | bn254 verification **BUILT**; UA kinds and signers/DKG (F1/F3) **SPECIFIED** |
| MuSig2 n-of-n | registry scheme 3 (bn254); UA kinds `musig2-secp256k1` `0x0110` (BIP-327) and `musig2-bn254` `0x0112` | UA registration recomputes KeyAgg on chain from the member list plus one aggregate PoP; nonce reuse leaks the key | bn254 verification **BUILT**; UA kinds and signers **SPECIFIED** |
| BLS aggregation (BN254 on private chains, BLS12-381 via EIP-2537) | registry schemes 4/5; UA `bls12381-minsig` `0x0106`, `bls-bn254-minsig` `0x0107`; `Bls12381.verifyMinSig`, RFC 9380 hash-to-curve (KAT tested) | one pairing check; never on the same curve as a Zether key | **BUILT** |
| Threshold ECDSA (MPC providers) | not a kind: the output is an ordinary ECDSA signature ⇒ native EOA (UA R296) | — | — |
| Smart-account policies (Safe, SubjectAccount) | scheme 7; UA: native contract id (never registered) | arbitrary policy via ERC-1271 | **BUILT** |

### 9.8 Universal Account summary (SPECIFIED, [UA](superpowers/specs/2026-10-06-universal-account-design.md) rev 1.4)

Short summary; UA R290–R318, R330–R331 and its kind table (§4.2 there) are normative. Nothing is built.

- **Ids** (R290–R293): native kinds use the chain's native id; every derived kind is
  `keccak256(keccak256("scaas.ua.<name>.v1") ‖ keyData)`, 32 bytes, top 96 bits non-zero; one hash (keccak256) in
  every family, so one key gives the same UA on every chain.
- **Kinds** (§4.2 there): native, never registered (R294) — `evm-eoa` `0x0001`, `evm-contract` `0x0002` (ERC-1271,
  incl. `SubjectAccount` and Safe), `hedera-native`, Solana, Stellar/Pi `G…`, Soroban `C…`, Aptos, Sui, Cosmos
  accounts, TON wallet (`0x0003`–`0x0016`). Derived, registered per chain — `webauthn-p256` `0x0100` (key data
  `x ‖ y ‖ rpIdHash`, no origin), `p256`, `ed25519`, `bip340`, `schnorr-bn254`, `schnorr-bls12381`, BLS min-sig
  (`0x0101`–`0x0107`); MuSig2/FROST on secp256k1 and bn254 (`0x0110`–`0x0113`); `msig` `0x0120`; `mldsa44`,
  `mldsa65`, `fndsa512` (`0x0130`–`0x0132`, enabled on every EVM chain with precompile or pure-Solidity verifiers
  within a per-chain gas budget, R313); `zether-bn254`, `zether-bls12381`, `pqz-mlwe` (`0x0140`–`0x0142`). Closed
  sets ZETHER, SIGNING and MEMBER are enforced where they are named (R303); MEMBER is per chain profile, so
  `hedera-native` is an `msig` member only in a registry whose `hederaNative` immutable is set (Hedera, HIP-632).
- **Registration** (R294–R297): `register(kind, keyData, pop, authRef, authPop)`; PoP over
  `keccak256(POP_TAG ‖ chainKeyHash ‖ chainUid ‖ registry_id ‖ ua ‖ authRef)`, never bound to the caller, so anyone may submit
  it; a non-zero `authRef` co-signs. Rogue-key defences per aggregate kind are checked on chain. The registry is
  monotonic and admin-free (R304); no rotation inside a UA — rotation is a new UA plus a transfer (R302).
- **Chain identity** (R330): a chain is `(chain_key, chain_uid)`, `chain_uid` = genesis hash (EVM, Hedera; non-EVM: the
  family's network id or a profile constant), a registry constructor immutable `chainUid()`. It is bound into the PoP
  digest, the registry's EIP-712 domain `salt` (`UAAuth`), the v3 `UAMetaTransaction` domain `salt` and the
  `metatx-cancel` digest, so two chains sharing a chain id (7622 or any other) never accept each other's signatures.
  The node checks registry address, `chainUid()` and the RPC's genesis hash per chain and holds the chain on a
  mismatch (NI rev 3.6 §9.1); clientkeys refuses a domain `salt` that differs from the profile's `chain_uid`.
- **EIP-7702** (R331): a delegated EOA stays a native EOA whose key is root; native ids are classified by code at
  verify time — empty ⇒ ECDSA; 7702 designator ⇒ ECDSA, else ERC-1271 through the delegate; other code ⇒ ERC-1271
  only. v2's "7702 = EOA, ECDSA only" rule is unchanged (R303).
- **One key = one purpose** (R298–R301), in four layers: separate hardened derivation per kind and account role on the
  tree `m/7622'/0'/<account>'/<kindNo>'/<i>'` (BIP-43 purpose `7622'`; role `kindNo`: `SubjectAccount` 2, Solana 16,
  Soroban `C…` 18, Aptos 19, Sui 20); registry `keyOwner[keyHash]` per curve group refuses a key under a second kind
  (`UAKeyInUse`); every UA signature is over the tagged `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖
  digest)`; EOAs stay unregistered and sign only wallet-native formats (EIP-712, incl. `UAAuth` behind the
  registry). clientkeys exposes UA keys only as `UAKey.signUA(purpose, digest)`.
- **Use** (R303, R306, R308, R309): v1/v2 tokens, DEX and mandates keep native ids; derived UAs hold EVM balances in a
  `bytes32` ledger on **MetaToken v3** (`UA_POOL` sentinel for ERC-20 observers) with its own
  `UAMetaTransaction` typehash, domain version `"3"`; verification goes through `requireAuthorized(ua, purpose,
  digest, auth)`.
- **`SubjectAccount`** is option (b), unchanged (R307, §9.4). Default for a phone user: a `webauthn-p256` UA
  registered gaslessly (`POST /v1/ua/register`, NI R320).
- **Optional** VC/eKYC layer (R310–R311): never mandatory; contracts see credentials only as `ComplianceRegistry`
  flags (AS R206). BBS presentations are never accepted as legal evidence; legal-recourse workflows require the
  account-bound KB-JWT with `nonce` = deal reference / `intent_id` (UA §9.2, §9.7).
- **Migration** (R312): the built Zether registry (§8.6, §14.5) is deleted and replaced at stream F1, dev chains only.

---

## 10. Sealed-bid tender (SPECIFIED)

Component spec: [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) rev 1.3 §A (R180–R188),
normative; no code. This section is its summary (the earlier text here, with bidder-signed reveals, replacement and
an `awardDeadline`, is superseded).

### 10.1 Problem

On a public ledger an open bid is visible to competitors in the mempool and in blocks (bid sniping, collusion). The
tender separates the **commitment** (hidden, bonded) from the **revelation** (after the deadline), and returns every
honest loser's deposit without anyone's approval.

### 10.2 Rules (summary)

| Item | Rule |
|---|---|
| Commit = deposit | One signature: the deposit token's own `pay` meta-tx (`to = tender`, `value = minDeposit`, `data = pay(depositRef)`, fee `NONE`, relayer bound to the tender); anyone submits `commitBid(tenderId, commitment, proof, m, sig)`; no tender-level signature, no allowance (R180) |
| Commitment | `keccak256(abi.encode(BID_TAG, chainid, tender, tenderId, bidder, price, salt))`, `BID_TAG = keccak256("scaas.tender.bid.v1")`, `price` `uint128`, 32-byte salt (R181) |
| Reveal, withdraw | permissionless, no signature; payouts go only to the destination the rules fix; no replacement in v1 (R182) |
| Forfeits | non-reveal, invalid (out-of-range) reveal, a declared violation class, or a HOLD bond claim ⇒ `slashSink`, fixed at creation, never a bidder (R183) |
| Reserve and ties | public `[minPrice, maxPrice]` only; tie-break = earliest commit `seq` (R184) |
| Cancel | buyer, until `commitDeadline`, with a `reasonRef`; every deposit refunds 100 % (R185) |
| Award window | `minBidders` valid reveals else `FAILED`; for `dqWindow` (≤ 7 d) the buyer may disqualify only the current leader, only while a next valid bid exists, with a public `reasonRef`, at most 2 times; buyer settles any time after reveals, anyone after the window; no `awardDeadline` (R185) |
| Deposit token | a registered, non-deprecated META kind from factory v1/v2; Zether refused; balance delta checked (R186) |
| Windows, bonds, admin | reveal window 1 h–30 d; `RETURN_ON_AWARD` or `HOLD_UNTIL_RELEASE`; one immutable contract per chain, no owner, pause or upgrade; `bidder ≠ buyer` (R187) |
| Families | EVM and Hedera first (same bytecode); others PLANNED (R188) |

Lifecycle: `createTender → OPEN → (REVEAL) → (AWARDABLE) → SETTLED | FAILED`, or `CANCELLED` before
`commitDeadline`; `REVEAL` and `AWARDABLE` are derived from time.

### 10.3 Invariants

I1 every cancelled-tender bidder, valid non-winning revealer and bidder disqualified without a declared class
receives exactly `minDeposit` through a permissionless call, without expiry; I2 conservation; I3 no price derivable
before its own reveal; I4 the winner is the best valid, non-disqualified bid by (rule, seq); I5 one settlement, one
payout per bid; I6 deposits enter only through `commitBid`; I7 no forfeiture for an undeclared reason (TSS §A.2.4).

### 10.4 Privacy and interface

Identity is disclosed at commit (the deposit's `from`) — SCaaS is not anonymous (§1.3); confidential bids are a
later extension. Interface and events (`TenderCreated`, `TenderCancelled`, `BidCommitted`, `BidRevealed`,
`BidDisqualified`, `TenderSettled`, `DepositRefunded`, `DepositSlashed`, `BondReleased`, `BondClaimed`): TSS §A.3.
ERP and bidder flows: TSS §A.5, `integration.md` §9.

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

All JSON, no cookies, no redirects. Errors are `{"error": "<CODE>", "detail": "<text ≤ 300 chars>"}` (gateway:
the stable contract `{error, code, detail, revert_data?}`, APP R178). NI rev 3.7 is the single normative place for
node routes, tables and config. Detail:
[NI §5–§7](superpowers/specs/2026-10-06-node-independence-design.md), [MESH §5](superpowers/specs/2026-10-05-relayer-mesh-design.md),
[A2 §5, §13](superpowers/specs/2026-10-06-mesh-gossip-amendment.md). Client usage: `integration.md`.

Error codes added by the 2026-10-07 folds (job API and gateway; per item in `POST /v1/jobs`):

| HTTP | Code | When | Source |
|---|---|---|---|
| 403 | `CALL_TARGET_REFUSED` | `call` selector/target not in the call table (§6.10); also re-checked at lease | PD CR-PD-1 (NI fold pending) |
| 422 | `BAD_PAYLOAD` (widened) | a job field differs from the signed payload | NI R344 |
| 422 | `VALUE_OUT_TOO_HIGH` | native value out above `chain.max_value_out` (intake and lease) | NI R345, net-ton R10-12 |
| 422 | `DEPOSIT_NOT_ALLOWED` | the job would make the lane fund a deposit a third party can reclaim (intake, re-checked before signing) | NI R346, RS12-20 |
| 422 | `ZERO_VALUE` | gateway Door A `transfer`/`pay` with `value == 0` | PD CR-PD-3 |
| 429 | `SUBJECT_THROTTLED` (+ `retry_after`) | the payload's `from` passed the grief threshold | NI R342 |
| — | job `dead`, `error = ATTEMPTS_EXHAUSTED` | `attempt_count > chain.max_attempts` | NI R341 |
| — | chain `halted`, reason `PROGRAM_UPGRADEABLE` | the chain's package/program is still upgradeable at activation or start | NI R348 |

### 12.1 Listeners and authentication

| Listener | Bind (config) | Credential | Never accepts |
|---|---|---|---|
| gateway | `[modules] gateway_bind` (`127.0.0.1:8547`) | `none` (loopback only) / `bearer` / `hmac` single shared secret ≥ 16 bytes (R54); CORS `gateway_cors_origins` | — |
| job API | `[api] bind` (`127.0.0.1:8548`) | HMAC per external-client API key: `X-Scaas-Key`, `X-Scaas-Timestamp` (±300 s), `X-Scaas-Nonce` (`[A-Za-z0-9_-]{1,64}`, single use until ts + 300 s), `X-Scaas-Signature = hex(HMAC-SHA256(secret, ts "." nonce "." METHOD " " path?query "\n" body))` (R92); no CORS | admin sessions, OIDC tokens (R109) |
| admin | `[modules] admin_bind` (`127.0.0.1:9108`) | open: `/healthz`, `/readyz`, `/metrics`, `/v1/admin/login`, `/v1/admin/auth-modes`, app files (`[app]`); otherwise `Authorization: Bearer` with prefix `scaas_s1.` (built-in session) or a JWT (OIDC) (R106) | API keys (R109) |
| metrics (optional) | `[modules] metrics_bind` (default: served on `admin_bind`) | none; only `/metrics`, `/readyz`, `/healthz` (OPS R230) | — |
| mesh bus | `[mesh] bind` (`0.0.0.0:8550`) and QUIC `/scaas/bus/1.2` | TLS 1.3 / QUIC client cert, SPKI pin of an active peer row; X25519MLKEM768 only | unpinned keys, TCP+Noise |
| gossip | `[gossip] listen` | libp2p Ed25519 identity, scoring | non-Ed25519 PeerIds |

API key secret = `HMAC-SHA256(master_key, "scaas-api-key/1" ‖ 0x00 ‖ key_id ‖ 0x00 ‖ u32be(generation))`;
the store keeps no secret (R92). **"API key" means only these R92 credentials of external server-side clients**
(Odoo and other ERPs/services): namespace-scoped, `submit`/`read` on the job and event API, never admin, never in a
browser, mobile or desktop app or extension (R106, R109). Two listeners on one port are refused at start.
Non-loopback job/admin binds need TLS in front. Body caps: gateway 64 KiB (1 MiB on the PQZ route only), job API
1 MiB.

### 12.2 Roles (R107)

`viewer ⊂ operator ⊂ admin`, plus `key_custodian` (not implied by `admin`). Every admin credential (built-in user
or OIDC token) carries roles; managing external-client API keys and built-in admin users needs `key_custodian`, and a
caller can grant only roles it holds. OIDC maps a per-issuer claim (`role` for ABP, `realm_access.roles` for
Keycloak; `scope` only for machine tokens).

| Capability | viewer | operator | admin | key_custodian |
|---|---|---|---|---|
| Read info, chains, lanes, tokens, namespaces, jobs (no payloads), audit, peers, policy, markets | ✓ | ✓ | ✓ | — |
| Pause/resume a chain, reset a breaker, cancel a job, suspend a peer, pause a market, ban a gossip peer | — | ✓ | ✓ | — |
| Change chain parameters, `fee_recipient`, tokens, lanes, namespaces, policy, peers, markets, gossip switches | — | — | ✓ | — |
| Create/rotate/revoke external-client API keys; manage built-in admin users | — | — | — | ✓ (roles ⊆ caller's) |

### 12.3 Route summary

| Route | Listener | Auth / role | Status |
|---|---|---|---|
| `POST /v1/metatx` `{chain, token, m, signature}` → `202 {"status":"queued"}` (target adds `intent_id`; Hedera 64-byte HIP-632 signatures, N2) | gateway | R54 | **BUILT** (EVM) |
| `GET /v1/gateway` (served chains incl. `chain_uid` for UA chains, tokens, fee recipient, DEX policy) | gateway | R54 | **SPECIFIED** (NI §5.5, N1) |
| `POST /v1/ops {chain, op}` (non-EVM `signed_op`) | gateway | R54 | **SPECIFIED** (N2) |
| `POST /v1/ua-metatx`, `POST /v1/ua/register` (the only gateway `call` job, to `chain.ua_registry`, R320) | gateway | R54 | **SPECIFIED** (N4) |
| `GET /v1/intents/{intent_id}` (gateway-origin rows only) | gateway | R54 | **SPECIFIED** |
| `POST /v1/dex/orders`, `GET /v1/dex/orders?maker=`, `POST /v1/dex/cancel`, `POST /v1/dex/cancel-all`, `GET /v1/dex/markets`, `GET /v1/dex/depth` (levels ≤ 200), `GET /v1/dex/trades`, `GET /v1/dex/ticker` | gateway | R54 | **BUILT** |
| `GET /v1/dex/depth?scope=network`, `GET /v1/dex/homes` | gateway | R54 | **SPECIFIED** (A2 §11.5) |
| `GET /v1/info` | job API | read | **SPECIFIED** |
| `POST /v1/jobs` (≤ 50 per batch; sponsorship `429 SPONSOR_BUDGET`/`SPONSOR_RATE`/`SPONSOR_TOO_SHORT`, `409 DUPLICATE_CALL {uid}`, `403 CALL_TARGET_REFUSED`, `422 VALUE_OUT_TOO_HIGH`/`DEPOSIT_NOT_ALLOWED`, `429 SUBJECT_THROTTLED`) | job API | submit | **SPECIFIED** |
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
| `GET/POST/PATCH/DELETE /v1/admin/users`, `/keys` (external-client API keys; `…/rotate`) | admin | viewer / key_custodian | **SPECIFIED** |
| `/v1/admin/deny`, `/v1/admin/sponsorship/*`, `/v1/admin/usage`, `…/chains/{key}/contracts`, `…/watch` | admin | viewer / operator / admin | **SPECIFIED** (NI §7.3; OPS, TSS) |
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
scaas-node key create --namespace odoo-prod --scopes "submit read"   # external-client API key, secret printed once
scaas-node key rotate|revoke KEY_ID
scaas-node store init                                           # once per new node: creates the store (0600)
scaas-node store restored                                       # mandatory after any restore: restore_epoch + 1
scaas-node lane accept-nonce | index reset                     # maintenance (OPS R241, R242)
scaas-node report usage --from DAY --to DAY                     # read-only (OPS §8.3)
```

Credential CLIs need no owner lock; maintenance CLIs run with the node stopped, take the owner lock and bump the
epoch; read-only CLIs take no lock (NI §7.2). Config automation without an IdP uses this CLI; with an IdP it uses OIDC client credentials (R109).
Status: `addresses`, `keystore new`, `store init`, `store restored` **BUILT**; the rest **SPECIFIED**. The node never
creates its store at start: a missing store file (unmounted volume, typo'd `[store] url`) refuses to start.

### 12.5 Admin authentication details (SPECIFIED, R106/R106a)

- Built-in users: Argon2id PHC (`m = 19 MiB, t = 2, p = 1`), passwords 12–256 bytes; login rate limit 5/min per
  name, 20/min per source; lockout after 10 failures for 900 s; uniform `401` with a dummy hash for unknown names.
  Session token `scaas_s1.<b64url(json{sub, ep, roles, iat, exp, auth_time})>.<b64url(HMAC)>`, key derived from
  `master_key` with label `scaas-admin-session/1`; TTL 900 s, refresh until `auth_time + 43 200 s`; `session_epoch`
  bump revokes all sessions of a user.
- Config automation (CI, Terraform, scripts): exactly two paths — an IdP service account using OIDC client
  credentials whose token carries `operator`/`admin`, or the host CLI; never a built-in user's password and never an
  API key (R109).
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
| W3B-01 | Meta-tx success rate | intents finalized (incl. `landed_elsewhere`) ÷ intents broadcast, 30 d | ≥ 99.5 % | fail over RPC, check lane balances, page operator | metric inputs **BUILT** (`scaas_relay_jobs{state}`); SLO **SPECIFIED** ([OPS](superpowers/specs/2026-10-06-operations-design.md) §3) |
| W3B-02 | Simulation zero-revert | broadcast transactions that reverted for a reason simulation would have caught ÷ broadcast; lost races (`consumed`) excluded | **0.00 %** (any occurrence is an incident); research guard: revert rate ≤ 0.5 % per 7 d including races | stop the chain's new work (breaker), investigate contract/simulation drift | gate **BUILT**; metric **SPECIFIED** ([OPS](superpowers/specs/2026-10-06-operations-design.md) R233) |
| W3B-03 | Gas budget adherence | gas spent ÷ approved budget per lane and window | ≤ 100 % (warn 90 %) | breaker `gas_budget` stops new work; notify finance owner | **BUILT** (R55) |
| W3B-04 | Finality latency | broadcast → final range delivered, p95 | ≤ chain hard finality + 60 s (Gnosis ≤ 240 s + 60 s; chain 7622 ≤ 15 s) | alert; check RPC quorum and indexer lag | lag gauge **BUILT** (`scaas_indexer_lag_blocks`); histogram **SPECIFIED** ([OPS](superpowers/specs/2026-10-06-operations-design.md) R234) |
| W3B-05 | Zether proof latency | client proof time + on-chain verification | to be set after measurement on target devices | optimize prover/verifier | **SPECIFIED** as a release benchmark ([OPS](superpowers/specs/2026-10-06-operations-design.md) R233) |
| W3B-06 | Relayer fee spread | fees earned − gas paid, per chain per month | may be negative (fee = 0 B2B) | monthly OPEX review | **SPECIFIED** ([OPS](superpowers/specs/2026-10-06-operations-design.md) §8.3) |

Additional operational SLOs (research §06.8): jobs final without manual intervention ≥ 99.5 %/month; outer-nonce gap
age = 0 for 99.9 % of the time; signed-but-orphaned transactions = 0.

**Metrics (BUILT, prefix `scaas_`):** `relay_jobs{chain,state}`, `payment_requests_attention{chain}`,
`indexer_lag_blocks{chain}`, `relayer_balance{chain,lane}`, `breaker_open{chain,lane,breaker}`,
`drift_alerts{chain}`, `submit_bump_skipped_consumed_total`. SPECIFIED additions: job API, feed, store owner,
admin, audit, OIDC, lane-foreign-nonce (NI §15), `finality_quorum{chain}` (single-provider trust visible, CR-PD-2),
`grief_*` (namespace aggregate, NI R342), mesh (MESH §12) and gossip/TLS (A2 §13.3) metrics.

**Trace contract (SPECIFIED, [OPS](superpowers/specs/2026-10-06-operations-design.md) §6; OTLP export PLANNED):** every submission span carries `chain_key`, `lane` (address),
`tx_hash`, `gas_used`, `effective_gas_price`, `entry_ref`, `mode`, `batch`/`nonce`, `finality_depth`, `job_uid`,
`namespace`. No payload data.

**Readiness** (`/readyz`, BUILT): per chain ≥ quorum RPCs answer within 3 s, indexer lag ≤ `max_index_lag`, upstream
reachable; snapshot refreshed every 10 s; 503 with reasons. SPECIFIED additions: store open and owned, lane used
outside this store, issuer failed closed, RPC endpoints disagree on a range's event set (CR-PD-2), chain held for an
upgradeable program (`PROGRAM_UPGRADEABLE`, R348), no gossip peer for 5 min (informational).

### 13.2 FinOps

- **Unit cost:** gas of every finalized job is converted to the deployment's reporting currency at the transaction
  time and allocated to the business document (`entryRef` → invoice/order). SPECIFIED ([OPS](superpowers/specs/2026-10-06-operations-design.md) §8).
- **Budgets:** per lane `gas_budget_per_hour`; per namespace `max_live_jobs`; sponsorship budgets per policy row
  (SPECIFIED, [TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) rev 1.3 §B1): day budget and hour /
  payer-hour counts taken at accept and released if the job ends before broadcast; `min_valid_secs` (default 120);
  a policy caps a tenant's spend only with `on_exhausted = reject` — `unsponsored` on a client namespace books to the
  namespace, is marked `sponsor_fallback` on the jobs feed and needs an audited `fallback_to_namespace` (R189).
- **Float:** each lane holds gas float for ~50 transactions; refill from treasury when below 30 % of target; the
  `balance_floor` breaker stops a lane at the floor. Auto-refill is PLANNED; today an operator refills (O8).
- **Indicative fixed costs** (research canon §C19, not re-estimated for all families): infrastructure ≈ $480–830 per
  month in year 1; minimum configuration ≈ $620 per month; third-party audit of all contract families is the largest
  one-off cost (O1).
- **Break-even** of independent relayers: §6.9.

### 13.3 RACI (SPECIFIED, [OPS](superpowers/specs/2026-10-06-operations-design.md) §9)

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
| Admin users and external-client API keys (key_custodian) | I | A | I | I | R |
| Controlled-token interventions (court orders) | I | C | A | C | R (submits the quorum transaction) |
| Curve / confidentiality horizon for a Zether token | C | A | C | C | I |
| Store restore and re-push acknowledgement | I | C | I | I | A/R |

Human approval is mandatory (never delegated to an agent) for: opening the land gate, the confidentiality horizon,
credit/gas budgets per agent, registering a new factory implementation, controlled-token interventions.

### 13.4 Incident response runbook (SPECIFIED, [OPS](superpowers/specs/2026-10-06-operations-design.md) §10)

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

Contract-level response is limited by design: permissionless tokens have **no pause**. Containment is off-chain
(stop relaying, pause markets) plus user communication; a controlled token may use its bounded pause (§4.5).

### 13.5 Disaster recovery (SPECIFIED, [OPS](superpowers/specs/2026-10-06-operations-design.md) §11)

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
                                      // META_SINGLE = 3, META_MULTI = 4; AS appends META_*_REG = 5..7
                                      // (SPECIFIED, R200); this file stays frozen with v1

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

`EVMLinkUpdated` from the SRS draft is not built (no relinking, RS2-9). The earlier `attributes(UA)` extension
proposal is withdrawn: compliance flags live in the separate `ComplianceRegistry` (AS R206). This interface is
deleted and replaced by `IUARegistry` at UA stream F1 (UA §6.1, §12; summary §9.8).

### 14.6 Regulated tokens — SPECIFIED ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §3.3)

The earlier `IRegulatedToken` proposal (court-ruling ids, `courtOrderBurn`, automatic reopening after a pause) is
withdrawn. The interface is AS §3.3: regulated children of the v2 tiers (kinds 5–7), `controls()` bits,
`issuer`/`compliance` roles, order records, freeze/forced transfer/pause with the bounds of §4.5, and a pinned
`ComplianceRegistry` with `requiredFlags`.

### 14.7 Sealed-bid tender — SPECIFIED ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §A.3)

The earlier `ISealedBidTender` sketch is withdrawn. The interface is TSS §A.3: `createTender`, `cancelTender(id,
reasonRef)`, `commitBid(id, commitment, eligibilityProof, m, sig)` (the deposit `pay` intent is the only
signature), permissionless `revealBid(id, bidder, price, salt)` and `withdrawDeposit(id, bidder)`,
`disqualifyWinner`, `settleTender`, `releaseBond`, `claimBond`, plus views `commitmentOf`, `depositRef`, `state`,
`bidOf`, `leaders`, `configOf` (§10).

### 14.8 Vesting — SPECIFIED ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §4.2)

The earlier `IVestingVault` proposal is withdrawn. The interface is AS §4.2: one `VestingGrant` clone per grant,
counterfactual funding through `predictGrant`, permissionless `release()` (§4.6).

### 14.9 Other built interfaces (reference)

| Contract | Key entry points |
|---|---|
| `MandateWallet` | `setMandate(token, delegate, maxPerPayment, maxPerPeriod, periodSeconds, expiry)`, `setPayee`, `revoke`, `payUnderMandate(token, payee, amount, entryRef, validUntil, sig)`, `revokeWithSig`, `executeAsOwner`, `isValidSignature`; typehashes `PayUnderMandate(address token,address payee,uint256 amount,bytes32 entryRef,uint256 validUntil)`, `RevokeMandate(address token,uint256 validUntil)` (SPECIFIED replacement `RevokeMandate(address token,uint64 epoch,uint256 validUntil)` + `epoch[token]`, CR-ADW-1) |
| `SubjectAccount` / `SubjectAccountFactory` | `initialize(firstKey, guardian)`, `isValidSignature`, `executeAsOwner(data, nonce, validUntil, signature)`, `addKey`/`removeKey`/`rotateKey`/`setGuardian`/`execute` (self), `initiateRecovery`/`completeRecovery`/`cancelRecovery`; factory `predict`, `deploy` (idempotent) |
| `OrderBookDex` | `settle(Match[]) returns (bool[])` (atomic per pair; none ⇒ `NothingSettled`), `cancel(CancelReq[])`, `invalidateNonces(maker, newMin, sig)`, `checkOrder`, `setMarket` (admin); `Order(address maker,address taker,address sellToken,address buyToken,uint256 sellAmount,uint256 buyAmount,uint256 nonce,uint256 expiry,uint32 maxFeePpm,uint8 flags,address relayer,uint8 feeMode,uint256 fee,address feeToken,address feeRecipient)`. SPECIFIED (DEX rev 1.1, new deployment, DX-FIX3): `_validSig` contract branch = assembly `staticcall` capped at 400 k for `SubjectAccount` clones by codehash, else 50 k, ≤ 32 B returndata, and `gasleft() ≥ cap·64/63 + margin` or the whole tx reverts (RS5-14) |
| `MetaTxDex` (legacy) | `settle(Leg a, Leg b)`: two `trade` meta-tx legs, fill-or-kill, no allowance, no route in the gateway |
| `IZetherVerifier` | `proofSystemId`, `curveName`, `isSupportedOnThisChain`, `verifyTransfer(statement, proof)`, `verifyBurn`, `generators`, point ops |

---

## 15. Roadmap, open questions, recorded contradictions

### 15.1 Roadmap

Order of streams per `TODO.md`, NI §17, A2 §17 and the component specs (owner rule: finish all specs before app
code; at most three agents, one heavy build at a time). Revisions and ruling ranges of every spec: §0.1.

| # | Stream | Content | Depends on | Status |
|---|---|---|---|---|
| 0 | Review | Every spec reviewed and folded 2026-10-07 (Codex on PQZ/UA/NI/TSS, Claude on the 16 older specs; dispositions inside each spec, review files in `docs/reviews/specs/`, git-ignored). Codex reviews still owed: AS, TW2, APP, OPS, S4F, MESH, A2, SCaaS.md, integration.md; owner review of NI §18.2; deferred full test runs after the repo split | — | in progress |
| 0′ | Fix first | The fix-first streams of the table below (bugs found in BUILT code by the 2026-10-07 reviews), before the first feature wave (NI P2 → P3, UA F0 → F1, app A1 + A0-evm) | §0 of `TODO.md` | **SPECIFIED** |
| 1 | S3 / S3′ | Envelope library, digests per family, `hub.sig`, conformance vectors; renames to `scaas-intent/1.2`; gossip message builders + `scaas-gossip-v1.json` | — | envelope **BUILT** (43 cases); gossip vectors open |
| 2 | P1 | Node store v2 on SQLite + config authority; `[identity]`, `[transport]`, `[gossip]` config parsing | S3 | **BUILT** |
| 3 | P2 | Job API, HMAC external-client API keys, built-in admin users, host CLI | P1 | **SPECIFIED** (NI rev 3.7) |
| 4 | P3 | Submit and lanes from the store (safety-critical); gateway journaled in `~gateway`; R321 batch journal | P2 | **SPECIFIED** |
| 5 | P4 | Indexer and `/v1/events`, watch lists, token subsets | P3 | **SPECIFIED** |
| 6 | P5 | Odoo push/sync client | P4 | **SPECIFIED** |
| 7 | P6 | Push e2e, cutover rehearsal and runbook; owner cutover per chain (testnet first) | P5 | **SPECIFIED** |
| 8 | P2b | OIDC mode (JWS verification over `ring`, R106a), full admin routes, audit export, CORS | P6 | **SPECIFIED** |
| 9 | P1b | PostgreSQL and MySQL backends | P2b | **SPECIFIED** |
| 10 | P7 | DEX book in the store | P1b | **SPECIFIED** |
| 11 | S1b′ | Company bus scope (`restricted`/`open`/`public`) delivered per job | P5 | **SPECIFIED** |
| 12 | S5′ | HTTPS mTLS bus, process-wide `aws-lc-rs` + X25519MLKEM768 | P1 | **SPECIFIED** |
| 13 | S6′ | Mesh pipeline over job rows; `may_gossip` hooks | S5′ | **SPECIFIED** |
| 14 | G1 | libp2p core: QUIC + TCP/Noise, Kademlia, gossipsub + scoring, sync, bus over QUIC | S6′ | **SPECIFIED** |
| 15 | G2 | Announces, exclusivity over gossip, landed hints | G1 | **SPECIFIED** |
| 16 | G3 | DEX book gossip (home-bound and relayer-unbound orders) | G2, P7 | **SPECIFIED** |
| 17 | S7″ | Multi-node e2e (MESH E1–E12 on both bus carriers + E-G1…E-G10) | G3 | **SPECIFIED** |
| 18 | P9 | Remove the pull path (`odoo.rs`, `[odoo]`, legacy Odoo service methods) after ≥ 14 days all-push | S7″ or calendar | **SPECIFIED** |
| 19 | S8″ | Spec corrections across older specs | P9 | **SPECIFIED** |
| 20 | Rename | `scaas` names in code, metrics, env, headers and on-chain tags | owner plan | **BUILT** (code); older component specs still cite old names |
| 21 | app A0–A18, N1–N4 | React + Vite console/dApp over **all seven families** (signers, UA accounts, gateway submission, DEX, Zether, PQZ tokens on the private chain, node admin by built-in login or OIDC); node additions `/v1/gateway`, `/v1/ops`, `/v1/ua-*`, N3 non-EVM DEX books ([APP](superpowers/specs/2026-10-06-scaas-app-design.md) §15) | node APIs, D, F | **SPECIFIED** (APP rev 1.2) |
| 22 | S4F D1–D7 | Backup switch, vault v2 (device key), scrypt `2^17`, Sui `fam_sui.verify`, Soroban/Aptos/Solana seed and passkey signers, `fam/*` and `wallets/*` connectors, role keys ([S4F](superpowers/specs/2026-10-06-signers-followups.md)) | F §8.1 | **SPECIFIED** (S4F rev 1.1) |
| 23 | UA F0–F10 | Kind libraries and vectors, EVM `UARegistry` + verifiers + Zether re-point, MetaToken v3, `UAKey` + MuSig2/FROST signers, VC layer, node `scaas-intent/1.3`, Odoo `blockchain.ua`, non-EVM registries, PQ kinds, DEX/mandate support ([UA](superpowers/specs/2026-10-06-universal-account-design.md) §16) | — | **SPECIFIED** (UA rev 1.4) |
| 24 | PQZ E-S0…E-S9, G-LIC | Parameter and `pqz-core` spikes, relations, Nethermind precompile, contracts, clients, retail WASM prover, node, review; licence gate ([PQZ](superpowers/specs/2026-10-06-pq-zether-design.md) §16) | F registry stream | **SPECIFIED** (PQZ rev 1.2) |
| 25 | TW2 T1–T8 | Token wrappers v2: `MetaTxCore` + named functions, three tiers, rates, multi-underlying (adjustable legs, admin-only execute, all-leg wrap pause), gasless unwrap op with `minOut`, factory v2, Hedera children, invariant suite, node/Odoo fields ([TW2](superpowers/specs/2026-10-06-token-wrappers-v2.md) §15) | — | contracts T1–T6, T8 **BUILT** (EVM + Hedera); T7 node/Odoo/SDK **SPECIFIED** |
| 26 | AS1–AS9 | Regulated module (kinds 5–7), `ComplianceRegistry`, `VestingGrant`, distributions, `ExchangeOffer`, templates, managed markets ([AS](superpowers/specs/2026-10-06-asset-suite-design.md) §13) | TW2 | **SPECIFIED** (AS rev 1.1) |
| 27 | TB1–TB3, SP1, RP1–RP2, CS1–CS2, PL1 | Tender, sponsorship policy, receiver-pays, crypto-shredding, `SponsorshipPool` (later) ([TSS](superpowers/specs/2026-10-06-tender-sponsorship-shredding.md) §8) | NI P3 | **SPECIFIED** (TSS rev 1.3); PL1 PLANNED-later |
| 28 | OP1–OP8 | W3B SLOs, telemetry, trace contract, FinOps usage, denylist, runbooks, DR ([OPS](superpowers/specs/2026-10-06-operations-design.md)) | NI P3 | **SPECIFIED** (OPS rev 1.2; some metrics BUILT); OTLP export PLANNED |
| 29 | CHAINID | Private chain id 9000 → 7622 (owner 2026-10-07): sweep the remaining specs (MESH, A2, TW2, APP, OPS, S4F, AS), `AuthScheme.sol:7` comment and the TRAPS.md heading; then genesis reset, rename `src/chains/private9000` and the foundry profile, node and Odoo chain records, `chain_uid` = genesis hash (UA R330, NI §9.1) | owner | specs partly swept (PD, ADW, R3D, ZD, UA, NI, PQZ done); code not yet landed |
| 30 | Other product features | KeyPool auto-refill, outbound treasury payouts, anchoring (Merkle/HCS), Celo `l1_batch`, Hedera HCS/scheduled tx, NFT kinds (TON payer tx hash on `mined` is done) | — | **PLANNED** |
| 31 | DX-FIX1…5 | DEX fixes (§3.4 F3): node DX-FIX1/2/5 fold into P7 if P7 starts first; contract DX-FIX3 (`OrderBookDex` 1271 cap, new deployment; PAY-FIX6 merges into it) and DX-FIX4 (non-EVM relayer binding, `min_nonce` caps) | — | **SPECIFIED** (DEX rev 1.1) |
| 32 | ZF-FIX1…3 | Zether fixes (§8): `ZetherMetaTx` 1271 cap + `FeeWouldStick` + disclosure NatSpec; invariant/subgroup/`D_out = O` tests; verifier/registry pin, chain-keyed cache, `schnorrSign` without `k` | — | **SPECIFIED** (ZD rev 1.1) |
| — | Owner/operator steps | O1 audit of every contract family; O2 registrar multisig; O3 real deployments; O4 7-day finality evidence + ≥ 2 RPCs; O5 reverse-proxy rate limits; O6/O7 KMS/HSM custody and lane signers; O8 lane funding; O9 land-gate decision; O10 subject-account onboarding; Z1–Z6 Zether gates; G-LIC (PQZ) | — | open |

**Fix-first streams** (order of `TODO.md` §1; bugs in BUILT code found by the 2026-10-07 reviews; code starts when the
spec phase ends):

| Order | Stream | Content | Ruling | Gate |
|---|---|---|---|---|
| 1 | **NET-TON-FIX1** | Node half: forward cap at intake and lease, `forward_nanoton` ≤ cap, `value_out` into `tx_cost`, TON Connect domain checked at every door | net-ton R10-12, R10-14; NI R340/R344/R345 | **BLOCKING**: no job API, mesh or gateway path may reach a TON lane before it lands |
| 1 | NET-TON-FIX2…4 | `tx_id` normalized hash + seqno lookup, balance/passkey simulation; contract `MAX_FORWARD_TON`, domain pin, revoke `nonce + 2`, DEX `excessTo`/bounces (new master); mesh `ton_op` signature | R10-13…17; NI R343 | — |
| 2 | **NR1** | Breaker meters `fee + value_out + deposits`; one billed retry; `max_attempts`; `subject_grief` + `429 SUBJECT_THROTTLED` | NI R340–R342 | after P3, **before P6** (first non-Odoo path) |
| 2 | **NR2** | Signed fields from the payload; `chain.max_value_out`; deposit rule (`DEPOSIT_NOT_ALLOWED`) | NI R344–R346 | with P3, **before P6**; TON part = NET-TON-FIX1 |
| 2 | **NR3** | Mesh/gateway signature checks per family (`hedera_ed25519`, cached key reads, `BAD_SIGNATURE`) | NI R343 | before S5 |
| 2 | **NR4** | Adapter journals (Sui coins, Solana durable nonce, TON seqno) in `outer_tx` | NI R347 | with P3 (needs R326) |
| 2 | **NR5** | Upgradeability read ⇒ `halted PROGRAM_UPGRADEABLE`; one public key per family | NI R348, R349 | after P1, with the family deploy gates |
| 3 | **PAY-FIX1** | Odoo: operator read-only on `blockchain.relay.job`, `action_requeue` group check, immutable job fields | PD CR-PD-1 (a)(b) | — |
| 3 | **PAY-FIX2** | Node `call` target/selector table (pull path and NI accept), `CALL_TARGET_REFUSED` | PD CR-PD-1 (c) | — |
| 3 | PAY-FIX3…5 | Event-set quorum (EVM/Hedera); Door A intake (`ZERO_VALUE`, floor, public fee-0 rule, per-`from` bucket); idempotent `signed` report | CR-PD-2, CR-PD-3, CR-PD-5 | — |
| 3 | PAY-FIX6, PAY-FIX7 | `OrderBookDex` 1271 cap (merged into DX-FIX3); DEX fee per fill rounded up + node matcher (needs a DEX ruling) | PD review L3, L4 | PAY-FIX7 waits for the DEX ruling |
| 3 | ADW-FIX1…4 | `MandateWallet` revoke epoch; Hedera ED25519 `executeAsOwnerRaw` test; role-path seed keys; `checkPayment(expectedToken)` | CR-ADW-1…4 | — |
| 4 | DX-FIX1…5 | DEX venue and contract fixes (row 31) | RS5-12…20 | — |
| 5 | R3-FIX1…14 | Cosmos passkey v2; shared WebAuthn vectors; event quorum (Sui/Solana/Soroban, Cosmos/TON); Soroban `pay_ref`; Solana build-time network; Sui `Keys`; guardians (Soroban, Cosmos, TON); TON domain set; lane-horizon constants; TON DEX bounces; Cosmos `Sweep` removed | CR-R3-1…10 | — |
| 5 | **R3-FIX15** | Immutable at deploy: Aptos `immutable`, Sui `make_immutable`, Solana `--final` after `initialize`, Cosmos `--no-admin`; deploy-script gate + negative test; redeploy dev deployments; update node/Odoo chain profiles | CR-R3-11 (owner) | — |
| 5 | WSF-FIX1…2 | Readable on-chain-rebuilt wallet text + `POLICY_PASSKEY_FOR_VALUE` (Solana, Sui after R3-FIX7) | CR-WSF-1 | — |
| 5 | NET-COSMOS-FIX1…3, NET-SUI-FIX1…4, NET-HEDERA-FIX1…3, NET-SOROBAN-FIX1…2, NET-APTOS-FIX1…3, NET-SOLANA-FIX1…3 | Per-family "fix" tables of the net-* specs (§7) | R9-3…8, RS7-9…14, R6-7…11, R8-9…15, RS11-20…26, RS12-19…25 | — |
| 5 | ZF-FIX1…3 | Zether fixes (row 32) | RS2-20…26 | — |

### 15.2 Open questions for the owner

Still open:

1. **Interpretations of NI §18.2** still to confirm: Odoo namespace `allow_call = true`; paused chain accepts and
   holds jobs; several companies may share a namespace (default one per database); status latency ≤ ~10 s live,
   ≤ 1 min idle; cancel of a published job reports "already sent"; repeated `entryRef` handling (TW2 T7).
2. **Private chain 7622 as a classical Zether dev chain** (Z3) and the **curve** policy for production Zether tokens
   (Z4).
3. **Soroban on the mesh**: accept the host auth nonce as the consumption signal (would qualify Soroban) or keep it
   job-API only.
4. **Second event source** to bound a compromised node's ability to fake `/v1/events` (NI §18.3).
5. Every OPS default number marked OA (OPS header: owner to approve).
6. **DEX venue fee per fill rounding** (PAY-FIX7): round up (`Math.Rounding.Ceil`) when the market fee is on, with the
   node matcher mirroring it — needs a DEX-spec ruling.

Answered since the previous revision: `bus_scope = public` is a separate opt-in; DEX books carry home-bound and
relayer-unbound orders per market; exclusive-assignment trust is automatic after 3 verified landings; QUIC offers
only the PQ group (A2 rev 2.1 §19). Receiver-pays is v2-only, no v1 router (TSS R193). Regulated tokens are factory
kinds 5–7 with issuer and compliance roles (AS R200, R202). Tender parameters: TSS R183–R187. UA purpose `7622'`,
MuSig2/FROST kinds kept, Soroban role `kindNo` 18 (UA rev 1.3). Private chain id 7622 (owner 2026-10-07; stream
CHAINID). Aptos/Sui/Solana programs immutable at deploy, Cosmos `--no-admin` (owner 2026-10-07, CR-R3-11; was R3D open
question Q1). `PqzToken` implements `IERC20MetaTx` (owner 2026-10-07, PQZ R284).

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
| Registry PoP challenge | `keccak256(registry ‖ encodedY ‖ msg.sender)` | Built: same, plus a second proof for the authorization key (`authPop`). UA (SPECIFIED): kind-tagged PoP over chain, registry, UA and `authRef`, never the caller, so registration is relayable; a non-zero `authRef` co-signs | Zether design §11.2; UA R295 |
| Account schemes | `AuthScheme` enum (8 values) incl. `PQ_COMMITMENT` (verify off chain) | UA kind table; PQ kinds verified on chain on every EVM chain; `PQ_COMMITMENT` retired | UA R293, R313 |
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

Contradictions inside this repository found while writing (fixed in their own files, not here):

| File | Says | Code / ruling | Status |
|---|---|---|---|
| `smartcontracts/evm/README.md` | "mode bitmask removed, wildcard `relayer == 0`" | `MetaTxLib` keeps the bitmask (`0xF3`) | fixed 2026-10-07 |
| `smartcontracts/evm/README.md` | "Zether is still interface only" | `ZetherToken`, verifiers, registry built (dev chains) | fixed 2026-10-07 |
| `smartcontracts/evm/README.md`, `src/chains/private9000/README.md` | chain 9000 profile `berlin`, pre-London, no BLS precompiles | `foundry.toml` `private9000 = prague`; the chain runs through Fusaka + BPO2 after the 2026-08-31 chainspec fix | fixed 2026-10-07 |
| round-3 design R32 | seed vault scrypt `N = 2^15` | `clientkeys` uses `N = 2^17` | resolved: S4F R259 (`N = 2^17`) |
| round-3 design §B.1 `Family` enum | six families | adapters for eight (`evm`, `hedera`, `cosmos`, `soroban`, `sui`, `ton`, `solana`, `aptos`) | resolved: R3D rev 1.1 §H.4 marks it superseded |
| MESH §3.4 | `ring` provider, no `aws-lc-rs` | reversed by R114 for rustls; NI R106a keeps `ring` for JWS verification | open (S8″) |
| NI §3 / §7.1 (rev ≤ 3.3) | job API `[api] bind` default `127.0.0.1:8547`, same as `gateway_bind` | NI rev 3.4: job API `127.0.0.1:8548`; two listeners on one port refused | resolved |
| node default `max_gas_per_tx` | 3,000,000 | a classical Zether transfer needs 3.36 M (Zether chains: set ≥ 4.2 M, ZD rev 1.1 §15); PQZ needs 16 M on the private chain | open (config) |
| component specs, `AuthScheme.sol:7`, TRAPS.md heading | private chain id 9000 | owner 2026-10-07: 7622; swept in UA rev 1.4, NI rev 3.6+, PQZ rev 1.3+, PD/ADW rev 1.1, R3D rev 1.1+, ZD rev 1.1 | open for MESH, A2, TW2, APP, OPS, S4F, AS, the code comment and TRAPS.md (stream CHAINID) |
| SCaaS.md (before this revision) §7.7, §7.6, §7.4, §7.2, §7.5 | Solana `MetaOp` 337 B; TON "TODO #8" open and a `BindKey` message; Soroban random nonce and one-shot `pay_ref`; Hedera `associateUnderlying()`; Aptos `upgrade_policy = compatible` | 336 B (`MetaOp::LEN`); TODO #8 done, key bound through `SignedOp.stateInit` (R10-5); deterministic nonce, `(from, pay_ref)` (R8-9); association in `initialize` (R6-8, TW2 R144); immutable at deploy (RS11-20) | fixed in this revision |
| R3D CR-R3-7 vs net-ton R10-14 | TON domain pinned as a per-wallet `domains` set changed by the owner's wallet | `domainHash` in the wallet init data issued by the master; node checks at every door | open: reconcile in NET-TON-FIX3 / R3-FIX11 (both rev 2026-10-07) |
| R3D CR-R3-9 vs net-ton R10-17 | TON DEX bounced payouts credited per owner (`unclaimed`) + permissionless `Claim` | bounce body is truncated to 256 bits (no destination): `bounced[master]` + evented admin `RefundBounced` | open: reconcile in NET-TON-FIX3 / R3-FIX13 |
| DEX RS5-15 vs net-soroban R8-10 | "relayer 0 = open" settlement form | Soroban has no open form (`Order.relayer` mandatory) | open: note in DEX spec (cross-spec nit, `TODO.md` §0) |
| PD PAY-FIX6 vs DEX DX-FIX3 | two streams for the `OrderBookDex` 1271 cap | same fix | open: merge PAY-FIX6 into DX-FIX3 |
| CR-PD-1 call table vs NI rev 3.7 §5.2 | NI lists no `CALL_TARGET_REFUSED`, no `chain_contract.kind = account_factory` | PD §15.4 amendment | open: NI fold pending; this document is normative meanwhile (§6.10) |
| TSS rev 1.3 NI-amends row | omits `job.sponsor_fallback` | NI rev 3.6 folded it | open (cross-spec nit) |
| CR-PD-1 call table vs TSS §A.5, AS §3, `integration.md` §9, §11 | tender calls (`createTender`, `commitBid`, keeper `revealBid`/`withdrawDeposit`/`settleTender`, bonds) and issuer/compliance interventions pushed as `call` jobs | not rows of the call table ⇒ `CALL_TARGET_REFUSED`; the factory is excluded outright | open: add rows (target `chain_contract.kind = tender`, the token's issuer/compliance contracts) in PD/NI, or keep these calls wallet-sent |
| `zether-prover/wasm-smoke.sh` | no `--target web` build | APP R164 runs the prover as a web worker | open (APP §17) |
