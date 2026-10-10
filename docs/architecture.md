# SCaaS architecture overview

> [!NOTE]
> **Not normative.** This page explains how the parts of SCaaS fit together and why. It defines no rules: every rule
> it mentions is defined once in a component doc (linked) and its rationale is in [decisions.md](decisions.md).
> Where this page and a component doc disagree, the component doc wins ([ARCH-POS-01](decisions.md#ARCH-POS-01)).
> For the product introduction, the doc map and reading order see [README.md](README.md).

**Contents**

| Section | Subsections |
|---|---|
| 1. [Positioning](#positioning) | [Authority model](#authority-model) · [What SCaaS is not](#what-scaas-is-not) · [Profiles](#profiles) |
| 2. [Service model](#service-model) | |
| 3. [Components](#components) | |
| 4. [Contract layer](#contract-layer) | [EVM token tree](#evm-token-tree) · [Meta-transactions](#meta-transactions) · [Accounts and keys](#accounts-and-keys) · [Confidential balances](#confidential-balances) · [Trading](#trading) · [Non-EVM families](#non-evm-families) |
| 5. [Node layer](#node-layer) | [Node roles](#node-roles) · [Topology](#topology) |
| 6. [Data flows](#data-flows) | [Client payment](#client-payment) · [Gasless transfer through door A](#gasless-transfer-through-door-a) · [DEX order to settlement](#dex-order-to-settlement-target-p2) · [UA registration by a relayer](#universal-account-registration-submitted-by-a-relayer-specified) · [Confidential wrap-shield, transfer, unshield-unwrap](#confidential-wrap-shield-multi-recipient-transfer-unshield-unwrap-target-p3) · [Disclosure by `SENDER_CP`](#disclosure-by-sender_cp) · [Mesh](#mesh-specified-transports) |
| 7. [Trust model](#trust-model) | [Authority after deployment](#authority-after-deployment) |
| 8. [Families](#families) | |
| 9. [Economics](#economics) | |
| 10. [Data protection](#data-protection) | |
| 11. [Glossary](#glossary) | |

<a id="positioning"></a>
## 1. Positioning

**SCaaS (SmartContract as a Service) means that the smart contracts themselves are the API services that run the
business services.** Payments, mandates, tokens and wrappers, the DEX, sealed-bid tenders, vesting, distributions and
confidential transfers are contract functions: code per network family that is immutable from the moment it is
deployed ([CTR-GEN-02](contracts/README.md#CTR-GEN-02)), deployed as EIP-1167 clones from an open factory on EVM and
as equivalent modules or programs elsewhere, and that checks the subject's signature, nonce, expiry and limits on
every call. ERPs, portals, mobile apps and AI agents call them the way they call any API. The contracts are the
product; everything else is a way to reach them:

- **Smart contracts** (`smartcontracts/`) — **the product.** One code base per network family: EVM (with Hedera as a
  per-chain variant), Cosmos, Soroban, Move (Aptos, Sui), TON and Solana ([networks/README.md](networks/README.md)).
  On EVM: the token tree — one meta-transaction base, kinds by code, features chosen at creation
  ([CTR-TOK-21](contracts/token-wrappers.md#CTR-TOK-21), [CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)) — the
  open factory, the DEX ([contracts/dex.md](contracts/dex.md)), accounts and mandates (Universal Account registry,
  `SmartKeyAccount`, `MandateWallet`; [contracts/accounts.md](contracts/accounts.md)), confidential balances
  ([contracts/zether.md](contracts/zether.md)), tender and the asset suite. Contract-level details:
  [§4 Contract layer](#contract-layer).
- **`scaas-node`** — infrastructure, not the product. **Anyone can run it**, and it doubles as a relayer: it submits
  subject-signed intents and pays their gas, journals every submission, indexes the chain, waits for finality and
  serves finalized facts back ([node/README.md](node/README.md)). How a node operates is up to whoever runs it: each
  operator sets its own acceptance, fee, sponsorship, denylist, gossip and peer policies and its own SLOs and
  monitoring. Operators are independent; the protocol guarantees (contract rules, signatures, nonces) do not depend on
  any of them, and the shipped defaults and the `scaas/ops` bundle are recommendations
  ([NODE-OPS-15](node/ops.md#NODE-OPS-15)).
- **Client-side signers** — `clientkeys` (passkey signer, 24-word seed vault, extension wallets) so that the subject
  signs on its own device ([clients/signers-clientkeys.md](clients/signers-clientkeys.md)).
- **`zether-prover`** — proofs for confidential amounts ([contracts/zether.md](contracts/zether.md),
  [contracts/pq-zether.md](contracts/pq-zether.md)).
- **The console and dApp** (`clients/app/`) — wallets, payments, DEX, Zether and node administration
  ([clients/app.md](clients/app.md)).

SCaaS depends on no ERP. Every ERP is one client of the node's job API, and every node is "standalone"
([ARCH-POS-05](decisions.md#ARCH-POS-05), [integration.md](integration.md)).

<a id="use-cases"></a>**Use cases.** Loyalty and rewards, B2B settlement between a brand and its distributors or
suppliers, and end-user payments — all three configurable from the first deployment; the technical focus is
meta-transactions, confidential amounts and stablecoins ([ARCH-POS-06](decisions.md#ARCH-POS-06)).

<a id="authority-model"></a>
### 1.1 Authority model

The difference between SCaaS and IaaS or BaaS is **who signs a valuable write**. In IaaS and BaaS the service is the
operator's server; in SCaaS the service is the contract, and a node only carries signed writes to it and reads facts
back. The three columns below:

- **IaaS**: cloud VM (e.g. EC2, Compute Engine) — the app issues JWTs, the server signs.
- **BaaS**: hosted backend (e.g. Supabase, Firebase) — the backend's auth issues JWTs, the server writes; row-level
  security reads `auth.uid()`.
- **SCaaS** — the client signs every valuable create/update.

| Criterion | IaaS | BaaS | SCaaS |
|---|---|---|---|
| Who signs a write | The application server; the client holds a server-signed JWT and the server writes on its behalf | The backend's auth service signs the JWT; the database executes; row-level security checks the `uid` | **The subject**: its device signs each operation with a passkey (WebAuthn P-256) or a wallet key. The relayer pays gas and holds no subject key |
| Trust root | The operator, the cloud provider (IAM, hypervisor), anyone holding the JWT signing key | The operator plus the project owner holding the JWT secret or the `service_role` key | The subject's authenticator or secure element, chain consensus, and contract code that is immutable at deploy on every family (no upgrade key in the trust root) |
| Who can forge a subject's write | Anyone with the JWT signing key, direct database write access or a compromised server/IAM — indistinguishable from the subject | Anyone with the JWT secret (mints any `uid`) or the `service_role` key (bypasses row-level security) | **Nobody without the subject's private key.** An operator or relayer can only refuse or delay (censorship, liveness); other relayers, or the subject or payee submitting itself, counter that |
| Non-repudiation | None: the server writes the log and can write any line | None, for the same reason | Per operation: a domain-separated signature with nonce and expiry, publicly verifiable forever |
| Audit trail | Application logs and cloud audit logs held by the operator | Database and platform logs held by the operator | An append-only distributed ledger; the ERP is a read-in replica ("Land") **through its node** |
| Authorization enforcement | Application code (an endpoint is easy to miss) | Row-level security (central, but the `service_role` key and policy bugs bypass it) | Immutable contract code checks signature, nonce, expiry and limits on **every** call; **no admin can move a subject's funds**, except the bounded, creation-time powers listed below |
| Revocation and rotation | Easy: short TTL, deny lists, rotate server keys | Easy: rotate the JWT secret, revoke refresh tokens | Harder: on-chain key rotation in a smart account; several passkeys or guardians for device loss ([contracts/accounts.md](contracts/accounts.md)) |
| Write latency and cost | Milliseconds; compute and database cost | Milliseconds; plan-based | Chain finality (seconds to minutes); gas per write, sponsored by a relayer ([Economics](#economics)) |
| Reads | Served by the server | Served by the backend with row-level security | **Unsigned**: through the node feeds, an indexer or the ERP, with ordinary JWT or session auth. Only valuable writes need client signatures |
| Land (booking into the ERP) | — | — | The ERP trusts **its own node** and, through it, the **RPC quorum**: an event is booked only when at least `quorum` independent providers return the same event set for a final range ([NODE-IDX-01](node/indexer-feeds.md#NODE-IDX-01)); `quorum = 1` is single-provider trust, and a compromised node can lie on `/v1/events`. "Verifiable without trusting a server" holds for **signatures**, not automatically for ERP bookings |
| Privacy | Data inside the operator's infrastructure | Same | Public ledger: both parties' identities are visible by design; amounts and balances can be hidden with Zether |
| Typical failure | A leaked JWT signing key or IAM credential = every user impersonated | A leaked JWT secret or `service_role` key = every user impersonated | A leaked key of **one** subject = only that subject, bounded by its mandate limits; a lost relayer = delay, never loss; no upgrade key exists to leak; a leaked admin key reaches only the bounded powers below, never subject balances outside the regulated class |

**Admin-power exceptions.** The complete list is in [contracts/README.md](contracts/README.md#admin-powers-complete-list);
each power is public, set at creation or bounded, and none moves a subject's balance except the regulated class's
forced transfer against a recorded order. Among them:

- a token's optional `owner`, who only administers (grants and revokes the roles of the flags chosen at creation,
  disables a flag that was not locked, renounces; [CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)), and the role
  holders of those flags, such as the `rateAdmin` (step-capped, timelocked rate changes) and the `guardian` (only
  `disableWrap`) ([CTR-TOK-10](contracts/token-wrappers.md#CTR-TOK-10));
- the `SCaaSDex` `admin` (as built `setMarket` with a market fee of at most 1 %, bounded by each order's signed
  `maxFeePpm`; specified: four powers — listing, the split of each order's signed fee between relayer and treasury,
  exchange targets, listed-only mode — never the amount, [CTR-DEX-03](contracts/dex.md#CTR-DEX-03));
- the admin `mint` of the standalone non-EVM tokens on Soroban, TON and CosmWasm (a supply power, not a balance power);
- the TON DEX admin `WithdrawFees` (fees only; bounced payouts are claimed by their owners, [NET-TON-03](networks/ton.md#NET-TON-03));
- the market admins of the other DEX programs (Soroban, Sui `AdminCap`, which also sets the network once, Aptos,
  which may also sweep assets sent by mistake to its own objects, and Solana `Config.admin`: market listing and fees);
- the `issuer`/`compliance` roles of regulated tokens (only that class, against a recorded order, [CTR-AS-17](contracts/asset-suite.md#CTR-AS-17)).

The Cosmos DEX holds no balances between transactions, so it has no `Sweep` ([NET-COS-04](networks/cosmos.md#NET-COS-04)).
There is **no upgrade key** on any family.

Design consequences:

1. **Scope of client signatures.** Every valuable create or update — transfer, payment, DEX order, tender bid,
   granting or changing authority, registering a key — carries the subject's signature. The server never holds a key
   to sign for a subject. The one exception is a custodial or delegated wallet that the subject or its organization
   **explicitly** entrusted, with limits and an approval log ([INT-ERP-02](integration.md#INT-ERP-02),
   [CTR-ACC-06](contracts/mandates.md#CTR-ACC-06), [INT-ERP-08](integration.md#INT-ERP-08)). The node signs
   client-built `call` jobs (whose own authorization lives in the calldata) only when target and selector are in its
   call table ([NODE-JOB-01](node/job-api.md#NODE-JOB-01)).
2. **Passkeys** (WebAuthn, P-256) sign `authenticatorData ‖ SHA-256(clientDataJSON)` whose `challenge` is the typed
   digest of the operation (EIP-712 on EVM, the family digest elsewhere). Verifiers check `type`, `challenge`,
   `rpIdHash`, `origin` (exact), the UP and UV flags and low-`s`, with **one `clientDataJSON` grammar and one shared
   vector file for every family** ([NET-ALL-04](networks/README.md#NET-ALL-04)).
3. **UX.** One biometric or PIN per signature; related operations are batched under one signature over a Merkle root
   of their digests ([CTR-ACC-08](contracts/accounts.md#CTR-ACC-08)).
4. **Anti-lock.** Subject signatures use **contract-level lanes and nonces**, never the subject's account sequence,
   so a stuck operation on one contract never blocks the subject elsewhere ([NET-ALL-02](networks/README.md#NET-ALL-02)).
5. **Reads, reports and workflow** keep using JWT or session auth as in IaaS/BaaS. SCaaS is the layer for write
   authority and value; it does not replace the application database.

<a id="what-scaas-is-not"></a>
### 1.2 What SCaaS is not

| Not | Why |
|---|---|
| A custodian | Relayer lanes hold gas only; the DEX holds no balances between transactions; subject funds stay in subject-controlled accounts or wallet contracts |
| A mixer | The identities of both parties are always visible; only amounts and balances can be hidden ([contracts/zether.md](contracts/zether.md)) |
| A database replacement | Business data stays in the client's system of record; only commitments, settlements and the minimum identity linkage go on chain ([Service model](#service-model)) |
| An upgradeable platform | No proxy upgrade on any contract that holds value; **immutable at deploy on every family** (EVM clones; Aptos `upgrade_policy = "immutable"`; Sui `make_immutable` on the `UpgradeCap` in the deploy run; Solana upgrade authority `None` after `initialize`; Cosmos instantiated `--no-admin`; TON and Soroban as built). Each family's deploy script fails if the result is still upgradeable, and the node holds such a chain `halted` with `PROGRAM_UPGRADEABLE` ([CTR-GEN-02](contracts/README.md#CTR-GEN-02), [NODE-STO-07](node/store.md#NODE-STO-07)). New behaviour = a new version plus voluntary migration |
| A token gatekeeper | The factory is open; provenance replaces allowlists. Controlled (regulated) tokens are an explicit creation-time choice, flags 5–8 ([CTR-AS-17](contracts/asset-suite.md#CTR-AS-17); [contracts/token-wrappers.md](contracts/token-wrappers.md), [contracts/asset-suite.md](contracts/asset-suite.md)) |
| A hosted node service | The node is infrastructure anyone can run; operators are independent, set their own policies and can only refuse or delay, never forge |
| A single-ERP product | Any ERP integrates through the same job API ([integration.md](integration.md)) |
| A market maker or profit-seeking relayer market | Relayer economics are cost recovery between parties with aligned interests; fee = 0 is the B2B default ([Economics](#economics)) |

<a id="profiles"></a>
### 1.3 Profiles

| Profile | Chains | Mesh | Typical relayers | Data exposure |
|---|---|---|---|---|
| **Public** (`profile = public`) | Public networks (Gnosis, Celo, Hedera, Cosmos chains, Sui, Aptos, TON, Solana, Stellar, Pi Network) | Open mesh (gossip, opt-in per chain, policy and job) plus the pull bus for partners | Issuer, distributors, partners, third-party open relayers | The ledger is public; private windows and the per-job bus scope control what is offered to peers ([INT-ERP-15](integration.md#INT-ERP-15)) |
| **Private / PoA** (`profile = private`, the default) | A permissioned chain (reference: chain 7622, Nethermind, Clique, one signer, forks through Fusaka, base fee 0; [networks/evm.md](networks/evm.md)) | No gossip, ever; pull bus only to admitted private peers, served by the origin only, over PQ-protected carriers | The operator's own nodes and admitted private peers | Chain-local; intents never leave the admitted set ([NODE-MESH-06](node/mesh.md#NODE-MESH-06), [NODE-MESH-12](node/mesh.md#NODE-MESH-12)) |
| **Consortium** | A permissioned or public chain shared by members | Pull bus between admitted members (SPKI-pinned mTLS or QUIC), optionally gossip for public chains | Each member runs a node | Per-job `bus_scope`: `restricted` (default), `open` (admitted peers) or `public` (also the open mesh) |

The single-node relayer that serves all three profiles without a mesh is BUILT; the mesh transports are SPECIFIED
([node/mesh.md](node/mesh.md), [node/gossip.md](node/gossip.md)).

<a id="service-model"></a>
## 2. Service model

**Dual loop: write out (anchor or settle), read in (land).**

```mermaid
flowchart TB
    subgraph OUT["1 · Write out (anchor / settle)"]
        direction LR
        S["Subject<br/>signs"] --> OB["Client<br/>outbox"] --> JA["Node<br/>job API"] --> SIM["Simulate"] --> JR["Journal"] --> BC["Broadcast"]
    end
    CH[("Chain")]
    subgraph IN["2 · Read in (land)"]
        direction LR
        RPC["Chain<br/>RPC"] --> FG["Finality gate<br/>+ RPC quorum"] --> NE["Normalized<br/>events"] --> FD["Feed<br/>/v1/events"] --> CA["Client<br/>applies"] --> BK["ERP<br/>book"]
    end
    OUT --> CH --> IN
```

The finality gate is `depth`, `tag` or `instant` per family, plus agreement across a quorum of RPC endpoints.

| | Write out | Read in |
|---|---|---|
| Initiator | User, agent, workflow, ERP action | Node indexer |
| Pipeline | Client outbox → push (`POST /v1/jobs`) → accept checks → lease → simulate → journal (`signed`) → broadcast → follow | `final_head` → quorum hash → `getLogs` or family scan → normalized events → `feed_item(range)` → client sync |
| Controls | Idempotency key, namespace grants, registered tokens, signed fields read from the payload ([NODE-LANE-16](node/submit-lanes.md#NODE-LANE-16)), normalization of unbound fields ([NODE-LANE-10](node/submit-lanes.md#NODE-LANE-10)), the `call` target table, value-out and deposit caps ([NODE-LANE-17](node/submit-lanes.md#NODE-LANE-17), [NODE-LANE-18](node/submit-lanes.md#NODE-LANE-18)), simulation gate, gas breakers and the per-subject grief score ([NODE-LANE-13](node/submit-lanes.md#NODE-LANE-13)–[NODE-LANE-15](node/submit-lanes.md#NODE-LANE-15)) | Finality mode plus an RPC quorum over the event set ([NODE-IDX-01](node/indexer-feeds.md#NODE-IDX-01)), contiguous ranges, dedup by `(chain, tx_hash, log_index)` |
| Hard rule | No broadcast without a committed journal entry ([NODE-GEN-02](node/README.md#NODE-GEN-02)) | **No business booking before the finality gate** ([NODE-GEN-08](node/README.md#NODE-GEN-08)) |

Three properties distinguish a contract call from an ordinary API call:

1. **Two-phase result.** An HTTP 200, a `tx_hash` or a mined receipt is not the result. The result is the finalized
   event (`PaymentSettled`, `MetaTransactionExecuted`, …) delivered on `/v1/events`.
2. **Permanent publication.** Calldata is public forever; only data that passes the four-condition test below may be
   put in a payload.
3. **No in-place rollback.** Reversal is a new compensating transaction (refund, burn, counter-transfer).

**The four-condition test for anchoring a commitment.** Data may be anchored on chain only if all four hold
([integration.md](integration.md#data-protection)):

1. **Commitment only.** No plaintext amounts outside value transfers, no account numbers, tax ids or party names.
   Business documents are referenced by an unlinkable value: a payment `entryRef` is 32 random bytes
   ([CTR-MTX-03](contracts/metatx.md#CTR-MTX-03)); other anchored records use a salted commitment such as
   `keccak256(salt ‖ payload)` with a per-record salt (current formats: [INT-ERP-23](integration.md#INT-ERP-23)).
2. **Separable, destroyable salt.** Each salt is 256-bit CSPRNG output, stored off chain in the client's secret store,
   keyed by the record. Deleting the salt makes the on-chain value permanently unlinkable (crypto-shredding).
3. **Corporate anchor address.** Commitments are published from one address per legal entity, never from
   per-counterparty addresses that would reveal a relationship graph.
4. **Batching for high-frequency streams.** Delivery proofs, decision logs and similar records are committed as a
   periodic Merkle root (hourly or daily), hiding business cadence.

Value transfers necessarily show sender, receiver and amount on public chains (the transparent mode); hiding amounts
uses Zether; hiding the relationship itself is out of scope by design ("not a mixer").

**Two-phase saga vs one-transaction atomic settlement.**

| | Two-phase saga (client-led) | One-transaction atomic settlement (SCaaS-led) |
|---|---|---|
| Use | Bridging to off-chain systems: bank rails, payment gateways, physical delivery, approvals | Token payments, DEX trades, mandates, tender deposits and refunds, loyalty |
| Mechanism | Client state machine with compensation steps; the on-chain step is one leg | Contract atomicity: all legs in one transaction or none |
| Failure | Can stall between phases; needs timeouts and compensation jobs | **Fee collected ⇔ operation completed**; any failure reverts everything and the nonce is not consumed |
| Latency | Bound by the slowest party (seconds to days) | One inclusion plus finality |
| Risk control | Maker-checker, compensations | `validUntil`, lane nonces, mandate caps, price limits signed by the subject |

When every leg is on chain, use one-transaction settlement. When a leg is off chain, anchor the on-chain leg **after**
the off-chain leg is irrevocable, or give the saga a funded on-chain compensation path. Atomic settlement is BUILT for
payments (the `pay` op), the DEX (`SCaaSDex.settle`, legacy `MetaTxDex`; specified: `SCaaSDex.mtxSettle`, one
taker against several makers, each leg verified by its sell token) and mandates (`MandateWallet.payUnderMandate`,
specified name `mtxPayUnderMandate`); generic saga orchestration is a client concern.

**Anchoring as proof of action.** For automated agents and workflows the anchor gives a tamper-evident proof that a
decision or commitment existed at a time, without publishing it; the relayers make agent payments frictionless (the
agent signs, a relayer pays gas); Zether keeps commercial amounts confidential while disclosure keeps them auditable.

<a id="components"></a>
## 3. Components

<details>
<summary><b>Every component</b> — path, role and status (EVM, Hedera and non-EVM contracts, scripts, node, store, prover, clients, CI)</summary>

| Component | Path | Role | Status |
|---|---|---|---|
| EVM contracts | `smartcontracts/evm/` (Foundry; `src/{common,metatx,factory,dex,wallet,account,registry,zether,hedera,chains}`) | Target: the token tree `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → kinds `NONE`, `UNDERLYING`, `NONE_ZETHER`, `UNDERLYING_ZETHER` ([CTR-TOK-21](contracts/token-wrappers.md#CTR-TOK-21)); the libraries `TradeLib`, `AdminLib`, `UnderlyingLib`, `ZetherLib`, `HederaLib`, with pay inline behind the `PAYABLE` flag in `MetaTokenBase` (no `PayLib`; [CTR-TOK-24](contracts/token-wrappers.md#CTR-TOK-24)); `OpenFactory` for tokens and DEX clones ([CTR-TOK-25](contracts/token-wrappers.md#CTR-TOK-25)); `SCaaSDex`; `MandateWallet`; `SmartKeyAccount`; `UniversalAccountRegistry`; the Zether verifiers (bn254, BLS12-381), `ZetherDisclosure`, `ZetherStatements`. Build profiles `private7622` (the private chain 7622), `zether`, `gnosis`, `celo` | BUILT (P1a–P1d): `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase`, kind `NONE` = `NoUnderlyingToken`, kind `UNDERLYING` = `UnderlyingToken` (1–8 legs, native-coin leg) + `UnderlyingLib`, `AdminLib`, `HederaLib`; still built: the older v1 line and `ZetherToken`. SPECIFIED: `createToken` (P1e), `TradeLib` (P2), the `*_ZETHER` kinds and `ZetherLib` (P3), P4–P5; `PqzToken` |
| Hedera contracts | the EVM implementations | No separate contracts: the EVM implementations deployed with `IS_HEDERA` (HIP-632 signatures, fail-closed HTS checks; [CTR-TOK-23](contracts/token-wrappers.md#CTR-TOK-23)) | BUILT (P1c–P1d): `IS_HEDERA` is an immutable of every implementation; `HederaLib` (`smartcontracts/evm/src/hedera/`) holds the HIP-632 path, and the HTS association is called from `UnderlyingLib` init; the Hedera wrapper children are deleted (the v1 `HederaMetaToken` goes with the v1 line) |
| Cosmos contracts | `smartcontracts/cosmos/` (CosmWasm workspace) | `scaas-token` (CW20 + meta-op), `scaas-mandate`, `scaas-dex`, shared `scaas-metaop` | BUILT |
| Soroban contracts | `smartcontracts/soroban/` | SEP-41 token + `pay`, mandate, DEX; native auth as the meta-tx (Stellar and Pi Network) | BUILT |
| Move contracts | `smartcontracts/move/{aptos,sui}/` | Package `scaas`: `meta` (per-subject account + lanes), mandate, DEX | BUILT |
| TON contracts | `smartcontracts/ton/` (Tact) | Jetton master/wallet with public key + lanes (`SignedTransfer`), mandate, escrow DEX | BUILT |
| Solana program | `smartcontracts/solana/` (Anchor) | Program `scaas`: subject account PDA, `LanePda`, mandate, DEX | BUILT |
| Build and test scripts | `smartcontracts/scripts/{build,test,deploy,devnet}.sh <family>`; `scripts/capped` | One entry point per family; heavy runs capped at 4 GB, one at a time | BUILT |
| `scaas-node` | `scaas-node/` | Rust relayer: gateway, submit lanes, indexer, drift, DEX venue, admin; mesh envelope library | BUILT with the legacy pull job source; store, job API, admin auth and gateway additions SPECIFIED; mesh transports SPECIFIED ([node/README.md](node/README.md)) |
| Node store | (in `scaas-node`) | Jobs, feeds, configuration authority, credentials, audit, DEX book, mesh tables; SQLite, PostgreSQL or MySQL | SQLite store BUILT; the rest SPECIFIED ([node/store.md](node/store.md)) |
| `zether-prover` | `clients/zether-prover/` (Rust, `cdylib` + `rlib`, WASM) | Key generation (EIP-2333 paths), ElGamal, Σ-protocol + Bulletproofs (n = 64), disclosure openings, BSGS, `zether-cli`, `zether-read-balance` | BUILT (unaudited); feature `pq` and `pqz-cli` SPECIFIED ([contracts/pq-zether.md](contracts/pq-zether.md)) |
| `clientkeys` | `clients/clientkeys/` (ESM, `@noble` / `@scure`) | Passkey signer, 24-word seed vault, Zether keys and balance cache | BUILT (EVM-centric); vault v2, non-EVM signers, `fam/*`, `wallets/*` and `UAKey` SPECIFIED ([clients/signers-clientkeys.md](clients/signers-clientkeys.md)) |
| `clients/app/` | `scaas/clients/app/` (React + Vite) | Console and dApp over every family: contracts, wallets, DEX book, Zether, node administration (built-in login or OIDC) | SPECIFIED ([clients/app.md](clients/app.md)) |
| ERP connectors | in the client's codebase | Outbox, push and sync jobs, payment provider, portal, DEX accounting | one worked example: [integration-odoo-example.md](integration-odoo-example.md) |
| CI | `.github/workflows/ci.yml` (`scaas-ci`) | forge tests (pinned OpenZeppelin v5.2.0, forge-std v1.16.2), `private7622` build, cargo clippy `-D warnings`, cargo test, EVM end-to-end on anvil | BUILT; CI for the prover, clientkeys and non-EVM end-to-end PLANNED |

</details>

**Target and built.** The contract sections below describe the target that the component docs specify. The built EVM
code already has the P1 base and the two public kinds (P1a–P1d) and still carries the older lines (the v1 tokens,
`ZetherToken`, `SubjectAccount`); every component doc says what is built in a *Transitional (BUILT)* note naming the
phase that replaces it: P1 the base, the two public kinds and `createToken` (P1e); P2 `TradeLib` and the DEX clone; P3 the Zether kinds; P4 `MandateWallet` and `SmartKeyAccount` on the
base; P5 node and client support for the new ABI ([contracts/token-wrappers.md](contracts/token-wrappers.md#transitional-built-tokens),
[contracts/metatx.md](contracts/metatx.md#transitional-built)). Nothing is deployed, so the target replaces the built
lines in place; there is no migration between them.

<a id="contract-layer"></a>
## 4. Contract layer

The contracts are the product ([Positioning](#positioning)), so most of the design work sits here. Four pressures
shape every EVM contract: code is **immutable** once deployed, so every power must be visible at creation and can
only shrink afterwards; a contract is limited to **24,576 bytes** (EIP-170), so features cannot all live in one
bytecode; subjects hold **no gas**, so every write must be relayable without giving the relayer any authority; and
amounts may need to be **private yet auditable**. The subsections show how each part answers them. Rules live in the
linked docs; this page only explains the fit.

<a id="evm-token-tree"></a>
### 4.1 EVM token tree

```mermaid
classDiagram
    MetaTxBase <|-- ERC20MetaTx
    ERC20MetaTx <|-- MetaTokenBase
    MetaTokenBase <|-- NoUnderlyingToken : NONE
    MetaTokenBase <|-- UnderlyingToken : UNDERLYING, 1-8 legs
    MetaTokenBase <|-- NoUnderlyingZetherToken : NONE_ZETHER
    MetaTokenBase <|-- UnderlyingZetherToken : UNDERLYING_ZETHER
    ZetherLayer <|-- NoUnderlyingZetherToken
    ZetherLayer <|-- UnderlyingZetherToken
    MetaTokenBase ..> TradeLib : trade
    MetaTokenBase ..> AdminLib : flags and roles
    MetaTokenBase ..> HederaLib : if IS_HEDERA
    UnderlyingToken ..> UnderlyingLib : legs
    UnderlyingZetherToken ..> UnderlyingLib : legs
    ZetherLayer ..> ZetherLib : proofs
    class MetaTxBase {
        <<abstract>>
        MetaTransaction, lanes, SigCheck
        mtxExecute, mtxBatch, cancelNonce
    }
    class ERC20MetaTx {
        <<abstract>>
        ERC-20, MetaTransfer, fee, UA ledger
    }
    class MetaTokenBase {
        <<abstract>>
        features, owner, roles, provenance
        pay inline if PAYABLE
    }
    class ZetherLayer {
        <<abstract>>
        acc and pending per UA, totalShielded
    }
    class TradeLib { <<library>> }
    class AdminLib { <<library>> }
    class UnderlyingLib { <<library>> }
    class ZetherLib { <<library>> }
    class HederaLib { <<library>> }
```

*The target tree ([CTR-TOK-21](contracts/token-wrappers.md#CTR-TOK-21), [CTR-MTX-07](contracts/metatx.md#CTR-MTX-07)),
the libraries ([CTR-TOK-24](contracts/token-wrappers.md#CTR-TOK-24)); the four post-quantum kinds are reserved, not built.*

One base serves every SCaaS contract: `MetaTxBase` carries the signed call, the nonce lanes and the one signature
check (`SigCheck`, [CTR-MTX-25](contracts/metatx.md#CTR-MTX-25)), so `MandateWallet`, `SmartKeyAccount` and
third-party contracts are gasless in the same way as tokens ([CTR-MTX-22](contracts/metatx.md#CTR-MTX-22)).
`ERC20MetaTx` adds what only a balance holder can do (the typed transfer, a fee in the token, the UA ledger), and
`MetaTokenBase` adds trade, pay and administration. Every token is made by `OpenFactory` as an EIP-1167 clone of a
registered implementation, initialized in the same call, and answers its own provenance
([CTR-TOK-25](contracts/token-wrappers.md#CTR-TOK-25), [CTR-TOK-17](contracts/token-wrappers.md#CTR-TOK-17)).

| Kind | `PAYABLE` | `MINTABLE` | `BURNABLE` | `RATE_ADJUSTABLE` | `WRAP_DISABLEABLE` | `FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST` |
|---|---|---|---|---|---|---|
| `NONE` | yes | yes | yes | — | — | yes |
| `UNDERLYING` | yes | — | — | yes | yes | yes |
| `NONE_ZETHER` | yes | yes | yes | — | — | refused |
| `UNDERLYING_ZETHER` | yes | — | — | yes | yes | refused |

*Valid features per kind: the "Valid kinds" column of [CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22); the
regulated flags 5–8 are [CTR-AS-17](contracts/asset-suite.md#CTR-AS-17).*

**Why kinds are code and features are flags.** EIP-170 caps every implementation at 24,576 bytes, and the built
`ZetherToken` is already over it ([CTR-ZTH-46](contracts/zether.md#CTR-ZTH-46)): one contract per combination of
features would not fit, and one contract with everything would not either. So the large, structural differences
(underlying legs or not, a confidential layer or not) are separate implementations, each audited for only what it
holds, while the small switches are bits chosen at creation; the code behind each switch exists once, in an external
library shared by every implementation, inside a per-implementation size budget
([CTR-TOK-24](contracts/token-wrappers.md#CTR-TOK-24)). A creator therefore gets "one leg, pay off, rate fixed" without
anyone writing a class for it.

**Why the owner can only give things up.** There is no upgrade key, so the flags a token is born with are the most it
can ever do: an optional `owner` grants and revokes the roles of those flags, may clear a flag that was not locked,
and may renounce, after which nobody administers the token (the existing role holders keep their roles; to freeze the
power set the owner revokes every role first); a role holder exercises only its flag
([CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22), [CTR-TOK-10](contracts/token-wrappers.md#CTR-TOK-10)).
Wallets read `features()`, `lockedFeatures()` and the role holders, so a holder can see the whole power set before
accepting a token. Hedera is not a creator's choice but a per-chain parameter of each implementation (`IS_HEDERA`,
[CTR-TOK-23](contracts/token-wrappers.md#CTR-TOK-23)); a wrapper leg may be the native coin
([CTR-TOK-26](contracts/token-wrappers.md#CTR-TOK-26)).

<a id="meta-transactions"></a>
### 4.2 Meta-transactions

```mermaid
flowchart LR
    SUB["Subject<br/>signs EIP-712 typed data"]
    SUB -->|"MetaTransfer<br/>transfer or payment"| SUBM
    SUB -->|"MetaTransaction<br/>any allowlisted function"| SUBM
    SUBM["Submitter pays gas<br/>company relayer, open relayer or payee"]
    SUBM -->|"mtxExecuteTransfer"| TOK["Token<br/>moves its own balance"]
    SUBM -->|"mtxExecute"| SELF["Any MetaTxBase contract<br/>runs a self-call"]
    TOK -.->|"optional fee in the token"| SUBM
    SELF -.->|"fee mode NONE outside tokens"| OFF["Gas booked off chain"]
```

*Two signed structs, one relayer path; the contract itself checks relayer binding, expiry, lane nonce and signature
before anything runs ([CTR-MTX-17](contracts/metatx.md#CTR-MTX-17), [CTR-MTX-23](contracts/metatx.md#CTR-MTX-23)).*

Subjects hold no gas, and many never will (a loyalty member, a supplier's clerk, an AI agent). So the subject signs
and anyone may submit: a relayer pays the gas and can delay or refuse an intent but never change it. The signature
is checked inside the contract it targets — the EIP-712 `verifyingContract` is that contract, and the domain `salt`
is the chain's `chain_uid` ([NET-ALL-22](networks/README.md#NET-ALL-22)) — so there is no trusted forwarder and no
bundler between the subject and its funds ([CTR-MTX-16](contracts/metatx.md#CTR-MTX-16)).

There are two signed structs because wallets must show what is signed. A transfer or payment is a typed
`MetaTransfer` that a wallet displays field by field ("send `value` to `to`", with `entryRef` for a payment); anything
else is a generic `MetaTransaction` whose `data` is a call of one of the contract's **own** functions, from a fixed
selector allowlist ([CTR-MTX-19](contracts/metatx.md#CTR-MTX-19)). The self-call runs first and the fee is charged
after, so a failed operation costs the subject nothing. Each subject has independent **lanes** (2D nonces), so a stuck
payment never blocks an unrelated one, and a payment request derives its own lane so it can be paid at most once
([CTR-MTX-03](contracts/metatx.md#CTR-MTX-03)).

Who pays is a commercial choice, not a contract change: the company relayer with fee 0 (the B2B default), a fee in
the token to an open relayer, the payee submitting the payer's signed cheque itself, or the payee co-signing to pay
the fee ([payers](contracts/metatx.md#payers), [receiver-pays](contracts/metatx.md#receiver-pays)). A sponsorship
policy is node configuration ([node/sponsorship.md](node/sponsorship.md)).

<a id="accounts-and-keys"></a>
### 4.3 Accounts and keys

```mermaid
flowchart LR
    subgraph DEV["Keys on the subject's device"]
        K1["secp256k1 key"]
        K2["Passkey P-256"]
        K3["ed25519, Schnorr, BLS,<br/>multisig, PQ, Zether keys"]
    end
    NAT["Native account<br/>EOA address"]
    UA["Universal Account<br/>32-byte id"]
    SKA["SmartKeyAccount<br/>ERC-1271, many keys"]
    MW["MandateWallet<br/>holds the payer's funds"]
    REG["UniversalAccountRegistry"]
    GUA["Guardian"]
    DEL["Delegate"]
    T["Token or any<br/>MetaTxBase contract"]
    K1 --> NAT & SKA
    K2 --> UA & SKA
    K3 --> UA
    REG -.->|"record with PoP"| UA
    GUA -.->|"recovery after a delay"| SKA
    NAT -->|"owns"| MW
    DEL -->|"pays within the caps"| MW
    NAT -->|"signs as itself"| T
    UA -->|"UA meta-tx"| T
    SKA -->|"ERC-1271"| T
    MW -->|"pays as the wallet"| T
```

*Who signs for whom: a key signs for a native account, a Universal Account or a `SmartKeyAccount`; a delegate signs
for a `MandateWallet` within caps its owner set.*

An account is whoever can produce a valid signature, and SCaaS has three forms ([contracts/accounts.md](contracts/accounts.md)).
A **native account** is what the chain already understands, and never registers. A **Universal Account** is the
default for subjects: a 32-byte id derived from key data, so any key type works on any family without a contract per
user ([universal-account](contracts/accounts.md#universal-account)). Because a token must know how to verify such a
key, the id is registered once per chain in the admin-free `UniversalAccountRegistry` with a proof of possession that
binds the chain, the registry, the id and `authRef` — but not the caller, so a relayer can submit the registration and
onboarding is gasless ([CTR-UA-07](contracts/accounts.md#CTR-UA-07)).

A UA never rotates: its key is its identity ([CTR-UA-13](contracts/accounts.md#CTR-UA-13)). A subject that needs a
stable address across key changes, guardian recovery or compatibility with contracts that only understand `address`
uses a **`SmartKeyAccount`**, an ERC-1271 contract with several keys whose key management is itself a meta-transaction
([CTR-ACC-11](contracts/accounts.md#CTR-ACC-11), [CTR-ACC-10](contracts/accounts.md#CTR-ACC-10)). Delegated payment
is not an account form: a **`MandateWallet`** holds the payer's funds and lets a delegate pay approved payees within
per-payment and per-period caps, revocable at once. It replaces an allowance: a bug in one mandate reaches only
the funds in that wallet, and the payer pays no gas for an `approve` ([CTR-ACC-06](contracts/mandates.md#CTR-ACC-06)).

<a id="confidential-balances"></a>
### 4.4 Confidential balances

```mermaid
flowchart LR
    U["Underlying leg<br/>ERC-20 or native coin"]
    subgraph TOK["UnderlyingZetherToken"]
        P["Public balance<br/>ERC-20"]
        S["Shielded balance<br/>acc and pending per UA"]
    end
    V["Zether verifier<br/>bn254 or BLS12-381"]
    R["UniversalAccountRegistry"]
    ST["ZetherStatements"]
    D["ZetherDisclosure"]
    U -->|"wrap"| P
    P -->|"unwrap"| U
    P -->|"zetherShield"| S
    S -->|"zetherUnshield"| P
    U -->|"zetherWrapShield"| S
    S -->|"zetherUnshieldUnwrap"| U
    S -->|"zetherTransfer, M legs"| S
    S -.->|"verify proof"| V
    S -.->|"requireAuthorized"| R
    ST -.->|"reads account state"| S
    D -.->|"reads transfer entry"| S
```

*Public and shielded paths of a confidential kind ([CTR-ZTH-44](contracts/zether.md#CTR-ZTH-44),
[CTR-ZTH-45](contracts/zether.md#CTR-ZTH-45)); `NONE_ZETHER` has only shield and unshield.*

Businesses need amounts hidden from competitors and visible to their auditor; identities stay public by design ("not
a mixer"). The confidential kinds therefore add a **layer over the public balance** instead of a separate token: the
public ERC-20 balance works as on any token, value enters the shielded balance from it or straight from an
underlying leg, and leaves the same two ways. The reserve invariant counts the shielded supply, and no minter can
create shielded value ([CTR-ZTH-44](contracts/zether.md#CTR-ZTH-44)). A shielded transfer has `M` recipient legs
under one proof; the sender may add **decoys** that receive an encryption of 0 so an observer cannot tell the real
recipient ([CTR-ZTH-37](contracts/zether.md#CTR-ZTH-37)).

Audit is a set of **openings**, not a backdoor. The sender can prove one leg's amount with `SENDER_CP` without
revealing the randomness that would open every leg, decoys included; a recipient opens its own leg; an optional
auditor key — best held as a k-of-n threshold key — reads the per-transfer auditor ciphertext and nothing else, and a
sender may leave the auditor out of a transfer, visibly ([CTR-ZTH-40](contracts/zether.md#CTR-ZTH-40),
[CTR-ZTH-41](contracts/zether.md#CTR-ZTH-41), [CTR-ZTH-42](contracts/zether.md#CTR-ZTH-42)). How much of each
transfer is stored for later disclosure is chosen per call (`HASH`, `BUNDLE`, `NONE`,
[CTR-ZTH-38](contracts/zether.md#CTR-ZTH-38)).

Verification and disclosure sit **outside** the token: one verifier per curve, the stateless `ZetherDisclosure` and
`ZetherStatements` serve every Zether token ([CTR-ZTH-43](contracts/zether.md#CTR-ZTH-43),
[CTR-ZTH-46](contracts/zether.md#CTR-ZTH-46)). That keeps each token under EIP-170 and gives a checker one canonical
contract to call. Confidential kinds refuse the regulated flags ([CTR-ZTH-47](contracts/zether.md#CTR-ZTH-47)), and
classical Zether is gated to development chains until its audit ([CTR-ZTH-02](contracts/zether.md#CTR-ZTH-02)).

<a id="trading"></a>
### 4.5 Trading

The order book lives in the node; on chain a DEX call matches or routes signed orders, pays every party in the same
call and ends holding nothing ([CTR-DEX-01](contracts/dex.md#CTR-DEX-01); sequence 3 in [Data flows](#data-flows)).
A SCaaS token needs **no allowance** to trade: the signer's `TradeOrder` names the one DEX that may pull its funds,
and the sell token itself checks the signature and the signed price limit before moving exactly the fill into that
DEX ([CTR-DEX-13](contracts/dex.md#CTR-DEX-13), [CTR-DEX-15](contracts/dex.md#CTR-DEX-15)). The order has no maker
or taker role, so the same signature can rest in the node's book or take, and the same orders can be executed against
AMM pools instead of makers, with the surplus above each signed limit paid to its signer
([exchange settlement](contracts/dex.md#exchange)). A leg in an outside token is checked by the DEX and pulled through
the separate `DexPuller`, so the DEX itself never holds a user allowance ([CTR-DEX-22](contracts/dex.md#CTR-DEX-22)).

Each `SCaaSDex` is a clone made by the same factory, with an admin written once at creation
([CTR-DEX-24](contracts/dex.md#CTR-DEX-24)). The factory's `isDex` is **advisory**: wallets and the node use it to
warn about or refuse an unknown DEX, but tokens never consult it, so the factory registrar gains no power over trades
([CTR-DEX-19](contracts/dex.md#CTR-DEX-19)). The fee rate is in each signed order; the DEX admin decides only who
shares it ([CTR-DEX-03](contracts/dex.md#CTR-DEX-03)).

<a id="non-evm-families"></a>
### 4.6 Non-EVM families

The other families implement the same three pieces — token, mandate, DEX — in their own idiom
([common model](networks/README.md#model)); the target signed kinds are `MetaCall` and `MetaTransfer` everywhere
([NET-ALL-26](networks/README.md#NET-ALL-26)).

| Family | Meta-tx mechanism (BUILT) | Account model | DEX settlement | Confidential |
|---|---|---|---|---|
| EVM, Hedera (reference) | `MetaTransaction` / `MetaTransfer` in the contract (EIP-712, `salt = chain_uid`) | native EOA or ERC-1271, Universal Account ledger in the token, `SmartKeyAccount` | `SCaaSDex` clone, token-verified `TradeOrder`s | Zether kinds (development chains); PQ Zether on chain 7622 ([contracts/pq-zether.md](contracts/pq-zether.md)) |
| Cosmos | contract-level `Relay{payload, auth}` | CW20 balances per account; passkey owners as UA ids ([NET-ALL-21](networks/README.md#NET-ALL-21)) | CW20 `TransferFrom` under an allowance to the DEX contract | none |
| Soroban (Stellar, Pi) | native Soroban authorization entries (nonce + ledger expiry) | native accounts or a custom account (`__check_auth`) | two `require_auth` in one call | none |
| Move — Aptos | contract-level, one `Account` object per owner with lanes | the `Account` object holds any asset | legs moved inside one transaction | none |
| Move — Sui | contract-level, shared `Account<T>` per subject with lanes | the `Account<T>` holds the coin | two `Account<T>` legs | none |
| TON | custom jetton wallet verifies `SignedOp` (cells) | the jetton wallet carries the public key and lanes | escrow (holds funds briefly; no `transferFrom`) | none |
| Solana | program-level, `SmartKeyAccount` PDA + `LanePda`; signature through the precompile instruction | the PDA owns SPL token accounts | DEX program | none |

*Details per family: [networks/README.md](networks/README.md#families-and-chains),
[DEX per family](networks/README.md#dex-per-family), [availability](networks/README.md#availability).*

<a id="node-layer"></a>
## 5. Node layer

The node carries signed writes to the contracts and finalized facts back; it never holds a subject key
([node/README.md](node/README.md)).

<a id="node-roles"></a>
### 5.1 Node roles

One binary; modules are switched in configuration ([node/README.md](node/README.md#roles)). Shapes: full node (all
roles), mesh relayer (submit + mesh), forwarder (mesh only) — every shape is ERP-free.

| Role | What it does | Listener |
|---|---|---|
| **gateway** (door A) | Public intake of signed meta-txs and DEX orders from anyone: normalize, simulate, enqueue ([node/gateway.md](node/gateway.md)) | `[modules] gateway_bind` (default `127.0.0.1:8547`); auth `none` (loopback only), `bearer` or `hmac` ([NODE-GW-02](node/gateway.md#NODE-GW-02)) |
| **job API** | External server-side clients push jobs, cancel, read feeds, push watch lists and token subsets ([node/job-api.md](node/job-api.md)) | `[api] bind` (default `127.0.0.1:8548`), HMAC per API key ([NODE-JOB-05](node/job-api.md#NODE-JOB-05)) |
| **submit** | Per-chain lanes: lease → simulate → journal → sign → broadcast → follow → replace or gap-fill; consumption checks ([node/submit-lanes.md](node/submit-lanes.md)) | — |
| **indexer** | Finality gate + RPC quorum → normalized events → `feed_item(range)`; drift reports ([node/indexer-feeds.md](node/indexer-feeds.md)) | — |
| **dex venue** | Price-time order book per market (limit, IOC, FOK, partial fills), settle jobs, final-event watcher; the book lives in the node store ([NODE-DEX-14](node/dex-venue.md#NODE-DEX-14)) | gateway `/v1/dex/*` |
| **mesh** | Envelope `scaas-intent/1.2`, acceptance policy, exclusivity, pull bus, gossip, landed hints, announces, DEX book replication ([node/mesh.md](node/mesh.md), [node/gossip.md](node/gossip.md)); the envelope library is BUILT with 43 conformance vectors | `[mesh] bind` (HTTPS mTLS), `[gossip] listen` (QUIC/TCP) |
| **admin** | `/healthz`, `/readyz`, `/metrics` (open); `/v1/admin/*` (roles) ([node/admin-auth.md](node/admin-auth.md)) | `[modules] admin_bind` (default `127.0.0.1:9108`); optional separate `[modules] metrics_bind` |

<a id="topology"></a>
### 5.2 Topology

```mermaid
flowchart TB
    subgraph CALLERS["Callers"]
        direction LR
        ADMINS["Admins<br/>app/ · automation · shell"]
        ERP["ERP / back office<br/>push job · sync job"]
        PUB["Wallets, app,<br/>partners, agents"]
        PEER["Admitted peers<br/>and open mesh"]
    end
    subgraph NODE["scaas-node"]
        direction LR
        AAPI["Admin API"]
        JAPI["Job API"]
        GW["Gateway"]
        MESH["Mesh / gossip"]
    end
    STORE[("Store")]
    LANES["Lanes"]
    IDX["Indexer"]
    CHAINS[("Chain RPCs")]
    ADMINS -->|"JWT / OIDC"| AAPI
    ERP -->|"HMAC key"| JAPI
    PUB -->|"public"| GW
    PEER -->|"mTLS · QUIC · gossip"| MESH
    AAPI --> STORE
    JAPI --> STORE
    GW --> STORE
    MESH --> STORE
    STORE --> LANES -->|"submit"| CHAINS
    CHAINS -->|"index"| IDX --> STORE
```

| Caller | Enters through | Endpoint or transport | Authentication |
|---|---|---|---|
| `clients/app/` (React + Vite) | admin API | login / session | JWT (built-in users, or an optional OIDC IdP) |
| Automation | admin API | admin endpoints | OIDC client credentials |
| Host shell | the store directly | `scaas-node admin …` (the CLI writes the store) | host access |
| ERP or back office, push job (outbox) | job API | `POST /v1/jobs`, cancel, `PUT /v1/watch`, `/v1/tokens` | API key (HMAC) |
| ERP or back office, sync job | job API | `GET /v1/jobs?cursor=`, `GET /v1/events?cursor=` | API key (HMAC) |
| Wallets, app, partners, agents | gateway | `/v1/metatx`, `/v1/ops`, `/v1/ua-*`, `/v1/dex/*` | the subject's signature in each intent |
| Admitted peers | mesh | HTTPS mTLS (X25519MLKEM768) `/v1/mesh/*`; QUIC `/scaas/bus/1.2` | pinned peer keys |
| Open mesh | gossip | libp2p gossipsub over QUIC (PQ) or TCP+Noise | per-message validation |
| Prometheus | metrics listener | `/healthz`, `/readyz`, `/metrics` (scrape) | — |

The store holds `job`, `job_event`, `feed_item`, `chain`, `token`, `lane`, `namespace`, keys, audit, `dex_*`,
`intent` and `gossip_*`; lanes (`submit` / `lane_runner`) send to the EVM, Hedera, Cosmos, Soroban, Aptos, Sui, TON
and Solana RPCs, and the indexer reads them back.

Transitional (BUILT): today the node pulls work from one ERP and writes indexed ranges back to it; a per-chain switch
moves each chain to the push model, and the pull path is removed in one step afterwards
([NODE-JOB-10](node/job-api.md#NODE-JOB-10), [node/runbooks.md](node/runbooks.md#cutover)).

<a id="data-flows"></a>
## 6. Data flows

Each flow is a caption plus a sequence diagram; the participants are named as in the component docs. Diagrams show
the target; the caption says what is built.

<a id="client-payment"></a>
### 6.1 Client payment

The subject signs on its device, the client's outbox pushes the intent to its own node, and the client books the
payment only from the finalized feed ([INT-ERP-18](integration.md#INT-ERP-18),
[NODE-GEN-08](node/README.md#NODE-GEN-08)); built: `mtxPay` on `MetaTokenBase` and the `pay` op of the v1 line.

```mermaid
sequenceDiagram
    participant DEV as Subject device
    participant ERP as Client app (ERP)
    participant JOB as Node job API
    participant LANE as Submit lane
    participant TOK as Token
    participant IDX as Indexer and feed
    ERP->>DEV: MetaTransfer typed data (entryRef, validUntil)
    DEV-->>ERP: signature (passkey or wallet key)
    ERP->>ERP: verify, write the outbox row in the business transaction
    ERP->>JOB: POST /v1/jobs (idempotency key)
    JOB->>JOB: recompute the digest, token registered, normalize unbound fields
    JOB->>LANE: job accepted
    LANE->>LANE: lease, simulate, journal signed, broadcast
    LANE->>TOK: mtxExecuteTransfer(t, sig)
    TOK-->>TOK: PaymentSettled(entryRef)
    IDX->>TOK: logs of the final range, RPC quorum
    IDX-->>ERP: GET /v1/events range item with PaymentSettled
    ERP->>ERP: book the payment
```

<a id="gasless-transfer-through-door-a"></a>
### 6.2 Gasless transfer through door A

Anyone posts a signed intent to the public gateway, which simulates before it queues
([NODE-GW-01](node/gateway.md#NODE-GW-01), [node/gateway.md](node/gateway.md)); built for EVM with the built digest
name `metaTxDigest`.

```mermaid
sequenceDiagram
    participant W as Wallet or partner
    participant GW as Node gateway
    participant LANE as Submit lane
    participant TOK as Token
    participant IDX as Indexer
    W->>GW: POST /v1/metatx (chain, token, m, signature)
    GW->>GW: breaker, strict parse, normalize unbound fields
    GW->>TOK: simulate the call
    TOK-->>GW: success
    GW->>GW: intent_id = mtxDigest, insert a job in ~gateway
    GW-->>W: 202 queued, intent_id
    LANE->>LANE: lease, journal signed, broadcast
    LANE->>TOK: mtxExecuteTransfer(m, signature)
    TOK->>TOK: relayer, expiry, lane nonce, signature, fee
    TOK-->>TOK: Transfer, MetaTransactionExecuted(digest)
    IDX->>TOK: read the final range
    W->>GW: GET /v1/intents/intent_id
    GW-->>W: job state
```

<a id="dex-order-to-settlement-target-p2"></a>
### 6.3 DEX order to settlement (target, P2)

Role-free `TradeOrder`s rest in the node's book and settle in one call that pays every party
([CTR-DEX-15](contracts/dex.md#CTR-DEX-15), [node/dex-venue.md](node/dex-venue.md)); built: DEX-signed orders over
allowances, `SCaaSDex.settle`, `OrderFilled` / `Matched`.

```mermaid
sequenceDiagram
    participant MK as Maker wallet
    participant TK as Taker wallet
    participant VEN as Node gateway and venue
    participant LANE as Submit lane
    participant DEX as SCaaSDex
    participant ST as Sell token (SCaaS)
    participant PUL as DexPuller
    MK->>VEN: POST /v1/dex/orders (TradeOrder, sig)
    VEN->>VEN: rest in the book, price-time priority
    TK->>VEN: POST /v1/dex/orders (TradeOrder, sig)
    VEN->>VEN: match one taker against its makers
    VEN->>LANE: settle job (call)
    LANE->>DEX: mtxSettle(settlements)
    DEX->>ST: mtxTrade(order, sig, fill) per SCaaS leg
    ST->>ST: signature, expiry, nonce, signed price limit
    ST-->>DEX: transfer the fill into the DEX
    DEX->>PUL: pull(token, from, fill) per outside-token leg
    DEX->>DEX: pay destinations, fee split, refunds, balances unchanged
    DEX-->>VEN: LegSettled, seen by the final-event watcher
    VEN-->>MK: fill on the book feed
```

On non-EVM families settlement is bound to the relayer, and the venue re-checks the on-chain market every poll
([DEX per family](networks/README.md#dex-per-family)). Orders the book cannot match may instead be exchanged against
AMM pools with `mtxExchange` ([CTR-DEX-20](contracts/dex.md#CTR-DEX-20)).

<a id="universal-account-registration-submitted-by-a-relayer-specified"></a>
### 6.4 Universal Account registration submitted by a relayer (SPECIFIED)

The proof of possession binds the chain, the registry, the id and `authRef` but not the caller, so the gateway can pay
for it ([CTR-UA-07](contracts/accounts.md#CTR-UA-07), [NODE-GW-03](node/gateway.md#NODE-GW-03)).

```mermaid
sequenceDiagram
    participant APP as Client app (clientkeys)
    participant GW as Node gateway
    participant LANE as Submit lane
    participant REG as UniversalAccountRegistry
    participant VER as Kind verifier
    APP->>APP: ua = uaOf(kind, keyData)
    APP->>REG: popDigest(ua, authRef), bound to chain_uid
    APP->>APP: the key signs the PoP
    APP->>GW: POST /v1/ua/register (chain, kind, keyData, pop, authRef)
    GW->>GW: recompute the id, not yet registered, PoP of cheap kinds
    GW->>LANE: call job in ~gateway to chain.ua_registry
    GW-->>APP: 202 queued
    LANE->>REG: register(kind, keyData, pop, authRef, authPop)
    REG->>VER: verify the PoP, capped staticcall
    VER-->>REG: valid
    REG->>REG: store the record, UARegistered(ua, kind, keyData, authRef)
    APP->>REG: isRegistered(ua)
```

<a id="confidential-wrap-shield-multi-recipient-transfer-unshield-unwrap-target-p3"></a>
### 6.5 Confidential: wrap-shield, multi-recipient transfer, unshield-unwrap (target, P3)

Value enters the shielded balance straight from an underlying leg and leaves straight to one
([CTR-ZTH-45](contracts/zether.md#CTR-ZTH-45), [CTR-ZTH-37](contracts/zether.md#CTR-ZTH-37)); built on development
chains only: `ZetherToken` with its own underlying, the `OP_ZTRANSFER` envelope op emitting
`ConfidentialTransfer(entryRef)`, and `ITransferDisclosure`.

```mermaid
sequenceDiagram
    participant SND as Sender (clientkeys, zether-prover)
    participant RLY as Node (relayer)
    participant TOK as UnderlyingZetherToken
    participant STM as ZetherStatements
    participant VER as Zether verifier
    participant RCV as Recipient
    SND->>RLY: MetaTransaction zetherWrapShield(u, amountIn, ua)
    RLY->>TOK: mtxExecute(m, sig)
    TOK->>TOK: pull leg u at its rate, credit pending of ua
    SND->>STM: transferStatement(token, ...)
    SND->>SND: prove M legs (real and decoys) under one proof
    SND->>RLY: MetaTransaction zetherTransfer(payload, proof, authSig, beneficiary)
    RLY->>TOK: mtxExecute(m, sig)
    TOK->>VER: verify, after the registry's requireAuthorized
    TOK->>TOK: debit the sender, credit each leg, store the bundle hash
    RCV->>TOK: zetherRollOver (relayed), then decrypt off chain
    RCV->>RLY: MetaTransaction zetherUnshieldUnwrap(..., u, recipient, amount, minOut)
    RLY->>TOK: mtxExecute(m, sig)
    TOK->>VER: verify the unshield proof
    TOK-->>RCV: pay leg u, nothing minted
```

<a id="disclosure-by-sender_cp"></a>
### 6.6 Disclosure by `SENDER_CP`

The sender proves one leg's amount without handing over `s`; the checker verifies off chain or through the stateless
`ZetherDisclosure`, and no attestation is written ([CTR-ZTH-40](contracts/zether.md#CTR-ZTH-40),
[CTR-ZTH-43](contracts/zether.md#CTR-ZTH-43), [CTR-ZTH-39](contracts/zether.md#CTR-ZTH-39)).

```mermaid
sequenceDiagram
    participant SND as Sender (clientkeys)
    participant CHK as Checker (auditor or counterparty)
    participant TOK as Zether token
    participant DSC as ZetherDisclosure
    SND->>SND: rebuild s from the seed and the on-chain sendCounter
    SND->>SND: SENDER_CP opening of leg j (A1, A2, z)
    SND->>CHK: token, entryRef, j, amount, opening
    alt off chain
        CHK->>TOK: bundles from the TransferBundles event or calldata
        CHK->>CHK: zether-prover verify_opening on leg j
    else through ZetherDisclosure
        CHK->>TOK: disclosure()
        CHK->>DSC: verifyTransferAmount(token, entryRef, j, amount, SENDER_CP, opening, bundles)
        DSC->>TOK: transferEntry(entryRef), verifier(), auditorKey()
        DSC->>DSC: bundles match the stored hash, DLEQ on leg j
        DSC-->>CHK: true or false (a view)
    end
    CHK->>CHK: record the result in its own books
```

<a id="mesh-specified-transports"></a>
### 6.7 Mesh (SPECIFIED transports)

The origin wraps a bus-eligible intent in `scaas-intent/1.2`, signs `hub.sig`, optionally assigns `exclusive` → peers
pull (bus) or receive (gossip) → acceptance levels L0–L3 → store → scheduler → a job in the `~mesh` namespace →
submit. Landed hints trigger consumption reads ([node/mesh.md](node/mesh.md)).

<a id="trust-model"></a>
## 7. Trust model

| Boundary | Crossing | Control |
|---|---|---|
| Subject device ↔ everything | Signatures only; keys never leave the device (seed, passkey, Zether secret `x`) | [CTR-ACC-08](contracts/accounts.md#CTR-ACC-08), [CLI-SGN-11](clients/signers-clientkeys.md#CLI-SGN-11), [CLI-SGN-10](clients/signers-clientkeys.md#CLI-SGN-10) |
| Client ↔ node job API | HMAC per API key, namespace-scoped, idempotent; API keys only for external **server-side** clients, never in browser, mobile or desktop apps or extensions | [NODE-JOB-04](node/job-api.md#NODE-JOB-04), [NODE-JOB-05](node/job-api.md#NODE-JOB-05), [NODE-ADM-06](node/admin-auth.md#NODE-ADM-06) |
| Operator ↔ node admin | Built-in users (Argon2id) or optional OIDC; roles; audit. Configuration automation uses OIDC client credentials or the host CLI | [node/admin-auth.md](node/admin-auth.md) |
| Anyone ↔ gateway | Optional bearer or HMAC; body cap 64 KiB; concurrency 32; simulate before queueing; reverse-proxy rate limit | [NODE-GW-02](node/gateway.md#NODE-GW-02) |
| Node ↔ peers | Bus: SPKI-pinned mTLS or QUIC, admission per request; gossip: scoring, rate limits, validation | [NODE-MESH-03](node/mesh.md#NODE-MESH-03), [NODE-GSP-02](node/gossip.md#NODE-GSP-02), [NODE-GSP-07](node/gossip.md#NODE-GSP-07) |
| Node ↔ chain | Simulation gate; finality gate = at least `quorum` independent endpoints agree on the final head **and on the normalized event set** of every range, else no ingest and `/readyz` red; `quorum = 1` is single-provider trust, reported at start and as `scaas_finality_quorum{chain}`; breakers | [NODE-IDX-01](node/indexer-feeds.md#NODE-IDX-01), [NODE-IDX-02](node/indexer-feeds.md#NODE-IDX-02), [NODE-LANE-05](node/submit-lanes.md#NODE-LANE-05) |
| Contract ↔ caller | Signature, lane nonce, expiry, `mode`, fee cap, contract-only allowance | [contracts/metatx.md](contracts/metatx.md), [CTR-TOK-01](contracts/token-wrappers.md#CTR-TOK-01) |
| Node ↔ secrets | TOML and keystores only; the store holds no secret | [NODE-STO-03](node/store.md#NODE-STO-03) |

The node is trusted for **liveness and for the truth of the event feed it serves** (a compromised node can lie on
`/v1/events`). It is never trusted with subject funds or subject keys. The event-set quorum bounds what one dishonest
RPC provider can inject (a provider sees pending payments through the node's own simulate calls); it does not bound a
compromised node — a second independent event source is PLANNED ([node/indexer-feeds.md](node/indexer-feeds.md#limitations)).

**Two key axes.** Authorization keys and confidentiality keys are separate:

| Axis | Key | Purpose | Custody |
|---|---|---|---|
| `auth_custody` | secp256k1 / ed25519 / P-256 signing keys | Authorizes spending (EIP-712, family `MetaCall`/`MetaTransfer`, WebAuthn) | The subject's device (passkey, seed vault) or wallet extension; for explicitly entrusted custodial or delegated wallets, a KMS/HSM (FIPS 140-3 Level 3) behind the custody adapter (PLANNED) |
| `conf_custody` | Zether secret `x` (bn254 or BLS12-381); PQ Zether 32-byte leaf | Decrypts balances, builds proofs | The subject's device (seed path ending `…/7`; the PQ leaf sealed in the key worker); for organizations a threshold-MPC or enclave key oracle with a narrow interface (`zk_mul_by_x(points, ctx)`, `zk_nonce_commit`, `zk_response`) — commercial HSMs do not support these curves (PLANNED) |

Leaking one axis does not compromise the other: a leaked signing key cannot read balances; a leaked `x` cannot move
funds (except for `SELF_SCHNORR` accounts). Relayer lane keys are a third, unrelated class (gas only,
[node/submit-lanes.md](node/submit-lanes.md)). The node never needs `x` ([clients/signers-clientkeys.md](clients/signers-clientkeys.md#custody-axes)).

**Key management of the relayer.** Lane keys sign outer transactions only (the `Signer` seam has a local signer
today; KMS/HSM signers plug in behind it); environment-variable key custody (`env:`) is for development only. A
payment request is pinned by the typed-data domain (`chainId`, `verifyingContract`, and — specified — `salt =
chain_uid`, the genesis hash) and expires at `validUntil`; a subject can revoke an unused signature with
`cancelMetaNonce(batch)` (specified name `cancelNonce`). On private chains the B2B fee mode is `NONE`
with `MODE_RESTRICT_RELAYER` and `fee = 0`; on public chains the gateway also accepts fee-paying intents from anyone.

<a id="authority-after-deployment"></a>
### 7.1 Authority after deployment

No contract has an upgrade key, so what each party can still do after deployment is fixed at creation and public.
The table is a map of the [complete admin-power list](contracts/README.md#admin-powers-complete-list) for the EVM
target; the rules are at the linked anchors.

| Who | Can | Cannot | Rule |
|---|---|---|---|
| Factory registrar (multisig before mainnet) | register implementation versions, deprecate a version (marks, never blocks), enable Zether on development chains | touch any token or DEX, change a deployed implementation, stop a token from working | [CTR-TOK-18](contracts/token-wrappers.md#CTR-TOK-18), [CTR-TOK-25](contracts/token-wrappers.md#CTR-TOK-25) |
| Token `owner` (optional; 0 = none) | grant and revoke the roles of the flags set at creation, clear a flag that was not locked, transfer or renounce ownership | set a flag, act on a flag without granting itself the role, touch a reserve | [CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22) |
| Token role holders (`minter`, `rateAdmin`, `guardian`, `issuer`, `compliance`) | the power of their flag only: mint to a public balance, a timelocked rate step, disable wrap, and on non-confidential kinds freeze, forced transfer against a recorded order, bounded pause, allowlist | mint into a shielded balance, touch a reserve, move balances outside `FORCE`, upgrade | [CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22), [CTR-AS-17](contracts/asset-suite.md#CTR-AS-17) |
| DEX `admin` (written once at creation) | list or delist a market, set the fee split, list exchange targets, switch listed-only mode | touch funds, change a signed fee amount, pause the whole DEX | [CTR-DEX-03](contracts/dex.md#CTR-DEX-03) |
| Auditor (ideally a k-of-n threshold key) | read the per-transfer auditor ciphertext `C_aud` of transfers that include it, give an `AUDITOR` opening | read anyone's balance (`acc`, `pending`), read a transfer whose sender left it out | [CTR-ZTH-41](contracts/zether.md#CTR-ZTH-41), [CTR-ZTH-42](contracts/zether.md#CTR-ZTH-42) |
| Relayers and nodes | submit, delay or refuse an intent; choose the fee recipient where the intent leaves it unbound | change any signed field, move funds, sign for a subject | [CTR-MTX-17](contracts/metatx.md#CTR-MTX-17), [NODE-LANE-16](node/submit-lanes.md#NODE-LANE-16) |
| `UniversalAccountRegistry`, `ZetherDisclosure`, `ZetherStatements` | nobody administers them | — | [CTR-UA-15](contracts/accounts.md#CTR-UA-15), [CTR-ZTH-43](contracts/zether.md#CTR-ZTH-43) |

<a id="families"></a>
## 8. Families

SCaaS groups chains into six families, each with one contract code base and one node adapter
([ARCH-POS-02](decisions.md#ARCH-POS-02)): `evm` (EVM chains including Hedera), `cosmos`, `soroban` (Stellar, Pi
Network), `move` (`aptos`, `sui`), `ton` and `solana`. Contract-level meta-transactions are the default on every
family; open relayers form the mesh. How each family realises the meta-tx, the account, the DEX and confidentiality
is summarised in [Non-EVM families](#non-evm-families); per-family detail, the head-of-line table and the availability
matrices are in [networks/README.md](networks/README.md).

<a id="economics"></a>
## 9. Economics

**Break-even of a fee-earning relayer** (an order-of-magnitude argument): a meta-tx on Gnosis costs about $0.00015 of
gas; at a 10× markup the margin is about $0.0015 per transaction; a relayer with an SLA RPC, a small VPS and gas float
costs about $45–70 per month, so break-even is about $60 / $0.0015 = **40,000 transactions per month**. Most
enterprises do not reach this early. Hence:

1. Relayers are run by parties with an aligned business interest (issuer, distributors, partners, the payee), not by a
   fee market. The only in-protocol reward is the intent's own `fee` / `feeRecipient`: no mesh sponsorship pool, no
   forwarder pay, no stake ([NODE-MESH-05](node/mesh.md#NODE-MESH-05)). The opt-in `SponsorshipPool` is an application
   contract, not a mesh reward ([NODE-SPN-04](node/sponsorship.md#NODE-SPN-04)).
2. **B2B default `fee = 0`** (`MODE_FEE_NONE` + `MODE_RESTRICT_RELAYER` to the company relayer,
   [INT-ERP-06](integration.md#INT-ERP-06)): gas is an operating expense of the company relayer, booked per
   transaction. `MODE_FEE_NONE` is also the cheapest mode (about 8,300 gas less than a fee-taking meta-tx).
3. Payee-side relaying removes the relayer dependence for incoming payments.
4. A sponsorship policy (gas subsidy for qualifying inbound payments) is a node policy row, never a contract feature
   ([node/sponsorship.md](node/sponsorship.md)).
5. The relayer fee-spread metric (SLI W3B-06) may be negative by design ([node/ops.md](node/ops.md)).

<a id="data-protection"></a>
## 10. Data protection

SCaaS takes no position on any one country's law ([ARCH-POS-04](decisions.md#ARCH-POS-04)). Deployments map these
technical controls to their own regime (GDPR-class: lawful basis, minimization, erasure, retention, cross-border
transfer, processor agreements):

1. **No personal data on chain.** On chain go addresses, amounts (or ciphertexts), random `entryRef`s, digests and
   commitments; never names, document numbers, tax ids, order numbers or free text. A CI guard on calldata types
   (allow `address`, `bool`, `uint*`, `int*`, `bytes32`, `bytes32[]`; deny `string` and `bytes` except declared proof
   and signature fields) is PLANNED.
2. **Linkage off chain.** The mapping address ↔ party lives in the client's system of record and can be erased there.
3. **Minimized node state.** The node store keeps payloads (payer, payee, amounts) only as long as needed
   (`job_retention_secs`: 30 days for terminal jobs; feeds 7 days); backups are encrypted, file mode 0600 or database
   grants ([node/store.md](node/store.md)).
4. **Logs carry no payloads** ([node/ops.md](node/ops.md)).
5. **Private chains and private bus scope** for data that must not reach third parties ([Profiles](#profiles)).

Crypto-shredding, disclosure for reconciliation and the land gate are in
[integration.md](integration.md#data-protection).

<a id="glossary"></a>
## 11. Glossary

<details>
<summary><b>Terms</b> — subject, intent, relayer, lane, namespace, finality gate, UA, kind, feature flag, opening and more</summary>

| Term | Meaning |
|---|---|
| **Subject** | The party whose value moves or whose authority is exercised: a person, a company, an AI agent, a device. Subjects sign; nobody signs for them. |
| **Intent** | A subject-signed, domain-separated authorization of exactly one operation on exactly one contract (a meta-transaction on EVM, a `MetaCall`/`MetaTransfer` elsewhere). Valid until `validUntil`; executes at most once. |
| **Envelope** | The wire wrapper of an intent between nodes: `scaas-intent/1.2` JSON with the family body, `intent_id`, origin signature `hub.sig`, optional `exclusive`, `hop_count` ([node/mesh.md](node/mesh.md#envelope)). |
| **`intent_id` / digest** | The 32-byte digest the contract computes and emits in `MetaTransactionExecuted.digest` (EVM: EIP-712 `_hashTypedDataV4`; other families: their family digest). The dedup key everywhere ([NODE-MESH-08](node/mesh.md#NODE-MESH-08)). |
| **Relayer** | A process holding gas-paying keys that submits subject intents as outer transactions. It cannot alter an intent; it can only submit, delay or refuse it. |
| **Node** | `scaas-node`, the Rust process that runs the relayer roles ([Node roles](#node-roles)). |
| **Lane** | One gas-paying relayer account on one chain (derived from a mnemonic at a BIP-44 account index, or a raw key), with its own outer nonce or sequence; a stuck lane never blocks another. Also the subject-side 2D nonce space: a **subject lane** = `(from, batch)` on EVM, `(subject, lane)` elsewhere ([NET-ALL-02](networks/README.md#NET-ALL-02)). |
| **Outer nonce** | The chain-level nonce or sequence of a relayer lane account; journaled before broadcast ([NODE-LANE-04](node/submit-lanes.md#NODE-LANE-04)). |
| **Family** | A group of chains sharing one contract code base and one node adapter: `evm` (incl. `hedera`), `cosmos`, `soroban`, `move` (`aptos`, `sui`), `ton`, `solana`. |
| **Chain** | One network, keyed by `chain_key = family:network` (`evm:100`, `hedera:296`, `sui:mainnet`, `aptos:1`, `ton:-239`, `solana:<genesis>`, `cosmos:<chain-id>`, `soroban:pubnet`). CAIP-2 is a display field only ([INT-ERP-10](integration.md#INT-ERP-10)). |
| **Profile** | `public` or `private` per chain; default `private` (fails closed). Private-chain intents never leave admitted private peers and never touch gossip. |
| **Namespace** | The node's tenant unit (`[a-z0-9-]{3,40}`; reserved `~gateway`, `~mesh`, `~dex`): granted chains, token subset, external-client API keys, quotas. The node has no notion of "company" ([NODE-JOB-03](node/job-api.md#NODE-JOB-03)). |
| **Store** | The node's durable state: jobs, job events, index ranges, configuration, key metadata, audit log, DEX book, mesh tables. SQLite, PostgreSQL or MySQL; one owner process per store ([NODE-STO-04](node/store.md#NODE-STO-04), [NODE-STO-06](node/store.md#NODE-STO-06)). |
| **Job** | A unit of submission work in the store (`metatx`, `call`, `signed_op` or `tombstone`), identified by `uid` and by its idempotency tuple ([NODE-JOB-02](node/job-api.md#NODE-JOB-02), [NODE-JOB-04](node/job-api.md#NODE-JOB-04)). |
| **Outbox** | The client-side table where a business transaction records "this must go on chain", committed atomically with the business change; the client pushes outbox rows to the node ([INT-ERP-18](integration.md#INT-ERP-18)). |
| **Feed** | A cursor-paged change log served by the node: `/v1/jobs` (job state changes) and `/v1/events` (finalized chain ranges, balances, DEX items) ([NODE-IDX-04](node/indexer-feeds.md#NODE-IDX-04), [NODE-IDX-05](node/indexer-feeds.md#NODE-IDX-05)). |
| **Anchor** | Write-out direction: publishing a commitment or settling value on chain. |
| **Land** | Read-in direction: a finalized on-chain fact delivered to a system of record. Nothing lands before the finality gate. |
| **Settlement** | A transfer of value whose on-chain execution completes a business obligation (payment, trade, tender award). |
| **`entryRef`** | The 32-byte reference carried by a payment op and emitted in `PaymentSettled`; links an on-chain payment to a business document; 32 random bytes ([CTR-MTX-03](contracts/metatx.md#CTR-MTX-03)). Some requirement texts call it `payId`. |
| **Finality gate** | The rule that decides when a block range is final: `depth` (n confirmations), `tag` (`finalized`) or `instant` (BFT families), plus a quorum of independent RPC endpoints returning the same event set ([NODE-IDX-02](node/indexer-feeds.md#NODE-IDX-02)). |
| **Consumed** | Job state: the subject nonce moved past the intent's nonce through a transaction this node did not land (or has not attributed yet). Never a failure by itself ([NODE-LANE-09](node/submit-lanes.md#NODE-LANE-09)). |
| **UA** | Universal Account: an account identifier derived from key data, an EOA generalised to every signature scheme — the native address for a chain's native accounts (never registered), otherwise `keccak256(keccak256(kind_tag) ‖ key_data)` (32 bytes, kind-tagged, top 96 bits non-zero), registered per chain with a proof of possession that binds the chain (`chain_key` and `chain_uid`, the genesis hash), the registry, the UA and `authRef` (not the caller, so registration is relayable) ([contracts/accounts.md](contracts/accounts.md)). The built registry uses the Zether-only `keccak256(encodedY)` form until the UA registry replaces it ([CTR-UA-22](contracts/accounts.md#CTR-UA-22)). |
| **Mandate** | An on-chain spending authorization held by a subject's wallet contract (`MandateWallet`): delegate, per-payment and per-period caps, payees, expiry, revocation ([CTR-ACC-06](contracts/mandates.md#CTR-ACC-06)). |
| **Kind** | The implementation a token is cloned from, chosen at creation: `NONE`, `UNDERLYING` (1–8 legs), `NONE_ZETHER`, `UNDERLYING_ZETHER`; the post-quantum kinds are reserved ([CTR-TOK-21](contracts/token-wrappers.md#CTR-TOK-21)). Code, not a setting. |
| **Feature flag** | A bit of a token's `features`, chosen at creation (`PAYABLE`, `MINTABLE`, `BURNABLE`, `RATE_ADJUSTABLE`, `WRAP_DISABLEABLE`, the regulated `FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST`); per flag locked or disableable, never set later ([CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)). |
| **Owner** | A token's optional administrator: grants and revokes the roles of its flags, may clear an unlocked flag, may renounce for good; it acts on a flag only through a role ([CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)). |
| **Role holder** | An account granted the role of a flag (`minter`, `rateAdmin`, `guardian`, `issuer`, `compliance`); it can use only that flag's power and keeps the role after the owner renounces ([CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)). |
| **Shield / unshield** | Moving value into or out of a confidential token's shielded (encrypted) balance, from or to the public balance (`zetherShield`, `zetherUnshield`) or straight from or to an underlying leg (`zetherWrapShield`, `zetherUnshieldUnwrap`) ([CTR-ZTH-45](contracts/zether.md#CTR-ZTH-45)). |
| **Decoy** | A recipient leg of a confidential transfer that receives an encryption of 0, added by the sender to hide the real recipient ([CTR-ZTH-37](contracts/zether.md#CTR-ZTH-37)). |
| **Opening** | Data that proves the amount of one confidential transfer leg to a checker without revealing a key: `SENDER_S`, `RECEIVER_X`, `AUDITOR`, `SENDER_CP` ([CTR-ZTH-40](contracts/zether.md#CTR-ZTH-40)). |
| **`chain_uid`** | The chain's genesis block hash: with `chain_key` it identifies a chain (a chain id alone is not unique), and it is the `salt` of every SCaaS signing domain ([NET-ALL-22](networks/README.md#NET-ALL-22)). |

</details>
