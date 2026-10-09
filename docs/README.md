# SCaaS — SmartContract as a Service

SCaaS: the smart contracts are the API services; `scaas-node` is the open relayer and indexer anyone can run in front
of them. This page is the entry point: the product introduction first, then the doc map. It is not normative; the rules
live in the component docs, and every rule's id, aliases and rationale are in [decisions.md](decisions.md).

## What SCaaS is

**In SCaaS the smart contracts themselves are the API services.** A payment, a spending mandate, a token, a wrapper
around an existing token, a DEX order, a sealed-bid tender, a vesting schedule, a dividend distribution or a
confidential transfer is a function of a contract. The contract checks the subject's signature, nonce, expiry and
limits on every call, and it is immutable from the moment it is deployed: nobody, including the people who wrote it,
can change what it does, and nobody can move a user's funds beyond the bounded, published powers listed in
[contracts/README](contracts/README.md#admin-powers-complete-list).

ERPs, web portals, mobile apps and AI agents call these contracts the way they call any API. The difference from an
ordinary web API is who authorizes a valuable write: **the subject signs it on its own device** (a passkey or a wallet
key), and a server only carries the signed write to the chain and reads the result back.

**Anyone can run `scaas-node` as a relayer, with their own policies.** The node is the open infrastructure in front of
the contracts: it accepts signed intents, pays their gas, journals every submission, waits for finality and serves
finalized facts back as feeds. Each operator decides what to accept, what to charge, what to sponsor, whom to peer
with and how to monitor. Operators are independent of each other and of SCaaS; the guarantees (signatures, nonces,
contract rules) never depend on any of them. A relayer can refuse or delay a request, never forge or alter one —
and the subject can always go to another relayer, or submit itself.

**The parts.** Contract families: gasless meta-transactions, tokens, accounts, mandates, a DEX, tenders, an asset
suite and the confidential layer. The node (`scaas-node`). Clients: signers, wallet connectors, a console and dApp.

**The EVM token model in one paragraph.** One base tree serves every token. A token has one of four kinds: `NONE` (a
plain issuer token), `UNDERLYING` (a wrapper of one to eight legs, each an ERC-20 or the native coin), or the same two
with the confidential layer, `NONE_ZETHER` and `UNDERLYING_ZETHER`
([CTR-TOK-21](contracts/token-wrappers.md#CTR-TOK-21)). Features are chosen at creation and never set later (disableable flags can be cleared): `PAYABLE`,
`MINTABLE`, `BURNABLE`, `RATE_ADJUSTABLE`, `WRAP_DISABLEABLE`, and for regulated tokens `FREEZE`, `FORCE`, `PAUSE`,
`ALLOWLIST`. One owner administers a token, grants roles and may renounce
([CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)). An open factory creates tokens and DEX clones.

## Who it is for

- **Businesses that settle with partners** — brands, distributors, suppliers, marketplaces — that want payments,
  mandates and settlement on chain without giving any server the power to move funds.
- **Issuers of loyalty points, stablecoin wrappers and regulated assets** — tokens with transparent rules, an open
  factory and, where needed, regulated features with issuer and compliance roles.
- **ERP and back-office teams** that need on-chain payments booked only once final, with idempotent submission and
  reconciliation built in.
- **Application and wallet developers** who want passkey sign-in-and-sign, gasless transactions for their users, and
  one signing model across many chains.
- **AI agents and automated workflows** that must act within signed, capped, revocable authority, and leave a
  tamper-evident trail.
- **Node operators** — from a company running its own relayer to a consortium of members or an open public relayer.

## What it offers

| Area | What you get | Read |
|---|---|---|
| Gasless meta-transactions | Users sign typed data; a relayer submits and pays gas; 2D nonces and lanes so one stuck operation never blocks another; fee policies from "free" (B2B) to fee-paying | [contracts/metatx.md](contracts/metatx.md) |
| Tokens and wrappers | Issuer tokens and wrappers of one to eight underlying legs (ERC-20 or the native coin) at fixed or adjustable rates; features chosen at creation; an open factory of immutable clones; contract-only allowances | [contracts/token-wrappers.md](contracts/token-wrappers.md) |
| Accounts | Universal Account: one account identifier derived from any key type (secp256k1, ed25519, P-256, BLS, post-quantum…), registered per chain with proof of possession, registration relayable; `SmartKeyAccount` with many keys (ERC-1271); passkey-controlled smart accounts with guardians and recovery | [contracts/accounts.md](contracts/accounts.md) |
| Mandates | `MandateWallet`: per-payment and per-period caps, approved payees and expiry | [contracts/mandates.md](contracts/mandates.md) |
| Payments | Payment references, idempotent submission, booking once final | [integration.md](integration.md) |
| Trading | A signed-order, price-time order book; settlement in one transaction; managed markets for regulated assets; DEX clones from the open factory | [contracts/dex.md](contracts/dex.md), [node/dex-venue.md](node/dex-venue.md) |
| Procurement | Sealed-bid tenders with deposits, commit/reveal and refunds | [contracts/tender.md](contracts/tender.md) |
| Asset tokenization | Regulated tokens, vesting and streaming, distributions, corporate actions, templates | [contracts/asset-suite.md](contracts/asset-suite.md) |
| Confidential amounts | Zether: identities visible, amounts and balances hidden; shield, multi-recipient transfer with decoys, unshield; disclosure to an auditor through four openings. A post-quantum variant (PQZ) waits for a lattice precompile on public chains | [contracts/zether.md](contracts/zether.md), [contracts/pq-zether.md](contracts/pq-zether.md) |
| Many chains | Six families — EVM (including Hedera), Cosmos, Soroban (Stellar, Pi Network), Move (Aptos, Sui), TON, Solana — with one signing and relaying model | [networks/README.md](networks/README.md) |
| The node | Job API for server-side clients, a public gateway, finality-gated event feeds, gas breakers, sponsorship policies, an admin API with built-in users or OIDC | [node/README.md](node/README.md) |
| Relayer mesh | Relayers that share intents with admitted partners or an open gossip network; private chains never leave the admitted set | [node/mesh.md](node/mesh.md), [node/gossip.md](node/gossip.md) |
| Operations | SLOs, metrics and alerts, FinOps usage reports, incident runbooks, backup and disaster recovery | [node/ops.md](node/ops.md), [node/runbooks.md](node/runbooks.md) |
| Client software | Passkey and seed-vault signers, wallet connectors, a console and dApp | [clients/signers-clientkeys.md](clients/signers-clientkeys.md), [clients/app.md](clients/app.md) |
| ERP integration | Outbox, push and sync, payment references, reconciliation, data protection by design | [integration.md](integration.md) |

What SCaaS is **not**: a custodian, a mixer, a database replacement, an upgradeable platform, a token gatekeeper or a
single-ERP product ([architecture.md](architecture.md#what-scaas-is-not)).

## Deployment shapes

- **Public chains** — your relayer, partners' relayers and open relayers serve the same contracts; nothing is hidden
  except what Zether hides.
- **Private or permissioned chain** — your own nodes and admitted peers only; intents never reach the public.
- **Consortium** — every member runs a node; members exchange intents over pinned, authenticated links.

See [architecture.md](architecture.md#profiles).

## How to start

1. **Understand the model** — read [architecture.md](architecture.md): the authority model (who signs), the service
   model (write out, read in, finality), and the trust model.
2. **Pick your path:**
   - *Integrating an ERP or back office:* [integration.md](integration.md) — onboarding, pushing jobs, feeds,
     reconciliation, the integration checklist; one worked connector in
     [integration-odoo-example.md](integration-odoo-example.md).
   - *Running a node:* [node/README.md](node/README.md) → [node/store.md](node/store.md) (configuration) →
     [node/runbooks.md](node/runbooks.md) (production gates, backup, incidents).
   - *Building a wallet or app:* [clients/signers-clientkeys.md](clients/signers-clientkeys.md) and
     [clients/app.md](clients/app.md).
   - *Reviewing or deploying contracts:* [contracts/README.md](contracts/README.md) (immutability, admin powers,
     production gates) and the network page of your chain under [networks/](networks/README.md).
3. **Check the status tags** — every section says whether it is BUILT, SPECIFIED or PLANNED
   ([status tags](#status-tags)). Confidential-amount contracts stay behind their production gate until an
   independent audit. The built code still has some older lines; the component docs mark them **Transitional (BUILT)**.
4. **Look up why** — every rule links to its entry in [decisions.md](decisions.md), with the reason and the cost of
   getting it wrong.
5. **Build and test** — `smartcontracts/scripts/{build,test}.sh <family>`; docs check:
   `python3 scripts/docs_check.py check`.

## Reading order

0. [../README.md](../README.md) — the idea from the ground up: a smart chain as infrastructure, contracts as API
   services, meta-transactions and fee models, open relayers, Zether and PQ Zether.
1. This page — what SCaaS is, who it is for, how to start.
2. [architecture.md](architecture.md) — positioning, authority model, service model, components, trust model,
   families, economics, data protection, glossary.
3. The component docs for your role (map below). Integrators: [integration.md](integration.md). Node operators:
   [node/README.md](node/README.md) then [node/runbooks.md](node/runbooks.md). Contract reviewers:
   [contracts/README.md](contracts/README.md). Wallet and app developers: [clients/](clients/signers-clientkeys.md).
4. [decisions.md](decisions.md) — why each rule holds, and the old-id alias index.

## Map

One table per area; ids in brackets are the rule prefixes each area owns.

**Overview**

| Doc | Covers |
|---|---|
| [architecture.md](architecture.md) | How the parts fit and why: contract layer, node roles, topology, sequence diagrams, trust model |
| [decisions.md](decisions.md) | The register: every ruling, its old ids, owner flag and rationale; `ARCH-POS` system-wide positions |

**Contracts** (`CTR-*`)

| Doc | Covers |
|---|---|
| [README](contracts/README.md) | Immutability, admin powers, production gates, build pins |
| [metatx.md](contracts/metatx.md) | `MetaTransaction` / `MetaTransfer`, lanes, `mtxExecute`, fees, names |
| [token-wrappers.md](contracts/token-wrappers.md) | Token tree and kinds, features and owner, libraries, rates and reserve, factory |
| [accounts.md](contracts/accounts.md) | Native accounts, Universal Account registry, `SmartKeyAccount` |
| [mandates.md](contracts/mandates.md) | `MandateWallet`: delegated payments without allowances |
| [dex.md](contracts/dex.md) | `TradeOrder`, the DEX, AMM exchange path, `DexPuller` |
| [tender.md](contracts/tender.md) | Sealed-bid tender |
| [asset-suite.md](contracts/asset-suite.md) | Regulated flags, vesting, distributions, `ExchangeOffer`, templates |
| [zether.md](contracts/zether.md) | Confidential layer: shield / transfer / unshield, proofs, disclosure |
| [pq-zether.md](contracts/pq-zether.md) | Post-quantum confidential tokens (lattice; waits for a precompile) |

**Node** (`NODE-*`)

| Doc | Covers |
|---|---|
| [README](node/README.md) | Roles, listeners, invariants |
| [store.md](node/store.md) | Jobs, feeds, configuration, audit tables |
| [job-api.md](node/job-api.md) | Server-side job intake, cancel, call tables |
| [submit-lanes.md](node/submit-lanes.md) | Lease, simulate, sign, broadcast, replace |
| [indexer-feeds.md](node/indexer-feeds.md) | Finality, normalized events, feeds |
| [gateway.md](node/gateway.md) | Public intake of signed intents |
| [admin-auth.md](node/admin-auth.md) | Admin endpoints and authentication |
| [sponsorship.md](node/sponsorship.md) | Who pays gas, sponsor rules |
| [dex-venue.md](node/dex-venue.md) | Order book, matching, settle jobs, trade engine |
| [mesh.md](node/mesh.md) · [gossip.md](node/gossip.md) | Relayer mesh envelope, acceptance, gossip |
| [ops.md](node/ops.md) · [runbooks.md](node/runbooks.md) | Operations, alerts, runbooks |
| [threat-model.md](node/threat-model.md) | Node threat model |

**Networks** (`NET-*`)

| Doc | Covers |
|---|---|
| [README](networks/README.md) | Common model, chain identity (`chain_uid`), signing domains, passkeys, availability |
| [evm.md](networks/evm.md) · [hedera.md](networks/hedera.md) | EVM chains and Hedera |
| [cosmos.md](networks/cosmos.md) · [soroban.md](networks/soroban.md) · [ton.md](networks/ton.md) | CosmWasm, Stellar / Pi, TON |
| [sui.md](networks/sui.md) · [aptos.md](networks/aptos.md) · [solana.md](networks/solana.md) | Move families and Solana |

**Clients** (`CLI-*`) and **integration** (`INT-*`)

| Doc | Covers |
|---|---|
| [signers-clientkeys.md](clients/signers-clientkeys.md) | Signers, key vault, what a wallet checks before signing |
| [app.md](clients/app.md) | Console and dApp |
| [integration.md](integration.md) | Connecting any ERP or back office |
| [integration-odoo-example.md](integration-odoo-example.md) | One worked ERP connector (example only) |

**Not normative**

| Where | What |
|---|---|
| [history/README.md](history/README.md) | Frozen designs, the original requirements note and its [trace](history/blockchain-trace.md), the old-id inventory (read-only) |
| `research/` | Background and rationale only |

## Precedence

When two sources disagree, the higher one wins ([ARCH-POS-01](decisions.md#ARCH-POS-01)):

1. **Owner rulings** — entries of [decisions.md](decisions.md) with `owner: yes`. They override everything below,
   including code that has not caught up.
2. **Component docs** — `node/`, `contracts/`, `networks/`, `clients/`, `integration.md`, each for its own subject.
3. **Code** — for pinned byte formats only (typehashes, KAT and conformance vectors). A difference between code and an
   owner ruling is a bug in the code.
4. **History** — `history/` (frozen designs and their review dispositions).
5. **Research** — `research/`, background only.

[architecture.md](architecture.md) and this page define no rules.

## Status tags

Every section of a component doc carries one tag:

| Tag | Meaning |
|---|---|
| **BUILT** | Code exists in this repository with tests; the text describes what the code does. |
| **SPECIFIED** | The rules are fixed here; code does not exist yet, or only partly. |
| **PLANNED** | Direction and constraints only; details are not fixed yet. |

Where something is partly built, the tag names the built part and the rest separately. Where BUILT code still differs
from the target, a short **Transitional (BUILT)** paragraph says what runs today and what removes it.

## Ids, aliases and history

- Each rule is defined once, at an HTML anchor carrying its id in its component doc; other docs link it
  (`node/job-api.md#NODE-JOB-04`) and never restate it. Ids are `<AREA>-<TOPIC>-<NN>`, never renumbered.
- Ids used before 2026-10-07 still appear in code comments. They resolve through the alias index at the end of
  [decisions.md](decisions.md#alias-index), or from a shell (old id in, new id, status and link out):

  ```
  python3 scripts/docs_check.py resolve R91
  ```

  Section references in code comments (`§5.2` of a design) point into the frozen copies under `history/specs/`;
  [history/README.md](history/README.md) maps the old short names to files.
- New design work starts as a draft under `superpowers/specs/` with provisional ids; on acceptance its rules move
  into the component docs, real ids are allocated in decisions.md, and the draft moves to `history/specs/`.

## Checks

`python3 scripts/docs_check.py check` verifies the register (every old id covered, every current id defined exactly
once), links, the absence of old ids and client-specific names in current docs, the research banners, and that diagrams are
Mermaid (C11: an ASCII-art block must become ```mermaid, or ```text when it is a layout or pseudocode);
`python3 scripts/docs_check.py facts check` verifies that every fact of the frozen sources landed in a current doc or
is classified as history. `python3 scripts/test_docs_check.py` tests the checker itself.
