# SCaaS — SmartContract as a Service

**A product introduction.** This page is not normative and defines no rules. The system overview is
[architecture.md](architecture.md); the doc map and the precedence of sources are in [README.md](README.md).

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

## Who it is for

- **Businesses that settle with partners** — brands, distributors, suppliers, marketplaces — that want payments,
  mandates and settlement on chain without giving any server the power to move funds.
- **Issuers of loyalty points, stablecoin wrappers and regulated assets** — tokens with transparent rules, an open
  factory and, where needed, a separate controlled class with issuer and compliance roles.
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
| Tokens and wrappers | Issuer tokens, wrappers of existing tokens at fixed or adjustable rates, multi-underlying wrappers; an open factory of immutable clones; contract-only allowances | [contracts/token-wrappers.md](contracts/token-wrappers.md) |
| Accounts | Universal Account: one account identifier derived from any key type (secp256k1, ed25519, P-256, BLS, post-quantum…), registered per chain with proof of possession; optional passkey-controlled smart accounts with guardians and recovery | [contracts/accounts.md](contracts/accounts.md) |
| Mandates | Mandate wallets with per-payment and per-period caps, approved payees and expiry | [contracts/mandates.md](contracts/mandates.md) |
| Trading | A signed-order, price-time order book; settlement in one transaction; managed markets for regulated assets | [contracts/dex.md](contracts/dex.md), [node/dex-venue.md](node/dex-venue.md) |
| Procurement | Sealed-bid tenders with deposits, commit/reveal and refunds | [contracts/tender.md](contracts/tender.md) |
| Asset tokenization | Regulated tokens, vesting and streaming, distributions, corporate actions, templates | [contracts/asset-suite.md](contracts/asset-suite.md) |
| Confidential amounts | Zether: identities visible, amounts and balances hidden, disclosure for audit; a post-quantum variant for private chains | [contracts/zether.md](contracts/zether.md), [contracts/pq-zether.md](contracts/pq-zether.md) |
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
   ([README.md](README.md#status-tags)). Confidential-amount contracts stay behind their production gate until an
   independent audit.
4. **Look up why** — every rule links to its entry in [decisions.md](decisions.md), with the reason and the cost of
   getting it wrong.
