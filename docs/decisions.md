# Decisions — ruling register

Every ruling of SCaaS has one entry here: its id, the old ids it replaces (aliases), its status, whether it is an
owner ruling, and **why** it holds. The rule itself is defined once, in the doc named by `normative`, at an anchor
`<a id="ID">`; other docs link that anchor and never restate it. Entries whose `normative` is `decisions.md` are
system-wide positions defined here. Precedence between sources is [ARCH-POS-01](#ARCH-POS-01); the doc map is
[README.md](README.md).

Each entry is a `###` heading `<ID> — <title>`, a meta line `- old: … · status: … · owner: yes|no · date: … ·
normative: <file#ID> · superseded-by: …`, then **Rule.** (only where useful as a summary, or for self-defining
entries), **Why.**, **Cost if wrong.** and **Source.** Superseded entries keep one sentence of what they said.

- **Ids** are `<AREA>-<TOPIC>-<NN>`: `ARCH-POS` (system-wide), `NODE-*` ([node/](node/README.md)), `CTR-*`
  ([contracts/](contracts/README.md)), `NET-*` ([networks/](networks/README.md)), `CLI-*` ([clients/](clients/app.md)),
  `INT-ERP` / `INT-ODOO` ([integration.md](integration.md)). `01`–`79` are current or open, `80`–`99` superseded,
  withdrawn or unused. Ids are never renumbered ([ARCH-POS-07](#ARCH-POS-07)).
- **`open`** = an owner question whose stated default is already applied in the normative text.
- **`old:`** lists the ids used before the 2026-10-07 reorganization (`R91`, `RS5-9`, `CR-PD-2`, `SCaaS:N4`, …);
  `CR-PD-1(c)` names one clause of a split ruling. The generated [alias index](#alias-index) at the end maps every old
  id to its new id(s); from a shell: `python3 scripts/docs_check.py resolve R91`.
- **Source** lines point into `history/` (frozen designs) and `research/` (background); both are read-only.

**Contents**

1. [Architecture and register policy](#1-architecture-and-register-policy)
2. [Node — General](#2-node--general)
3. [Node — Store](#3-node--store)
4. [Node — Job API](#4-node--job-api)
5. [Node — Submit lanes](#5-node--submit-lanes)
6. [Node — Indexer and feeds](#6-node--indexer-and-feeds)
7. [Node — Gateway](#7-node--gateway)
8. [Node — Admin and auth](#8-node--admin-and-auth)
9. [Node — Sponsorship](#9-node--sponsorship)
10. [Node — DEX venue](#10-node--dex-venue)
11. [Node — Mesh](#11-node--mesh)
12. [Node — Gossip](#12-node--gossip)
13. [Node — Operations](#13-node--operations)
14. [Node — Runbooks](#14-node--runbooks)
15. [Node — Threat model](#15-node--threat-model)
16. [Contracts — General](#16-contracts--general)
17. [Contracts — Meta-transactions](#17-contracts--meta-transactions)
18. [Contracts — Token wrappers and factory](#18-contracts--token-wrappers-and-factory)
19. [Contracts — Accounts and mandates](#19-contracts--accounts-and-mandates)
20. [Contracts — DEX](#20-contracts--dex)
21. [Contracts — Sealed-bid tender](#21-contracts--sealed-bid-tender)
22. [Contracts — Asset suite](#22-contracts--asset-suite)
23. [Contracts — Zether (classical)](#23-contracts--zether-classical)
24. [Contracts — Universal Account](#24-contracts--universal-account)
25. [Contracts — Post-quantum Zether](#25-contracts--post-quantum-zether)
26. [Networks — common model](#26-networks--common-model)
27. [Networks — EVM](#27-networks--evm)
28. [Networks — Hedera](#28-networks--hedera)
29. [Networks — Cosmos](#29-networks--cosmos)
30. [Networks — Soroban](#30-networks--soroban)
31. [Networks — Sui](#31-networks--sui)
32. [Networks — Aptos](#32-networks--aptos)
33. [Networks — Solana](#33-networks--solana)
34. [Networks — GRAM](#34-networks--gram)
35. [Clients — signers and clientkeys](#35-clients--signers-and-clientkeys)
36. [Clients — SCaaS app](#36-clients--scaas-app)
37. [Integration — ERP](#37-integration--erp)
38. [Integration — example connector](#38-integration--example-connector)
39. [Alias index](#alias-index)

## 1. Architecture and register policy

These entries define themselves (`normative: decisions.md`): they are system-wide positions, and
[architecture.md](architecture.md) and [README.md](README.md) only explain them.

<a id="ARCH-POS-01"></a>
### ARCH-POS-01 — Source precedence: owner rulings first
- old: owner:2026-10-06:precedence · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-01 · superseded-by: —

**Rule.** When two sources disagree, the higher one wins: (1) owner rulings, i.e. entries of this register with
`owner: yes`; (2) the component docs under `node/`, `contracts/`, `networks/`, `clients/` and `integration.md`, each
for its own subject; (3) code, but only for pinned byte formats (typehashes, KAT and conformance vectors); (4)
`history/`; (5) `research/`, which is background only. [architecture.md](architecture.md)
and [README.md](README.md) are not normative. A difference between code and an owner ruling is a bug in the code, not
in the ruling.
**Why.** The earlier system specification ranked itself above the component specs while restating them, and the
copies drifted; the specs disagreed with each other in several places. One register of rulings plus one normative home
per rule removes the second copy. Owner rulings override code that has not caught up, so a ruling is never "undone" by
an implementation shortcut.
**Cost if wrong.** A reader who trusts the overview instead of the component doc applies a stale rule; the checker
keeps ids out of the overview so there is nothing to trust there.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 33; [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) §4 K14.

<a id="ARCH-POS-02"></a>
### ARCH-POS-02 — Family taxonomy
- old: owner:2026-10-06:families · status: current · owner: yes · date: 2026-10-06 · normative: decisions.md#ARCH-POS-02 · superseded-by: —

**Rule.** SCaaS supports six families; a family is a group of chains that share one contract code base and one node
adapter: `evm` (EVM chains, including Hedera), `cosmos` (CosmWasm), `soroban` (Stellar and Pi Network), `move` (Aptos
and Sui), `ton` and `solana`. A chain is keyed `chain_key = family:network`. This replaces the earlier list of
"Six ecosystems" (EVM, Hedera, GRAM, Sui, Soroban, Cosmos).
**Why.** Hedera runs EVM contracts and shares the EVM code base and signer, so it is not a family of its own; Aptos and
Sui share the Move language but not their object models, so they are one family with two adapters; Aptos and Solana
were added by the owner. A taxonomy by code base matches how contracts, adapters, tests and the availability matrices
are organized ([networks/README.md](networks/README.md)).
**Cost if wrong.** Counting by ecosystem duplicates the EVM rules for Hedera and hides that one Move fix must be made
twice.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 92; [history/blockchain.md](history/blockchain.md) line 17.

<a id="ARCH-POS-03"></a>
### ARCH-POS-03 — `scaas` names everywhere
- old: owner:2026-10-06:naming · status: current · owner: yes · date: 2026-10-06 · normative: decisions.md#ARCH-POS-03 · superseded-by: —

**Rule.** Every product name is a `scaas` name: the node `scaas-node`, the envelope `scaas-intent/1.2`, the pay-lane
label `scaas.pay.lane`, environment variables `SCAAS_*`, metrics `scaas_*`, HTTP headers `X-Scaas-*`, EIP-712 domain
names `"SCaaS …"`, tags `scaas.*`, `SCAAS-ZETHER-*`, `scaas/zether/…`. Clients read the domain a deployed contract
reports (`eip712Domain()`) instead of assuming a string.
**Why.** SCaaS is a standalone product; the first implementation carried the brand of its first client in node,
envelope, lane and environment names, which tied every operator and every other client to that brand. The rename has
landed in code.
**Cost if wrong.** A domain string assumed by a client breaks signatures against any deployment that kept an older
name; reading `eip712Domain()` avoids it.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) lines 93, 102.

<a id="ARCH-POS-04"></a>
### ARCH-POS-04 — Market-neutral protocol and docs
- old: owner:2026-10-06:market-neutral · status: current · owner: yes · date: 2026-10-06 · normative: decisions.md#ARCH-POS-04 · superseded-by: —

**Rule.** SCaaS names no country's law, currency or regulator in its protocol, contracts or docs. Data protection is
specified as technical controls (no personal data on chain, off-chain linkage, minimized node state, crypto-shredding,
disclosure) that a deployment maps to its own regime (GDPR-class: lawful basis, minimization, erasure, retention,
cross-border transfer, processor agreements).
**Why.** SCaaS is sold worldwide. A rule written for one market either does not apply elsewhere or reads as a
compliance claim the product cannot make for every deployment.
**Cost if wrong.** A deployment in a market with stricter rules must add controls on its side; the generic controls
are designed to be the strict superset.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) lines 94, 1959.

<a id="ARCH-POS-05"></a>
### ARCH-POS-05 — The node is independent of any ERP
- old: R87, owner:2026-10-06:node-independent · status: current · owner: yes · date: 2026-10-06 · normative: decisions.md#ARCH-POS-05 · superseded-by: —

**Rule.** `scaas-node` never connects to an ERP. Every ERP, portal or application is one client among others: it
pushes jobs to the node's job API and reads the node's feeds. The node's control plane is its own store and admin API;
every node is "standalone". This supersedes the earlier design in which the node claimed jobs from an ERP database and
the ERP stayed the control plane.
**Why.** One product serves many ERPs; a node that depends on one ERP's database, models and RPC is a component of
that ERP, not a service. Keeping the journal, configuration and feeds in the node's own store also keeps
journal-before-broadcast local, without an ERP round trip.
**Cost if wrong.** The ERP learns job and chain state by polling the feeds instead of being called; the client's sync
schedule bounds the delay.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 109; [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 37.

<a id="ARCH-POS-06"></a>
### ARCH-POS-06 — Three use cases from the first wave
- old: UD:§1:use-cases, UD:§15:D12, canon:D12 · status: current · owner: yes · date: 2026-08-30 · normative: decisions.md#ARCH-POS-06 · superseded-by: —

**Rule.** SCaaS serves three use cases, all configurable from the first deployment: loyalty and rewards, B2B
settlement between a brand and its distributors or suppliers, and end-user payments. The technical focus is
meta-transactions, confidential amounts (Zether) and stablecoins.
**Why.** The owner chose full configuration over a staged launch. The three cases share one token, meta-transaction
and settlement core; what differs is configuration (fee mode, sponsorship, custody, confidentiality).
**Cost if wrong.** Enabling B2B from the start makes organizational custody of signing and decryption keys a launch
requirement rather than a later option.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) lines 38, 862.

<a id="ARCH-POS-07"></a>
### ARCH-POS-07 — Register policy: open entries, defaults, superseded owner rulings
- old: reorg:Q2, reorg:Q10, reorg:Q13, reorg:Q14 · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-07 · superseded-by: —

**Rule.** Ids are `<AREA>-<TOPIC>-<NN>`; `01`–`79` are current or open, `80`–`99` superseded, withdrawn or unused.
Ids are never renumbered or reused; a clarification keeps its id, a reversal creates a new id and the old one becomes
`superseded`. Status `open` means an owner question whose stated default is already applied in the normative text.
Interpretations awaiting confirmation keep their stated defaults as `open` entries. Requirements of the original
requirements note that no design ever ruled on are recorded as `open` entries, `PLANNED` where a seam exists. Earlier
owner decisions that a later ruling replaced are recorded as `superseded` owner rulings, not re-opened; unruled items
of the earlier decision log are `open` entries.
**Why.** Nothing the owner asked for or decided may disappear silently, and nothing may be decided silently either: an
`open` entry makes the default visible and keeps it reversible.
**Cost if wrong.** An `open` default that the owner later reverses needs a new id and a doc change; the alias index
keeps the old reference resolvable.
**Source.** [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) §3.1, §8 (Q2, Q10, Q13, Q14).

<a id="ARCH-POS-08"></a>
### ARCH-POS-08 — Market-specific research stays private
- old: reorg:Q9 · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-08 · superseded-by: —

**Rule.** The research note on one market's law and the large raw tool-output file stay in `research/` while the
repository is private and are removed before any public release. Neither ever enters the current docs.
**Why.** The market-neutral rule ([ARCH-POS-04](#ARCH-POS-04)) keeps market law out of the product; the files remain
useful background for the owner meanwhile.
**Source.** [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) §8 Q9.

<a id="ARCH-POS-09"></a>
### ARCH-POS-09 — Work plans stay in history and the TODO list
- old: reorg:Q11 · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-09 · superseded-by: —

**Rule.** Implementation work items (their scope, gates and dependencies) stay in the frozen design specs under
`history/` and are tracked in the repository TODO list; there is no roadmap document under `docs/`, and the current
docs carry no work-item ids.
**Why.** Work plans change weekly; normative docs that cite them go stale with every plan change.
**Source.** [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) §4 K22, §8 Q11.

<a id="ARCH-POS-10"></a>
### ARCH-POS-10 — Client data platforms are out of scope
- old: — · status: current · owner: no · date: 2026-10-07 · normative: decisions.md#ARCH-POS-10 · superseded-by: —

**Rule.** SCaaS delivers finalized facts and operating data: the event feed, the job feed, metrics, usage reports and
disclosure openings. What a client builds on top of them is the client's platform and out of scope: landing tables in a
data warehouse, projections into operational, vector, knowledge-graph, semantic-metric or OLAP stores, AI tool
gateways, and an enterprise-wide multi-plane target architecture.
**Why.** Those layers depend on the client's data model and tooling; SCaaS stays a service whose interface is the
contracts plus the node's feeds ([node/indexer-feeds.md](node/indexer-feeds.md), [node/ops.md](node/ops.md)).
**Cost if wrong.** A client that wants these projections builds them from `/v1/events` and `/v1/jobs`; nothing in the
feeds prevents it.
**Source.** [history/blockchain.md](history/blockchain.md) lines 38–48, 56–74; [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) §2.5.

<a id="ARCH-POS-11"></a>
### ARCH-POS-11 — Documentation language and structure
- old: — · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-11 · superseded-by: —

**Rule.** The docs are English throughout and self-contained. Rulings carry new component ids with the old ids as
aliases in this register. The old system specification is frozen as `history/SCaaS-2026-10-07.md` for reference;
[README.md](README.md) is the entry page and product introduction (non-normative). Line-budget overruns of the Zether, PQ
Zether, network pages and the node overview are accepted, and so is the overrun of this register (owner
2026-10-07).
**Why.** One language and one id scheme for a product used worldwide; the old ids stay resolvable for code comments
(`python3 scripts/docs_check.py resolve <id>`).
**Source.** [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) §8 (owner answers 2026-10-07).

### ARCH-POS-80 — EVM-only, META-only first scope
- old: R1 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NET-ALL-02, CTR-ZTH-01, CTR-ZTH-18, CTR-ZTH-19, CTR-UA-02, CTR-UA-16, CTR-UA-22, INT-ERP-11, ARCH-POS-02

It said: the first build covers EVM chains and the plain meta-tx token only; confidential amounts, non-EVM families
and the mesh are out of scope.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 660.

### ARCH-POS-81 — Legal deferred to a separate chapter
- old: UD:§1:legal · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: ARCH-POS-04

It said: legal questions are deferred to a separate chapter that does not block the buildable parts.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 47.

## 2. Node — General

### NODE-GEN-01 — Node holds no subject funds or keys
- old: SCaaS:N1, UD:§23.2 · status: current · owner: yes · date: 2026-10-07 · normative: node/README.md#NODE-GEN-01 · superseded-by: —

**Owner ruling (2026-10-07).** Lane keys hold gas only and never hold a role on any contract, dev deployments included; role-holding targets go through a Safe (NODE-JOB-19).
**Why.** Funds and subject keys stay with subjects and contracts; a compromised node can only stop working or lie on its feed. A relayer signs only the outer transaction, with its `authKey`; it never needs a subject's confidential key `x`: it cannot decrypt the amount, build the proof or change any field (all are in the signed digest), and that blindness is the property, not a limitation. A server holds `x` only when the company itself sends from its own confidential treasury, which is custody, not relay; the key oracle that serves it is small (under 300 lines; the enclave image under 5,000 lines including the crypto backend), so it stays out of the node process, which parses strangers' bytes.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 880; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2055.

### NODE-GEN-02 — No broadcast without committed journal
- old: SCaaS:N2 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-02 · superseded-by: —

**Why.** A transaction broadcast without a durable record can be signed twice after a crash.
**Cost if wrong.** Double spends of lane nonces.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 881.

### NODE-GEN-03 — No outer nonce abandoned
- old: SCaaS:N3 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-03 · superseded-by: —

**Why.** An abandoned nonce blocks every later transaction of the lane.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 882.

### NODE-GEN-04 — One live outer tx per intent
- old: SCaaS:N4 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-04 · superseded-by: —

**Why.** Two live outer transactions for one intent waste gas and confuse tracking.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 883.

### NODE-GEN-05 — No bump after consumption
- old: SCaaS:N5 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-05 · superseded-by: —

**Why.** Once the subject nonce is consumed, a bump can only revert and burn gas.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 884.

### NODE-GEN-06 — Never dead because landed elsewhere
- old: SCaaS:N6 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-06 · superseded-by: —

**Why.** An intent that landed through another relayer succeeded; reporting it dead would make clients re-ask the subject.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 885.

### NODE-GEN-07 — Unbound wire values never submitted
- old: SCaaS:N7 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-07 · superseded-by: —

**Why.** Unbound wire values (relayer, fee recipient) are normalized first, so nobody can steer our lane to pay them.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 886.

### NODE-GEN-08 — Nothing booked before finality
- old: SCaaS:N8 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-08 · superseded-by: —

**Why.** Clients book money; booking before finality books reorged payments.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 887.

### NODE-GEN-09 — Breakers never block indexing or rescues
- old: SCaaS:N9 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-09 · superseded-by: —

**Why.** Breakers limit new spending; stopping rescues or indexing would turn a cost guard into an outage.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 888.

### NODE-GEN-10 — One owner process per store
- old: SCaaS:N10 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-10 · superseded-by: —

**Why.** Two writers on one store break nonce and journal guarantees.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 889.

### NODE-GEN-11 — Every paid outer tx metered
- old: SCaaS:N11 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-11 · superseded-by: —

**Why.** Every outer transaction costs the lane; unmetered ones escape budgets.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 890.

### NODE-GEN-12 — Signed fields read from payload
- old: SCaaS:N12 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-12 · superseded-by: —

**Why.** The signed payload is the truth; side fields from the caller can disagree with it.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 891.

### NODE-GEN-13 — Value out and deposits capped
- old: SCaaS:N13 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-13 · superseded-by: —

**Why.** Jobs that move lane value out must be capped, or a client can drain gas float.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 892.

### NODE-GEN-14 — Intents signature-checked before chain calls
- old: SCaaS:N14 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-14 · superseded-by: —

**Why.** Checking signatures first keeps forged intents from costing RPC calls.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 893.

### NODE-GEN-15 — Adapter restart state in store
- old: SCaaS:N15 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-15 · superseded-by: —

**Why.** Adapter state outside the store is lost on restore and cannot be fenced.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 894.

### NODE-GEN-16 — No upgradeable program, one key per family
- old: SCaaS:N16 · status: current · owner: no · date: 2026-10-07 · normative: node/README.md#NODE-GEN-16 · superseded-by: —

**Why.** An upgradeable program can change under the node; one key per family keeps custody simple.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 895.

### NODE-GEN-17 — One Rust app for the daemon tier
- old: UD:§23, UD:§23.3 · status: current · owner: yes · date: 2026-08-31 · normative: node/README.md#NODE-GEN-17 · superseded-by: —

**Why.** One binary with roles by configuration means one release, one test matrix and one operations story.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2014; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2154.

### NODE-GEN-18 — scaas-node layout: module moves and job seam first
- old: reorg:Q12 · status: current · owner: yes · date: 2026-10-07 · normative: node/README.md#NODE-GEN-18 · superseded-by: —

**Why.** Code that mirrors the docs is easier to review; the job seam first keeps tests green during the move.
**Source.** [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) line 1228.

### NODE-GEN-80 — One Rust node, ERP as control plane
- old: UD:§21.2 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05

It said: one Rust node, ERP as control plane.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1341.

### NODE-GEN-81 — Lane diagram with ERP control plane
- old: UD:§23.6 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05, NODE-JOB-06, INT-ERP-16

It said: lane diagram with ERP control plane.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2261.

### NODE-GEN-82 — ERP addon is control plane, not a node
- old: UD:§23.8 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05

It said: eRP addon is control plane, not a node.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2319.

## 3. Node — Store

### NODE-STO-01 — Node refuses max_valid_for_secs above horizon
- old: CR-PD-4(node), CR-R3-8(node) · status: current · owner: no · date: 2026-10-07 · normative: node/store.md#NODE-STO-01 · superseded-by: —

**Why.** A signature valid longer than the family keeps replay state would be replayable.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 901; [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 700.

### NODE-STO-02 — paused blocks sending, halted blocks indexing
- old: R53 · status: current · owner: no · date: 2026-10-06 · normative: node/store.md#NODE-STO-02 · superseded-by: —

**Why.** Pause stops spending, halt also stops reading; two levers for two situations.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 526.

### NODE-STO-03 — RPC endpoints only in node config
- old: R20, R95 · status: current · owner: yes · date: 2026-10-06 · normative: node/store.md#NODE-STO-03 · superseded-by: —

**Why.** RPC URLs may embed keys and are dial targets; only the host's config may set them. Config authority is the node store, in the owner's words "toml bootstraps; admin API mutations persist"; the one admin-editable dial target, mesh peer URLs, is admin-only, audited and behind its own SSRF guard.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 727; [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 117; [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 1019.

### NODE-STO-04 — One store always on, one owner
- old: R88, UD:§23.1, UD:§23.7 · status: current · owner: yes · date: 2026-10-06 · normative: node/store.md#NODE-STO-04 · superseded-by: —

**Why.** One store with one owner keeps every guarantee in one transaction domain.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 110; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2024; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2297.

### NODE-STO-05 — Finality, pause, index cursor in node
- old: R96 · status: current · owner: no · date: 2026-10-06 · normative: node/store.md#NODE-STO-05 · superseded-by: —

**Why.** Finality and pause are node decisions; clients only read them.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 119.

### NODE-STO-06 — SQLite, PostgreSQL or MySQL, storage only
- old: R111 · status: current · owner: yes · date: 2026-10-06 · normative: node/store.md#NODE-STO-06 · superseded-by: —

**Why.** Operators choose the database they run; the store is storage only, with fencing for safety.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 136.

### NODE-STO-07 — Node halts chains with upgradeable programs
- old: R348 · status: current · owner: yes · date: 2026-10-07 · normative: node/store.md#NODE-STO-07 · superseded-by: —

**Why.** An upgradeable program can change under the node's assumptions.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 154.

### NODE-STO-08 — Paused chain accepts and holds jobs
- old: NI:I2 · status: open · owner: no · date: 2026-10-07 · normative: node/store.md#NODE-STO-08 · superseded-by: —

**Why.** A paused chain keeps accepting so clients need not retry; jobs wait.
**Cost if wrong.** Default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1611.

### NODE-STO-09 — Names chosen where sources gave none
- old: NI:I7 · status: open · owner: no · date: 2026-10-07 · normative: node/store.md#NODE-STO-09 · superseded-by: —

**Why.** Names had to be chosen where the design gave none; recorded so they can be revisited.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1617.

### NODE-STO-10 — Gas cap warning for confidential tokens
- old: — · status: current · owner: no · date: 2026-10-07 · normative: node/store.md#NODE-STO-10 · superseded-by: —

**Why.** Classical Zether transfers need about 3.36 M gas; the 3 M default would silently reject them, so configuration warns.

### NODE-STO-80 — In-memory gateway queue and DEX book
- old: R16 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-DEX-01, NODE-DEX-01, INT-ERP-12, NODE-STO-04, NODE-DEX-14

It said: in-memory gateway queue and DEX book.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 718.

## 4. Node — Job API

### NODE-JOB-01 — Call jobs limited to selector/target table
- old: CR-PD-1(c) · status: current · owner: yes · date: 2026-10-08 · normative: node/job-api.md#NODE-JOB-01 · superseded-by: —

Change: a token's own signed entry points travel only as `metatx` jobs. Source add: §3 MG-3, MG-6, §7 NODE-JOB-01/19.

### NODE-JOB-02 — One journal, node-computed digests
- old: R89 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-02 · superseded-by: —

**Why.** One journal and node-computed digests let no tenant squat another's intent.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 111.

### NODE-JOB-03 — Namespaces are the tenant unit
- old: R90 · status: current · owner: yes · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-03 · superseded-by: —

**Why.** Namespaces bound everything a credential can see and do.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 112.

### NODE-JOB-04 — Idempotency key and payload hash
- old: R91 · status: current · owner: yes · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-04 · superseded-by: —

**Why.** Retries never duplicate; JCS makes the hash independent of key order and whitespace.
**Cost if wrong.** A changed payload under one key flags attention instead of a duplicate.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 113.

### NODE-JOB-05 — Machine credentials: namespaced HMAC keys
- old: R92 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-05 · superseded-by: —

**Why.** HMAC sends no secret on the wire and binds requests to a namespace.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 114.

### NODE-JOB-06 — Claim is a CAS inside one owner
- old: R97(claim) · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-06 · superseded-by: —

**Why.** With one owner process a claim is a compare-and-set, no distributed lock.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 120.

### NODE-JOB-07 — Cancel is a node CAS
- old: R98(node) · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-07 · superseded-by: —

**Why.** Cancel races with leasing; a CAS in the node decides it once.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 121.

### NODE-JOB-08 — Relayer-bound jobs pinned to their lane
- old: R102 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-08 · superseded-by: —

**Why.** A relayer-bound intent can only be landed by its lane.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 126.

### NODE-JOB-09 — call jobs are a namespace capability
- old: R103 · status: current · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-09 · superseded-by: —

**Why.** Only namespaces that need calls may make them.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 127.

### NODE-JOB-10 — Per-chain pull/push flag, then removal
- old: R104 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-10 · superseded-by: —

**Why.** Clients move chain by chain from pull to push; legacy code is removed in one step once all chains are on push.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 128.

### NODE-JOB-11 — Cancel-by-origin tombstones bounded
- old: R323 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-11 · superseded-by: —

**Why.** Tombstones for jobs not yet pushed must not grow without bound.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 140.

### NODE-JOB-12 — Empty namespace token subset means none
- old: R324 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-12 · superseded-by: —

**Why.** An empty subset must not mean 'all tokens'; fail closed.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 141.

### NODE-JOB-13 — Live-call uniqueness per namespace
- old: R325 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-13 · superseded-by: —

**Why.** Live-call dedupe per namespace prevents one tenant from blocking another's call.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 142.

### NODE-JOB-14 — Intake authority re-checked in insert tx
- old: R327 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-14 · superseded-by: —

**Why.** Grants may change between check and insert; re-checking in the transaction closes the race.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 144.

### NODE-JOB-15 — Migrated ERP namespace gets allow_call
- old: NI:I1 · status: open · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-15 · superseded-by: —

**Why.** A migrated ERP client needs calls it used before; default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1610.

### NODE-JOB-16 — Shared namespace via origin.scope
- old: NI:I3 · status: open · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-16 · superseded-by: —

**Why.** Several entities of one client can share a namespace if origin.scope separates their keys; default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1612.

### NODE-JOB-17 — Cancel of published job reports already sent
- old: NI:I5 · status: open · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-17 · superseded-by: —

**Why.** A published job may land; cancel reports that instead of pretending.
**Cost if wrong.** Default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1614.

### NODE-JOB-18 — Tombstone quota and rate defaults
- old: NI:I8(tombstones) · status: open · owner: no · date: 2026-10-07 · normative: node/job-api.md#NODE-JOB-18 · superseded-by: —

**Why.** Default quotas bound tombstone abuse; default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1619.

### NODE-JOB-19 — Call table: permissionless selectors, role-holder Safe row
- old: reorg:Q1 · status: current · owner: yes · date: 2026-10-08 · normative: node/job-api.md#NODE-JOB-19 · superseded-by: —

Change: rows renamed (`SmartKeyAccount.mtxExecuteAsOwner`, `MandateWallet.mtxPayUnderMandate`/`mtxRevoke`/`mtxExecuteAsOwner`, `SCaaSDex.mtxSettle`/`mtxCancelOrders`/`mtxInvalidateNonces`); the DEX row admits only DEXes on the chain profile's list; chain-bound targets must report `chainUid() = chain_uid`; no role function is on any token allowlist, so role calls stay on the role holder's contract also for gasless token calls (OQ1). Source add: §3 MG-2, MG-3, MG-4, MG-6, §7, §10 OQ1.

### NODE-JOB-20 — Meta-tx `data` read through the implementation's selector allowlist
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: node/job-api.md#NODE-JOB-20 · superseded-by: —

**Why.** The token gateway runs a transfer, a payment or a self-call of the token's own allowlisted functions (owner: "functions of the token itself", "a fixed per-implementation selector allowlist"); a fixed op list in the node would refuse every new operation and need a node release each time. Reading the published `mtxSelectors()` table per immutable implementation keeps intake, pricing (fee class, amount argument), display and the canonical-encoding check exact, and keeps role functions out of the token path.
**Cost if wrong.** The node relays self-calls whose fee basis it misreads, or refuses valid wraps/burns; a non-canonical dynamic encoding would give one intent two mesh identities.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §2 A1–A3, §3 MG-1, MG-2, MG-5, MG-6.
Change (2026-10-08): the table covers every SCaaS contract on `MetaTxBase`, not only tokens; `metatx` jobs name their struct (`call` | `transfer`); a `MetaTransfer` counts as selector `transfer`/`pay` in the breaker. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-7, GC-8.

Under "Node — Submit lanes":
Change (2026-10-08): non-EVM `signed_op` jobs carry `op_kind` `call`/`transfer`; the node relays only the `mtx_` entries it lists per contract (`SELECTOR_NOT_ALLOWED` otherwise) and breaks per `(from, function)`. Source add: `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, §5.

### NODE-JOB-80 — Node talks to ERP only over json/2
- old: R6 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: ARCH-POS-05, NODE-JOB-06, INT-ERP-16, INT-ERP-18

It said: node talks to ERP only over json/2.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 677.

### NODE-JOB-81 — Result queue default, node-configured callbacks
- old: UD:§22.9 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: NODE-IDX-04, ARCH-POS-05

It said: result queue default, node-configured callbacks.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1955.

## 5. Node — Submit lanes

### NODE-LANE-01 — USD-denominated gas velocity limits
- old: req:blockchain.md:usd-velocity · status: open · owner: yes · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-01 · superseded-by: —

**Why.** Limits in a reporting currency need a price source the node does not have.
**Cost if wrong.** Open; gas-unit limits apply meanwhile.
**Source.** [history/blockchain.md](history/blockchain.md) line 353.

### NODE-LANE-02 — Legacy pull: signed report idempotent, nonce held
- old: CR-PD-5 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-02 · superseded-by: —

**Why.** The legacy client may resend reports; idempotency keeps nonces consistent.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 910; [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 244.

### NODE-LANE-03 — Outer tx keys behind Signer trait
- old: R15, UD:§1:custody, UD:§23.5 · status: current · owner: yes · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-03 · superseded-by: —

**Why.** A Signer trait lets KMS or HSM replace local keys without touching lanes.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 715; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 43; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2233.

### NODE-LANE-04 — Never abandon an outer nonce
- old: R18 · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-04 · superseded-by: —

**Why.** A skipped nonce blocks the lane forever.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 720.

### NODE-LANE-05 — Circuit breakers never block indexing
- old: R55 · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-05 · superseded-by: —

**Why.** Breakers stop spending, never the reading of the chain.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 528.

### NODE-LANE-06 — ChainAdapter and per-lane runner
- old: R58(adapter) · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-06 · superseded-by: —

**Why.** One adapter trait per family and one runner per lane keep families independent.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 531.

### NODE-LANE-07 — Local secp256k1/ed25519 signer, KMS seam
- old: R59 · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-07 · superseded-by: —

**Why.** Local signing suffices for development and private chains; production public chains use KMS.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 532.

### NODE-LANE-08 — Lane keys: raw key or mnemonic
- old: R60 · status: current · owner: no · date: 2026-10-03 · normative: node/submit-lanes.md#NODE-LANE-08 · superseded-by: —

**Why.** A mnemonic derives many lanes from one backup.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 533.

### NODE-LANE-09 — Consumption check before bump or resend
- old: R80, UD:§22.1, UD:§22.8 · status: current · owner: yes · date: 2026-10-05 · normative: node/submit-lanes.md#NODE-LANE-09 · superseded-by: —

**Why.** A bump after the subject nonce is consumed only burns gas.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 80; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1690; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1930.

### NODE-LANE-10 — Normalize unbound relayer and feeRecipient
- old: R84, R100 · status: current · owner: no · date: 2026-10-06 · normative: node/submit-lanes.md#NODE-LANE-10 · superseded-by: —

**Why.** Unbound relayer and feeRecipient fields would let anyone redirect the fee.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 84; [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 124.

### NODE-LANE-11 — A batch is several jobs journaled together
- old: R321 · status: current · owner: no · date: 2026-10-08 · normative: node/submit-lanes.md#NODE-LANE-11 · superseded-by: —

**Why.** A batch lands several jobs in one transaction; journaling them together keeps them atomic in the store.
**Cost if wrong.** Planned.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 138.
Change (2026-10-08): `mtxBatchTransfer` batches `transfer` jobs and `mtxBatch` `call` jobs, never mixed. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G5, §3 GC-8.

### NODE-LANE-12 — Outer transaction is a store row
- old: R326 · status: current · owner: no · date: 2026-10-06 · normative: node/submit-lanes.md#NODE-LANE-12 · superseded-by: —

**Why.** Tracking outer transactions as rows makes bumps, gap-fills and costs auditable.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 143.

### NODE-LANE-13 — Breaker meters what the lane pays
- old: R340 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-13 · superseded-by: —

**Why.** Budgets must meter what the lane actually pays, including failures.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 146.

### NODE-LANE-14 — One retry after billed failure, attempt cap
- old: R341 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-14 · superseded-by: —

**Why.** A failure that cost gas is retried once; more retries are a grief vector.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 147.

### NODE-LANE-15 — Per-subject grief score, every family
- old: R342 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-15 · superseded-by: —

**Why.** Subjects that repeatedly cost us gas get throttled, on every family.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 148.

### NODE-LANE-16 — Signed fields read from the payload
- old: R344 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-16 · superseded-by: —

**Why.** The payload is what the chain executes; read fields from it.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 150.

### NODE-LANE-17 — Value out per job capped
- old: R345 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-17 · superseded-by: —

**Why.** Value out of the lane must be capped per job.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 151.

### NODE-LANE-18 — Lane-funded deposits refunded or bounded
- old: R346 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-18 · superseded-by: —

**Why.** Deposits funded by the lane must come back or stay bounded.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 152.

### NODE-LANE-19 — Adapter journals live in the store
- old: R347 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-19 · superseded-by: —

**Why.** Adapter journals in the store survive restarts and restores with the rest.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 153.

### NODE-LANE-20 — One custody key per family
- old: R349 · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-20 · superseded-by: —

**Why.** Raw-digest signing on several families needs exactly one custody key per family.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 155.

### NODE-LANE-21 — outer_tx row for every signed tx
- old: NI:I8(outer-tx) · status: open · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-21 · superseded-by: —

**Why.** Every signed transaction gets a row so none is lost from tracking; default applied.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1619.

### NODE-LANE-22 — Node simulates unwrap jobs, never batches them
- old: R148(node) · status: current · owner: yes · date: 2026-10-08 · normative: node/submit-lanes.md#NODE-LANE-22 · superseded-by: —

Change: a gasless unwrap is `mtxExecute` with the token's allowlisted `unwrap` calldata (`to = value = 0`); the pseudo-op and `mtxUnwrap*` are transitional. Source add: §3 MG-2, MG-3, §7 CTR-MTX-12.

### NODE-LANE-23 — Simulation gate before every broadcast
- old: — · status: current · owner: no · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-23 · superseded-by: —

**Why.** Simulating before broadcast keeps predictable reverts from spending gas; a simulation that cannot run fails closed.
**Cost if wrong.** Some reverts remain (state changes between simulation and inclusion); they are measured (W3B-02).

### NODE-LANE-24 — Per-lane in-flight depth: tunable default 16
- old: — · status: current · owner: yes · date: 2026-10-07 · normative: node/submit-lanes.md#NODE-LANE-24 · superseded-by: —

**Owner ruling (2026-10-07).** `max_inflight = 16` stays as a tunable default (per-chain config `[[chains]] max_inflight`), not a design constant.
**Why.** 16 is the default per-sender pending limit of common execution clients (`txpool.accountslots`); chains differ, so the depth is configuration.
**Cost if wrong.** Too high: transactions beyond the pool limit are dropped and must be replaced; too low: lane throughput is capped below what the chain allows.

### NODE-LANE-25 — Breaker per (from, selector) for self-calls
- old: — · status: current · owner: no · date: 2026-10-08 · normative: node/submit-lanes.md#NODE-LANE-25 · superseded-by: —

**Why.** A self-call can pass simulation and fail on chain for reasons specific to one function (paused wraps during a rate change, reserve level, a confidential send counter, a signer front-running its own intent); a per-subject counter alone would also block that subject's unrelated payments.
**Cost if wrong.** Relayer gas drained by one subject repeating one failing call, or a subject's payments throttled for an unrelated wrap failure.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §3 MG-6; §12 M11.

Under "Node — Gateway":

### NODE-LANE-80 — Six-member Family enum
- old: R58(family-enum) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: ARCH-POS-02

It said: six-member Family enum.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 531.

## 6. Node — Indexer and feeds

### NODE-IDX-01 — Finality quorum over normalized event sets
- old: CR-PD-2, CR-R3-2 · status: current · owner: no · date: 2026-10-07 · normative: node/indexer-feeds.md#NODE-IDX-01 · superseded-by: —

**Why.** Comparing one block hash cannot detect a provider that drops or invents logs; comparing the normalized event set can.
**Cost if wrong.** A lying RPC books fake payments.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 878; [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 275; [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 646.

### NODE-IDX-02 — Node decides finality: depth or tag
- old: R11(gate) · status: current · owner: no · date: 2026-10-06 · normative: node/indexer-feeds.md#NODE-IDX-02 · superseded-by: —

**Why.** Finality differs per family; the node, not the client, applies the right rule.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 699.

### NODE-IDX-03 — No reorg handling after hard finality
- old: R12 · status: current · owner: no · date: 2026-10-03 · normative: node/indexer-feeds.md#NODE-IDX-03 · superseded-by: —

**Why.** Hard finality is the model's base; reorg handling after it would add complexity for an event outside the model.
**Cost if wrong.** A violation needs manual reconciliation (runbook).
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 703.

### NODE-IDX-04 — Change feeds for jobs and events
- old: R93 · status: current · owner: no · date: 2026-10-06 · normative: node/indexer-feeds.md#NODE-IDX-04 · superseded-by: —

**Why.** Clients poll two cursors (jobs, events) instead of receiving callbacks the node must retry.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 115.

### NODE-IDX-05 — Event feed items equal ingest arguments
- old: R94 · status: current · owner: no · date: 2026-10-06 · normative: node/indexer-feeds.md#NODE-IDX-05 · superseded-by: —

**Why.** Feed items carry exactly what the ingest needs, so clients do not re-read the chain.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 116.

### NODE-IDX-06 — Repeated entryRef: node flags, client checks
- old: NI:I6 · status: current · owner: yes · date: 2026-10-07 · normative: node/indexer-feeds.md#NODE-IDX-06 · superseded-by: —

**Why.** Owner: both — the client system must know about an overpayment so that the business can later decide to refund the payer. The node already indexes every `PaymentSettled`, so one uniqueness check per `(chain_key, token, entryRef)` serves every client; the client keeps its own check because a node only knows the history it has indexed. The field name `repeat_of` is chosen here.
**Cost if wrong.** Without the flag each client re-implements duplicate detection and some miss overpayments; without the client check a new or restored node would hide a repeat whose first payment it never indexed.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1615.

### NODE-IDX-07 — Second independent event source
- old: reorg:Q7 · status: open · owner: yes · date: 2026-10-07 · normative: node/indexer-feeds.md#NODE-IDX-07 · superseded-by: —

**Why.** A compromised node can lie on its feed; a second independent source would detect it.
**Cost if wrong.** Planned.
**Source.** [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) line 1221.

### NODE-IDX-80 — Quorum on one block hash
- old: R11(quorum) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NODE-IDX-01

It said: quorum on one block hash.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 699.

## 7. Node — Gateway

### NODE-GW-01 — Door A is not a free gas faucet
- old: CR-PD-3 · status: current · owner: no · date: 2026-10-07 · normative: node/gateway.md#NODE-GW-01 · superseded-by: —

**Why.** A public door that relays fee-0 intents from fresh keys is a free gas faucet.
**Cost if wrong.** Lane gas drained, breaker trips.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 891.

### NODE-GW-02 — Gateway auth bearer or hmac
- old: R54 · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-02 · superseded-by: —

**Why.** Operators choose an open or authenticated door; one credential kind per listener.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 527.

### NODE-GW-03 — Gateway call jobs only for UA registration
- old: R320 · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-03 · superseded-by: —

**Why.** Only UA registration needs a call through the gateway; everything else is signed by subjects.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 137.

### NODE-GW-04 — Gateway CORS only with auth none
- old: R328 · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-04 · superseded-by: —

**Why.** Browsers may call an open gateway directly; with credentials, CORS would expose them.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 145.

### NODE-GW-05 — Gateway info route, CORS, error contract
- old: R159(gateway) · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-05 · superseded-by: —

**Why.** Clients discover what a gateway serves before they sign.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 113.

### NODE-GW-06 — Stable gateway error contract
- old: R178 · status: current · owner: no · date: 2026-10-06 · normative: node/gateway.md#NODE-GW-06 · superseded-by: —

**Why.** Wallets and apps branch on error codes; a stable contract keeps them working across releases.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 132.

### NODE-GW-07 — Every SCaaS contract bound to the chain's chain_uid
- old: — · status: current · owner: no · date: 2026-10-08 · normative: node/gateway.md#NODE-GW-07 · superseded-by: —

**Why.** `chain_uid` is the salt of every SCaaS domain; a contract cannot read its own genesis hash after block 256, so a wrong constructor value can only be caught off chain. The node compares each contract's `chainUid()` with the RPC's genesis hash and the profile at activation and every start, and reads per-user wallets and accounts before relaying for them.
**Cost if wrong.** Correct signatures fail on a mis-deployed contract, or — if the value equals another chain's — signatures replay across chains.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §3 MG-4, MG-6; §13 L-12(b).

Under "Node — DEX venue":

### NODE-GW-80 — Three intake doors with trust levels
- old: UD:§22.2 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05, NODE-GSP-01, NODE-GSP-04

It said: three intake doors with trust levels.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1750.

## 8. Node — Admin and auth

### NODE-ADM-01 — Gossip admin routes and columns
- old: R127(admin) · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-01 · superseded-by: —

**Why.** Gossip state (peers, scores, bans, trust) is operator data like any other; one admin surface keeps one auth and audit path.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 88.

### NODE-ADM-02 — Admin auth: built-in users plus optional OIDC
- old: R106 · status: current · owner: yes · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-02 · superseded-by: —

**Why.** Small deployments need no IdP; organisations with one get SSO. Two modes, one role model.
**Cost if wrong.** A deployment without OIDC relies on node passwords; Argon2id and lockout bound guessing.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 130; [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 1021.

### NODE-ADM-03 — OIDC JWT validation rules
- old: R106a(oidc) · status: current · owner: yes · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-03 · superseded-by: —

**Why.** A strict, allowlisted validator closes the known JWT confusion attacks (alg, key, audience, ID-token-as-access).
**Cost if wrong.** A lax check is an admin takeover.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 131.

### NODE-ADM-04 — Admin roles and no escalation
- old: R107 · status: current · owner: yes · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-04 · superseded-by: —

**Why.** Separating config power from credential power makes fee redirection or key minting a two-role act.
**Cost if wrong.** One person holding both can still misuse; the RACI procedure covers it.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 132.

### NODE-ADM-05 — Bootstrap and break-glass via host CLI
- old: R108 · status: current · owner: yes · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-05 · superseded-by: —

**Why.** The first admin and recovery must work with no running API and no IdP; host access already implies full power.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 133.

### NODE-ADM-06 — API keys and admin credentials never cross
- old: R109 · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-06 · superseded-by: —

**Why.** A leaked client key must never reach configuration, and admin credentials must never be scripted into clients.
**Cost if wrong.** Mixing them turns a client compromise into a node compromise.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 134.

### NODE-ADM-07 — Hash-chained audit log per mutation
- old: R110(audit) · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-07 · superseded-by: —

**Why.** A hash chain makes silent edits of the audit table detectable; the off-host log mirror survives store loss.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 135.

### NODE-ADM-08 — Admin-user mutations never exceed caller
- old: R322 · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-08 · superseded-by: —

**Why.** Without the superset rule an operator could create or reset a stronger admin and take over.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 139.

### NODE-ADM-09 — LAST_ADMIN counts built-in users only
- old: NI:I8(last-admin) · status: open · owner: no · date: 2026-10-07 · normative: node/admin-auth.md#NODE-ADM-09 · superseded-by: —

**Why.** OIDC callers are not node users; counting them would let an IdP change lock the node out.
**Cost if wrong.** Default applied; an owner may revisit.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1619.

### NODE-ADM-10 — App serving with CSP on admin listener
- old: R159(serving) · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-10 · superseded-by: —

**Why.** Serving the console from the node avoids a second web host; a strict CSP bounds script injection.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 113.

### NODE-ADM-11 — App served only on admin listener
- old: R160 · status: current · owner: no · date: 2026-10-06 · normative: node/admin-auth.md#NODE-ADM-11 · superseded-by: —

**Why.** The public listeners stay API-only; static files there would widen their attack surface.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 114.

### NODE-ADM-80 — JWS verification on ring
- old: R106a(ring) · status: superseded · owner: yes · date: 2026-10-06 · normative: — · superseded-by: NODE-GSP-03

It said: jWS verification on ring.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 131.

## 9. Node — Sponsorship

### NODE-SPN-01 — Sponsorship policy is a node store row
- old: R189 · status: current · owner: yes · date: 2026-10-07 · normative: node/sponsorship.md#NODE-SPN-01 · superseded-by: —

**Why.** Sponsorship is an operator choice, configured as data, matched per job.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 132.

### NODE-SPN-02 — Budget unit, reservation and rate counters
- old: R190 · status: current · owner: no · date: 2026-10-07 · normative: node/sponsorship.md#NODE-SPN-02 · superseded-by: —

**Why.** Budgets in native units are exact; reservations at accept prevent overspend.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 152.

### NODE-SPN-03 — Sponsorship admin routes and audit
- old: R191 · status: current · owner: no · date: 2026-10-06 · normative: node/sponsorship.md#NODE-SPN-03 · superseded-by: —

**Why.** Sponsorship changes spend money; they are admin-only and audited.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 167.

### NODE-SPN-04 — SponsorshipPool opt-in contract, mesh fee-only
- old: R194 · status: current · owner: no · date: 2026-10-06 · normative: node/sponsorship.md#NODE-SPN-04 · superseded-by: —

**Why.** An on-chain pool lets sponsors fund relays without trusting one node; on the mesh only the fee path applies.
**Cost if wrong.** Planned.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 199.

## 10. Node — DEX venue

### NODE-DEX-01 — Durable off-chain book, price-time, partial fills
- old: R35(book) · status: current · owner: yes · date: 2026-10-08 · normative: node/dex-venue.md#NODE-DEX-01 · superseded-by: —

Change: settlement is `mtxSettle` (one taker against one or more makers, NODE-DEX-15). Source add: §3 MG-8.3.

### NODE-DEX-02 — Failed matches attributed by evidence; (as built) fee token limited
- old: RS5-13 · status: current · owner: no · date: 2026-10-08 · normative: node/dex-venue.md#NODE-DEX-02 · superseded-by: —

Change: attribution reads the `orderHash` in token and DEX errors of `mtxSettle`; with no separate relayer fee the fee-token limit applies to the built venue only. Source add: §3 MG-8.2, MG-8.3, §7 CTR-DEX-06.

### NODE-DEX-03 — No WebSocket; clients poll
- old: RS5-5 · status: current · owner: no · date: 2026-10-03 · normative: node/dex-venue.md#NODE-DEX-03 · superseded-by: —

**Why.** Polling is enough for book depth and trades and keeps the node free of long-lived push connections.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 406.

### NODE-DEX-04 — DEX watcher has its own cursor
- old: RS5-8 · status: current · owner: no · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-04 · superseded-by: —

**Why.** The DEX watcher reads different events at a different pace; its own cursor keeps it independent of the main indexer.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 410.

### NODE-DEX-05 — Rounding dust: skip and remove dust makers
- old: RS5-12 · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-05 · superseded-by: —

**Why.** Fills that round to zero cannot settle; skipping and removing dust makers keeps the book matchable.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 420.

### NODE-DEX-06 — OOG ERC-1271 orders are never restored
- old: RS5-14(node) · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-06 · superseded-by: —

**Why.** An ERC-1271 check that ran out of gas cannot be proven valid again; restoring it would loop failures.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 431.

### NODE-DEX-07 — Committed balance includes unsettled fills
- old: RS5-16 · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-07 · superseded-by: —

**Why.** Counting unsettled fills in the committed balance prevents over-commitment of one maker's funds.
**Cost if wrong.** Without it a maker can be matched beyond what it holds.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 442.

### NODE-DEX-08 — Re-check on-chain market every poll
- old: RS5-17 · status: current · owner: no · date: 2026-10-08 · normative: node/dex-venue.md#NODE-DEX-08 · superseded-by: —

Change: with signed per-order fees the check covers listing, recorded token kinds and the fee split. Source add: §3 MG-8.3 (admin powers), MG-8.4.

### NODE-DEX-09 — IOC single maker on Move/Solana
- old: RS5-18 · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-09 · superseded-by: —

**Why.** Move and Solana settle one maker per transaction; multi-maker IOC would need atomicity they lack.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 446.

### NODE-DEX-10 — Late settled trade debits restored order
- old: RS5-20(r105) · status: current · owner: no · date: 2026-10-07 · normative: node/dex-venue.md#NODE-DEX-10 · superseded-by: —

**Why.** A trade that settles after its order was restored must still reduce that order, else it is filled twice.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 449.

### NODE-DEX-11 — Managed markets: home-bound, eligibility at intake
- old: R214(node) · status: current · owner: yes · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-11 · superseded-by: —

**Why.** Managed markets enforce eligibility on chain; checking at intake avoids matches that would revert.
**Source.** [history/specs/2026-10-06-asset-suite-design.md](history/specs/2026-10-06-asset-suite-design.md) line 176.

### NODE-DEX-12 — DEX book gossip, two order modes
- old: R124 · status: current · owner: yes · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-12 · superseded-by: —

**Why.** Book gossip lets several venues show one market; two modes separate home-bound orders from settle-by-anyone orders.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 85.

### NODE-DEX-13 — DEX homes trusted automatically
- old: R128 · status: current · owner: yes · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-13 · superseded-by: —

**Why.** Wallets need a default set of homes that settle honestly; trust is earned from chain-credited settles.
**Cost if wrong.** Auto-trust can be farmed; the credit rules bound it.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 89.

### NODE-DEX-14 — DEX book lives in the node store
- old: R105 · status: current · owner: no · date: 2026-10-06 · normative: node/dex-venue.md#NODE-DEX-14 · superseded-by: —

**Why.** The book belongs to the node's single store, with one owner and one backup story.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 129.

### NODE-DEX-15 — mtxSettle over role-free TradeOrders; the venue arranges taker and makers
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: node/dex-venue.md#NODE-DEX-15 · superseded-by: —

**Why.** Owner rulings: SCaaS legs are token-verified orders with no maker allowance; an order carries no role (the node or submitter decides taker and makers at settlement), keeps `relayer` as the matching party, adds `dex` as the only place funds go, signs one `fee` rate, and every order in a settlement fills at least `max(minFill, 50 %)`. The book keeps price-time; per-role pricing is venue intake policy, not an on-chain setting.
**Cost if wrong.** The venue builds settlements the contracts refuse (minimum fill, fee bound), charges a role rate the signer never accepted, or misses that a one-settlement FOK may span several makers.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §2 A7, A10, A12–A15; §3 MG-8.1–MG-8.4.
Change (2026-10-08): outside legs are funded by an allowance to the DEX's `DexPuller`; intake reads `allowance(from, puller)`. Source add: `history/specs/2026-10-08-dex-exchange-design.md` §3 DS-4.

### NODE-DEX-16 — The venue serves only DEXes on the chain profile's DEX list
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: node/dex-venue.md#NODE-DEX-16 · superseded-by: —

**Why.** The token requires only that `dex` is a contract; a contract made to look like a DEX can report any fill and take the signed amount. The owner accepted that residual risk (2026-10-08) and placed the defence off chain: the node never routes, settles, replicates or lists an order for an unlisted DEX.
**Cost if wrong.** The node lends its relay and its book to a phishing contract.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §4 (phishing `dex`), §3 MG-6; §8 Q5; §13 N-H1.

Under "Networks — common model":

### NODE-DEX-17 — TradeEngine: exchange-only intake, book first, AMM routes, fees by role
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: node/dex-venue.md#NODE-DEX-17 · superseded-by: —

**Why.** The node runs its own algorithm over the same orders (owner): book matching first, then coincidences of wants and AMM routes (quoted by `eth_call`, at most 3 hops, cycles), resting orders filled through AMMs when a route reaches their limit; a floor below the quote by a buffer costs the signer nothing because the surplus comes back; exchange-only orders (no listed market, or a cycle) never rest in the book. Off unless the chain enables it.
**Cost if wrong.** Without a book-first rule the venue pays pool fees for liquidity it already holds; without the intake split a cycle order would rest in a book that can never match it.
**Source.** `history/specs/2026-10-08-dex-exchange-design.md` §2 S3, §3 DS-7.

### NODE-DEX-18 — The node keeps no surplus: income is the relayer share of the signed fee
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: node/dex-venue.md#NODE-DEX-18 · superseded-by: —

**Why.** Owner: the surplus is the signer's and the node's income is only the relayer share. The contract pays all output that reaches the DEX to the signers; what it cannot see is output routed elsewhere, so the node never sets a swap recipient outside the DEX and publishes quote and result per plan (`/v1/dex/exchanges/{ref}`).
**Cost if wrong.** A node that keeps part of the route output turns its quote into a hidden fee on top of the signed one.
**Source.** `history/specs/2026-10-08-dex-exchange-design.md` §2 S4, S6, §3 DS-7.

### NODE-DEX-80 — DEX book persisted in ERP
- old: RS5-2 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NODE-DEX-14

It said: dEX book persisted in ERP.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 400; [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 13.

### NODE-DEX-81 — Book accepts only own-relayer orders
- old: RS5-9 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NODE-DEX-12

It said: book accepts only own-relayer orders.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 411; [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 15.

### NODE-DEX-82 — DEX chains run one lane only
- old: RS5-11 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NODE-JOB-08

It said: dEX chains run one lane only.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 414; [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 16.

## 11. Node — Mesh

### NODE-MESH-01 — Pull bus for admitted peers
- old: R70 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-01 · superseded-by: —

**Why.** Admitted partners exchange intents by pull; the receiver controls its load.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 70.

### NODE-MESH-02 — Commit-ordered bus seq and store id
- old: R71(seq) · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-02 · superseded-by: —

**Why.** A commit-ordered seq gives gap-free cursors; a new store id resets them after a restore.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 71.

### NODE-MESH-03 — mTLS peers pinned by SPKI, Ed25519
- old: R72 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-03 · superseded-by: —

**Why.** SPKI pins need no CA and identify peers by key.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 72.

### NODE-MESH-04 — Origin is in its own round-robin
- old: MESH:I1, MESH:I2, MESH:I3, R74, UD:§22.5 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-04 · superseded-by: —

**Why.** Round-robin exclusivity shares submissions fairly; the origin takes its turn too.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 1386; [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 1387; [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 1388; [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 74; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1842.

### NODE-MESH-05 — Mesh reward is the intent fee only
- old: R75 · status: current · owner: yes · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-05 · superseded-by: —

**Why.** The intent fee is the only reward; no token, no extra economics.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 75.

### NODE-MESH-06 — Chain profile, default private
- old: R76 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-06 · superseded-by: —

**Why.** Chains default to private so nothing leaks before an operator opts in.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 76.

### NODE-MESH-07 — Families on the bus; Soroban out
- old: R77 · status: current · owner: yes · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-07 · superseded-by: —

**Why.** v1 covers families whose intents are self-contained; Soroban is not.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 77.

### NODE-MESH-08 — intent_id is the contract digest
- old: R78 · status: current · owner: yes · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-08 · superseded-by: —

**Why.** Using the contract's digest as id lets every node dedupe and match events without a separate registry.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 78.

### NODE-MESH-09 — Envelope spec scaas-intent/1.2
- old: R81 · status: current · owner: no · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-09 · superseded-by: —

**Why.** A versioned, public envelope lets independent implementations interoperate.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 81.

### NODE-MESH-10 — Mesh numbers, all config
- old: R82 · status: current · owner: no · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-10 · superseded-by: —

**Why.** All mesh numbers are configuration, with published defaults.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 82.

### NODE-MESH-11 — Multi-process one-binary test topology
- old: R83, UD:§21.3 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-11 · superseded-by: —

**Why.** Several processes of one binary test the mesh as deployed. Two processes of one binary with different configuration catch wire-format errors but not misreadings of the spec; only the public conformance vectors stand in for a second implementation, so they must be complete, not token.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 83; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1365.

### NODE-MESH-12 — Private rows served only by origin
- old: R85 · status: current · owner: no · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-12 · superseded-by: —

**Why.** Private rows never leave their origin, so no forwarder can leak them.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 85.

### NODE-MESH-13 — may_submit needs a registered token
- old: R86, UD:§22.6 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-13 · superseded-by: —

**Why.** A node only submits for tokens it knows and has registered.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 86; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1877.

### NODE-MESH-14 — Missing policy row means forward only
- old: MESH:I4 · status: current · owner: yes · date: 2026-10-05 · normative: node/mesh.md#NODE-MESH-14 · superseded-by: —

**Why.** Without a policy row the safe default is forward-only.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 1389.

### NODE-MESH-15 — Bus scope arrives per job
- old: R99 · status: current · owner: yes · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-15 · superseded-by: —

**Why.** Bus scope belongs to each job, set by its producer.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 123; [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 1020.

### NODE-MESH-16 — Verify signatures before any chain call
- old: R343 · status: current · owner: no · date: 2026-10-07 · normative: node/mesh.md#NODE-MESH-16 · superseded-by: —

**Why.** Signature checks before chain calls stop forged intents from costing RPC.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 149.

### NODE-MESH-17 — receiver_fee jobs use restricted bus scope
- old: R193(node) · status: current · owner: no · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-17 · superseded-by: —

**Why.** A receiver-fee co-signature must not travel to open peers.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 181.

### NODE-MESH-18 — UA intents in scaas-intent/1.3
- old: R316 · status: current · owner: no · date: 2026-10-06 · normative: node/mesh.md#NODE-MESH-18 · superseded-by: —

**Why.** UA intents need a different body; a minor version keeps old nodes safe.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 320.

### NODE-MESH-19 — Fee-0 intents allowed; acceptance policy decides
- old: UD:§3.4b · status: current · owner: yes · date: 2026-08-30 · normative: node/mesh.md#NODE-MESH-19 · superseded-by: —

**Why.** Fee-0 intents are legitimate for sponsored or B2B flows; the acceptance policy decides.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 179.

### NODE-MESH-20 — Node is a capability matrix, not modes
- old: UD:§21.4 · status: current · owner: yes · date: 2026-08-31 · normative: node/README.md#NODE-MESH-20 · superseded-by: —

**Why.** Capabilities combine freely; fixed modes would need a second implementation. The earlier "Mode 1 / mode 2" split suggested a global enum, while there are three independent axes (ingest, pool, submit) and submit varies per `(chain, contract)`: a node may submit on one chain and only forward for another. The gateway shape is the old "mode 1". The research shapes "private pool" and "private relayer" (a private-mempool pair) showed that the mesh needs a pull mode next to gossip, with an explicit peer allowlist instead of discovery; the bus pull with pinned peers is that mode (the research table had called the mesh module "ingest + pool" and assumed gossip). Two queues shared the name "pool": the mesh-facing intent queue and the submit job queue, which exists even when nothing is pooled; the research note named "relay-pool" described the second. The store is now the mesh-facing queue.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1394.

### NODE-MESH-21 — One policy lookup table, static columns
- old: UD:§22.4 · status: current · owner: yes · date: 2026-08-31 · normative: node/mesh.md#NODE-MESH-21 · superseded-by: —

**Why.** One lookup with static columns keeps acceptance cheap and predictable.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1817.

### NODE-MESH-22 — Open lifecycle questions
- old: UD:§22.10 · status: open · owner: yes · date: 2026-08-31 · normative: node/mesh.md#NODE-MESH-22 · superseded-by: —

**Why.** Two lifecycle questions stay open until real traffic answers them.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1997.

### NODE-MESH-23 — MAX_HOPS = 4 is arbitrary
- old: UD:§22.10.1 · status: open · owner: yes · date: 2026-08-31 · normative: node/mesh.md#NODE-MESH-23 · superseded-by: —

**Why.** Four hops is a guess; re-tuned after a multi-site run. "Arbitrary" marks a number with no measurement behind it; node docs label such defaults so they are re-tuned after a measured run.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1999.

### NODE-MESH-24 — Soroban stays on the job API, not the mesh
- old: reorg:Q6 · status: open · owner: yes · date: 2026-10-07 · normative: node/mesh.md#NODE-MESH-24 · superseded-by: —

**Why.** Soroban intents need simulation footprints a forwarder cannot verify; job API only until a design exists.
**Cost if wrong.** Default applied.
**Source.** [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) line 1220.

### NODE-MESH-80 — R68-R69 left unused
- old: R68, R69 · status: unused · owner: no · date: 2026-10-05 · normative: — · superseded-by: —

Numbers left unused in the old scheme; registered so the alias index is complete.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 5.

### NODE-MESH-81 — Mesh SQLite store, ERP control plane
- old: R71(store) · status: superseded · owner: yes · date: 2026-10-05 · normative: — · superseded-by: ARCH-POS-05, NODE-STO-04, NODE-JOB-02, NODE-DEX-14, NODE-STO-06

It said: mesh SQLite store, ERP control plane.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 71.

### NODE-MESH-82 — Acceptance policy authoritative in ERP
- old: R79 · status: superseded · owner: yes · date: 2026-10-05 · normative: — · superseded-by: NODE-STO-03, NODE-MESH-15

It said: acceptance policy authoritative in ERP.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 79.

### NODE-MESH-83 — Open relayer: two modes, two implementations
- old: UD:§21 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: NODE-MESH-20, ARCH-POS-05

It said: open relayer: two modes, two implementations.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1304.

### NODE-MESH-84 — Relay-only vs network-node modes
- old: UD:§21.1 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: NODE-MESH-20

It said: relay-only vs network-node modes.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1316.

### NODE-MESH-85 — Lifecycle common to Rust and ERP nodes
- old: UD:§22 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05

It said: lifecycle common to Rust and ERP nodes.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1671.

### NODE-MESH-86 — Queue clocks and promote-after window
- old: UD:§22.7 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: INT-ERP-15, NODE-MESH-10

It said: queue clocks and promote-after window.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1912.

### NODE-MESH-87 — promote_after vs 300 s ERC-20 expiry
- old: UD:§22.10.2 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: INT-ERP-15

It said: promote_after vs 300 s ERC-20 expiry.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2001.

### NODE-MESH-88 — Callback subject registry on public nodes
- old: UD:§22.10.4 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: NODE-IDX-04, ARCH-POS-05

It said: callback subject registry on public nodes.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2008.

## 12. Node — Gossip

### NODE-GSP-01 — Gossip required alongside the pull bus
- old: R112, UD:§6 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-01 · superseded-by: —

**Why.** The pull bus covers admitted partners; gossip reaches the open network. Both are needed. The open network uses libp2p gossipsub v1.1 instead of a home-grown protocol: it is the stack the ERC-4337 shared mempool mandates (`eth-infinitism/bundler-spec/p2p-specs/p2p-interface.md`), and its peer scoring is the network-layer anti-spam primitive; intents are validated before they are forwarded, so spam costs real money.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 73; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 224.

### NODE-GSP-02 — Selectable carriers; admitted peers PQ only
- old: R113 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-02 · superseded-by: —

**Why.** QUIC is the default; TCP covers networks that block UDP. Admitted peers carry private data, so PQ only.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 74.

### NODE-GSP-03 — PQ key exchange via aws-lc-rs, classical identity
- old: R114 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-03 · superseded-by: —

**Why.** Harvest-now-decrypt-later threatens key exchange today; identity forgery needs a live quantum attacker. One crypto library keeps the build small.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 75.

### NODE-GSP-04 — Wire names and topics use scaas and chain_key
- old: R115 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-04 · superseded-by: —

**Why.** Product-neutral names and chain keys make topics unambiguous across networks.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 76.

### NODE-GSP-05 — One Ed25519 node key for all identities
- old: R116 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-05 · superseded-by: —

**Why.** One key and separate signing contexts make rotation one action and keep signatures non-interchangeable.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 77.

### NODE-GSP-06 — Gossip wire is bus JSON, content message-id
- old: R117 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-06 · superseded-by: —

**Why.** Reusing the bus JSON keeps one codec; a content-addressed message id makes duplicates collapse.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 78.

### NODE-GSP-07 — Gossip validation pipeline and Reject rule
- old: R118, UD:§22.3 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-07 · superseded-by: —

**Why.** Rejects cost the sender score; only faults decidable from the bytes may reject, so honest peers are never punished. Checking the meta nonce with `eth_call` at receipt is exact but does not run at gossip speed: a node receiving 500 intents a second would make 500 RPC calls a second just to filter garbage. The freshness check is therefore one batched read, off the event loop and failing open for forwarding.
**Cost if wrong.** Over-rejecting eclipses a node by itself.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 79; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1767.

### NODE-GSP-08 — Peer scoring and limits
- old: R119 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-08 · superseded-by: —

**Why.** Fixed, published scoring numbers make peer behaviour predictable and testable.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 80.

### NODE-GSP-09 — Own Kademlia DHT with dial filter
- old: R120 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-09 · superseded-by: —

**Why.** An own DHT namespace and dial filter stop the node from being used to scan private networks.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 81.

### NODE-GSP-10 — Exclusivity over gossip, automatic trust
- old: R121 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-10 · superseded-by: —

**Why.** Exclusivity reduces duplicate submissions; automatic trust requires a chain-credited track record.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 82.

### NODE-GSP-11 — Landed hints only trigger a chain read
- old: R122 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-11 · superseded-by: —

**Why.** A hint can be false; only a chain read may change state.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 83.

### NODE-GSP-12 — Signed versioned announce
- old: R123 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-12 · superseded-by: —

**Why.** Announces are signed and versioned so replays and rollbacks are refused.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 84.

### NODE-GSP-13 — Anti-entropy sync protocol
- old: R125 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-13 · superseded-by: —

**Why.** Anti-entropy fills gaps after partitions without replaying the whole pool.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 86.

### NODE-GSP-14 — Gossip crates and resource budget
- old: R126 · status: current · owner: yes · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-14 · superseded-by: —

**Why.** Pinned crates and a resource budget keep gossip from crowding the host.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 87.

### NODE-GSP-15 — Native UA verification before gossip
- old: R317 · status: current · owner: no · date: 2026-10-06 · normative: node/gossip.md#NODE-GSP-15 · superseded-by: —

**Why.** UA intents must be verified natively before forwarding, else invalid ones spread.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 327.

### NODE-GSP-16 — Sybil resistance of forward scoring
- old: UD:§22.10.3 · status: open · owner: yes · date: 2026-08-31 · normative: node/gossip.md#NODE-GSP-16 · superseded-by: —

**Why.** Forward scoring can be gamed by Sybils; no known cheap fix.
**Cost if wrong.** Open.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2004.

### NODE-GSP-80 — rustls ring crypto provider
- old: — · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NODE-GSP-03

An earlier design used the rustls ring provider for TLS; replaced by aws-lc-rs for PQ key exchange.

## 13. Node — Operations

### NODE-OPS-01 — readyz and metrics on admin port
- old: R51 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-01 · superseded-by: —

**Why.** Monitoring must not depend on the public gateway; the admin port always exists.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 524.

### NODE-OPS-02 — Gossip metrics
- old: R127(metrics) · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-02 · superseded-by: —

**Why.** Gossip health is visible without per-peer labels, which would be unbounded.
**Source.** [history/specs/2026-10-06-mesh-gossip-amendment.md](history/specs/2026-10-06-mesh-gossip-amendment.md) line 88.

### NODE-OPS-03 — Prometheus metrics, label allowlist
- old: R230 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-03 · superseded-by: —

**Why.** A hand-written renderer avoids a dependency; the label allowlist keeps cardinality bounded.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 61.

### NODE-OPS-04 — SLOs evaluated outside the node
- old: R231 · status: current · owner: yes · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-04 · superseded-by: —

**Why.** Monitoring on the monitored host fails with it; an external dead-man's switch catches that.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 71.

### NODE-OPS-05 — Three severities
- old: R232 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-05 · superseded-by: —

**Why.** Pages that do not mean integrity or outage train people to ignore pages.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 77.

### NODE-OPS-06 — W3B as the node measures it
- old: R233 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-06 · superseded-by: —

**Why.** Each job counts once; landed-elsewhere is success; a revert streak opens a breaker.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 79.

### NODE-OPS-07 — Job stage timing metric
- old: R234 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-07 · superseded-by: —

**Why.** Stage timings show where latency comes from; in-memory samples lost on restart are acceptable.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 92.

### NODE-OPS-08 — Ops watch for registered tokens
- old: R235 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-08 · superseded-by: —

**Why.** Leg backing needs node data; code-hash pins need none, so they stay outside the node.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 99.

### NODE-OPS-09 — Traces without OpenTelemetry SDK
- old: R236 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-09 · superseded-by: —

**Why.** OpenTelemetry would be the heaviest dependency set; logs plus job events already trace a job.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 109.

### NODE-OPS-10 — JSON logs, redaction, retention
- old: R237 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-10 · superseded-by: —

**Why.** Logs must never carry personal or secret data; retention bounds what a node holds.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 114.

### NODE-OPS-11 — FinOps measurement and usage_day
- old: R238 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-11 · superseded-by: —

**Why.** Jobs are purged after 30 days; a durable daily rollup keeps a fiscal year of cost data.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 124.

### NODE-OPS-12 — Integrity rechecks of index and audit
- old: R242 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-12 · superseded-by: —

**Why.** A finality violation or audit break is a human-judgement event; holding stops the damage.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 162.

### NODE-OPS-13 — Capacity rating and label caps
- old: R244 · status: current · owner: no · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-13 · superseded-by: —

**Why.** Unbounded labels are a monitoring outage; caps are constants.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 176.

### NODE-OPS-14 — Subject denylist, operator choice
- old: R246 · status: current · owner: yes · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-14 · superseded-by: —

**Why.** An order binds the operator it is addressed to; a precise, evidenced lever beats pausing a namespace.
**Cost if wrong.** No on-chain effect; the party can use other operators.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 185.

### NODE-OPS-15 — Operators independent; ops are recommendations
- old: R247, UD:§13.1 · status: current · owner: yes · date: 2026-10-06 · normative: node/ops.md#NODE-OPS-15 · superseded-by: —

**Why.** Contracts carry the guarantees; node operators are independent and set their own policies.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 192; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 706.

### NODE-OPS-16 — OPS default numbers approved as stated
- old: reorg:Q8 · status: current · owner: yes · date: 2026-10-07 · normative: node/ops.md#NODE-OPS-16 · superseded-by: —

**Why.** Defaults are needed to start; each stays operator-tunable.
**Source.** [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) line 1222.

## 14. Node — Runbooks

### NODE-RUN-01 — RACI roles
- old: R239 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-01 · superseded-by: —

**Why.** Separating credential power from config power, and roles across keys, bounds single-person misuse.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 130.

### NODE-RUN-02 — Restore is fixed and starts paused
- old: R240 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-02 · superseded-by: —

**Why.** A restored store holds jobs cancelled after the backup; starting paused gives clients time to cancel them.
**Cost if wrong.** One manual resume per chain.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 137.

### NODE-RUN-03 — CLI lane accept-nonce
- old: R241 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-03 · superseded-by: —

**Why.** After a restore the chain is ahead of the journal; adopting nonces is the only way back besides a new lane.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 148.

### NODE-RUN-04 — DR drills scheduled and exported
- old: R243 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-04 · superseded-by: —

**Why.** An untested restore is not a restore.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 172.

### NODE-RUN-05 — Incident command by accountable role
- old: R245 · status: current · owner: no · date: 2026-10-06 · normative: node/runbooks.md#NODE-RUN-05 · superseded-by: —

**Why.** The accountable role of the failing component leads; evidence first, no silent rewinds.
**Source.** [history/specs/2026-10-06-operations-design.md](history/specs/2026-10-06-operations-design.md) line 180.

## 15. Node — Threat model

### NODE-SEC-01 — Merge processes, not privileges
- old: — · status: current · owner: no · date: 2026-10-07 · normative: node/threat-model.md#NODE-SEC-01 · superseded-by: —

**Why.** One process can still keep trust boundaries; bounding each credential to its listener limits compromise.

### NODE-SEC-80 — Separate DB roles per module
- old: UD:§23.4 · status: superseded · owner: yes · date: 2026-08-31 · normative: — · superseded-by: ARCH-POS-05, NODE-STO-04

It said: separate DB roles per module.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2211.

## 16. Contracts — General

### CTR-GEN-01 — Separate blockchain CI; forge libs pinned by tag
- old: R52 · status: current · owner: no · date: 2026-10-03 · normative: contracts/README.md#CTR-GEN-01 · superseded-by: —

**Why.** Contracts break in ways the node tests do not see; pinning the forge libraries by tag makes a CI run reproducible because `lib/` is not committed.
**Cost if wrong.** An unpinned dependency changes bytecode between two runs and a deployed address no longer matches its audited source.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:525`
Change (2026-10-19): controller proposal (owner may override) — **forge libraries pinned by commit and source checksum, one place for CI and local builds** (the second code review, on-chain part (plan Task 5g, branch `rev2-chain-sol`; triage W-A…W-S in `pqz-core/research/code-review-2026-10-19/U-agy-chain.md`, row W-N; report `V2-claude-ua-account-wallet.md` V2-6). Before: CI installed OpenZeppelin `fda6b85f` and forge-std tag `v1.16.2` from env variables, while local builds (every SCaaS testnet deployment) used whatever `lib/` held — an untracked symlink, the README said "v5.2+", this entry's normative text "v5.2.0" — and the local forge-std was master `88c8a288` (2026-08-28), not `v1.16.2`. Now `scripts/evm_libs.sh` holds each pin (repository, commit, source directory, sha256 over the `sha256sum` lines of its `*.sol` files sorted by path): `install` runs `forge install --no-git` at the commits (both CI jobs), `check` compares any `lib/` (a checkout, a symlink, a CI install) with the pins (CI after the install; locally before a build that is deployed). OpenZeppelin stays `fda6b85f` (no bytecode changes); CI's forge-std moves from `v1.16.2` to `88c8a288`, the tree every local test ran with (tests and scripts only). Why not a git submodule: the repo installs `lib/` without submodule bookkeeping (CI), the main checkout's `lib/openzeppelin-contracts` is a symlink a submodule would collide with, and a submodule pins a commit but checks no local tree; the checksum covers a symlinked or copied checkout too. Vendoring the sources (allowed: source, not binaries) gives the same guarantee for ~ 400 files in the tree; not needed. Verified: a fresh `install` into an empty tree and the local `lib/` give the pinned digests. Same row: `IUARegistry` declares `chainKeyHash()` (the spec's interface had it; `UARegistry` exposes it as a public immutable). Status: **done** (`a94c9ffd`).

### CTR-GEN-02 — Value-holding programs immutable from deploy
- old: CR-R3-11, UD:§20.2, owner:2026-10-07:immutable · status: current · owner: yes · date: 2026-10-07 · normative: contracts/README.md#CTR-GEN-02 · superseded-by: —

**Why.** Users can verify once what a program does and rely on it forever; an upgrade key is an admin key over every balance. Rejected alternatives: UUPS/ERC-1822 proxies "for all contracts", `ReentrancyGuardUpgradeable` + an admin `Pausable` on every function, and "delegate to share code, support many versions": versions are new implementations behind immutable clones, and a registry must never be upgradeable.
**Cost if wrong.** A bug is permanent for that deployment; the remedy is a new deployment plus voluntary migration, so audits and the deploy gate must precede real funds.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:714`, `research/_USER-DECISIONS.md:1140`, `history/SCaaS-2026-10-07.md:40`. Owner wording for the Aptos, Sui and Solana programs: "Bất biến ngay khi deploy" (immutable as soon as deployed).

### CTR-GEN-03 — Contracts in their own tree per family
- old: UD:§1:smartcontracts-tree · status: current · owner: yes · date: 2026-08-30 · normative: contracts/README.md#CTR-GEN-03 · superseded-by: —

**Why.** Each family has its own toolchain; one tree per family keeps builds and audits separable.
**Cost if wrong.** Mixed trees force every family build to know every other toolchain.
**Source.** `research/_USER-DECISIONS.md:46`

### CTR-GEN-04 — Issuer choices are not protocol decisions
- old: UD:§20.5 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/README.md#CTR-GEN-04 · superseded-by: —

**Why.** SCaaS ships a protocol, not a token catalogue; names, symbols, rates and roles belong to the issuer who answers for them.
**Cost if wrong.** If SCaaS made issuer choices it would carry issuer liability and become a gatekeeper.
**Source.** `research/_USER-DECISIONS.md:1272`

### CTR-GEN-05 — salt = chain_uid in every SCaaS EIP-712 domain and chain-bound digest
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/README.md#CTR-GEN-05 · superseded-by: —

**Why.** Chain ids collide (the private chain's earlier id was a public testnet's), so every domain carries the genesis hash as `salt` through one helper, with one source per contract (an implementation immutable for clones, a constructor argument elsewhere) checked against the RPC by the deploy gate and the node. The owner ruled that a fork of a chain we run is a new chain (new chain id and `chain_key`); a PoA chain re-created from the same genesis is refused by a unique `extraData` nonce.
**Cost if wrong.** A signature for one chain verifies on another that shares its chain id; a second salt source lets a clone declare another chain.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 (fixed constraints), §3 MG-4, §10 OQ3, §12 (H9, M4).

### CTR-GEN-06 — CREATE2 deployer with a fixed salt for every contract
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/README.md#CTR-GEN-06 · superseded-by: —

**Why.** The owner moved every deployment (implementations, factories, registries, DEX) to a deterministic CREATE2 deployer: addresses follow from init code, so contracts with a `chain_uid` constructor argument (and their clones and accounts) differ per chain, and others share one address everywhere; safety rests on the salted digests, not on addresses.
**Cost if wrong.** CREATE addresses depend on deployer nonces and drift between chains and redeploys.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A11, §3 MG-4.

## 17. Contracts — Meta-transactions

### CTR-MTX-01 — Payment is a MetaTransfer with entryRef ≠ 0
- old: R2(op) · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-01 · superseded-by: —

**Why.** A payment is one signed typed `MetaTransfer` with its reference (`mtxExecuteTransfer`, `mtxPay`), not a self-call, so `PaymentSettled` keeps its fee fields and wallets show recipient, amount and reference field by field; until 2026-10-08 it was the `pay(bytes32)` shape of the single struct.
**Cost if wrong.** A separate payment entry point would duplicate the pipeline and its audit surface; making payment a self-call would lose the fee in `PaymentSettled`.
**Source.** `history/specs/2026-10-03-blockchain-payments-design.md:664`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-1, MG-5.
Change (2026-10-08): a payment is a `MetaTransfer` with `entryRef ≠ 0`, run through `mtxExecuteTransfer`, `mtxPay` or `mtxPayReceiverFee`; `PaymentSettled` unchanged. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-4.

### CTR-MTX-02 — Clone domain: implementation name, version 1, clone verifyingContract, salt chain_uid
- old: R5 · status: current · owner: no · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-02 · superseded-by: —

**Why.** Clones share the implementation name and the one version `"1"`; each clone is its own `verifyingContract` and the domain carries `salt = chain_uid` from the implementation's immutable, so a signature never replays on another token or another chain with the same chain id.
**Cost if wrong.** A shared domain would let a signature move between clones; without the salt it would move between chains that share a chain id.
**Source.** `history/specs/2026-10-03-blockchain-payments-design.md:674`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-4.
Change (2026-10-08): every SCaaS contract on `MetaTxBase` signs in `("SCaaS <Contract>", "1", chainId, contract, chain_uid)`; both structs of a contract share its domain. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-1.

### CTR-MTX-03 — Random entryRef; pay lane derived from it
- old: R9(lane) · status: current · owner: no · date: 2026-10-03 · normative: contracts/metatx.md#CTR-MTX-03 · superseded-by: —

**Why.** A random `entryRef` cannot be guessed or front-run, and deriving the pay lane from it lets the contract enforce pay-once without a request registry.
**Cost if wrong.** Sequential references leak volumes and allow pre-emptive lane exhaustion.
**Source.** `history/specs/2026-10-03-blockchain-payments-design.md:692`
Change (2026-10-27): **review C5-9, no gas run (controller ruling, owner may override)**: the metatx.md §8 Amsterdam figures (lane first write about 98 k, `mtxPay` 181,810, CTR-MTX-27 estimate about +200-230 k) are the existing `AMS_*` constants of `MetaTxGasV2.t.sol`, not a new measurement; a fresh gas run needs the owner to stop other heavy sessions. The pre-Amsterdam table stays, marked as such. Cost until a re-measure: the CTR-MTX-27 estimate is an estimate. Status: **done** as documentation (review2 T8).

### CTR-MTX-04 — Pay-once holds under lane horizon H
- old: CR-PD-4(issuer) · status: current · owner: no · date: 2026-10-07 · normative: contracts/metatx.md#CTR-MTX-04 · superseded-by: —

**Why.** Pay-once is a protocol rule only within the lane horizon; stating the horizon makes the guarantee checkable instead of implied.
**Cost if wrong.** Clients that assume unconditional pay-once could double-pay after the horizon.
**Source.** `history/specs/2026-10-03-blockchain-payments-design.md:901`
Change (2026-10-27): **review C0-12 (controller proposal, owner may override)**: `cancelNonce(batch)` advances a lane by one, so it invalidates the one intent signed for the current nonce, not every pending intent: with E5 and E6 signed ahead one cancel kills E5 and makes E6 executable at once (every executed intent is still signed and bounded by `validUntil`). metatx.md is corrected (k pending intents need k cancels). The code option, `cancelNonceTo(batch, newNonce)` with a UA twin (it would also close V3-02), is not built: it adds an entry point to every token and the review rates the harm as bounded. Status: **done** (review2 T8, branch `review2-fix`; documentation only).

### CTR-MTX-05 — Receiver-pays via payee co-signed ReceiverFee
- old: R192 · status: current · owner: no · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-05 · superseded-by: —

Change (2026-10-13): owner — the UA twin `uaPayReceiverFee(UAMetaTransfer t, payerAuth, fee, feeRecipient, rfValidUntil, payeeAuth)`: payer and payee are ids; the payee co-signs the same `ReceiverFee` over the payer's UA digest, a derived payee through `requireAuthorized` under purpose `receiver-fee`; event `UAReceiverFeePaid`. SPECIFIED (UA-5a). The address-path function is BUILT (P1b/P1c), not planned. Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.8.

**Why.** Receiver-pays needs the payee to consent to the fee; a co-signed `ReceiverFee` keeps both parties bound to the same numbers.
**Cost if wrong.** Without the payee signature a relayer could charge the payee arbitrarily.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:172`
Change (2026-10-08): `paymentDigest` is the digest of the payer's `MetaTransfer`; `mtxPayReceiverFee` takes `MetaTransfer t`. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-5.

### CTR-MTX-06 — Receiver-pays shape; every tier of the one base
- old: R193(shape) · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-06 · superseded-by: —

**Why.** Receiver-pays keeps its fixed shape (fee `NONE` on the payer, restricted relayer, pay lane with nonce 0, payee-signed absolute fee); with the v1 line deleted it is available on every tier of the one base, still not in `mtxBatch`.
**Cost if wrong.** A looser shape would let a submitter attach the co-signature to another intent.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:181`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-9.
Change (2026-10-08): the payer shape is a `MetaTransfer` with `entryRef ≠ 0`, fee `NONE`, relayer bound, `payLane`/0; not in `mtxBatchTransfer`. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-5.

### CTR-MTX-07 — One meta-tx tree: MetaTxBase, ERC20MetaTx, MetaTokenBase
- old: R131 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-07 · superseded-by: —

**Why.** The owner folded every meta-transaction base into one, `ERC20MetaTx` (the built `MetaTxCore` renamed): the v1 `ERC20MetaTx`/`MetaToken`/`HederaMetaToken`, factory v1 and `ZetherMetaTx` go, and the struct, typehash and one domain version serve every token. Nothing is deployed, so no version coexists.
**Cost if wrong.** Two or three bases keep two security models and three pipelines in sync by hand.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:72`; `history/specs/2026-10-07-metatx-generic.md` §2 A4, A8, §3 MG-9.
Change (2026-10-08): `ERC20MetaTx is MetaTxBase`: the token base adds the fee in this token, the typed `MetaTransfer` path, `payLane`, receiver-pays, trade and the UA path on the generic base (CTR-MTX-22); `PqzMetaTx` disappears too (CTR-PQZ-21). Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-2.
Change (2026-10-08): the tree is `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase`; trade and pay sit in `MetaTokenBase`, not `ERC20MetaTx`; the kinds, Hedera and the Zether kinds sit on it. Source add: `history/specs/2026-10-08-token-tree-design.md` §2 (T10), §3.

### CTR-MTX-08 — Fee never goes to the payee
- old: R132 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-08 · superseded-by: —

**Why.** A fee that goes to the payee lets a payee inflate its own receipts; the check applies to the transfer and payment shapes and `payWithFee`, and a self-call has no payee.
**Cost if wrong.** Payees could disguise discounts or extract hidden charges through the fee field.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:78`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-5.
Change (2026-10-08): the payee check applies to every `MetaTransfer` (payee = `t.to`) and to `payWithFee`; a `MetaTransaction` has no payee. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-4.

### CTR-MTX-09 — Named meta-tx functions are thin entry points
- old: R138 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-09 · superseded-by: —

**Why.** Named functions (`mtxTransfer`, `mtxTransferWithFee`, `mtxExecuteWithFee`, `mtxPay`, `mtxBatch`) are readable in wallets and explorers but only route into the one pipeline; the unwrap pseudo-op and its named functions are gone because `mtxExecute` runs the real `unwrap`.
**Cost if wrong.** Logic in the named functions would drift from the generic path.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:119`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-3.
Change (2026-10-08): the named functions keep their signatures and build the struct of their kind — `mtxTransfer`, `mtxTransferWithFee`, `mtxPay` a `MetaTransfer`, `mtxExecuteWithFee`, `mtxBatch` a `MetaTransaction`; nothing is merged (owner); `mtxExecuteTransfer` and `mtxBatchTransfer` are added (CTR-MTX-23, CTR-MTX-24). Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G4, §3 GC-5.

### CTR-MTX-10 — mtxPay payId is entryRef, lane on chain
- old: R139 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-10 · superseded-by: —

**Why.** `payId` is the payment reference and the lane is derived on chain, so a client cannot mislabel the lane; `cancelNonce` replaces `cancelMetaNonce` in the per-path caveat.
**Cost if wrong.** Client-chosen lanes would break pay-once.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:124`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-3.
Change (2026-10-08): a payment on a client-chosen lane uses `mtxExecuteTransfer` (owner G6); the generic `pay` shape is gone. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G6, §3 GC-5.

### CTR-MTX-11 — One intent, one digest; no second typehash for the same struct; batches atomic
- old: R140 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-11 · superseded-by: —

**Why.** One typehash per struct keeps every signer and verifier on one digest rule; different structs in the token's domain (`UAMetaTransaction`, `TradeOrder`, `CancelOrder`, `InvalidateNonces`) are not a second hash of `MetaTransaction`. `mtxBatch` is atomic with a fresh ticket per item.
**Cost if wrong.** A second hash of the same struct invites cross-path replay; a non-atomic batch leaves half-paid states.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:131`; `history/specs/2026-10-07-metatx-generic.md` §7 (CTR-MTX-11 row).
Change (2026-10-08): one intent, one digest across two structs: transfer and payment only as `MetaTransfer`, calls only as `MetaTransaction`; batches never mix structs; `UAMetaTransfer` joins the different-struct list. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G5, §3 GC-1, GC-5.

### CTR-MTX-12 — Gasless unwrap is mtxExecute(unwrap) with minOut
- old: R148(contract) · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-12 · superseded-by: —

**Why.** A gasless unwrap lets holders exit without native gas; it is now `mtxExecute` with the wrapper's real `unwrap` calldata (fee class `AMOUNT`, fee after the call), and `minOut` still protects against rate moves between signing and execution.
**Cost if wrong.** Without `minOut` a relayer could time execution against the holder; a pseudo-op duplicates the direct function's checks.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:172`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-2, §7.

### CTR-MTX-13 — Public fee modes NONE, PERCENT, FIXED; 1 % cap on amount bases
- old: UD:§3.1, UD:§11:fee-denominator · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-13 · superseded-by: —

**Why.** Three fee modes cover the business cases with a 1 % cap (10 000 ppm of a 1e6 denominator) on transfer, payment and `AMOUNT` selectors; the owner narrowed the cap so that calls moving no amount pay an absolute, uncapped `FIXED` fee (CTR-MTX-20).
**Cost if wrong.** More modes multiply audit cases; an uncapped percentage would let a signer be overcharged by a misreading; a cap on a zero basis would make wrap and cancel fee-less forever.
**Source.** `research/_USER-DECISIONS.md:107`, `research/_USER-DECISIONS.md:450`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-5, §10 OQ4.
Change (2026-10-08): fees exist only where `_chargeFee` is overridden (every token); any other SCaaS contract accepts `NONE` only and the sponsor pays native gas (owner G2). Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G2, §3 GC-2.

### CTR-MTX-14 — EIP-712 typed data, not personal_sign
- old: UD:§4 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/metatx.md#CTR-MTX-14 · superseded-by: —

**Why.** EIP-712 typed data is what wallets display; `personal_sign` of a hash shows the user nothing they can check. The first committed code hashed with `toEthSignedMessageHash()` (`personal_sign`) while the design sketch signed with `wallet._signTypedData(domain, types, data)` (EIP-712); the design was right and the code was changed.
**Cost if wrong.** Users would sign blind hashes, the precondition for drain attacks.
**Source.** `research/_USER-DECISIONS.md:206`

### CTR-MTX-15 — Two structs, one nonce space; no forwarder; drop feeToken, innerGasLimit; keep mode
- old: UD:§24, UD:§24.1 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-15 · superseded-by: —

**Why.** Meta-tx logic lives in the token, so there is no trusted forwarder; `feeToken` and `innerGasLimit` were dropped and `mode` kept, split into two nibbles: the low nibble holds flags (`RESTRICT_RELAYER` 0x01, `RESTRICT_FEE_RECIPIENT` 0x02), the high nibble an enum of the fee mode (`NONE` 0x00, `PERCENT` 0x10, `FIXED` 0x20); `if (mode & MODE_FEE_PERCENT)` is a bug, because `MODE_FEE_FIXED = 0x20` lacks bit 0x10 but a future 0x30 would have it; validation checks unknown flag bits and enum values above 2. `data` is an allowlisted call of the contract itself — the owner's explicit `to`/`value`/`data` never meant a fixed op list; since 2026-10-08 a transfer or payment is a typed `MetaTransfer` beside it, because a token transfer is a special case of a meta-transaction, not its definition (owner). Rejected: the early `IEIP1776` sketch (`tokenContract`, `batchNonce`, `expiry`, `meta_nonce(from, batchId)`).
**Cost if wrong.** A forwarder becomes a shared trust root for every token; an op list makes `wrap`, `burn`, `addReserve` and `fund` impossible to relay.
**Source.** `research/_USER-DECISIONS.md:2504`, `research/_USER-DECISIONS.md:2534`; `history/specs/2026-10-07-metatx-generic.md` §1, §3 MG-1.
Change (2026-10-08): two structs share one lane space: the generic `MetaTransaction{from, data, batch, nonce, validUntil, mode, relayer, fee, feeRecipient}` for a call of any SCaaS contract and the token-only typed `MetaTransfer{from, to, value, entryRef, …}` that wallets display field by field; `data` is always a self-call; `transfer`/`pay` are never allowlisted; new typehashes and KATs (`metatx_kat.json`, `metatransfer_kat.json`). Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G1, G10, §3 GC-1.

### CTR-MTX-16 — No generic forwarder; the token calls only itself; all or nothing
- old: UD:§24.2, UD:§24.3 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-16 · superseded-by: —

**Why.** No generic forwarder means each token owns its replay protection; legacy tokens are wrapped instead of trusted. The prototype's flaw was a call **out** with the signer's calldata, not executing calldata: the token now runs allowlisted functions of itself only. The owner accepted the new invariant: transfer and payment check everything before the fee; a self-call runs first and pays after, and any failure reverts everything with the inner revert data, so the user never pays for an operation that did not happen.
**Cost if wrong.** A generic forwarder would let one bug affect every legacy token at once; charging before a self-call could not let a wrap pay from minted units.
**Source.** `research/_USER-DECISIONS.md:2570`, `research/_USER-DECISIONS.md:2586`; `history/specs/2026-10-07-metatx-generic.md` §1, §2 A1, §3 MG-1, §10 OQ2.
Change (2026-10-08): the logic lives in every SCaaS contract (`MetaTxBase`), not only tokens; `mtxExecute` calls one of the contract's own allowlisted functions, a token's transfer and payment run through `mtxExecuteTransfer`. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-2, GC-3.

### CTR-MTX-17 — mtxExecute runs the signer's calldata on the token itself
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-17 · superseded-by: —

**Why.** The owner asked for the explicit `to`/`value`/`data` envelope to execute any function of the token itself, so `wrap`, `burn`, `addReserve`, `cancelNonce` and Zether ops become gasless without a forwarder; `executeMetaTransaction` stays as the EIP-1776 alias returning `bool` for tender and outside tools. The pipeline is cheap-first, writes the nonce before the call, bubbles inner reverts and charges a self-call's fee after it.
**Cost if wrong.** A hand-written op dispatch must grow per function and diverges from the direct functions' checks; swallowing errors would charge users for nothing.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A1, A3, §3 MG-1.
Change (2026-10-08): `mtxExecute` serves every SCaaS contract and `data` is always a self-call: the shape table is gone; the signature check is the virtual `_requireValidSignature`; the fee is `_chargeFee` after the call and is refused outside `NONE` where not overridden. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-3.

### CTR-MTX-18 — Transient sender and one-shot ticket
- old: — · status: current · owner: no · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-18 · superseded-by: —

**Why.** The signer is stored in transient slots and `_msgSender()` trusts it only for `msg.sender == this` with a live ticket, so no calldata suffix can spoof a sender (the ERC-2771 + multicall class); the guard admits exactly one self-call and consumes the ticket, so guarded functions still run under `mtxExecute` while any re-entry reverts. Every direct `msg.sender` read is listed and a lint pins the ones that stay; `from ≠ this` and no transfers to `this` remove the exploit's fuel.
**Cost if wrong.** A same-slot guard blocks every guarded self-call; a trusted calldata sender lets an attacker spend tokens parked at the token's address.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §3 MG-1, §3.1, §12 (H1, H2).

### CTR-MTX-19 — Fixed selector allowlist per implementation
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-19 · superseded-by: —

**Why.** The owner chose a fixed per-implementation allowlist, published by `mtxSelectors()` with fee classes; `approve`, `transferFrom`, `transfer`, `payWithFee`, every `mtx…` entry and every role function are never listed (the owner flipped the earlier default: role holders act through their own contract, whose caps and guards a signature check would skip). Every listed function is `nonReentrant`; dynamic Zether arguments are canonicalized by the node.
**Cost if wrong.** An open allowlist lets a signature reach role functions or `approve`; a second encoding of one intent splits its digest.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A2, §3 MG-2, §10 OQ1.
Change (2026-10-20, owner): every state-changing `mtx*` function is relayable, even with no fee: itself a meta-tx entry point or an allowlisted self-call with outer fee `NONE` / `FIXED` 0 (general rule in `contracts/metatx.md`, CTR-MTX-19). Status: BUILT for the confidential tokens (Zether roll-overs, PQZ `mtxRollOver` / `mtxPrepareAcc`), commit `b5e61c96`; the audit of the other contracts found no gap (every other `mtx*` write is an envelope entry point carrying its own signature).
Change (2026-10-08): `transfer` and `pay` are never allowlisted (they are `MetaTransfer`s); rows added for `PqzToken`, `MandateWallet` and `SmartKeyAccount` (fee `NONE` only on the latter two). Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-1, GC-6, GC-10.
Change (2026-10-27): **review C0-18 (controller proposal (1), owner may override)**: the native-coin `mtxWrapShield` is the **one exception** to "every state-changing `mtx*` is relayable" (owner 2026-10-20, above). It is `payable` and takes the leg from `msg.value`; the relayed self-call carries no value, so a relayer cannot supply the signer's native coin (`NativeValueMismatch`). The holder wraps directly, then relays `mtxShield` (the two-step route accounts.md already records for a UA source). The ERC-20 leg is relayable on `mtxExecute`. The other option, a value-carrying relay path (a `payable` envelope, `msg.value` bound to the authorization, the relayer reimbursed from the signer's balance), was not taken: it adds a payable entry to every token. Written into metatx.md CTR-MTX-19, zether.md CTR-ZTH-34 and pq-zero-knowledge.md §7.11. Status: **done** (review2 T8, branch `review2-fix`; documentation only, no code change).
Change (2026-10-27): **review C0-3 follow-up (controller ruling, owner may override)**: the retired `mtxConfidentialTransferNoBundle` selector, called directly, reverts with empty data (the PQZ precedent, `PqzNone.t.sol`): a named error would need a fallback stub, which is code-size work (owner: none before Glamsterdam). Through a relayer the allowlist answers `MtxSelectorNotAllowed`, the clear error. Status: **done** (review2 T5 `41b798d9`; recorded in review2 T8).

### CTR-MTX-20 — Fee classes per selector: AMOUNT(i) and ABSOLUTE
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-20 · superseded-by: —

**Why.** A self-call carries no amount field, so the fee basis comes from the selector: `AMOUNT(i)` uses argument `i` with the 1 % cap, `ABSOLUTE` allows only an uncapped `FIXED` amount (or `NONE`), extending the confidential rule to public calls that move no amount; the wallet shows the exact fee.
**Cost if wrong.** A fee on a zero `value` is either always zero or uncheckable; a percentage of a hidden or absent amount is meaningless.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §3 MG-5, §10 OQ4.
Change (2026-10-08): a `MetaTransaction` has no amount field, so the basis always comes from the selector; on contracts that charge no fee every class admits `NONE` only. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G2, §3 GC-2.

### CTR-MTX-21 — mtx names for every signature-authorized entry point
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-21 · superseded-by: —

**Why.** Every external function whose authority comes from a subject's signature starts with `mtx` (tokens, `ZetherToken` rollover, `MandateWallet`, `SmartKeyAccount`, `SCaaSDex`), so readers and the node's call table tell signed paths from direct ones at a glance; `executeMetaTransaction` stays as the alias; EIP-712 type names and non-EVM op names are unchanged.
**Cost if wrong.** Mixed names hide which entry points need a signature and which only a caller.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A3, §3 MG-3.
Change (2026-10-08): entry table: every contract on `MetaTxBase` has `mtxExecute`/`mtxBatch`/`cancelNonce`; tokens add `mtxExecuteTransfer`, `mtxBatchTransfer`; `MandateWallet` and `SmartKeyAccount` named entries build a `MetaTransaction`. The non-EVM line is unchanged here. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G4, §3 GC-5, GC-6.
Change (2026-10-08): the non-EVM exception is gone — non-EVM families name signed entries `mtx` in their own case (NET-ALL-28). Source add: `history/specs/2026-10-08-nonevm-metacall-design.md` §6 Q1.

### CTR-MTX-22 — MetaTxBase: the generic base of every SCaaS contract; fee NONE unless overridden
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-22 · superseded-by: —

Change (2026-10-13): owner — the generic UA path (`uaExecute`, `uaBatch`, `uaCancelNonce`, the UA allowlist, the cancel-used set, the registry immutable) moves from `ERC20MetaTx` into `MetaTxBase` with a virtual `_chargeUAFee` refusing every mode but `NONE`, so `MandateWallet` and any contract on the base take UA signers; balances, `_uaMove` and the typed UA path stay in `ERC20MetaTx`. SPECIFIED (UA-5c). Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.12, UP-13, O7, Q8.

**Why.** SCaaS meta-transactions exist so that someone other than the subject pays for a call of any SCaaS contract, not only for moving tokens (owner: a family-tree contract whose edits a service company pays for in native gas). One generic base gives every contract the struct, digest, lanes, ticket, allowlist and `mtxExecute`; a contract that holds no charged balance cannot collect a fee, so `_chargeFee` refuses every mode but `NONE` unless a token overrides it, and the sponsor settles with the user off chain.
**Cost if wrong.** A token-only base forces every other contract to invent its own signed struct and nonce rules (as `MandateWallet` and `SmartKeyAccount` did); a fee field such a contract cannot collect would mislead signers.
**Source.** `history/specs/2026-10-08-metatx-generic-call-design.md` §1, §2 G2, G3, §3 GC-2, GC-7.

### CTR-MTX-23 — The typed path: MetaTransfer through mtxExecuteTransfer
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-23 · superseded-by: —

**Why.** A token transfer is a special case of a meta-transaction (owner); keeping it as a typed struct (`to`, `value`, `entryRef`) lets outside wallets show "send value to to" instead of opaque `data` (owner G1 (b)), and `mtxExecuteTransfer` takes the struct as given so a payment can use a client-chosen lane (owner G6).
**Cost if wrong.** Without the typed struct a transfer would be hex in every outside wallet; without the struct entry a payment could use only `payLane`.
**Source.** `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G1, G6, §3 GC-1, GC-4, GC-5.

### CTR-MTX-24 — mtxBatchTransfer beside mtxBatch
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-24 · superseded-by: —

**Why.** With transfers in their own struct, `mtxBatch(MetaTransaction[])` can no longer carry the payments the node batches; a typed batch keeps that saving (owner G5 1a) under the same atomic rules, and a batch never mixes the two structs.
**Cost if wrong.** Payments could no longer be batched, or one batch function would have to decode two structs.
**Source.** `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G5, §3 GC-5.

### CTR-MTX-25 — One SigCheck
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/metatx.md#CTR-MTX-25 · superseded-by: —

**Why.** One internal `SigCheck` (ECDSA low-s, ERC-1271 with the gas-cap rule, the HIP-632 hook) serves `MetaTxBase`, `SCaaSDex`, `MandateWallet` and `SmartKeyAccount`; `SigLib`, which has no importer, is deleted. Today the check is written six times and the HIP-632 override four times.
**Cost if wrong.** Copies drift: a fix to the gas cap or the low-s rule lands in one contract and not in the others.
**Source.** `history/specs/2026-10-08-token-tree-design.md` §1, §4.

### CTR-MTX-26 — Payment metadata by commitment: mtxPayMeta / uaPayMeta
- old: — · status: current · owner: yes · date: 2026-10-26 · normative: contracts/metatx.md#CTR-MTX-26 · superseded-by: —

**Why.** The owner asked for metadata on a payment id. `payId = keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`
lets the existing signature over `entryRef` bind the metadata, so there is no new struct field, no second typehash
(CTR-MTX-11), and `payId` stays unlinkable (CTR-MTX-03). `mtxPayMeta` / `uaPayMeta` publish it in `PaymentMeta`; plain
`mtxPay` with the same id keeps it off chain. Every tier and every non-EVM family (owner 2026-10-26). A new typed
struct with a `meta` field (native wallet display) was rejected: a second struct path and more bytecode in every token.
**Cost if wrong.** Wallets show only the opaque `entryRef`, so a connector that skips the commitment check shows the
user metadata the signature does not bind.
**Source.** `research/mtx-relay-fees.md` §2, §5 (owner answers 2026-10-26: "OK, vậy phần mtxPayMeta như vậy đi").
Change (2026-10-27, controller call, owner may override; status: current; commit: metatx-split T7 fix 1): the `meta` body encodings are fixed and family-neutral (one rule for every chain kind) inside `meta = abi.encode(uint16 schema, bytes body)`: schema 1 the raw UTF-8 bytes; schema 2 `abi.encode(string creditorRef, string invoiceNo, uint64 dueDate)`, `dueDate` in Unix seconds; schema 3 `abi.encode(uint256 chainId, bytes32 target, bytes32 callHash)`, `target` as 32 bytes (an EVM address left-padded with zeros, other families their native 32-byte id), `callHash = keccak256(callData)` (research §3); schema 4's inner layout (KEM wrap ‖ AES-256-GCM) stays undefined, a later client item. The shared vectors `smartcontracts/vectors/metatx/paymeta.json` follow them; `long_body_4096` is a hash vector only. Source add: `superpowers/specs/2026-10-27-metatx-split-design.md` §6.1.

### CTR-MTX-27 — MtxRelayFee: token fee for a fee-less call
- old: — · status: current · owner: yes · date: 2026-10-26 · normative: contracts/metatx.md#CTR-MTX-27 · superseded-by: —

**Why.** The owner wants a payer to pay, in an mtx token, for a fee-less call such as a PqChat message: the relayer
pays the gas, and the payer pays the relayer. Tender's deposit (CTR-TND-01) already binds a payment to an action
through `entryRef` and the relayer binding. A stateless router generalises it to any target, without token logic in
the target and without changing any token: `ref` commits to (chain, target, call bytes); the payment is bound to the
router as relayer; the router runs the call through an unprivileged executor, then the payment. Owner answers
(2026-10-26): the controller names it and places it in `src/metatx/` with a `DeployBase` CREATE2 deployment; open to
every relayer by default; public balances only; every token tier; non-EVM too (GRAM by escrow); PQ payers sign twice
(option (a), after first picking (c)); no budget mode for now. Rejected: a pay-and-call hook in every token (ERC-1363
style: a new outbound call and bytecode in each token); one combined PQ signature with a transient verified mark
(option (c), studied). CTR-MTX-16's "no generic forwarder" stands: the router grants no authority.
**Cost if wrong.** If the router called targets itself, a `callData` could execute another router-bound payment
through a token, with no call behind it.
**Source.** `research/mtx-relay-fees.md` §3, §5 (owner answers 2026-10-26; "Có, viết spec luôn đi").
Change (2026-10-27, controller call 2026-10-27, owner may override; status: current; commit: metatx-split T9 fix 1): (1) the router refuses a target without code, `RelayTargetNoCode(target)`: a counterfactual target (a `SmartKeyAccountFactory` prediction, a CREATE2 clone) relayed before its deploy would succeed as an empty call, pay the fee and burn the lane (against CTR-MTX-13); CTR-MTX-27 gets a ninth conformance item for every family: the target must exist as code / an executable program / an instantiated contract at relay time. (2) `RelayFeePaid.payee` is `bytes32` (a padded address, or the UA id of a derived payee), like `payer`; the other families' events follow this form. (3) The router refuses `t.to == EXECUTOR` (UA: `pad(EXECUTOR)`), and clients never pay or approve the executor. Cost if wrong: a target deployed in the same transaction before the relay is still accepted; a relay cannot pre-pay a target's deploy. Source add: `superpowers/specs/2026-10-27-metatx-split-design.md` §7.1, §7.2.
Change (2026-10-27, controller call 2026-10-27, owner may override; status: current; commit: metatx-split T10 fix 1): Soroban only. (3) The token's `PayRef` set is keyed by `(from, pay_ref)` for `pay` and `pay_meta`, the per-payer lane of the EVM (`payLane(ref)` in the payer's nonce space), so nobody can pre-burn another payer's `ref` / `payId` with a 0-amount `pay(attacker, attacker, 0, ref, ..)`. (4) The Soroban `relay` takes a payer-signed `salt: BytesN<32>` that enters `ref` (Soroban's call bytes are not unique, the target's auth lives in auth entries): `ref = keccak256("scaas.relayfee" ‖ network id ‖ xdr(target) ‖ keccak256(xdr((func, args))) ‖ salt)`, so the same payer can fee-pay two identical calls. (5) Before a relay-fee job the node checks the configured router, a registered token and `amount >= relay_fee.min_amount` (spec §9 names no key; `params.relay_fee = { router, min_amount }`, default 1); the indexer decoding of `PaymentMeta` / `RelayFeePaid` and the `max_pay_meta_bytes` config move to Task 17 for every family. (6) The relayer's `require_auth` is not satisfied by the transaction source alone: the node adds an explicit `SourceAccount` auth entry rooted at the `relay` call.
Change (2026-10-27, controller call 2026-10-27, owner may override; status: current; commit: metatx-split T11): Solana only. (1) `relay_fee`'s `ref = keccak256("scaas.relayfee" ‖ Config.network ‖ target program ‖ keccak256(call) ‖ salt)` with `call = target ‖ u8 n ‖ (pubkey ‖ is_signer ‖ is_writable)×n ‖ data` (the account count added to the spec's preimage so the account list and the data cannot be re-split) and `salt = args.extra`, the payer-signed `MetaOp.extra` (no new argument: a Solana target's own authorisation lives outside its data, so two identical calls need distinct refs). (2) The pay-meta and relay-fee once-set is the payer's lane PDA `[b"lane", Account, lane]`, already per payer: nobody can pre-burn a payer's `payId` / `ref`. (3) New errors `PayMetaShape` (pay-meta `pay_ref` / lane / nonce mismatch), `RelayFeeShape`, `RelayTargetNoCode` (the target is not an executable program). (4) Open mode pays the lane's ATA directly, so `PaymentSettled.to` and `RelayFeePaid.payee` name the lane (no hop through the marker, which never holds tokens and never signs). (5) No executor: `scaas` invokes the target with plain `invoke` (no PDA signer seeds). Because `invoke` forwards the outer transaction's signer privileges, `relay_fee` refuses on chain (`RelayFeeShape`, before the CPI) any target account flagged signer, the lane or any co-signer, so the router grants no authority to whichever relayer submits it (CTR-MTX-16; T11 fix 1). The node refuses the same, and the lane as a target account, before simulating. Cost if wrong: a target that needs a signer (a rent payer) cannot be fee-relayed through the generic `relay_fee`.
Change (2026-10-27, owner 2026-10-27; status: current; commit: metatx-split T11 fix 2): owner 2026-10-27: Solana uses static relay_fee_<entry> wrappers (as Sui/Aptos); generic CPI relay_fee kept for external programs. Wrapped: `manage_signed`, `mandate_open`, `mandate_revoke_signed`, `mandate_close_signed`, `cancel_signed`, `invalidate_nonces_signed` (every fee-less signed entry of `scaas` but `open_passkey`, excluded as a scope choice: account creation is not among the entries Sui / Aptos wrap, controller call 2026-10-27, owner may override; `settle` is a trade with its own market fee and the pay entries are payments). Each runs the entry's body in-process, then the router payment (marker as relayer, open mode pays the lane), atomically. `ref` uses the Solana preimage with target = `scaas` and `call` = the entry's instruction as if sent alone (declared accounts with their flags, `discriminator ‖ Borsh(arguments)`, its `auth` included), salt `args.extra`. To nest beside any entry's accounts, `RelayPay` no longer reads instruction arguments (`subject` and `lane_pda` are derived, checked and the lane PDA created in the shared body); `manage_signed` persists its Account before returning so a wrapper's payment reads the new key set. The self-target refusal of the generic `relay_fee` stays.
Change (2026-10-27, controller call 2026-10-27, owner may override; status: current; commit: metatx-split T11 fix 3): the wrapper ref hashes the router marker in the lane slot (lane-agnostic, as Sui/Aptos): `call`'s first account (the inner entry's `lane`, flags as declared) is the marker PDA `[b"relayfee"]`, so the payer signs before any lane is known, open mode stays open to every relayer, and a job moved to another lane still settles. Cost if wrong: none found; the lane is still the transaction's signer and the entry's rent payer.
Change (2026-10-27, controller call 2026-10-27, owner may override; status: current; commit: metatx-split T12): Cosmos only. (1) `ref = keccak256("scaas.relayfee" ‖ chain id bytes ‖ target (canonical address bytes, 32 for a contract) ‖ keccak256(msg))`, `msg` the exact bytes the executor sends; no salt: the target sees the unprivileged `relayexec` and no funds, so nothing outside `msg` authorises the call, and the SCaaS fee-less signed entries carry their signature and nonce / once-ref inside `msg` (token `Relay` / `RelayPayMeta`, mandate `PayUnderMandate`, DEX `Settle`); the entries authorised by `info.sender` (mandate `Revoke` / `Withdraw`, DEX admin) fail through the router, so nothing is paid. (2) The router refuses a target without contract info (`relayfee: target is not an instantiated contract`), `op.to == executor`, and non-empty funds; the executor refuses funds and every caller but its router. (3) Re-entry into the router is refused by a stored flag set in `Relay` and cleared in the reply of its last message (CTR-MTX-27 conformance; CosmWasm allows re-entry). (4) The router computes its executor's address with `instantiate2_address(code checksum, router, "scaas.relayexec")` at instantiate (its one stored item besides the flag). (5) `relay_fee_paid` (`ref`, `target`, `token`, `payer`, `payee`, `amount`, bech32 `Addr`s) is the router's own event, so wasmd lists it before the sub-messages' events; it exists only when the whole transaction succeeded. (6) The token's lanes are already per payer (`NONCES[(from, lane)]`), so `RelayPayMeta` and the router payment are once per `(payer, payId / ref)` and an attacker's 0-amount pay of the same id uses its own lane. (7) Node: `op.kind = "pay_meta"` (`op.salt`, `op.meta`) builds `relay_pay_meta`; `op.kind = "relay_fee"` (`op.contract` = `params.relay_fee.router`, `op.extra.target`, `op.extra.msg` hex) builds the router's `Relay` after the policy, ref, lane, nonce and relayer checks; a `params.relay_fee.router` that is set but is not a lowercase 32-byte contract address of the chain's prefix is a startup error.
Change (2026-10-27, controller call 2026-10-27, owner may override; status: current; commit: metatx-split T12 fix 1): Cosmos only. (1) The router and the executor have no admin: a migrated router is the bound relayer of every payment signed to it and could settle one without running the call (CTR-MTX-13). `Relay` queries the router's own `ContractInfo` and refuses while `admin` is set (`relayfee: the router has an admin`; a failed query fails closed); the executor is instantiated with `admin: None`; deploy tooling instantiates `relayfee` with `--no-admin`; clients check `ContractInfo.admin == None` before signing `relayer = router`. (2) The router as its own target is refused by the re-entry flag. (3) A `params.relay_fee.min_amount` that is not a non-negative integer is a node startup error, like an unparsable `router`. (4) `build-wasm.sh` links with `-C link-arg=--allow-undefined` (cosmwasm-std 3.0.10 declares its host imports without `wasm_import_module = "env"`, and newer rustc no longer passes the flag) and then fails unless every wasm import is a cosmwasm-std `env` host function (`cosmwasm-check` when installed, else a stdlib import-section parser).
Change (2026-10-27, controller call 2026-10-27, owner may override; status: current; commit: metatx-split T13): Sui only. (1) `meta::relay_pay_meta` derives `pay_ref = meta_pay_id(salt, meta)`, `lane = pay_lane(pay_ref)`, `nonce = 0` on chain and runs `relay_pay`'s body (a private `settle` shared with `relay_pay` and `pay_routed`), emitting `PaymentMeta` before `PaymentSettled`; the once-set is the payer's own `Account.lanes`, so once per `(payer, payId)` and another payer's pay of the same id uses its own table. (2) `scaas::relayfee` has one static wrapper per fee-less signed entry (`relay_manage`, `relay_revoke_with_sig`, `relay_cancel`, `relay_invalidate_nonces`); each runs the entry, then `meta::pay_routed` (`public(package)`), which fixes `pay_ref = ref`, `lane = pay_lane(ref)`, `nonce = 0`, `relayer = marker` on chain, so a payment settles only for the call it was signed for; `dex::cancel`'s `false` aborts the relay (`ECallRefused`). (3) `ref = keccak256("scaas.relayfee" ‖ network ‖ original package id ‖ keccak256(call) ‖ salt)`, `call` = BCS of the entry's name and every argument (objects as ids, the entry's `Auth` included), `salt` = the payment's payer-signed `extra`; no sender and no lane, so any relayer may submit. (4) Marker = the shared `RelayFee` object (created in `init`); plain `relay_pay` / `relay_pay_meta` refuse a payment bound to it (`EWrongRelayer`: no sender is an object); open mode pays `ctx.sender()`, the marker is never paid. (5) manage / cancel / invalidate pay from the account the entry names (Move allows one `&mut` per object in a PTB command); paying another coin or another payer's account for these needs a further wrapper variant (not built). (6) Upgrade authority: `relayfee` is a module of the `scaas` package, so it shares the token's `UpgradeCap` and cannot be upgraded separately; the router's trust equals the token's, so no code change. NET-SUI-15 (immutable package) is still SPECIFIED; as built the publisher keeps the `UpgradeCap`. (7) Node: `op.kind = "pay_meta"` (`op.salt`, `op.meta`) builds `relay_pay_meta`; `op.kind = "relay_fee"` (`op.extra.call` = the call bytes, `op.extra.registry`, `op.extra.mandate_coin_type` for revoke) builds `relayfee::relay_<entry>` after the checks: payment relayer = `params.relay_fee.router` (the `RelayFee` id), registry registered and the paying account derived from it and the payer, `amount ≥ min_amount`, canonical call bytes of a wrapped entry naming the paying account, `pay_ref == ref`, `lane == pay_lane(ref)`, `nonce == 0`; an unparsable `router` or `min_amount` is a startup error. (8) Fix 1 (controller call 2026-10-27, owner may override; commit: metatx-split T13 fix 1): `RelayFee` exists only if `relayfee` is in the package's first publish (Sui runs no `init` for a module added by an upgrade); for manage / cancel / invalidate the payer is the call's own account, so a sponsor needs `_from` variants (not built); the node refuses a plain pay / pay-meta whose `to` is the configured router marker, and a malformed `tokens[].address` is a startup error.
Change (2026-10-28, controller call 2026-10-27, owner may override; status: current; commit: metatx-split T14): Aptos only. (1) `meta::relay_pay_meta` (`package entry`) derives `pay_ref = meta_pay_id(salt, meta)`, `lane = pay_lane(pay_ref)`, `nonce = 0` on chain and runs `relay_pay`'s body (a private `settle` shared with `relay_pay` and `pay_routed`), emitting `PaymentMeta` before `PaymentSettled`; the view `pay_meta_check` is its `pay_check` twin; the once-set is the payer's own `Account.lanes`, so once per `(payer, payId)`. (2) `scaas::relayfee` has one `package entry` wrapper per fee-less signed entry (`relay_manage_signed`, `relay_mandate_open`, `relay_revoke_signed`, `relay_cancel_signed`, `relay_invalidate_nonces_signed`); each runs the entry, then `meta::pay_routed` (`package`), which fixes `pay_ref = ref`, `lane = pay_lane(ref)`, `nonce = 0`, `relayer = marker` on chain; `dex::cancel_signed`'s body moved to `package fun dex::cancel(…): bool` and a `false` (order already closed) aborts the relay (`ECALL_REFUSED`). (3) `ref = keccak256("scaas.relayfee" ‖ chain_id (1 byte) ‖ @scaas ‖ keccak256(call) ‖ salt)`: Aptos's `MetaOp` domain carries a `u8` chain id, not network bytes, so `chain` is that byte; `call` = BCS of the entry's name and every argument (signature included, lane signer excluded), `salt` = the payment's payer-signed `extra`; no sender, no lane. (4) Marker = `object::create_object_address(&@scaas, b"scaas.relayfee")`, a derived address no transaction can sign for: plain `relay_pay` / `relay_pay_meta` refuse a payment bound to it (`EWRONG_RELAYER`); open mode pays the lane; the marker is never paid; nothing is stored, so `relayfee` needs no `init_module`. (5) Any Account pays (no Sui-style one-account limit). (6) Upgrade authority: `relayfee` is a module of the `scaas` package, so the code object's owner can upgrade it only together with `meta`; the router's trust equals the token's, so no code change; NET-APT-20 (immutable) is still SPECIFIED, as built `upgrade_policy = "compatible"`. (7) Node: `op.kind = "pay_meta"` (`op.salt`, `op.meta`) builds `relay_pay_meta` (or calls `pay_meta_check` while the Account is not open); `op.kind = "relay_fee"` (`op.extra.call` = the call bytes, optional `op.ref`) builds `relayfee::relay_<entry>` after the checks: payment relayer = `params.relay_fee.router`, which must equal `relayfee::marker()` of the package (else a startup error), the asset a registered token, `amount ≥ min_amount`, canonical call bytes of a wrapped entry, `pay_ref == ref`, `lane == pay_lane(ref)`, `nonce == 0`; a plain pay / pay-meta to the marker is refused; a relay-fee job whose payer's Account is not open is refused (simulation cannot run it); a malformed `tokens[].address` or `min_amount` is a startup error. (8) Fix 1 (controller call 2026-10-28, owner may override; commit: metatx-split T14 fix 1): the Aptos node refuses a plain pay / pay-meta to `relayfee::marker()` of the package whether or not a router is configured (the marker is derived, so it is always known); on Aptos and Sui an unknown `op.kind` is refused (only none = plain pay, `pay_meta`, `relay_fee`), so a typo never burns the `(payer, payId)` lane as a plain pay without publishing `meta`.

### CTR-MTX-80 — No named mtxPay; accepted gas cost
- old: R2(cost) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-MTX-09, CTR-MTX-10, CTR-MTX-11

**What it said.** An earlier design had no named `mtxPay` and accepted the generic path's gas cost.

### CTR-MTX-81 — Unconditional pay-once per request
- old: R9(pay-once) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-MTX-04, NET-ALL-01, NODE-STO-01

**What it said.** An earlier design promised unconditional pay-once per payment request.

### CTR-MTX-82 — Drop GSN gas fields and per-mille setter
- old: UD:§3.5 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-MTX-15

**What it said.** An early proposal dropped the GSN gas fields and a per-mille fee setter.

### CTR-MTX-83 — Relayer wildcard instead of mode bitmask
- old: UD:§5 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-MTX-15

**What it said.** An early proposal replaced the mode bitmask with a relayer wildcard.

### CTR-MTX-84 — Reconcile three struct variants
- old: UD:§11:struct-variants · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-MTX-15

**What it said.** An early note reconciled three different meta-tx struct variants.

### CTR-MTX-85 — Transfer and payment as data shapes of the one MetaTransaction
- old: — · status: superseded · owner: yes · date: 2026-10-08 · normative: — · superseded-by: CTR-MTX-15, CTR-MTX-23

**What it said.** From 2026-10-07 to 2026-10-08 one 11-field `MetaTransaction{from, to, value, data, …}` carried a transfer (`data` empty), a payment (`data = pay(bytes32)`) and self-calls (`to = value = 0`).

## 18. Contracts — Token wrappers and factory

### CTR-TOK-01 — Only contracts call approve, are spenders, or call transferFrom
- old: R26 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-01 · superseded-by: —

Change (2026-10-13): owner — a Universal Account never grants or holds an allowance either (no `uaApprove`); contracts move a UA's funds only against signed, named intents (CTR-UA-27). Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.4, UP-10, Q2.

**Why.** An allowance held or granted by an EOA is the classic drain vector; the owner narrowed the rule to the **caller** of `approve` as well, so an EOA never holds or grants an allowance on a SCaaS token in any form (no meta-tx `approve`, no permit). Contract accounts approve through their own call path, where their guards run; a `TradeOrder`'s `dex` must be a contract and nothing more (owner-accepted residual risk, CTR-DEX-19). Outside tokens are not ours: an EOA may approve our wrapper on USDT.
**Cost if wrong.** EOA phishing approvals drain balances; a gasless ERC-1271 `approve` would bypass Safe guards and thresholds.
**Source.** `history/specs/2026-10-03-blockchain-payments-addendum-wallets.md:198`. Owner wording: "spender là hợp đồng" (the spender is a contract); `history/specs/2026-10-07-metatx-generic.md` §2 A5, A6, §3 MG-7, §8 Q5.

### CTR-TOK-02 — Three tiers, one implementation per tier, on ERC20MetaTx
- old: R129 · status: superseded · owner: yes · date: 2026-10-08 · normative: — · superseded-by: CTR-TOK-21

**What it said.** Three tiers (no underlying, single, multi) with one implementation each on `MetaTokenBase is ERC20MetaTx`; replaced by the kinds `NONE` and `UNDERLYING` (1–8 legs) plus the Zether kinds, with features as flags.

### CTR-TOK-03 — One factory OpenFactory; append-only kinds; chainUid check
- old: R130 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-03 · superseded-by: —

**Why.** With nothing deployed, the owner kept only the factory v2 code, renamed `OpenFactory`; the version catalogue stays append-only and the factory registers only implementations whose `chainUid()` equals its own, so a clone's domain salt has one source. The kinds are [CTR-TOK-21](contracts/token-wrappers.md#CTR-TOK-21) and the creation API [CTR-TOK-25](contracts/token-wrappers.md#CTR-TOK-25).
**Cost if wrong.** Two factories split provenance and tender checks; a mismatched implementation would mint clones whose signatures verify on no chain.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:66`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-4, MG-9, §7 (CTR-TOK-03/12 row).

Change (2026-10-20): owner rulings 2026-10-19 / 2026-10-20 (plan 5g-Z1) — the constructor takes `Canonical` (the
confidential verifiers, CTR-ZTH-20) and `registerImplementation` checks a confidential release against it
(`NotCanonicalVerifiers`); `deprecate` is immediate and `createToken` refuses a deprecated version (`VersionDeprecated`;
tokens already made are untouched; was "marks but never blocks"); the record per (kind, version) stays a plain mapping so
a later `usableFrom` notice period (plan 5g-Z2) is a small addition. Status: built, commit `690a295a` (plan Task 5g-Z1).

Change (2026-10-20): owner rulings 2026-10-20 (plan 5g-Z2) — **the factory deploys every release on a versioned
environment.** The constructor is `(registrar, chainUid, noticePeriod)` (5g-Z1's `Canonical` removed). The registrar
publishes per kind (and one DEX domain) a versioned, append-only, never-changed `Env {factory, chainUid, registry,
smartKeyAccountImpl, hedera, deps, libs, libCodeHashes}` (`publishEnv`, `publishDexEnv`; the factory's own factory and
`chainUid`, else `EnvInvalid`) and releases code with `deployImplementation(kind, version, envVersion, initcode,
implArgs)` / `deployDexImplementation(version, envVersion, initcode, implArgs)`: the factory checks each library's code
hash, `CREATE2`s `initcode ‖ abi.encode(envVersion, env, implArgs)`, checks `kind()` / `factory()` / `chainUid()` and
records `Release {implementation, envVersion, envHash, usableFrom, deprecated}`; the events carry the env hash, the
init-code hash (without the appended arguments) and the code hash. `registerImplementation` /
`registerDexImplementation` are removed. (1) **Notice period** (owner ruling 2026-10-20, confirmed): a release is
usable `noticePeriod` seconds after its deployment (`VersionNotYetUsable`); the deploy's `NOTICE_PERIOD` defaults to
10 minutes on the SCaaS testnet, 3 days on 22776, 0 elsewhere. (2) **Library pins** (owner ruling 2026-10-20, confirmed):
`Env.libs` is the registrar's list of the libraries the release links, each pinned by code hash
(`LibraryCodeHashMismatch`); the factory does not parse the init code to compare the list with its link references.
(3) **Env binding** (owner ruling 2026-10-20: **no** to "`deployImplementation` binds the kind's latest env"; the final
rule belongs to a later governance-matrix spec): interim, **controller proposal 2026-10-20, owner may override** —
`deployImplementation` / `deployDexImplementation` take an explicit `envVersion` that must be published for that kind
or the DEX (`EnvUnknown(domain, envVersion)`), recorded in the `Release`; an older env stays usable for a new release.
Status: built on branch `rev2-zether-z2`, commit `0f88e66f` (plan Task 5g-Z2).

Change (2026-10-20): **owner ruling 2026-10-20 — every mainnet gets a notice period of at least 3 days** (replaces the
defaults of item (1) above) and the review 5g-Z2 fixes. (1) `DeployBase` is safe by default: a fixed list of test / dev
chains (31337, 1337, the node e2e's anvils 31900–31999, 7622, Hedera 296–298 and the public testnets of
`chain-uids.json`: 11155111, 560048, 17000, 63, 97, 10200, 80002, 84532, 11142220, 44787, 11155420, 421614, 43113,
59141) may use any period (default 10 minutes on the SCaaS testnet, 0 on the others); every other chain is a mainnet (22776, Hedera
295, Ethereum, BSC, an unknown chain) with default and floor 3 days, and a `NOTICE_PERIOD` below it reverts. A
`NOTICE_PERIOD` over `uint64` reverts instead of truncating. (2) The `OpenFactory` constructor caps the period at 30 days
(`MAX_NOTICE_PERIOD`, `NoticePeriodTooLong`; controller choice: near `2^64` every `deployImplementation` overflows
`usableFrom` and the immutable period would brick the catalogue). (3) `publishEnv` / `publishDexEnv` refuse a library
code hash `0` (no account) or `keccak256("")` (no code), a pin that checks nothing (`EnvInvalid`). Status: built on
branch `rev2-zether-z2` (review-fix commits listed in `smartcontracts/evm/runs/2026-10-20-5gz2-wip.txt`).

### CTR-TOK-04 — Conversion rate num/den, rounding favours contract
- old: R133 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-04 · superseded-by: —

**Why.** Rates as `(num, den)` with rounding in favour of the contract keep reserves solvent under every rounding path.
**Cost if wrong.** Rounding in favour of users leaks value per operation and can drain reserves.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:84`

### CTR-TOK-05 — Internal reserve accounting and solvency invariant
- old: R134 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-05 · superseded-by: —

**Why.** Internal reserve accounting ignores donations and forced sends, so the solvency invariant is checkable from the contract's own state.
**Cost if wrong.** Balance-based accounting lets an attacker skew rates with a donation.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:91`

### CTR-TOK-06 — Fixed or timelocked adjustable rate at creation
- old: R135 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-06 · superseded-by: —

**Why.** The issuer chooses at creation between a fixed rate and a timelocked adjustable one; holders see the choice before they wrap.
**Cost if wrong.** A silently adjustable rate is an admin key over holders' value.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:98`

### CTR-TOK-07 — Multi-underlying any-of with disable-only guardian
- old: R136 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-07 · superseded-by: —

**Why.** Multi-underlying is any-of with a disable-only guardian: holders can always exit through any enabled leg and nobody can add a leg. Rejected: a weighted basket that mints from a group of tokens at fixed proportions — it needs price oracles and rebalancing, which the immutable design forbids.
**Cost if wrong.** A basket would introduce oracle and rebalancing risk into every wrap and unwrap.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:108`

### CTR-TOK-08 — Decimals are display only
- old: R137 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-08 · superseded-by: —

**Why.** Decimals are display only; arithmetic uses raw units, so a decimals mismatch can never misprice a wrap.
**Cost if wrong.** Scaling by decimals inside the contract adds rounding paths and errors.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:115`

### CTR-TOK-09 — NoUnderlyingToken holder burn, renounceable minter
- old: R141 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-09 · superseded-by: —

**Why.** A `NoUnderlyingToken` lets holders burn and its minter retire, which matches self-issued tokens; both are now the flags `BURNABLE` and `MINTABLE`, the minter a granted role whose holder may `renounceRole` ([CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)).
**Cost if wrong.** A non-renounceable minter is a permanent admin key.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:135`

### CTR-TOK-10 — Only creation-time visible admin exceptions
- old: R142 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-10 · superseded-by: —

**Why.** Only publicly visible admin exceptions exist, so a holder can read every power over a token before acquiring it. Features stay creation-time ([CTR-TOK-22](contracts/token-wrappers.md#CTR-TOK-22)); the earlier creation-time-only roles are superseded by roles the owner grants and revokes (owner ruling), all public on chain.
**Cost if wrong.** Hidden or later-added powers would make provenance meaningless.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:138`

### CTR-TOK-11 — Fee-on-transfer-out and rebasing underlyings unsupported
- old: R143 · status: current · owner: no · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-11 · superseded-by: —

**Why.** Fee-on-transfer-out and rebasing underlyings break 1:1 accounting; they are refused rather than half-supported.
**Cost if wrong.** Supporting them silently would make reserves drift from supply.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:144`

### CTR-TOK-12 — Voluntary v2 migration; domain read per token
- old: R146 · status: superseded · owner: no · date: 2026-10-08 · normative: — · superseded-by: CTR-TOK-03, CTR-MTX-02

**What it said.** v1 clones and factory v1 stayed untouched beside v2 and holders migrated voluntarily; clients read the domain and pay lane per token.
**Why.** Nothing is deployed, so the v1 line is deleted instead of migrated (CTR-TOK-03); reading the domain per token survives in CTR-MTX-02.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:156`; `history/specs/2026-10-07-metatx-generic.md` §2 A4, §7.

### CTR-TOK-13 — Multi rates adjustable per leg, default off
- old: R147 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-13 · superseded-by: —

**Why.** Per-leg adjustable multi rates are an issuer option, off by default.
**Cost if wrong.** Default-on adjustability would surprise holders of plain wrappers.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:160`

### CTR-TOK-14 — Gasless wrap through permit is planned only
- old: R149 · status: superseded · owner: no · date: 2026-10-08 · normative: — · superseded-by: CTR-TOK-20, CTR-MTX-19

**What it said.** A gasless wrap through an EIP-2612/Permit2 op was planned only.
**Why.** Gasless wrap is now `mtxExecute(wrap)` under an allowance on an outside underlying (CTR-MTX-19) or `mtxWrap` by signature for a SCaaS underlying (CTR-TOK-20); no permit op is needed.
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:184`; `history/specs/2026-10-07-metatx-generic.md` §7 (CTR-TOK-14 row).

### CTR-TOK-15 — Open factory: anyone creates tokens
- old: UD:§20 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/token-wrappers.md#CTR-TOK-15 · superseded-by: —

**Why.** An open factory means anyone can create tokens or wrap any token; SCaaS is not a gatekeeper.
**Cost if wrong.** Spam tokens exist; provenance getters (CTR-TOK-17) let clients filter them.
**Source.** `research/_USER-DECISIONS.md:1079`

Change (2026-10-20): owner 2026-10-19 (plan 5g-Z1, CTR-ZTH-20) — the factory stays open for token creation; what the
creator no longer chooses is a confidential token's verifier: it is fixed by the implementation release (constructor
immutables, registered only on the factory's canonical set), and the creator picks it only by picking the version. Status: built, commit `690a295a` (plan Task 5g-Z1).

Change (2026-10-20): owner 2026-10-20 (plan 5g-Z2) — the confidential release's verifiers are the `deps` of the env
version the registrar names at `deployImplementation` (CTR-TOK-03 Change of 2026-10-20), immutables of its code by
construction; the creator still picks them only by picking the version. Status: built on branch `rev2-zether-z2`, commit `0f88e66f` (plan Task 5g-Z2).

### CTR-TOK-16 — getWrapper keyed by creator and underlying
- old: UD:§20.3 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/token-wrappers.md#CTR-TOK-16 · superseded-by: —

**Why.** Wrappers are looked up by `(creator, underlying)`, so two creators never collide and no global "official" wrapper exists. Three lookups answer three questions: getWrapper(creator, underlying) is A's xDAI wrapper; getWrapperCount / getWrapperAt list all of A's xDAI wrappers (one per curve or fee schedule); deployCountFor / deployedFor list every zDAI wrapper of every creator so the market can compare A with B. There is no uniqueness on `underlying` alone and no name or symbol review: `zDAI-A` and `zDAI-B` coexist normally.
**Cost if wrong.** A global wrapper slot invites squatting.
**Source.** `research/_USER-DECISIONS.md:1210`

### CTR-TOK-17 — Provenance getters instead of gatekeeping
- old: UD:§20.4 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/token-wrappers.md#CTR-TOK-17 · superseded-by: —

**Why.** Every token answers immutably who created it and from which implementation; clients decide trust instead of the factory.
**Cost if wrong.** Clients that ignore provenance can be shown look-alike tokens.
**Source.** `research/_USER-DECISIONS.md:1255`

Change (2026-10-20): owner 2026-10-19 (plan 5g-Z1) — provenance gains `isRegisteredToken(token)` (made from a registered
version, `version ≠ 0`); a version-0 token is unvetted code and clients and the gateway treat it so. For confidential
tokens the factory is the published source of the canonical verifiers (CTR-ZTH-20) instead of a client-side list. Status: built, commit `690a295a` (plan Task 5g-Z1).

Change (2026-10-20): owner 2026-10-20 (plan 5g-Z2) — the factory publishes a confidential token's verifiers through its
release: `releaseOf(kind, version)` gives `envVersion` and `envHash`, `envOf(kind, envVersion).deps` the addresses (5g-Z1's
`zetherVerifiers` / `pqzVerifier` views are removed with `Canonical`). Status: built on branch `rev2-zether-z2`, commit `0f88e66f` (plan Task 5g-Z2).

### CTR-TOK-18 — Factory is the critical immutable artifact
- old: UD:§20.6 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/token-wrappers.md#CTR-TOK-18 · superseded-by: —

**Why.** The factory is the most critical immutable artifact: every clone inherits its code choices.
**Cost if wrong.** A factory bug is inherited by every token created through it until a new factory ships.
**Source.** `research/_USER-DECISIONS.md:1288`

Change (2026-10-20): owner 2026-10-20 (plan 5g-Z2) — the chain and verifier checks leave the factory for the
implementations' `initialize`: a Zether token reverts `VerifierUnsupportedOnThisChain` when the release's transfer
verifier's `isSupportedOnThisChain()` is false or unanswered (`ZetherLib.init`, was the factory's `_checkZether`), and
outside a dev chain (`ZetherSafety`); a PQZ token runs `PqzSafety` (was also `_checkPqz`). The factory keeps one generic
gate, `setKindEnabled(kind, on)` (registrar; it replaces `setZetherEnabled` / `setPqzEnabled`); **controller proposal,
owner may override:** the plain kinds start enabled, the confidential kinds disabled, and `setKindEnabled` itself runs
no chain check (the token's `initialize` does). Status: built on branch `rev2-zether-z2`, commit `0f88e66f` (plan Task 5g-Z2).

### CTR-TOK-19 — Multi wrap checks only its own leg's reserve
- old: — · status: current · owner: yes · date: 2026-10-06 · normative: contracts/token-wrappers.md#CTR-TOK-19 · superseded-by: —

**Why.** The reserve rule (CTR-TOK-05) stays per leg: `wrap`/`addReserve` on leg A check only leg A's `balanceOf ≥ reserve`, and a shortfall on another leg is disclosed and alerted on instead of blocking intake. Rejected: checking every leg on a multi `wrap` and `addReserve` (at most 8 `balanceOf`, as `executeRate` already does) — it would amend CTR-TOK-05.
**Cost if wrong.** After one leg loses backing, new deposits into a good leg mint at par into an under-backed pool and early exiters take the good assets those deposits brought; the mitigation is off-chain (per-leg backing alerts, issuer pausing intake by communication, wallets showing per-leg backing).
**Source.** `history/specs/2026-10-06-token-wrappers-v2.md:596` (owner decision 2026-10-06, implementation review L3); `history/specs/2026-10-06-token-wrappers-v2.md:925` (the open question it answers)

### CTR-TOK-20 — Signature wrap of a SCaaS underlying (mtxWrap)
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-20 · superseded-by: —

Change (2026-10-13): owner — `uaWrap(u, UATradeOrder, auth)`: the same wrap by signature with a UA order pulled by the underlying's `uaTrade`, minting to a `bytes32` destination (derived: `_uaMint`); event `UAWrapped`. SPECIFIED (UA-5b). Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.3.

Change (2026-10-13): built as ruled (UA-5b): `uaWrap` in `UnderlyingToken` / `UnderlyingLib`. Controller ruling, confirmed by the owner 2026-10-13: it emits `UAWrapped` only (no `Wrapped`), the leg check is ERC-165 on `IUALedger` before the pull (C5b-9). Source add: plan `superpowers/plans/2026-10-13-ua5b-trade-dex.md`.

**Why.** An EOA holding a SCaaS underlying cannot approve the wrapper, so the owner accepted a signature wrap: the holder signs a `TradeOrder` in the underlying's domain naming the wrapper as `dex`; the wrapper pulls through the underlying's `mtxTrade`, checks the received amount and mints in the same call, paying the relayer from the order's `fee`.
**Cost if wrong.** Without it, holders of SCaaS underlyings could never wrap (or fund Zether) without a contract account.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A9, §3 MG-7b.

### CTR-TOK-21 — One implementation per kind; the token tree
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-21 · superseded-by: —

**Why.** Two axes: the kind is code (`NONE`, `UNDERLYING` with 1–8 legs, `NONE_ZETHER`, `UNDERLYING_ZETHER`; four PQZ kinds reserved), the features are flags; the tree is `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → kinds. Single and Multi merge (the leg count says which); Hedera is a deploy-time `IS_HEDERA`, not a child contract; every token can trade. The built code carries three generations side by side and the Zether token duplicates a second wrapper tier.
**Cost if wrong.** Per-combination contracts multiply audits and overflow EIP-170 (today `ZetherToken` is 4,363 B over); a creator could not pick "single underlying, payable off, confidential".
**Source.** `history/specs/2026-10-08-token-tree-design.md` §1, §2 (T1, T3, T9, T10, T13), §3.

Change (2026-10-20, owner): **the reserved kinds `NONE_ZETHER_PQZ` and `UNDERLYING_ZETHER_PQZ` are dropped** (a token carries at most one confidential layer; a holder who wants both uses two tokens). Ids 6 and 7 are not reused for anything else; the enum entries go with the `mtxShield` / `mtxUnshield` rework (no layer argument needed; CTR-ZTH-45 change) — all chains are test-only. Specs to update with it: token-wrappers.md kind table, pq-zero-knowledge.md, contracts/README.md. Status: decided; code change with plan Task 5h.

Change (2026-10-20, controller record): **kinds 6 and 7 dropped, as built** (plan 5h D21, Task 3z `7733910e`, merge `f8715b65`): `NONE_ZETHER_PQZ` / `UNDERLYING_ZETHER_PQZ` are gone from `IOpenFactory.TokenKind` (ids not reused), the four `KindReserved` checks and the error are removed, and the factory's ABI decoder rejects 6 and 7 (`Factory.t.sol` asserts the failure). The kind table in token-wrappers.md and the contracts/README picture caption were updated; the SVG pictures still show the reserved boxes (docs follow-up). Status: decided (owner); built.

### CTR-TOK-22 — Features are flags: features, lockedFeatures, owner, roles, disableFeature
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-22 · superseded-by: —

**Why.** One administration word chosen at creation (bits 0–8: `PAYABLE`, `MINTABLE`, `BURNABLE`, `RATE_ADJUSTABLE`, `WRAP_DISABLEABLE`, `FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST`); per flag the creator picks locked or disableable (the owner may clear it once, never set it). Owner ruling: issuers administer through one `owner` (optional; candidate OpenZeppelin `AccessControlDefaultAdminRules`, decided in P1) who grants and revokes the roles and disables disableable flags, and can give everything up: after `renounceOwnership()` role holders keep their roles, so an unchangeable token means revoking every role first. The built `renounceMinter`, `renounceRateAdmin`, `renounceGuardian` correspond to the holder's `renounceRole`, `disableControls` to `disableFeature`. Validation lives in the token's `initialize` (`FeatureInvalidForKind`, `LockedNotSubset`, `RoleWithoutFeature`); `PAYABLE` is default off; `PAYABLE` and `BURNABLE` have no role and are always locked (`disableFeature` reverts `FeatureLocked(bit)`); the token refuses flags 5–8 on a confidential kind; a minter never mints into a shielded balance.
Change (2026-10-09): `PAYABLE` and `BURNABLE` have no role and are always treated as locked; `disableFeature(PAYABLE|BURNABLE)` reverts `FeatureLocked(bit)`.
**Cost if wrong.** Per-class powers cannot express a mix; an unvalidated factory-side check would let `createTokenUnregistered` bring a token with inconsistent roles.
**Source.** `history/specs/2026-10-08-token-tree-design.md` §2 (T2, T5, T8, T11), §5.

### CTR-TOK-23 — Hedera is IS_HEDERA, not a child contract
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-23 · superseded-by: —

**Why.** Hedera is a per-chain variant, so each implementation carries an immutable `IS_HEDERA`; when set the signature check takes the HIP-632 path and `UnderlyingLib` associates HTS underlyings fail-closed (`HederaLib`). The three Hedera children and four copies of the override go for about 0.5–1 KB per implementation.
**Cost if wrong.** Hedera children triple the deployable set and keep four copies of one override in sync by hand.
**Source.** `history/specs/2026-10-08-token-tree-design.md` §2 (T3, T13), §3.

### CTR-TOK-24 — External libraries, ERC-7201 namespaces, size budget
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-24 · superseded-by: —

**Why.** Heavy logic moves to external libraries linked at deploy (`TradeLib`, `PayLib`, `AdminLib`, `UnderlyingLib`, `ZetherLib`, `HederaLib`); the transfer hot path and the per-transfer administration check stay inline. Each module keeps state in its own ERC-7201 namespace so libraries never overlap; each token implementation is capped at 20,480 B (about 4 KB of room for later streams) and CI fails above it.
**Cost if wrong.** Without the split the rewrite does not fit EIP-170 (24,576 B); shared storage between libraries would corrupt silently.
**Source.** `history/specs/2026-10-08-token-tree-design.md` §1, §4.

### CTR-TOK-25 — Creation API: createToken, createTokenUnregistered, TokenConfig, TokenCreated
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-25 · superseded-by: —

**Why.** One `TokenConfig` (name, symbol, decimals, features, lockedFeatures, owner, roles, initial supply, legs, rate, confidential parameters) replaces the per-kind `initData`; `CREATE2` clone and `initialize` in one call; one `TokenCreated` event; registry views `isToken`, `isDex` and `versionOf`; `createDex` and `DexConfig` (CTR-DEX-24); one `IOpenFactory` and one `IFactoryToken`.
**Cost if wrong.** Per-kind encodings keep a second parsing surface in the factory, node and clients; a deployed-but-uninitialized clone can be front-run.
**Source.** `history/specs/2026-10-08-token-tree-design.md` §7.

Change (2026-10-20): owner 2026-10-19, option (a) (plan 5g-Z1) — `createTokenUnregistered` refuses every confidential kind
(`UnregisteredConfidentialKind`, kinds 2–7) and stays for the plain kinds, recorded as version 0 and flagged unvetted
(`isRegisteredToken` false); `ConfidentialConfig.verifier` must be 0 (the release's verifier, CTR-ZTH-20; the field stays
until the creation API is replaced in plan 5g-Z2). Status: built, commit `690a295a` (plan Task 5g-Z1).

Change (2026-10-20): owner rulings 2026-10-20 (plan 5g-Z2) — **generic creation API.** `createToken(kind, version, bytes
initArgs, salt)`, `createTokenUnregistered(kind, implementation, bytes initArgs, salt)` (plain kinds only) and
`createDex(version, bytes initArgs, salt)`; every implementation answers `initialize(address creator, uint64 version,
bytes initArgs)`; the kinds of this repository decode `initArgs = abi.encode(TokenConfig)`, `SCaaSDex`
`abi.encode(DexConfig)`; the factory never reads `initArgs`. **Owner ruling 2026-10-20 (confirmed): `initialize` takes no
`Env`**, and the split stays explicit — the implementation carries what never changes for it (the `Env` in its
constructor: verifiers, registry, chain, libraries), each instance carries its own configuration from `initArgs`
(rates, features, roles, the confidential settings). `ConfidentialConfig.verifier` is removed (7 fields). The factory's
index and the one `TokenCreated` read the token's `underlyings()`, `features()`, `lockedFeatures()` and `owner()` after
`initialize`; `createToken` refuses an unknown, deprecated or not-yet-usable release and a disabled kind (`KindDisabled`).
Status: built on branch `rev2-zether-z2`, commit `0f88e66f` (plan Task 5g-Z2).

### CTR-TOK-26 — A leg may be the native coin
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/token-wrappers.md#CTR-TOK-26 · superseded-by: —

**Why.** Owner: wrap like the standard wrapped coins (WETH, WXDAI), because some chains have no standard wrapped native token.
**Cost if wrong.** Issuers on such chains cannot back a token by the native coin.
**Source.** `history/specs/2026-10-08-token-tree-design.md` T16.

### CTR-TOK-80 — No EOA approve lockdown
- old: R4 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-TOK-01

**What it said.** An earlier design did not lock EOA approvals.

## 19. Contracts — Accounts and mandates

### CTR-ACC-01 — SmartKeyAccount clones; salt binds key and guardian
- old: RS4-1 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts.md#CTR-ACC-01 · superseded-by: —

**Why.** Counterfactual clones with a salt binding the first key and the guardian give a predictable address that nobody else can claim.
**Cost if wrong.** A salt of the key alone would let anyone deploy the account with a hostile guardian.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:11`

### CTR-ACC-02 — Signature is keyIndex, Merkle proof, sig
- old: RS4-3 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts.md#CTR-ACC-02 · superseded-by: —

**Why.** One signature encoding `(keyIndex, proof, sig)` covers single operations and Merkle batches for both key types.
**Cost if wrong.** Two encodings would double the parsing and test surface.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:19`

### CTR-ACC-03 — Guardian recovery adds a key after two days
- old: RS4-4 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts.md#CTR-ACC-03 · superseded-by: —

**Why.** Guardian recovery adds a key after a two-day delay that any existing key can cancel, so a lost device is recoverable and a rogue guardian is visible.
**Cost if wrong.** An instant recovery would let a compromised guardian take the account.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:23`

### CTR-ACC-04 — Authenticator signCount is not checked
- old: RS4-5 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts.md#CTR-ACC-04 · superseded-by: —

**Why.** Synced passkeys report a zero or non-monotonic signCount; checking it would lock out legitimate users.
**Cost if wrong.** A cloned authenticator is not detected by the counter; the account relies on device security instead.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:27`

### CTR-ACC-05 — 400k ERC-1271 cap only for SmartKeyAccount clones; salted account domain
- old: RS4-10 · status: current · owner: no · date: 2026-10-08 · normative: contracts/accounts.md#CTR-ACC-05 · superseded-by: —

**Why.** Only `SmartKeyAccount` clones, identified by codehash, get the 400 k ERC-1271 cap that the Solidity P-256 path needs; everything else keeps 50 k. The account's domain carries `salt = chain_uid` from the factory, so its address differs per chain.
**Cost if wrong.** A global 400 k cap lets any contract wallet grief relayers with expensive validation.
**Source.** `history/plans/2026-10-03-r3-passkey-seed.md:43`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-4.

### CTR-ACC-06 — Delegated payment uses MandateWallet, no allowance
- old: R25 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/mandates.md#CTR-ACC-06 · superseded-by: —

Change (2026-10-13): owner — owner, delegate and payees may be UAs (CTR-ACC-12; SPECIFIED, UA-5c). Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.12, Q8.

**Why.** Delegated payment through a dedicated `MandateWallet` (`mtxPayUnderMandate`) with per-token limits never exposes the payer's main balance to an allowance; a mandate is not an allowance, since the wallet, a contract, is the token's caller. The wallet's domain is salted with a deployer-chosen `chain_uid`, so the node checks it before relaying.
**Cost if wrong.** An allowance-based mandate would be an unlimited spender on the payer's tokens.
**Source.** `history/specs/2026-10-03-blockchain-payments-addendum-wallets.md:196`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-3, MG-4, MG-7.
Change (2026-10-08): `MandateWallet` is a `MetaTxBase` contract: the delegate signs a `MetaTransaction` with `data = payUnderMandate(token, payee, amount, entryRef)` or `revoke(token, epoch)`, fee `NONE`; the typed `PayUnderMandate`/`RevokeMandate` go; named entries keep their signatures and derive their lane (`"scaas.mandate.pay"`/`"scaas.mandate.revoke"`, nonce 0). Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G3, §3 GC-6.
Change (2026-10-19): controller proposal (owner may override) — **mandate periods are fixed windows on the grid of the mandate's start** (the second code review, on-chain part (plan Task 5g, branch `rev2-chain-sol`; triage W-A…W-S in `pqz-core/research/code-review-2026-10-19/U-agy-chain.md`, row W-L; report `V2-claude-ua-account-wallet.md` V2-4). `MandateWallet.payUnderMandate` reset an ended period to `periodStart = now`, so the first payment after an idle stretch opened a window where the delegate chose; now `periodStart += ⌊(now − periodStart) / periodSeconds⌋ · periodSeconds`, the window that holds `now`, so the boundaries stay on the grid `setMandate` (or a reset) started and the owner can compute them. A fixed window still admits `maxPerPeriod` just before and again just after a boundary — at most `2 · maxPerPeriod` within any `periodSeconds`, as before; the grid does not remove that, and the triage's "no double cap across a boundary" needs a rolling window, i.e. the payment history on chain (rejected: unbounded storage and gas per payment). `mandates.md` CTR-ACC-06 states the semantics and tells an owner who needs a hard bound per `periodSeconds` to set half the cap. Test `test_period_windows_stay_on_the_grid` (fails on the old reset). Deployed bytecode: `MandateWallet` (and `HederaMandateWallet`). Status: **done** (`a59168c5`).
Change (2026-10-19): **owner ruling W-L — the fixed period grid is accepted.** The owner accepts the grid of fixed windows as built (`a59168c5`, merged in the 5g integration `b37a49cf`): a delegate can spend `maxPerPeriod` just before and again just after a boundary, so at most `2 · maxPerPeriod` within any `periodSeconds`, as mandates.md CTR-ACC-06 documents; no rolling window (it needs the payment history on chain: unbounded storage, or a ring buffer with a payment-count cap). An owner who needs a hard bound per `periodSeconds` sets half the cap, or a shorter period with a proportional cap (P/2 with cap/2 gives at most 1.5× over any interval of length P). Status: **ruled** (owner, 2026-10-19); mandates.md says so.

### CTR-ACC-07 — Signed mandate revocation bound to epoch
- old: CR-ADW-1 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/mandates.md#CTR-ACC-07 · superseded-by: —

**Why.** A signed revocation (`mtxRevoke`, renamed from `revokeWithSig`) bound to an epoch revokes every outstanding mandate signature at once and works gaslessly.
**Cost if wrong.** Without the epoch a revoked delegate could replay an older mandate.
**Source.** `history/specs/2026-10-03-blockchain-payments-addendum-wallets.md:296`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-3.
Change (2026-10-08): the epoch travels in the revoke data, `revoke(token, epoch)`, on the lane `keccak256("scaas.mandate.revoke" ‖ token ‖ epoch)`. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-6.

### CTR-ACC-08 — Passkey subjects, Merkle batch, account key lifecycle
- old: R31(account) · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-ACC-08 · superseded-by: —

**Why.** Retail subjects use passkeys they already have; Merkle batching gives one biometric prompt for many lines; one grammar and check order apply in every family.
**Cost if wrong.** Per-family WebAuthn checks drift, and one lax family (suffix origin, crossOrigin) becomes the phishing target.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:519`

### CTR-ACC-09 — SmartKeyAccount kept as optional option (b)
- old: R307 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/accounts.md#CTR-ACC-09 · superseded-by: —

**Why.** `SmartKeyAccount` stays available as option (b) for users who want a stable address across key rotation.
**Cost if wrong.** Removing it would force every rotation to move funds.
**Source.** `history/specs/2026-10-06-universal-account-design.md:238`

### CTR-ACC-10 — SmartKeyAccount key management is a MetaTransaction signed by the account itself
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/accounts.md#CTR-ACC-10 · superseded-by: —

**Why.** `SmartKeyAccount` moves onto `MetaTxBase` like every SCaaS contract (owner G3); its keys include passkeys with no address, so the account itself is `from` and verifies the signature against its own key set (owner G9); the typed `OwnerCall` and its single nonce go, the lanes and vectors are shared with every contract.
**Cost if wrong.** An account that signed as one of its keys could not use passkeys; a separate owner struct keeps a second digest rule and nonce space alive.
**Source.** `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G3, G9, §3 GC-6.

### CTR-ACC-11 — The multi-key contract account is SmartKeyAccount in every chain family
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/accounts.md#CTR-ACC-11 · superseded-by: —

**Why.** "Smart" marks a contract account and "key" its many keys; the old name said nothing a reader could use. One name in every family (EVM `SmartKeyAccount` and `SmartKeyAccountFactory`, the Solana, Sui, Aptos and Soroban equivalents) is renamed in code in phase P4, all at once.
**Cost if wrong.** Two names live side by side in code and docs for longer than P4; a half-renamed family reads as a different contract.
**Source.** `history/specs/2026-10-08-token-tree-design.md` T15.

### CTR-ACC-12 — A UA may own, delegate and receive under a MandateWallet
- old: — · status: current · owner: yes · date: 2026-10-13 · normative: contracts/mandates.md#CTR-ACC-12 · superseded-by: —

**Why.** `bytes32` owner, delegate and payees with the generic UA pipeline of `MetaTxBase` let a UA use a mandate without a wallet-specific signature path; a derived owner gets no ERC-1271 answer because callers cap 1271 at 50 k gas (a PQ check needs up to 5.95 M) and a 1271 answer would be a generic signing oracle for a UA key (CTR-UA-10 layer 1).
**Cost if wrong.** A derived owner cannot pay by hand through ERC-1271; it acts through `uaExecute(execute(…))` on the wallet.
**Source.** owner, 2026-10-13 (Q8); `history/specs/2026-10-13-ua-parity-design.md` §4.12, O7.

### CTR-ACC-80 — Typed owner and mandate structs (OwnerCall, PayUnderMandate, RevokeMandate)
- old: — · status: superseded · owner: yes · date: 2026-10-08 · normative: — · superseded-by: CTR-ACC-06, CTR-ACC-07, CTR-ACC-10

**What it said.** `SmartKeyAccount` and `MandateWallet` each verified their own EIP-712 structs (`OwnerCall(bytes data,uint256 nonce,uint256 validUntil)`, `PayUnderMandate(…)`, `RevokeMandate(…)`) with their own nonce rules.

## 20. Contracts — DEX

### CTR-DEX-01 — Complete DEX with token-verified orders and no allowances for SCaaS tokens
- old: R35(contract) · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-01 · superseded-by: —

**Why.** An off-chain persistent book with on-chain settlement gives exchange UX without custody. The owner moved order verification into the sell token (role-free `TradeOrder`, funds only into the named DEX), kept both paths, and made the DEX pay out and end every call with unchanged balances; the fee rate is the signed one.
**Cost if wrong.** Trusting the book for prices would let the operator fill against users; DEX allowances keep EOA approvals alive.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:554`; `history/specs/2026-10-07-metatx-generic.md` §2 A7, A10, §3 MG-8.
Change (2026-10-08): the same `TradeOrder`s can also be executed against AMM pools — multi-hop routes, cycles — through `mtxExchange` (CTR-DEX-20), with the surplus paid to the signers (CTR-DEX-21). Source add: `history/specs/2026-10-08-dex-exchange-design.md` §1, §2 S3, §3 DS-1.

### CTR-DEX-02 — Cancel signatures never expire; per token and per DEX
- old: RS5-10 · status: current · owner: no · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-02 · superseded-by: —

**Why.** Cancel signatures (`CancelOrder`, `InvalidateNonces`) never expire, so a cancellation cannot lapse before the order does; they now live on each sell token (`mtxCancelOrder`, `mtxInvalidateNonces` per order lane) and on the DEX for outside-token orders.
**Cost if wrong.** An expiring cancel could resurrect an order the signer withdrew.
**Source.** `history/specs/2026-10-03-dex-design.md:119`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-8.2, MG-8.4.

### CTR-DEX-03 — Admin set once at creation: list markets and set the fee split
- old: RS5-1 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-03 · superseded-by: —

**Why.** The admin, set once at creation (CTR-DEX-24) with no setter, has two powers — `setMarket(base, quote, listed)` and `setFeeSplit(relayerSharePpm, treasury)` — and changes who receives fees and in what proportion, never the amount, which comes only from the signed `fee`.
**Cost if wrong.** An admin that sets the fee amount could raise it on resting orders; any custody power is custody by another name.
**Source.** `history/specs/2026-10-03-dex-design.md:398`; `history/specs/2026-10-07-metatx-generic.md` §2 A15, §3 MG-8.3.
Change (2026-10-08): `admin` is written once by `initialize` of a factory-made clone, no longer an immutable (CTR-DEX-24); two more powers, `setExchangeTarget` (list or delist an exchange target or executor) and `setListedOnly` (DEX-wide listed-only mode, default off); neither touches funds or a fee amount (CTR-DEX-23). Source add: `history/specs/2026-10-08-dex-exchange-design.md` §2 S1, S2, §3 DS-6.

### CTR-DEX-04 — IOC closed on chain at its single pull
- old: RS5-3 · status: current · owner: no · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-04 · superseded-by: —

**Why.** An IOC order is pulled once and `pulled[h] = amount` at that pull, so its remainder cannot fill later; Path B implies IOC.
**Cost if wrong.** A dangling IOC remainder could fill at a stale price.
**Source.** `history/specs/2026-10-03-dex-design.md:402`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-8.2.

### CTR-DEX-05 — FOK is minFill = amount, checked on chain
- old: RS5-4 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-05 · superseded-by: —

**Why.** Fill-or-kill is the order's `minFill = amount` with nothing pulled yet, enforced by the token (Path A) or the DEX (Path B, outside legs), so a partial fill can never settle.
**Cost if wrong.** Trusting the book for FOK lets a buggy matcher partially fill.
**Source.** `history/specs/2026-10-03-dex-design.md:404`; `history/specs/2026-10-07-metatx-generic.md` §2 A13, §3 MG-8.1.

### CTR-DEX-06 — Relayer FIXED fee pro-rata, rounds down
- old: RS5-6(relayer-fee) · status: superseded · owner: no · date: 2026-10-08 · normative: — · superseded-by: CTR-DEX-17

**What it said.** A separate per-order relayer fee (`FeeMode`, `fee`, `feeToken`, `feeRecipient`) was charged pro-rata per fill and rounded down.
**Why.** The owner replaced it with one signed DEX fee rate whose relayer share the DEX pays per its admin split (CTR-DEX-17).
**Source.** `history/specs/2026-10-03-dex-design.md:407`; `history/specs/2026-10-07-metatx-generic.md` §2 A15, §7 (CTR-DEX-06 row).

### CTR-DEX-07 — MetaTxDex kept as unrouted legacy
- old: RS5-7 · status: superseded · owner: no · date: 2026-10-08 · normative: — · superseded-by: CTR-DEX-16, CTR-DEX-01

**What it said.** `MetaTxDex` stayed deployed as an unrouted legacy two-leg settlement over `trade` op legs.
**Why.** The trade op is gone with the op dispatch; `SCaaSDex.mtxSettle` covers its fill-or-kill case, so `MetaTxDex` is deleted.
**Source.** `history/specs/2026-10-03-dex-design.md:409`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-8.4, §7 (CTR-DEX-07 row).

### CTR-DEX-08 — SCaaSDex caps ERC-1271 gas by codehash
- old: RS5-14(contract) · status: current · owner: no · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-08 · superseded-by: —

**Why.** The DEX's own signature checks (outside-token legs, DEX-domain cancels) cap ERC-1271 gas by codehash (400 k for `SmartKeyAccount` clones, else 50 k) and refuse to run with too little gas left; SCaaS legs get the same cap inside their token.
**Cost if wrong.** Uncapped 1271 lets a signer grief the settler; a 63/64 starvation could fake a failed check.
**Source.** `history/specs/2026-10-03-dex-design.md:431`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-8.4.
Change (2026-10-19): controller proposal (owner may override) — **an outside token cannot forge the starvation errors** (the second code review, on-chain part (plan Task 5g, branch `rev2-chain-sol`; triage W-A…W-S in `pqz-core/research/code-review-2026-10-19/U-agy-chain.md`, row W-O; report `V3-claude-common-metatx-dex.md` V3-01). `mtxSettle` re-raises a settlement's `SigCheckGasStarved` / `UAVerifyGas` for the whole call; an admin-listed outside token (or an ERC-777-style hook behind a payout) could revert with those bytes, so one counterparty voided a relayer's whole batch. Fix at the source: no call the DEX makes into a token returns the token's revert data — the puller pulls by `trySafeTransferFrom`, `_send` / `_sendTo` pay by `trySafeTransfer`, `_bal` reads `balanceOf(this)` by a one-word `staticcall`; each failure reverts `SafeERC20FailedOperation(token)`. Only the DEX, a SCaaS token (factory-registered code, no hooks) or the registry can then raise the two errors, so the re-raise rule stays and a real starvation still reverts the whole call. Deviation from the triage ("honour them only when the DEX frame itself is low on gas"): a real `UAVerifyGas` can come back with most of the gas (a `mldsa65` hold of 5.95 M refused at its start; caps up to `verifyBudget`, 12 M), so a threshold sound for real starvations lets a forger through on every batch below ≈ 6–13 M gas, and a tighter one turns real starvations into `MatchFailed`, which the node drops (NODE-DEX-06); the source fix has neither problem. Cost: the `MatchFailed` reason of a failed token call is `SafeERC20FailedOperation(token)` instead of the token's own error, for every token the DEX calls, SCaaS tokens included (`_send` / `_sendTo` / `_bal` serve all tokens): an outside token's `ERC20InsufficientAllowance(puller, …)`, and a regulated SCaaS payout's `Frozen` / `NotEligible` / `TokenPaused`, now all read `SafeERC20FailedOperation(token)` (the venue's NODE-DEX-11 pre-check carries the regulated attribution); a returnbomb token now returns one word. Tests: `test_forgedStarvationFromAnOutsideToken_isOnlyMatchFailed` (pull, payout, balance read × both selectors: only that settlement fails, the other settles); the existing starvation tests unchanged. Deployed bytecode: `SCaaSDex` (and the `DexPuller` it deploys). Status: **done** (`c65f897e`). Follow-up (5g integration, branch `rev2-chain-int`; review of W-O F1 / F2; controller proposal, owner may override): (1) a token call that returns **no data** (it ran out of gas, or the token has no code) reverts **empty** again, so `MatchFailed`'s reason stays empty, which the node and the client contract read as `out_of_gas` (NODE-DEX-06, dex-venue.md, TODO P2b-2, the ERP connector contract); anything else reverts `SafeERC20FailedOperation(token)` (`SCaaSDex._tokenFailed`, used by `_send` and `_bal`; the same check inline in `DexPuller.pull`). Empty data matches neither starvation selector, so a token still cannot forge one. Test `test_starvedOutsideTokenCall_isAnEmptyMatchFailed` (pull, payout, balance read run out of gas: empty reason, the other settlement settles; fails before the follow-up), `test_forgedStarvationFromAnOutsideToken_isOnlyMatchFailed` still passes. (2) The texts (this entry, dex.md, the `mtxSettle` comment, asset-suite.md) say "every token" instead of "outside token" and list the regulated-reason loss above. Bytecode: `SCaaSDex` 22,953 B, `DexPuller` 643 B. Status: **done** (`5de4be5a`).

### CTR-DEX-09 — Non-EVM settlement bound to the relayer
- old: RS5-15(non-evm) · status: current · owner: no · date: 2026-10-07 · normative: contracts/dex.md#CTR-DEX-09 · superseded-by: —

**Why.** Non-EVM settlement is bound to the relayer, so a third party cannot front-run a matched pair.
**Cost if wrong.** Unbound settlement lets copycats steal relayer fees.
**Source.** `history/specs/2026-10-03-dex-design.md:438`

### CTR-DEX-10 — min_nonce capped by family word width
- old: RS5-19 · status: current · owner: no · date: 2026-10-07 · normative: contracts/dex.md#CTR-DEX-10 · superseded-by: —

**Why.** `min_nonce` is capped by each family's word width so a maker cannot brick its own nonce space by overflow.
**Cost if wrong.** An uncapped value could wrap or exhaust the nonce space.
**Source.** `history/specs/2026-10-03-dex-design.md:448`

### CTR-DEX-11 — DEX fee rounds up, once per order per settlement
- old: RS5-21 · status: current · owner: no · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-11 · superseded-by: —

**Why.** `dexFee = ceil(receiveFill · fee / 10⁶)` on the order's aggregate received amount in a settlement, so many small fills cannot evade the fee by rounding and the token's `FeeAboveSigned` bound holds for a taker filled by several makers.
**Cost if wrong.** Round-down lets dust fills trade fee-free; per-maker ceilings could exceed the signed bound.
**Source.** `history/specs/2026-10-03-dex-design.md:455`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-8.3.

### CTR-DEX-12 — Managed market venue contract and arbiter
- old: R214(contract) · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-12 · superseded-by: —

**Why.** A managed market is an `SCaaSDex` instance whose admin is the venue operator's multisig; the regulated token's own checks arbitrate on chain, and a settlement that slipped through intake fails alone.
**Cost if wrong.** Mixing managed rules into the open DEX would gate everyone.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:176`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-8.3.

### CTR-DEX-13 — TradeOrder: one role-free struct for every leg
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-13 · superseded-by: —

**Why.** The owner modernized the earlier `MtxTradeOrder` with the old field names: `from`, `receiveToken`, `amount`, `receiveAmount`, `minFill`, `fee`, `relayer` (the matching party), `dex` (the only puller and recipient), `destination` (accepted by the owner), `flags`, `batch`, `nonce`, `validUntil`, signed in the sell token's salted domain. No role and no counterparty field: taker or maker is arranged at settlement, and `relayer` decides who may match.
**Cost if wrong.** Role fields freeze an order's side; a counterparty field duplicates `relayer`; an unsigned price on escrow legs lets the DEX set it.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A10, A12, A14, §3 MG-8.1.

### CTR-DEX-14 — Minimum fill: max(minFill, 50 %) for every order in a settlement
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-14 · superseded-by: —

**Why.** The owner kept the signer's `minFill` under the old 50 % protocol floor (`MIN_FILL_PPM`), applied on the sold and received side to the taker and every maker, so no order is matched as junk; `minFill = amount` is fill-or-kill and the last remainder of a Path A order may close below it.
**Cost if wrong.** Tiny fills force makers to re-create orders and inflate on-chain work.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A13, §3 MG-8.1.

### CTR-DEX-15 — The sell token verifies the order and moves funds only into dex
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-15 · superseded-by: —

Change (2026-10-13): owner — step 4 is skipped when `pulled[h] ≠ 0` (verified at the first pull or cancel; `h` binds every field), on the token and on the DEX's outside legs; `minNonce` is keyed by `bytes32` (natives padded: same slots), one floor for `TradeOrder` and `UATradeOrder`. SPECIFIED (UA-5b). Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.6, UP-12, O6, Q6.
Change (2026-10-19): controller proposal (owner may override) — **on-chain review W-S, SOL-02 (plan Task 5g, branch `rev2-chain-pqz`, commit `fb7600cb`; U SOL-02, P3):** the price limits `move · receiveAmount > receiveFill · amount` (`TradeLib.record`, Path A) and `sold · receiveAmount > recv · amount` (`SCaaSDex._calc`, ESCROW, CTR-DEX-16) are compared over 512 bits (`TradeLib.mulGt`, `Math.mul512`): the same verdict for every input whose products fit (fuzzed against the plain products), `PriceLimit` instead of a panic past 2^256. SOL-01 (floor rounding dust of `pqzUnshieldUnwrap`, favours solvency) and SOL-03 (`PqzSafety` / `ZetherSafety` chain allowlists, 22776 added at its launch gate) recorded as by design. Bytecode: `TradeLib` (+85 B), `SCaaSDex` (+58 B). Tests `test_pathA_priceLimit_hugeAmounts`, `testFuzz_mulGt`, `test_mulGt_past2pow256`, `test_pathB_priceLimit_hugeReceiveAmount`. Status: **done** (`fb7600cb`, merged `734b9c76`).

**Why.** `mtxTrade` checks the caller is the named contract `dex`, the relayer binding, expiry, order lane, flags, amounts, the fee cap, the signature and `pulled[h] < amount`; on Path A it also checks fill, overfill, minimum, price and fee figures against the signed values; it moves funds to `dex` only, so no allowance is needed and a signer reads one address to know where its funds can go.
**Cost if wrong.** A token that trusts a caller-chosen route or recipient turns every order into a permit.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A7, §3 MG-8.2, §12 (C1, H7, M1), §13 (N-M1).
Change (2026-10-08): `o.receiveToken == address(this)` is allowed (a cycle order sells X for more X on the exchange path); `SelfOrder` stays for `from` and `dex`; known flags gain `LISTED_POOLS = 4`, which the token does not interpret. Source add: `history/specs/2026-10-08-dex-exchange-design.md` §2 S3, §3 DS-2.
Change (2026-10-27): **review C6-5 (controller proposal, owner may override)**: an order with `nonce ≥ 2^128` is refused at the pre-check (`NonceAboveCap(orderHash)`): no lane floor could ever reach it (`minNonce` is capped at `2^128`, CTR-DEX-02), only a per-order cancel would. The node's intake (`scaas-node` `dex.rs`) and `clientkeys` `checkTradeOrder` refuse it the same way. Status: **done** (review2 T6 `4623478d`, T7 `1b26e5ff`).

### CTR-DEX-16 — mtxSettle: everything through the DEX, balances unchanged
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-16 · superseded-by: —

Change (2026-10-13): owner — legs become tagged (`{sellToken, shape, order, sig, fill}`, shape 0 `TradeOrder`, shape 1 `UATradeOrder`); the UA rules are CTR-DEX-26. SPECIFIED (UA-5b). Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.7, O3, Q5.

**Why.** One taker against many makers per settlement: check, match at maker prices, pull every leg into the DEX, pay every destination, fee share and refund in the same call, then assert the DEX's balance of every token unchanged. One choke point and one invariant replace per-party delta checks, which misfire on shared addresses; listing only exact-transfer tokens makes conservation catch a misbehaving token.
**Cost if wrong.** Payments outside the DEX would leave the token trusting a fill it cannot see; dust or donations could be paid out.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §3 MG-8.3, §12 (M1, M3), §13 (N-M3).
Change (2026-10-08): outside-token legs are pulled through the `DexPuller` (CTR-DEX-22). Source add: `history/specs/2026-10-08-dex-exchange-design.md` §3 DS-4.
Change (2026-10-27): **review C6-8, the controller rulings of the P2b build recorded in full (owner may override)**: (1) there is no `checkOrder` view on the DEX: the dex.md §10 reads are the intake (P2b-2, `f4afbcac`); (2) `MatchFailed` keeps the first 256 bytes of a settlement's revert data (`MAX_REASON`) and `SigCheckGasStarved` reverts the whole call (P2b-2, `f4afbcac`). Status: **done** (built in P2b-2; recorded in review2 T8).
Change (2026-10-27): **review C6-1 (controller proposal, owner may override)**: every call the DEX or its puller makes into any token (`balanceOf`, `transferFrom`, `transfer`, `TokenCall`) is forwarded at most `TOKEN_GAS = 500,000` gas, so a hook or hostile token cannot burn the gas a later capped verify needs; running out is an ordinary failed call with empty return data (`MatchFailed`, the node's `out_of_gas`). The README row offered a per-settlement gas budget and / or this cap; only the cap was built: a `Settlement.gas` field changes the ABI the node and `clientkeys` encode. Cost if wrong: a token whose transfer needs more than 500,000 gas cannot settle on the DEX. Status: **done** (review2 T6 `49769894`).

### CTR-DEX-17 — One signed fee rate; the DEX distributes it per the admin split
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-17 · superseded-by: —

**Why.** The owner kept one fee field, `fee` (ppm, ≤ 1 %), on what the signer receives in any role; the DEX charges at most that, once per order per settlement, and splits it at once between the submitting relayer and the treasury. There is no separate relayer fee; maker/taker pricing is node intake policy.
**Cost if wrong.** Several fee fields multiply what a signer must check; fees kept in the DEX break conservation.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §2 A15, §3 MG-8.3.
Change (2026-10-27): **review C6-8 (controller ruling of P2b-1, owner may override)**: `FeeSplitInvalid` refuses a treasury of 0 or the DEX at `initialize` / `setFeeSplit` unless the relayer share is 100 %, so no share can stay in the DEX; the `FeeWouldStick` check the first design named is not built (P2b-1, `27b9e92a`; conservation backstops). Status: **done** (built in P2b-1; recorded in review2 T8).

### CTR-DEX-18 — Outside-token legs: the same order, checked by the DEX
- old: — · status: current · owner: no · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-18 · superseded-by: —

**Why.** A token SCaaS does not control cannot verify a `TradeOrder`, so the DEX does, with the same checks, as a `DexOrder` in its own salted domain with `o.dex == this`, its own `pulled`/`minNonce`, no `ESCROW`, and a pull under the party's allowance; token kinds come from the listing (via the factory's provenance), never from the leg.
**Cost if wrong.** A leg-declared kind could send a fallback-only "token" down the `mtxTrade` path; unchecked outside legs would trade at any price.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §3 MG-8.4, §13 (N-M2).
Change (2026-10-08): the pull is `DexPuller.pull` under the party's allowance to the puller, never to the DEX, so an exchange interaction cannot spend a user allowance (CTR-DEX-22). Source add: `history/specs/2026-10-08-dex-exchange-design.md` §3 DS-4.
Change (2026-10-27): **review C6-4 (controller proposal, owner may override)**: on the exchange path a receive-only outside token with a transfer fee pays signers below their signed floor and conservation does not catch it (the DEX measures its own balance; the fee comes out of the recipient's side); the settle path pulls both tokens and is safe. The loss is bounded by the token's fee. Recorded in dex.md (CTR-DEX-18, -21): list exact-transfer tokens only, delist a token that shows a fee; a recipient-balance check was not built. **Review C6-9**: `setMarket` refuses `base == quote` and a zero token (`BadMarket`). Status: **done** (documented in review2 T8; C6-9 built in review2 T6 `4623478d`).

### CTR-DEX-19 — dex must be a contract, nothing more (owner-accepted residual risk)
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-19 · superseded-by: —

**Why.** The owner decided against a token-side DEX registry or codehash allowlist: the token requires only that `dex` is a contract and consults no registry (the factory's `isDex`, CTR-DEX-24, is advisory, for clients and the node). A phishing contract named as `dex` can take the signed amount; the mitigations are off chain — clients warn and by default refuse to build or sign for a `dex` off the chain profile's DEX list (for `mtxWrap`: a registered wrapper), wallets show `dex`, and the node routes only to listed DEXes.
**Cost if wrong.** A user who overrides the client refusal and signs for a malicious contract loses the signed amount.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §4, §8 Q5, §13 (N-H1).
Change (2026-10-08): wording only — the token consults no registry; the factory's advisory `isDex` (CTR-DEX-24) is for clients and the node.

### CTR-DEX-20 — mtxExchange: TradeOrders executed against AMMs, multi-hop and cycles
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-20 · superseded-by: —

**Why.** On a chain with AMM liquidity an order the book cannot match can still fill at or above its signed price, a route through several pools can beat one pool, and a signer may want a cycle X→…→X. The owner wanted no new signed struct: the same `TradeOrder` is executed by the node's own algorithm instead of against `makers[]` — (a) `mtxExchange`, the DEX calling each interaction itself (CoW model), (b) `mtxExchangeVia`, a submitter-named executor (UniswapX model); `receiveFill` is a floor, one plan is atomic, and `ExchangeLegSettled` carries `limitReceive` so a client verifies the result without trusting the submitter. Named `mtxExchange` by the owner (first `mtxSolve`).
**Cost if wrong.** Without it AMM liquidity stays out of reach and every order without a book counterpart waits; a DEX-specific router per AMM kind would need new contract code for every venue.
**Source.** `history/specs/2026-10-08-dex-exchange-design.md` §1, §2 S3, S5, S7, §3 DS-1.
Change (2026-10-19): controller proposal (owner may override) — **DEX and metatx hygiene** (the second code review, on-chain part (plan Task 5g, branch `rev2-chain-sol`; triage W-A…W-S in `pqz-core/research/code-review-2026-10-19/U-agy-chain.md`, row W-Q; report `V3-claude-common-metatx-dex.md` V3-04 a–f). (a) **Sweep rule, no accounting**: the DEX holds nothing between calls; a balance that reaches it outside a settlement or plan (a mistaken transfer, a fee an interaction earns, e.g. `mtxWrap`'s fee minted to the DEX as submitter) belongs to nobody, and the next exchange-path submitter may move it through an interaction in any token outside its plan (plan tokens must end at their snapshots); dex.md CTR-DEX-20 says so; explicit accounting rejected (bytecode and gas for funds the protocol never puts there). (b) `sellToken == receiveToken` on the exchange path stays allowed — **refuted as a finding**: a cycle order sells X for more X through AMM routes by design (CTR-DEX-20 "multi-hop and cycles", dex.md CTR-DEX-15 step 1, CLI-SGN-37's cycle label; `test_exchange_profitableCycle_xToX`); the settle path refuses it because a book match of X against X is meaningless. A refusal was tried and reverted on that test. (c) `_classify` is **not** re-checked per leg: `deprecate` only marks a version (CTR-TOK-18), a per-leg check costs two factory calls per leg, and making a listed token outside voids every order signed in its token domain — the DEX admin's call, by re-listing (dex.md CTR-DEX-18). (d) Factory doc drift fixed (token-wrappers.md kinds table, CTR-TOK-18 registrar powers, CTR-TOK-25, §6.2; `IOpenFactory`'s enum comment): kinds 4–5 are built behind the PQZ gate, 6–7 reserved; the registrar also has `registerDexImplementation` and `setPqzEnabled`. (e) `mtxWrap` emits `Wrapped(destination or from, u, received, minted − fee)` and `uaWrap` `UAWrapped(to, u, received, minted − fee)` (field renamed `from` → `to`, same topic hash): the credited party and what it got; the return value stays the gross `minted`. (f) `nonReentrant` on `payWithFee`, `payWithFeeToUA`, `mint`, `mintToUA`, the role and owner functions (`MetaTokenBase`), `disableWrap`, `proposeRate`, `cancelRate`, `executeRate`, `disableFeature` (`UnderlyingToken`) and `SmartKeyAccount.initiateRecovery` / `completeRecovery`; CTR-MTX-18 names the exceptions (`initialize`; the plain ERC-20 `transfer` / `approve` / `transferFrom`, which make no outside call). None of them made an outside call, so no live path closes; the rule becomes true. The `UnderlyingZetherToken` / `UnderlyingPqzToken` overrides of `disableFeature` and `executeRate` (zether/, pqz/, open on this branch) got the guard in the 5g integration (`7b507c3a`; test `test_reentryIntoTheRestatedAdminEntriesRefused` in `ZetherUnderlying.t.sol` and `PqzUnderlying.t.sol`: a hook leg re-entering either mid-pull gets `Reentrancy`, before `NotOwner`; +265 B each, `UnderlyingPqzToken` 60,105 B against the 65,536 B test-chain limit). Tests: the `Wrapped` / `UAWrapped` assertions of `MtxWrap.t.sol` / `UAWrap.t.sol`; `test_native_reentryIntoEveryEntry_isRefused` (13 entries re-entered from a native payout, all `Reentrancy`); `test_executeCannotReenter` (the recovery entries). Deployed bytecode: `SCaaSDex`, every token implementation, `SmartKeyAccount`. Status: **done** (`0fd4cc65`).

### CTR-DEX-21 — The exchange surplus goes to the signers, on chain
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-21 · superseded-by: —

**Why.** Output above the floors belongs to the signers (owner): per receive token the excess over the floors and Path B refunds is split pro rata by floor, the remainder to the last leg; any other leftover reverts; the surplus pays no DEX fee. With strict conservation and fixed floors alone, a better-than-quoted AMM output would revert the plan.
**Cost if wrong.** A surplus left to the submitter turns every quote buffer into the submitter's income; a leftover assigned arbitrarily would hide route bugs.
**Source.** `history/specs/2026-10-08-dex-exchange-design.md` §2 S4, §3 DS-3.

### CTR-DEX-22 — DexPuller: the DEX holds no user allowance
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-22 · superseded-by: —

**Why.** An exchange interaction runs as the DEX, so any allowance the DEX held could be spent by `outsideToken.transferFrom(victim, attacker, x)`. Outside-token holders approve an immutable puller that only the DEX can call, and the DEX calls it only after its own `DexOrder` checks (CoW's vault-relayer pattern).
**Cost if wrong.** An allowance on the DEX itself makes every open-mode interaction a theft path for every outside-token holder.
**Source.** `history/specs/2026-10-08-dex-exchange-design.md` §3 DS-4, §4.

### CTR-DEX-23 — What an exchange interaction may call; listed targets by flag or admin mode
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-23 · superseded-by: —

**Why.** Interactions may target any contract by default (owner), except the DEX and the puller, and never with the `mtxTrade` selector (else a victim's resting order naming this DEX could be pulled with an invented fill and the amount moved out while conservation balances). The owner wanted both guards on targets: the signer's `LISTED_POOLS` flag per order and the admin's DEX-wide listed-only mode; the listing then applies to every target and to an executor, whose inner calls the DEX cannot see.
**Cost if wrong.** Without the selector block, any resting order is drainable; without a listing option, a signer who distrusts unknown pools has no on-chain guarantee.
**Source.** `history/specs/2026-10-08-dex-exchange-design.md` §2 S1, S2, S5, §3 DS-5, DS-6.
Change (2026-10-27): **review C6-8, the controller rulings of P2c recorded in full (owner may override)**: (1) `increaseAllowance(address,uint256)` and Permit2 `approve(address,address,uint160,uint48)` are refused as `ForbiddenSelector` on every interaction target, as `mtxTrade` / `uaTrade` are; (2) every allowance an `approve` interaction granted is set back to 0 after the last interaction; (3) `receivedFloor` is the gross floor (before the DEX fee), so the company books `receivedFloor − dexFee + surplus`. Other allowance-raising calls (e.g. `increaseApproval`) are neither refused nor reset (review C6-10: documented, conservation bounds a call, the admin lists targets accordingly). Status: **done** (built in P2c `dbf27a5e`; recorded in review2 T8).

### CTR-DEX-24 — Factory-made DEX clones; the DEX registry is advisory
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/dex.md#CTR-DEX-24 · superseded-by: —

**Why.** `OpenFactory.createDex` makes an `SCaaSDex` clone with `admin` written once by `initialize` and the `DexPuller` deployed by `initialize`; `isDex` serves clients and the node, and tokens never consult it, because requiring a factory-made DEX would give the factory admin too much power over trades (CTR-DEX-19 unchanged).
**Cost if wrong.** If tokens required `isDex`, the factory admin could stop trading; without the registry, clients and the node have no on-chain list of genuine DEX versions.
**Source.** `history/specs/2026-10-08-token-tree-design.md` T12, §7.

Change (2026-10-20): owner 2026-10-20 (plan 5g-Z1) — `deprecateDex(version, reason)` (registrar, immediate,
`DexImplementationDeprecated`) and `isDexDeprecated`; `createDex` refuses a deprecated version (`DexVersionDeprecated`);
DEXes already made are untouched. Status: built, commit `690a295a` (plan Task 5g-Z1).

Change (2026-10-20): owner rulings 2026-10-20 (plan 5g-Z2) — `createDex(version, bytes initArgs, salt)` with
`initArgs = abi.encode(DexConfig)` and `SCaaSDex.initialize(creator, version, initArgs)`; the DEX release is deployed by the
factory on a published DEX env (`publishDexEnv`, `deployDexImplementation(version, envVersion, initcode, implArgs)`, the
`SmartKeyAccount` implementation and the linked `TradeLib` from the env; the explicit `envVersion` is the interim
controller proposal of CTR-TOK-03, owner may override) and is usable after the notice period
(`DexVersionNotYetUsable`). Status: built on branch `rev2-zether-z2`, commit `0f88e66f` (plan Task 5g-Z2).

### CTR-DEX-25 — UATradeOrder: a UA's order, verified by its token
- old: — · status: current · owner: yes · date: 2026-10-13 · normative: contracts/dex.md#CTR-DEX-25 · superseded-by: —

Change (2026-10-13): built as ruled (UA-5b): `UATradeOrder`, `uaTrade`, `uaCancelOrder`, `uaInvalidateNonces` and the views in `ITradeToken` / `ERC20MetaTx`, `TradeLib` on one internal form with `bytes32` `minNonce` (one floor per id both ways), verify once on both paths (CTR-DEX-15 step 4), purpose `trade` in `UAKinds` and the six UA libraries, `uatrade_kat.json`. Controller rulings, confirmed by the owner 2026-10-13: the `ua*` trade functions revert `UALedgerOff` while the ledger is off, a padded native `from` included (C5b-2); one internal order form, a `TradeOrder` read as a `UATradeOrder` in memory (C5b-1). Source add: plan `superpowers/plans/2026-10-13-ua5b-trade-dex.md`.

**Why.** `TradeOrder.from` is an `address`, so a UA needs its own struct (`bytes32 from`, `bytes32 destination`) in the sell token's domain, signed under the new purpose `trade`; the token runs CTR-DEX-15 unchanged on the fields both structs share, moves the fill by `_uaMove`, and shares `minNonce` by id. Widening `TradeOrder` for everyone was rejected: native wallets keep displaying an `address`, and existing vectors and node encoders stay.
**Cost if wrong.** Two order structs for clients, node and vectors.
**Source.** owner, 2026-10-13 (Q3, Q4); `history/specs/2026-10-13-ua-parity-design.md` §4.6 (UP-11), O2, O4.

### CTR-DEX-26 — UA legs: tagged legs in SCaaSDex, one book
- old: — · status: current · owner: yes · date: 2026-10-13 · normative: contracts/dex.md#CTR-DEX-26 · superseded-by: —

Change (2026-10-13): built as ruled (UA-5b): tagged `Leg` / `ExchangeLeg`, shape-1 legs on SCaaS ledger tokens pulled by `uaTrade`, payouts and Path B refunds to derived ids by `transferToUA`, `UALegSettled` / `UAExchangeLegSettled`, `UAVerifyGas` re-raised, `uaTrade` refused in interactions; the node sends shape-0 legs and indexes `UALegSettled` (its UA intake, `bytes32` book and PQ gossip after UA F5, C5b-11). `SCaaSDex` is 23,493 B, under EIP-170, so it does not join the size baseline (C5b-14; the cost line above expected it to cross). Controller rulings, confirmed by the owner 2026-10-13: `SelfTrade(bytes32)` (C5b-3), `LegShapeUnknown(uint8)` (C5b-4), "ledger on" = the listing's `tokenKind == SCaaS` and `registry() ≠ 0`, no ERC-165 (C5b-5), a derived destination checked only by the receive token's `transferToUA` at the payout, so an unregistered one is `MatchFailed` (C5b-6), shape-0 bytes after the 13 words ignored (C5b-7). Measured: two `mldsa65` legs 12,124,252 transaction gas; three revert `UAVerifyGas`. Source add: plan `superpowers/plans/2026-10-13-ua5b-trade-dex.md`.

**Why.** Extending `SCaaSDex` in place (a `shape` tag and an encoded order per leg) keeps one book in which UA and native orders match; UA legs only in SCaaS ledger tokens, payouts and refunds to UAs by `transferToUA`; `UAVerifyGas` reverts the whole `mtxSettle` as `SigCheckGasStarved` does, so a starved submitter cannot turn a valid order into `MatchFailed`; `uaTrade` is refused in interactions as `mtxTrade`. A second DEX implementation was rejected: two books, no cross-matching.
**Cost if wrong.** The `Leg` / `ExchangeLeg` ABI changes (nothing deployed); the DEX crosses EIP-170 (size baseline; owner: Glamsterdam); PQ legs bound a settlement to the EIP-7825 cap, so the node packs settlements by kind.
**Source.** owner, 2026-10-13 (Q5); `history/specs/2026-10-13-ua-parity-design.md` §4.7, O3.

### CTR-DEX-80 — Fill-or-kill two-leg MetaTxDex settlement
- old: R3 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-DEX-01, NODE-DEX-01, INT-ERP-12

**What it said.** The first design settled two `MetaTxDex` legs fill-or-kill.

### CTR-DEX-81 — DEX fee on received side rounds down
- old: RS5-6(dex-fee) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-DEX-11

**What it said.** An earlier rule rounded the DEX fee on the received side down.

## 21. Contracts — Sealed-bid tender

### CTR-TND-01 — Deposit and commitment are one pay signature
- old: R180 · status: current · owner: no · date: 2026-10-08 · normative: contracts/tender.md#CTR-TND-01 · superseded-by: —

**Why.** The deposit and the bid commitment are one `pay` signature, submitted by the tender through the `executeMetaTransaction` alias (which returns the `bool` the tender decodes), so a bidder cannot commit without paying the deposit; the shape is unchanged.
**Cost if wrong.** Separate steps let a bidder commit and never deposit.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:62`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-1.
Change (2026-10-08): the deposit is a payment `MetaTransfer` (`entryRef = depositRef`) and `commitBid` takes it and calls `mtxExecuteTransfer`. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-6.

### CTR-TND-02 — Commitment hash binds chain, tender and bidder
- old: R181 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-02 · superseded-by: —

**Why.** The commitment hash binds chain, tender and bidder, so it cannot be copied to another tender or bidder.
**Cost if wrong.** An unbound commitment could be replayed by another bidder.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:70`

### CTR-TND-03 — Permissionless reveal and withdraw; no bid replacement
- old: R182 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-03 · superseded-by: —

**Why.** Reveal and withdraw are permissionless and bids cannot be replaced, so nobody depends on the organizer to finish.
**Cost if wrong.** Organizer-only reveal lets the organizer suppress bids.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:76`

### CTR-TND-04 — Forfeited deposits go to immutable slashSink
- old: R183 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-04 · superseded-by: —

**Why.** Forfeited deposits go to an immutable `slashSink`, so the organizer cannot profit from disqualifying bidders.
**Cost if wrong.** A mutable sink rewards fake disqualification.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:82`

### CTR-TND-05 — Public price range; earliest commit wins ties
- old: R184 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-05 · superseded-by: —

**Why.** A public price range and earliest-commit tie-break make the winner deterministic from on-chain data.
**Cost if wrong.** Hidden ranges or discretionary ties invite manipulation.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:87`

### CTR-TND-06 — Early cancel only; bounded leader disqualification
- old: R185 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-06 · superseded-by: —

**Why.** The organizer may cancel only early and disqualify the leader only within bounds, so a tender cannot be steered after reveal.
**Cost if wrong.** Unbounded disqualification is a veto over the result.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:92`

### CTR-TND-07 — Deposit token from the one factory's registered implementation
- old: R186 · status: current · owner: no · date: 2026-10-08 · normative: contracts/tender.md#CTR-TND-07 · superseded-by: —

**Why.** The deposit token must be a tier kind of the one `OpenFactory` from a registered, non-deprecated implementation, so its transfer semantics are known and one `TokenKind` enum decodes `versionOf`.
**Cost if wrong.** An arbitrary token could block refunds or fake deposits.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:107`; `history/specs/2026-10-07-metatx-generic.md` §7 (CTR-TND-07 row).

### CTR-TND-08 — Fixed windows, bond policies, no admin
- old: R187 · status: current · owner: no · date: 2026-10-06 · normative: contracts/tender.md#CTR-TND-08 · superseded-by: —

**Why.** Fixed windows and bond policies with no admin make the timeline enforceable by anyone.
**Cost if wrong.** An admin-adjustable window can be bent for a favoured bidder.
**Source.** `history/specs/2026-10-06-tender-sponsorship-shredding.md:114`

## 22. Contracts — Asset suite

### CTR-AS-01 — Regulated module as separate implementations, kinds 5-7
- old: R200 · status: superseded · owner: yes · date: 2026-10-08 · normative: — · superseded-by: CTR-AS-17

**What it said.** The regulated module ships as separate implementations (kinds 5–7) registered in the one `OpenFactory`; replaced by the regulated controls as flags 5–8 on the ordinary kinds.

### CTR-AS-02 — Regulated module is a third creation-time exception
- old: R201 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-02 · superseded-by: —

**Why.** The regulated controls (flags 5–8 of CTR-TOK-22) are a third creation-time exception, visible before anyone acquires the token.
**Cost if wrong.** Adding it later would break the provenance promise.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:80`

### CTR-AS-03 — Issuer and compliance roles; renouncing relaxes
- old: R202 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-03 · superseded-by: —

**Why.** Issuer and compliance roles are separate; losing a role (a holder's `renounceRole`, or the owner's revoke, CTR-TOK-22) only relaxes control.
**Cost if wrong.** One combined role would concentrate every power in one key.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:87`

### CTR-AS-04 — Forced transfer only against a recorded order
- old: R203 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-04 · superseded-by: —

**Why.** A forced transfer requires a recorded order, so it leaves an auditable reason on chain.
**Cost if wrong.** Unrecorded forced transfers are indistinguishable from theft.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:94`

### CTR-AS-05 — Freeze semantics and bounded freeze duration
- old: R204 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-05 · superseded-by: —

**Why.** Freezes have defined semantics and a bounded duration, so a freeze is not a silent confiscation.
**Cost if wrong.** Unbounded freezes are de facto seizures.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:102`

### CTR-AS-06 — Global pause up to 7 days with cooldown
- old: R205 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-06 · superseded-by: —

**Why.** A global pause lasts at most 7 days with a cooldown, so it cannot become a permanent lock.
**Cost if wrong.** Unbounded pauses trap holders indefinitely.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:111`

### CTR-AS-07 — Allowlist through ComplianceRegistry, receivers only
- old: R206 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-07 · superseded-by: —

Change (2026-10-13): owner — a constraint for when the suite is built: the registry and the freeze set key accounts by `bytes32` (natives padded) and the per-transfer checks hook the UA ledger too, UA → UA included; no code until AS. Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.13, Q10.

**Why.** Allowlisting runs through the address-keyed `ComplianceRegistry` and checks receivers only, so holders can always exit to an allowed address.
**Cost if wrong.** Checking senders too could trap holders who lost status.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:118`

### CTR-AS-08 — Regulated checks at the shape step and in _update
- old: R207 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/asset-suite.md#CTR-AS-08 · superseded-by: —

**Why.** Regulated checks sit at the pipeline's shape step and in `_update`, which also covers self-calls and `mtxTrade`, so every path (direct and meta-tx) is covered and a failing transfer costs the relayer only the cheap prefix.
**Cost if wrong.** A check in one path only is bypassed through the other.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:126`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-1.

### CTR-AS-09 — No regulated power touches reserves, rates or legs
- old: R208 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-09 · superseded-by: —

**Why.** No regulated power touches reserves, rates or legs, so compliance cannot be used to move backing value.
**Cost if wrong.** Compliance roles over reserves would be custody.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:138`

### CTR-AS-10 — One counterfactual VestingGrant clone per grant
- old: R209 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-10 · superseded-by: —

**Why.** One counterfactual `VestingGrant` clone per grant isolates grants and gives each a predictable address.
**Cost if wrong.** A shared vesting pool mixes beneficiaries' risks.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:145`

### CTR-AS-11 — Merkle distributions from a node-indexed snapshot
- old: R210 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-11 · superseded-by: —

**Why.** Distributions are Merkle claims from a node-indexed snapshot, so gas scales with claimants, not holders.
**Cost if wrong.** On-chain iteration over holders does not scale and can be griefed.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:155`

### CTR-AS-12 — Splits are migrations through ExchangeOffer
- old: R211 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-12 · superseded-by: —

**Why.** Splits are migrations through `ExchangeOffer`, so no token ever rebases.
**Cost if wrong.** Rebasing breaks integrations and 1:1 reserves.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:162`

### CTR-AS-13 — ExchangeOffer exact multiples and protected obligations; TradeOrder leg
- old: R212 · status: current · owner: no · date: 2026-10-08 · normative: contracts/asset-suite.md#CTR-AS-13 · superseded-by: —

**Why.** `ExchangeOffer` uses exact multiples and protects outstanding obligations, so a migration never strands value; its gasless leg is a `TradeOrder` it pulls as `dex` (the trade op it used is gone).
**Cost if wrong.** Inexact ratios leave dust and disputes.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:167`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-7b, MG-8.

### CTR-AS-14 — Asset templates are off-chain presets
- old: R213 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-14 · superseded-by: —

**Why.** Asset templates are off-chain presets over the same implementations, so adding a template needs no contract change.
**Cost if wrong.** On-chain templates would need upgradeable code or new audits per template.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:173`

### CTR-AS-15 — Action contracts have no owner or upgrade
- old: R216 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-15 · superseded-by: —

**Why.** Action contracts have no owner and no upgrade.
**Cost if wrong.** An owner on an action contract is a backdoor over the assets it holds.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:187`

### CTR-AS-16 — ELIGIBLE_CONTRACT only on pass-through contracts
- old: R217 · status: current · owner: no · date: 2026-10-06 · normative: contracts/asset-suite.md#CTR-AS-16 · superseded-by: —

**Why.** `ELIGIBLE_CONTRACT` is granted only to pass-through contracts, so allowlisting a contract cannot launder transfers to ineligible holders.
**Cost if wrong.** Eligible contracts that hold and release value would bypass the receiver check.
**Source.** `history/specs/2026-10-06-asset-suite-design.md:193`

## 23. Contracts — Zether (classical)

### CTR-AS-17 — Regulated controls are flags 5-8 on the ordinary kinds
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/asset-suite.md#CTR-AS-17 · superseded-by: —

**Why.** `FREEZE`, `FORCE`, `PAUSE` and `ALLOWLIST` are creation-time flags (locked or disableable, CTR-TOK-22) of every non-confidential kind, with their code in `AdminLib` and their state in the `scaas.admin` namespace; the rules CTR-AS-03…09 apply to any token with one of the flags. The confidential kinds refuse flags 5–8 in `initialize`.
**Cost if wrong.** Separate regulated kinds multiply implementations (three tiers times Hedera times Zether); a confidential balance can be frozen but not seized on public chains.
**Source.** `history/specs/2026-10-08-token-tree-design.md` §2 (T8, T11), §5.

### CTR-ZTH-01 — Full classical Zether, unaudited, dev-chain gated
- old: R34(scope), UD:§12, UD:§12.2, UD:§12.3, UD:§12.4, UD:§12.7.6, UD:§15:D2, UD:§19:curve-param, UD:§20.1, UD:§25, UD:§25:flipped, UD:§25:ruling, canon:D1, canon:D2, canon:D17 · status: current · owner: yes · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-01 · superseded-by: —

Change (2026-10-19): controller proposal (owner may override) — **on-chain review W-I, bn254 part (plan Task 5g, branch `rev2-chain-pqz`, commit `fa5ce5fe`; V1-07, P3 defence in depth):** `G1Bn254.add` / `mul` / `msm` / `isValid` and both `modexp` calls (`G1Bn254._modexp`, `ZetherVerifierBase._inv`) require the exact return size (64 / 32 bytes) after the call, as the BLS12-381 wrappers do; a chain without `0x05`–`0x07` answers "success, empty". The check is a separate statement after the `staticcall` (Yul evaluates `and(staticcall(…), eq(returndatasize(), n))` right to left, which read the previous call's size; caught by the full suite). Bytecode: both Zether verifiers and the UA verifiers built on `G1Bn254` (BLS min-sig, FROST, MuSig2, Schnorr bn254 / BLS12-381, Zether Schnorr): +5…27 B runtime and +5…32 B init (the `G1Bn254` users +5…17 B, `ZetherVerifierBn254` +27 B runtime / +32 B init; `runs/2026-10-19-5g-pqz-sizes.txt`). Test `ZetherCurvesReturnSize.t.sol`. Status: **done** (`fa5ce5fe`, merged `734b9c76`).

**Why.** The owner wants full classical Zether now (identity visible, amounts hidden), built, unaudited and gated to dev chains, with bn254 and BLS12-381 verifiers. The curve is a property of each token (chosen by its verifier address), not a system setting: bn254 uses the Byzantium (2017) precompiles 0x06/0x07/0x08 with 64-byte G1 points; BLS12-381 needs the Prague precompiles 0x0b to 0x10 and 128-byte G1 points (measured with `eth_call` to 0x0b on Gnosis). rollOver is `PUBLIC` by default and `OWNER_ONLY` by opt-in, per `(account, token)`: owner signing protects only if it covers every path that advances the account sequence, so per account `accSeq[a]` advances without the owner's consent exactly when `mode[a] == PUBLIC`. The `PUBLIC` branch is safe because rollOver is a no-op when `pendingSeq[a] == lastRolledPendingSeq[a]`, so a griefer must fund the victim before each attempt.
**Cost if wrong.** Unaudited cryptography on a public chain could mint; the gate (CTR-ZTH-02) is what prevents that.
**Source.** `history/specs/2026-10-03-blockchain-round3-design.md:546`, `research/_USER-DECISIONS.md:463`, `research/_USER-DECISIONS.md:483`, `research/_USER-DECISIONS.md:508`, `research/_USER-DECISIONS.md:537`, `research/_USER-DECISIONS.md:691`, `research/_USER-DECISIONS.md:860`, `research/_USER-DECISIONS.md:1060`, `research/_USER-DECISIONS.md:1093`, `research/_USER-DECISIONS.md:2630`, `research/_USER-DECISIONS.md:2638`, `research/_USER-DECISIONS.md:2653`, `research/_USER-DECISIONS.md:859`, `research/_USER-DECISIONS.md:864`

### CTR-ZTH-02 — Classical Zether gated to dev chains 31337/1337
- old: RS2-1 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-02 · superseded-by: —

**Why.** A hard-coded dev-chain allowlist in every constructor keeps unaudited Zether off real networks even with a manual deploy.
**Cost if wrong.** A configurable gate is one transaction away from production use.
**Source.** `history/specs/2026-10-03-zether-design.md:583`

Change (2026-10-20): owner 2026-10-20 (plan 5g-Z2) — the factory's Zether flag `zetherEnabled` (settable only on a dev
chain) is replaced by the generic kind gate `setKindEnabled` (kinds 2–3 start disabled); the dev-chain allowlist itself is
unchanged and now enforced, for the factory path, in the token's `initialize` and the verifier constructors (a factory
on a non-dev chain can enable the kind, but every creation reverts). Status: built on branch `rev2-zether-z2`, commit `0f88e66f` (plan Task 5g-Z2).

### CTR-ZTH-03 — No epochs; verifier takes the full statement; fund from the public balance
- old: RS2-2 · status: current · owner: no · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-03 · superseded-by: —

Change (2026-10-27): review C0-9, controller proposal (1) taken with the owner's C0-1 ruling of 2026-10-27 (the same `…/v3` bump; owner may override) — **every Zether debit statement carries `validUntilBlock`** (header word 15, offset 480; the header is 512 bytes), the payload's word 2 (`be32(accSeq) ‖ be32(sendCounter) ‖ be32(validUntilBlock) ‖ …` on the single, multi-recipient and unshield payloads); the token refuses it once `block.number > validUntilBlock` with `TransferExpired(uint256 validUntilBlock)`, before the verifier, direct and relayed, and in the statement views — the PQZ header's rule (zether.md §7 *Expiry*). The proof binds the word, so a published direct-path proof no longer stays a bearer instrument until `accSeq` / `sendCounter` move. Status: **done** (review2 T3, branch `review2-fix`; `proofSystemId` / `proofSystemIdMulti` = `keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"[ ‖ "/multi"])`, `…/v2` refused).

**Why.** Proofs take the full statement and there are no epochs, removing epoch-boundary races; the state-change summary now has `fund` burning public units (CTR-ZTH-35). Rejected: the early `IZetherToken` sketch with epoch-based `simulateAccounts`, `getPendingBalance` per epoch and an epoch `rollOver()`.
**Cost if wrong.** Epochs force retries at boundaries and couple liveness to block timing.
**Source.** `history/specs/2026-10-03-zether-design.md:586`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-7b, §7.

### CTR-ZTH-04 — shieldScale is raw units per shielded unit
- old: RS2-3, UD:§2 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-04 · superseded-by: —

**Why.** `shieldScale` is raw underlying units per shielded unit, a single integer that keeps the 2^54 bound meaningful for any decimals; `fund` now draws `amount · shieldScale` raw units of the public balance instead of pulling the underlying. The bound exists because the amount is exponential ElGamal and BSGS recovers it in `O(sqrt(b))`; 2^44 is the last BSGS table size that fits a phone. Raising `shieldScale` is cheaper than buying bits and costs only granularity.
**Cost if wrong.** Scaling by decimals inside the circuit would add rounding paths.
**Source.** `history/specs/2026-10-03-zether-design.md:588`, `research/_USER-DECISIONS.md:49`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-7b.

### CTR-ZTH-05 — Inner fee to beneficiary pending; outer fee public
- old: RS2-4, UD:§10:fee-layers · status: current · owner: yes · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-05 · superseded-by: —

**Why.** Two fee layers: an inner confidential fee to a beneficiary's pending balance and an outer public fee for the relayer. A holder whose money is all confidential has no public token to pay an outer fee; the inner fee (`C_fee`, debited from the encrypted balance) is the only way such an account can pay a relayer. Fee first, amount second: the proof shows `fee >= 0`, `v >= 0`, `b - fee >= 0` and `(b - fee) - v >= 0` together.
**Cost if wrong.** One fee layer would either leak the amount or leave relayers unpaid.
**Source.** `history/specs/2026-10-03-zether-design.md:590`, `research/_USER-DECISIONS.md:351`

Change (2026-10-20, owner ruling D19, built in plan 5h Task 3z `7733910e`): the inner fee is no longer `pend_ben += [fee]G`: `ZetherLib` debits `totalShielded -= fee` and returns it, and the token pays `fee · shieldScale` from `SHIELD_POOL` to the beneficiary's **public** UA-ledger balance (needs a registered, UA-ledger-enabled beneficiary; visible on `UATransfer`). The relation is unchanged (`fee` was public in the statement). This is the `txFee` of CTR-PQZ-06. Status: decided; built.

### CTR-ZTH-06 — Envelope binding covers envelope fields except data; passed by the ticket
- old: RS2-5 · status: current · owner: no · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-06 · superseded-by: —

**Why.** The envelope binding covers every envelope field except `data` (and now `chainUid`), so a proof cannot be stripped or re-wrapped; the base computes it and passes it to the self-call through the transient ticket instead of `relayed*` functions.
**Cost if wrong.** An unbound proof can be lifted into another envelope with another fee recipient.
**Source.** `history/specs/2026-10-03-zether-design.md:592`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-2.1, §7.
Change (2026-10-08): `MetaTransaction` has no `to`/`value`, so the binding drops them: `(tag, chainid, chainUid, token, from, batch, nonce, validUntil, mode, canonRelayer, fee, canonFeeRecipient)`. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-10.

### CTR-ZTH-07 — Outer FIXED fee uncapped; PERCENT forbidden
- old: RS2-6, UD:§3, UD:§3.2, UD:§3.4 · status: current · owner: yes · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-07 · superseded-by: —

**Why.** Confidential ops take only an absolute FIXED outer fee; PERCENT would reveal the amount through the fee.
**Cost if wrong.** A percentage fee on a hidden amount is an amount oracle.
**Source.** `history/specs/2026-10-03-zether-design.md:594`, `research/_USER-DECISIONS.md:102`, `research/_USER-DECISIONS.md:124`, `research/_USER-DECISIONS.md:164`

### CTR-ZTH-08 — ZetherToken on the one meta-tx base
- old: RS2-7, UD:§10 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-08 · superseded-by: —

**Why.** Zether is a child of the meta-transaction layer, so every confidential token is gasless; with one base the separate `ZetherMetaTx` mixin goes and Zether is a `ZetherLayer` on `MetaTokenBase` (kinds `NONE_ZETHER`, `UNDERLYING_ZETHER`, CTR-TOK-21), using the base's nonce, envelope, fee and ticket; its entry points are allowlisted self-calls of `mtxExecute` (CTR-ZTH-34). An early code draft declared `ISecureERC20 is IERC20`, which would have left confidential tokens without meta-transactions. Rejected: the early `IZetherToken` interface sketch (`schnorrAddress`, `zetherNonce`, `EncryptedBalance` structs, `transferConfidential` with a `metaTx.amount = 0` wrapper).
**Cost if wrong.** A second pipeline for Zether duplicates replay protection and fee logic.
**Source.** `history/specs/2026-10-03-zether-design.md:595`, `research/_USER-DECISIONS.md:331`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-9.

### CTR-ZTH-09 — Auditor key immutable, set at initialize
- old: RS2-8 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-09 · superseded-by: —

**Why.** The auditor key is immutable and set at `initialize`; there is no setter.
**Cost if wrong.** A settable auditor key would let an admin start reading every future transfer.
**Source.** `history/specs/2026-10-03-zether-design.md:596`

### CTR-ZTH-10 — Underlying must be an ERC-20 in v1
- old: RS2-11 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-ZTH-44

**What it said.** The underlying must be an ERC-20 in v1 (no native coin, no self-minted confidential supply); replaced by the confidential layer, which keeps no underlying of its own and reuses `UnderlyingLib`, so a native leg is allowed (CTR-TOK-26).
**Source.** `history/specs/2026-10-03-zether-design.md:600`

### CTR-ZTH-11 — fund and rollOver direct; transfer/burn enveloped
- old: RS2-12 · status: superseded · owner: no · date: 2026-10-08 · normative: — · superseded-by: CTR-ZTH-34

**What it said.** `fund` and `rollOver*` were direct calls; only transfer and burn travelled in envelopes.
**Why.** `fund`, public `wrap`/`unwrap`, transfer and burn all run through `mtxExecute` (CTR-ZTH-34); the signed rollover functions carry their own signature.
**Source.** `history/specs/2026-10-03-zether-design.md:601`; `history/specs/2026-10-07-metatx-generic.md` §7 (CTR-ZTH-11 row).

### CTR-ZTH-12 — No AEAD memo; client decrypts by BSGS
- old: RS2-13 · status: current · owner: no · date: 2026-10-05 · normative: contracts/zether.md#CTR-ZTH-12 · superseded-by: —

**Why.** No AEAD memo: the client decrypts balances itself with BSGS, so no extra ciphertext format needs securing.
**Cost if wrong.** A memo would be a second encryption to audit and key-manage.
**Source.** `history/specs/2026-10-03-zether-design.md:603`

### CTR-ZTH-13 — Direct transferConfidential carries no outer fee
- old: RS2-14 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-13 · superseded-by: —

**Why.** A direct confidential transfer carries no outer fee; the caller pays its own gas.
**Cost if wrong.** An outer fee on direct calls would need an unbound recipient.
**Source.** `history/specs/2026-10-03-zether-design.md:605`

### CTR-ZTH-14 — Disclosure bundle stored; unsupported underlyings are UnderlyingLib's rule
- old: RS2-15, ZL:D6 · status: current · owner: yes · date: 2026-10-05 · normative: contracts/zether.md#CTR-ZTH-14 · superseded-by: —

**Why.** The disclosure bundle is stored per transfer so the parties can prove amounts later (the multi-recipient entry points choose what is stored, [CTR-ZTH-38](contracts/zether.md#CTR-ZTH-38)); the refusal of fee-on-transfer underlyings moved to the `UnderlyingLib` rule ([CTR-TOK-11](contracts/token-wrappers.md#CTR-TOK-11)), because the confidential layer has no underlying of its own.
**Cost if wrong.** Without the bundle disclosures depend on off-chain archives; FoT underlyings break the reserve invariant.
**Source.** `history/specs/2026-10-03-zether-design.md:607`, `history/specs/2026-10-05-zether-limits.md:18`

### CTR-ZTH-15 — Verifier forwards gas to precompiles; simulate first
- old: RS2-16 · status: current · owner: no · date: 2026-10-03 · normative: contracts/zether.md#CTR-ZTH-15 · superseded-by: —

**Why.** The verifier forwards `gas()` to the precompiles and clients simulate first, so a precompile repricing does not silently fail proofs.
**Cost if wrong.** Pinned gas stipends break when precompile prices change.
**Source.** `history/specs/2026-10-03-zether-design.md:609`

### CTR-ZTH-16 — zetherRollOverSigned accepts pendingSeq at least expected
- old: RS2-17 · status: current · owner: no · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-16 · superseded-by: —

**Why.** `zetherRollOverSigned` (CTR-ZTH-45; built: `rollOverSigned`) accepts `pendingSeq` at least the expected value, so a free public rollover in between does not invalidate a signed one.
**Cost if wrong.** An equality check lets anyone grief signed rollovers.
**Source.** `history/specs/2026-10-03-zether-design.md:612`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-3.

### CTR-ZTH-17 — zetherRollOverSigned requires a new credit
- old: RS2-19 · status: current · owner: no · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-17 · superseded-by: —

**Why.** `zetherRollOverSigned` requires a new credit, so it cannot be replayed to no effect.
**Cost if wrong.** Replays would burn the owner's relayer fees.
**Source.** `history/specs/2026-10-03-zether-design.md:614`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-3.

### CTR-ZTH-18 — Range bits n_v = n_b = 64, sound
- old: RS-NV64-1, ZL:D1, ZL:D2 · status: current · owner: yes · date: 2026-10-05 · normative: contracts/zether.md#CTR-ZTH-18 · superseded-by: —

**Why.** Range bits `n_v = n_b = 64` are sound with the 2^54 cap; every honest value fits and no wrap-around is provable.
**Cost if wrong.** Fewer bits would reject honest balances; an unsound pair would allow minting.
**Source.** `history/specs/2026-10-03-zether-design.md:623`, `history/specs/2026-10-05-zether-limits.md:13`, `history/specs/2026-10-05-zether-limits.md:14`

### CTR-ZTH-19 — Configurable client BSGS plus device balance cache
- old: RS-NV64-2, ZL:D4, ZL:D5 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-19 · superseded-by: —

**Why.** Client BSGS is configurable and a device balance cache avoids repeated discrete logs.
**Cost if wrong.** A fixed BSGS table either wastes memory or fails on large balances.
**Source.** `history/specs/2026-10-03-zether-design.md:644`, `history/specs/2026-10-05-zether-limits.md:16`, `history/specs/2026-10-05-zether-limits.md:17`

### CTR-ZTH-20 — Clients and gateway pin canonical verifier and registry
- old: RS2-20 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-20 · superseded-by: —

Change (2026-10-19): controller proposal (owner may override) — **on-chain review W-B, Zether twin (plan Task 5g, branch `rev2-chain-pqz`): recorded, no code change; owner decision open.** The class (a creator-chosen fake verifier drains a factory-listed Zether wrapper) is this rule's accepted design: clients and the gateway pin canonical verifiers by address; the factory does not gatekeep (CTR-TOK-15, CTR-TOK-17); Zether runs on dev chains only (CTR-ZTH-02). The PQZ fix does not carry over: PQZ verdicts come from one consensus precompile at a fixed address, a Zether verifier is Solidity whose codehash differs per deployment (`generatorStore` immutable), so a code-hash pin needs a verifier change, and a registrar allowlist in `OpenFactory` would reverse CTR-TOK-15 / -17. Options for the owner: (a) keep (this record, the default); (b) a registrar-set Zether verifier allowlist in `OpenFactory`; (c) derive `generatorStore` from the verifier's own address and pin the two verifier codehashes in `ZetherSafety`. Status: recorded.

**Why.** Clients and the gateway pin the verifier and registry addresses per chain profile.
**Cost if wrong.** A spoofed verifier address would accept forged proofs in the client's view.
**Source.** `history/specs/2026-10-03-zether-design.md:661`

Change (2026-10-19): **owner ruling — one canonical Zether verifier per curve, fixed at deployment, as PQZ pins its precompile** (on-chain review W-B, Zether half; supersedes the "clients pin, the factory does not refuse" stance for the verifier). An admin-managed verifier list was rejected: it only moves the trust from the token creator to the factory admin (a leaked admin key or a mistake admits a fake verifier again). Design (owner, same day: store the address at deployment instead of the CREATE2 / codehash pin first drafted): the Zether token implementations take their curve's verifier as an `immutable` constructor argument, `init` no longer accepts a `verifier`, so every clone uses it; `OpenFactory` records the verifiers at its deployment and refuses a Zether implementation whose verifier differs. No runtime admin, no CREATE2, no codehash pin; the trust is in whoever deploys the stack (already the case); a new verifier is a new implementation version. Check whether the UA registry's Zether kinds use the same verifiers and fix them the same way. Status: decided; build in plan Task 5g-Z (after the 5g integration, before 5h).

Change (2026-10-20): **owner rulings 2026-10-19 / 2026-10-20, final design built in plan 5g-Z1** (replaces the
2026-10-19 "store the address at deployment" text above in its details; same principle, no admin list). (1) Verifier
layout (2) of three measured (`smartcontracts/evm/runs/2026-10-19-5gz.txt`): per curve a transfer verifier
(`verifyTransfer`, `verifyTransferMulti`, the group operations), a burn verifier (`verifyBurn`) and one shared
inner-product verifier (generators and range proofs, `verifyRange` by `STATICCALL`, fixed in the other two's
constructors); same statements, proofs and verdicts; per-call code 11.2 + 7.2 KB (transfer) / 5.2 + 7.2 KB (burn) instead of
16.0 KB; verify gas within +7 k (single, burn) and lower for multi (−65 k bn254, −590 k BLS at M = 8); reason: smaller
code per call, generators computed once per curve. (2) The Zether implementations take the disclosure contract, the
transfer verifier and the burn verifier, the PQZ implementations their `UAPqzVerifier`, as constructor immutables;
`ConfidentialConfig.verifier` must be 0 for every confidential kind (`BadInit`). (3) The curve (PQZ: the proof system) is
an attribute of the release (`curve()`, `proofSystemId()`); version numbers carry no curve meaning. (4) `OpenFactory`'s
constructor fixes the canonical sets (`Canonical`: per curve transfer / burn verifier and disclosure, per PQZ proof system
the verifier; views `zetherVerifiers`, `pqzVerifier`; no setter); `registerImplementation` refuses a confidential release
whose immutables are not one set (`NotCanonicalVerifiers`). (5) Limit stated in the spec: a deliberately malicious
registrar can still register bytecode that reports canonical addresses; the registrar key is the trust root for code
(multisig / UA msig recommended; a timelock is an option, not built). (6) The UA registry's Zether kinds (`zether-bn254`,
`zether-bls12381`) verify with `ZetherSchnorr*Verifier`, fixed in the registry constructor (immutables), not with the proof
verifiers: no change needed. The generic per-kind environment, factory-deployed
code and library code-hash pins are plan 5g-Z2. Status: built, commit `690a295a` (plan Task 5g-Z1).

Change (2026-10-20): **owner rulings 2026-10-20, plan 5g-Z2** (replaces item (4) of the 5g-Z1 change above; same
principle, no admin list). The verifiers come from the release's environment instead of a factory-constructor
`Canonical` set: `Env.deps` of a `*_ZETHER` kind = transfer, burn and inner-product verifier and `ZetherDisclosure` of one
curve (positions 0–3), of a `*_PQZ` kind = the `UAPqzVerifier` (position 0); the factory deploys the implementation with
that env appended to its init code, so the verifiers are constructor immutables of the release by construction, and
`NotCanonicalVerifiers`, `zetherVerifiers`, `pqzVerifier` are removed. The Zether constructor refuses missing code, two
verifiers of different proof systems, verifiers not fixed to `deps[2]` and a Hedera env (`BadInit`; **controller
proposal, owner may override:** the Hedera refusal, for PQZ too — no confidential kind targets Hedera). A new verifier
set is a new env version plus a new release; tokens of older versions keep theirs. Limit restated: the factory proves
which env and libraries a release was deployed with, not what its code does; the registrar's key stays the trust root.
Status: built on branch `rev2-zether-z2`, commit `0f88e66f` (plan Task 5g-Z2).

Change (2026-10-20): review 5g-Z2 P2-2, controller choice (owner may override) — the Zether constructor also checks each
verifier's role: the transfer and burn verifiers are two addresses, the transfer verifier answers `ringSize()` (one word)
and the burn verifier does not (`BadInit`); a swapped or duplicated pair passed the proof-system and inner-product checks
and would have accepted shields that no transfer or unshield could move. `ringSize()` is chosen over a new role constant
because the deployed verifier contracts already have it. `ZetherLib.init` keeps `VerifierUnsupportedOnThisChain` typed
when the verifier's `curveName()` reverts (empty name). Limit restated: the factory proves which env was appended and that
the env's listed libraries had their pinned code hashes, not which libraries the code links nor what it does. Status:
built on branch `rev2-zether-z2` (review-fix commits listed in `smartcontracts/evm/runs/2026-10-20-5gz2-wip.txt`).

### CTR-ZTH-21 — Zether envelopes use the base's ERC-1271 cap by codehash
- old: RS2-21 · status: current · owner: no · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-21 · superseded-by: —

**Why.** Zether envelopes get the same codehash-based ERC-1271 cap as every token of the base (400 k for `SmartKeyAccount` clones).
**Cost if wrong.** An uncapped check lets contract wallets grief relayers; a 50 k cap fails every passkey account.
**Source.** `history/specs/2026-10-03-zether-design.md:664`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-9.

### CTR-ZTH-22 — Mandatory invariant, subgroup and D_out tests
- old: RS2-23 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-22 · superseded-by: —

**Why.** Invariant, subgroup and `D_out` tests are mandatory before any gate is lifted.
**Cost if wrong.** Missing subgroup tests have broken real Zether-like systems.
**Source.** `history/specs/2026-10-03-zether-design.md:670`

### CTR-ZTH-23 — Outer fee recipient equal to token reverts
- old: RS2-24 · status: current · owner: no · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-23 · superseded-by: —

**Why.** An outer fee recipient equal to the token reverts, and the base refuses every transfer to the token's own address, so fees cannot be locked in the token.
**Cost if wrong.** Fees sent to the token are stuck forever.
**Source.** `history/specs/2026-10-03-zether-design.md:675`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-1.

### CTR-ZTH-24 — Client balance-cache key includes the chain
- old: RS2-25 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-24 · superseded-by: —

**Why.** The client balance-cache key includes the chain, so two chains with the same token address do not mix balances.
**Cost if wrong.** A shared cache shows wrong balances after a chain switch.
**Source.** `history/specs/2026-10-03-zether-design.md:676`

### CTR-ZTH-25 — Public schnorrSign export takes no nonce k
- old: RS2-26 · status: current · owner: no · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-25 · superseded-by: —

**Why.** The public `schnorrSign` export takes no nonce `k`, so callers cannot reuse nonces.
**Cost if wrong.** A caller-supplied nonce reused twice leaks the key.
**Source.** `history/specs/2026-10-03-zether-design.md:678`

### CTR-ZTH-26 — MAX_TOTAL_SHIELDED stays 2^54
- old: ZL:D3 · status: current · owner: yes · date: 2026-10-05 · normative: contracts/zether.md#CTR-ZTH-26 · superseded-by: —

**Why.** `MAX_TOTAL_SHIELDED` stays 2^54: it is the BSGS decryption bound, not a per-transfer maximum.
**Cost if wrong.** Raising it makes client decryption impractical.
**Source.** `history/specs/2026-10-05-zether-limits.md:15`

### CTR-ZTH-27 — Zether runs on the private chain first
- old: UD:§1:private-chain · status: open · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-27 · superseded-by: —

**Why.** Open owner decision: whether classical Zether runs on the private chain first.
**Cost if wrong.** Deciding without the audit and gas data could put unaudited cryptography on a shared chain.
**Source.** `research/_USER-DECISIONS.md:42`

### CTR-ZTH-28 — Tiered Zether fees leak the amount
- old: UD:§3.3 · status: open · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-28 · superseded-by: —

**Why.** Open owner decision: a tiered Zether fee leaks the amount band; only flat fees are safe today.
**Cost if wrong.** A tiered fee turns the fee into an amount oracle.
**Source.** `research/_USER-DECISIONS.md:149`

### CTR-ZTH-29 — Independent open-source disclosure verifier CLI
- old: UD:§12.7.5 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-29 · superseded-by: —

**Why.** An independent open-source disclosure verifier lets any counterparty check a disclosure without trusting SCaaS. It reads from an archive node or a signed chain export, takes `(entryRef, v, s)` and prints PASS or FAIL with every intermediate value; it is deterministic, so two examiners get the same result.
**Cost if wrong.** Disclosure checked only by SCaaS tools is trust in SCaaS.
**Source.** `research/_USER-DECISIONS.md:676`

### CTR-ZTH-30 — Derive s from seed via PRF
- old: UD:§13.2 · status: current · owner: yes · date: 2026-08-30 · normative: contracts/zether.md#CTR-ZTH-30 · superseded-by: —

Change (2026-10-27): owner ruling 2026-10-27, C0-1 (ii) — **every auditor copy of an audited multi-recipient leg has its own randomness `t_j`**, derived like `s`: `t_j = HKDF-SHA256(seed_zether, "SCAAS-ZETHER-AUD-T-V1" ‖ chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖ salt ‖ be32(j), L = 64) mod r` (`j` 0-based; prover `derive_t`; the salt is re-drawn if `s` or any `t_j` is 0), so it is independent of `s` and of the other legs and the sender re-derives it for recovery (CTR-ZTH-50). The single format keeps its one copy under `s`. Status: **done** (review2 T3, branch `review2-fix`; `proofSystemId` / `proofSystemIdMulti` = `keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"[ ‖ "/multi"])`, `…/v2` refused).

Change (2026-10-11): owner — `s = HKDF-SHA256(seed_zether, "ZTX/s/v2" ‖ chainUid ‖ token ‖ fromUA ‖ sendCounter ‖ salt)` with 16 fresh random bytes per build, published with the transfer and not checked by the contract (built in P3b). The counter-only form reused `s` on a retry (`C_aud₁ − C_aud₂ = [v₁ − v₂]G`, failed-transaction calldata is public); the built amount-mixing form made the sender remember amounts. Source add: owner, 2026-10-11.

**Why.** The sender randomness `s` is derived from the seed by a PRF, so nothing per transfer needs storing. The research sketch was s = HKDF-SHA256(seed_zether, info = "ZTX/s/v1" ‖ chainId ‖ tokenAddress ‖ fromUA ‖ sendCounter) with the `sendCounter` read from the chain, so a wallet restored from its seed alone can still prove every past transfer.
**Cost if wrong.** Stored randomness is one more secret to lose or leak.
**Source.** `research/_USER-DECISIONS.md:727`

### CTR-ZTH-31 — Fallback: accept stale accSeq for credits only
- old: UD:§25:fallback · status: open · owner: yes · date: 2026-09-03 · normative: contracts/zether.md#CTR-ZTH-31 · superseded-by: —

**Why.** Open owner contingency: if rollover griefing spreads, accept a stale `accSeq` for credits only (a credit only raises the balance, so the range statement does not weaken); that is a protocol change and needs the cryptography review. The immediate escape hatch for one account is `setRollOverMode(OWNER_ONLY)`, one transaction; epochs are not the fallback.
**Cost if wrong.** Without a fallback a griefer could keep a busy account from spending.
**Source.** `research/_USER-DECISIONS.md:2688`

### CTR-ZTH-32 — Production curve for classical Zether tokens
- old: reorg:Q5(curve) · status: open · owner: yes · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-32 · superseded-by: —

**Why.** Open owner decision: the production curve for classical Zether (bn254 or BLS12-381); BLS12-381 is more secure and not cheaper.
**Cost if wrong.** Choosing bn254 for money at rest accepts ~100-bit security.
**Source.** `history/plans/2026-10-07-docs-reorg.md:1241`

Change (2026-10-20, owner): **classical Zether uses BLS12-381 only** (closes this open question). Reasons: ~117–126-bit vs ~100-bit security for long-lived encrypted balances; EIP-2537 is live on every EVM target chain of the 2026-10-11 survey and on the SCaaS testnet / 22776; the planned Rust verifier precompile and the MSM ruling of 2026-10-17 are BLS12-381. Cost accepted (measured, §19): `verifyTransfer` +8 %, minimum transfer gas limit +19 %, shield +35 %, rollover +44 %, 128-byte points; Hedera (bn254 only) gets no Zether (owner: not needed). The bn254 Zether line — verifier instance, `proofSystemId` `…/bn254/…`, UA kind `zether-bn254` 0x0140 and its Schnorr verifier, deploy steps, vectors — moves to `legacy/` (backup, not delete); the prover keeps its curve-generic code but builds and tests BLS12-381 only. The bn254 signing UA kinds (`schnorr-bn254`, `bls-bn254-minsig`, `frost-bn254`, `musig2-bn254`) are not affected. Status: decided; built with UA-6 (kind; branch `ua6`, commits c4ece459, 97fe4778) and plan Task 5h (tokens).

Change (2026-10-20, owner, plan review): the bn254 Zether line moves to `legacy/` **in UA-6** (UA-6 design U10), not in a separate task; 5h assumes BLS12-381-only Zether. Status: decided.

Change (2026-10-20, owner; UA-6 U10 accepted): **UA-6 moves the whole bn254 Zether line to `legacy/`** — the kind `zether-bn254` (0x0140) and its Schnorr verifier `ZetherSchnorrBn254Verifier`, `ZetherTypes.KIND_ZETHER_BN254` / `TAG_ZETHER_BN254`, registry slot 12, the bn254 token verifier instances and `proofSystemId`, `DeployBase` steps, fixtures switched to `useBls = true`, the bn254 rows of `kinds.json` / `signatures.json` and `r33_keys.json`, the bn254 KATs and prover-cross tests, and the clients' bn254 Zether paths move to `smartcontracts/evm/legacy/ua6/` and the clients' legacy folders (backup, not delete); the `bn254-g1` keyHash group stays (`schnorr-bn254`, `musig2-bn254`, `frost-bn254`). The earlier split ("kind with UA-6, tokens with plan Task 5h") is replaced because the Zether fixture registers bn254 accounts and the kind cannot leave while the bn254 token line runs; plan 5h drops its Z-BLS task. Spec §6. Status: decided; built in UA-6.

### CTR-ZTH-33 — the SCaaS testnet is not a classical-Zether dev chain
- old: reorg:Q5(dev-chain) · status: open · owner: yes · date: 2026-10-07 · normative: contracts/zether.md#CTR-ZTH-33 · superseded-by: —

**Why.** Open owner decision: the SCaaS testnet is not a classical-Zether dev chain until the owner decides.
**Cost if wrong.** Treating it as dev would put unaudited classical Zether on the shared private chain.
**Source.** `history/plans/2026-10-07-docs-reorg.md:1241`

### CTR-ZTH-34 — Zether runs through the generic self-call
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-34 · superseded-by: —

**Why.** `transferConfidential`, `burn`, `fund`, public `wrap`/`unwrap` are allowlisted self-calls; the confidential ones take the envelope binding from the transient ticket (tag `RELAYED`) and use binding 0 otherwise, so a proof lifted from a pending meta-tx fails as a direct call. `relayedTransfer`/`relayedBurn`/`relayedBurnDecoded`, `OuterFee` and the `OP_ZTRANSFER`/`OP_ZBURN` ops are deleted; the outer fee is the base's, `ABSOLUTE` class.
**Cost if wrong.** Losing the binding reopens envelope stripping; a second dispatch path for Zether keeps two fee pipelines.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §3 MG-2, MG-2.1, §12 (H6).
Change (2026-10-20, Task R, owner): relayed roll-over on both layers, the outer fee may be 0 (supersedes "the roll-overs stay off the allow-lists" of 5h D20 / spec §5.11 and Task 3b). On `NoUnderlyingZetherToken` / `UnderlyingZetherToken`, address and UA envelope, fee class `ABSOLUTE`: `mtxRollOver(bytes32,uint256)`, `mtxRollOverBatch(bytes32[])`, `mtxRollOverSigned` and `mtxSetRollOverMode` (the signed pair keep their owner signature check inside). Status: BUILT, commit `b5e61c96` (tests in `ZetherUA5c.t.sol`, `ZetherRelay.t.sol`, `ZetherUnderlying.t.sol`).
Change (2026-10-08): `m.to`/`m.value` are gone from the struct; a public transfer is a `MetaTransfer`; `PqzToken` relays the same way. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-10.
Change (2026-10-27): **review C3-2, `uaSigner` required (controller ruling, owner may override)**: the prover's relayed `proveTransferMulti` requires `uaSigner` (`"ecdsa"` = the `mtxExecute` envelope, adds 0; `"fndsa512"` | `"mldsa65"` = `uaExecute`, adds that kind's verify cap) and refuses a relayed build without it: the prover cannot tell the relay path from the envelope binding, and an unminable build is worse than an explicit field. Cost if wrong: one more required field for wallet callers (test-only chains, no compatibility). Status: **done** (review2 T7 `1b26e5ff`, `64e6c1fb`).
Change (2026-10-27): **review C3-2 / T3, prover per-`M` `gas_limits` re-measured, measured 2026-10-27, controller (owner request, re-measure)**: `ZetherGasLimit` `test_measure_*` now reports REGULAR gas (EIP-7825's 2^24) and EIP-8037 STATE gas apart (`vm.lastCallGas`, one isolated transaction per cell at 2^24 + 40 M; forge gas is deterministic) and stops on the regular cap less the 1 % margin; the prover's BLS12-381 `gas_limits` are the regular column (`HASH_RECORD_GAS` stays on the legacy bn254 rows only, which cannot be re-measured: no bn254 verifier since UA-6). New largest `M` (direct / relayed): compact 8 / 8 with or without the auditor (was 7 / 7, 8 / 7), BUNDLE with the auditor 7 / 7 (was 6 / 6), BUNDLE without 8 / 8 (was 7 / 6); `test_edge_*` settles all of them on chain. State gas has no prover API field: wallets take the limit from `eth_estimateGas`, the figures are in zether.md §19; the largest total is 37.9 M (BUNDLE with the auditor, M = 7, relayed). Run log `smartcontracts/evm/runs/2026-10-27-zether-gas-v3.txt`. Status: **done** (branch `gas-zether`, pending the owner's merge).
Change (2026-10-27, final review): **review C3-2 follow-up, more `uaSigner` kinds (controller proposal, owner may override)**: the prover also accepts `mldsa44` (4.25 M), `slhdsa128s` (1.4 M), `ed25519` (0.21 M), `p256` / `webauthn-p256` (0.4 M), the gen-1 verify caps of accounts.md (verify-cap table, lines 1440-1455), and a numeric `uaSignerGas` for any other kind (an `msig`); estimates, not measured. `openMemo` no longer returns `needKeys` (`recoverTransfer` takes no keys).


### CTR-ZTH-35 — fund draws from the caller's public balance
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-35 · superseded-by: —

**Why.** The owner accepted that `fund` always burns `amount · shieldScale` public Zether units from the caller instead of pulling the underlying again: one path for every Zether token, the escrow invariant unchanged by construction, and an EOA holding a SCaaS underlying can wrap by signature and then fund.
**Cost if wrong.** An EOA with a SCaaS underlying could not fund at all; two funding paths double the escrow arguments.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §3 MG-7b, §10 OQ5, §13 (N-M5).

### CTR-ZTH-36 — chainUid in every chain-bound Zether digest
- old: — · status: current · owner: no · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-36 · superseded-by: —

**Why.** The statement header, envelope binding, disclosure challenge, rollover and mode digests and `entryRef` carry `chainUid` beside `chainid`, and the built registry takes it in its PoP; a re-created chain restarts `modeNonce`, `accSeq`, `sendCounter` and block numbers, so without it captured signatures and proofs would replay there.
**Cost if wrong.** A mode or rollover signature, or a proof, replays on a chain that reuses the chain id.
**Source.** `history/specs/2026-10-07-metatx-generic.md` §3 MG-4, §13 (N-M4).

### CTR-ZTH-37 — One transfer to M recipients, one proof; transferConfidential is the multi-recipient transfer
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-37 · superseded-by: —

Change (2026-10-27): owner ruling 2026-10-27, C0-1 (ii) — review C0-1 (P0): with the one `s` for the auditor copies `C_aud_j − C_aud_k = [v_j − v_k]G` was public (decoys identical, the real leg's amount a 64-bit discrete log). Now `C_aud_j = [v_j]G + [t_j]Y_a`, `D_aud_j = [t_j]G` (both `O` with the auditor off); statement `Y_f Y_a C_acc D_acc D_out C_deb be32(M) (Y_tj C_out_j C_aud_j D_aud_j)_j`; proof `V_b A_y A_D A_deb A_bal A_Vb (V_vj A_out_j A_aud_j A_Daud_j A_Vvj)_j z_x z_s z_b z_gb (z_vj z_gvj z_tj)_j BP…`; E6_j `[z_vj]G + [z_tj]Y_a − [c]C_aud_j − A_aud_j`, new E6′_j `[z_tj]G − [c]D_aud_j − A_Daud_j`; `D_aud_j ≠ O` and no two legs sharing `C_aud` or `D_aud` with the auditor on (the verifier refuses it); off ⇒ `A_aud_j = A_Daud_j = O`, `z_tj = 0`. Option (i) (public per-leg `h_j` under the one `s`) was rejected as broken: `h_k·C_aud_j − h_j·C_aud_k = [h_k v_j − h_j v_k]G`. With the auditor on, `Y_f == Y_a` or any `Y_tj == Y_a` reverts `AuditorKeyAsParty()` (both formats, before the verifier and in the statement views). No interim `M ≥ 2` refusal (controller ruling: the fix landed on the same branch). Status: **done** (review2 T3, branch `review2-fix`; `proofSystemId` / `proofSystemIdMulti` = `keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"[ ‖ "/multi"])`, `…/v2` refused).

**Why.** The owner wants a sender to add randomly chosen decoy recipients receiving 0 and hide the real one, with one proof and one shared `s` (handing `s` over opens every leg, decoys included, accepted); the sender stays public. The multi-recipient transfer is `transferConfidential`; the single-recipient format is kept unchanged as `transferConfidentialSingle`.
**Cost if wrong.** Without it each decoy is a separate transfer at ≈ 3.3 M gas; without the kept single format, existing proofs and vectors break.
**Source.** `history/specs/2026-10-08-zether-multi-recipient-design.md` §2 (Z1-Z3, Z7, Z8), §3, §4.
Change (2026-10-27): the Zether `proofSystemId` label `…/v3` (and the multi-recipient id `keccak256(label ‖ "/multi")`, the `proofSystemIdMulti` bump) is part of the **owner ruling 2026-10-27 on C0-1 (ii)**, which names the bump; the zether.md wording "label: controller ruling, pending the owner" is corrected. Status: **done** (review2 T3 built `…/v3`; wording fixed in review2 T8).

### CTR-ZTH-38 — Three transfer entries; the plain name is the mode's default
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-38 · superseded-by: —

Change (2026-10-27): owner ruling 2026-10-27, C0-3 — **follow the ciphertext rule (ciphertexts stay in contract state, never only a hash plus calldata / events)**: commit-reveal (HASH) stores `R = salt ‖ B_1 ‖ … ‖ B_M` by SSTORE2 (the slot `entryPtrs[entryRef]` holds the pointer; `TransferBundles` still emits `R`, and the stored bytes hash to the old `keccak256(R)` commitment), BUNDLE stores `R` inline; **NONE is retired** — `mtxConfidentialTransferNoBundle`, `OP_MULTI_NONE` and `TransferMode.NONE` are removed (a call to the old selector hits the token's unknown-selector path and reverts; it is off every allow-list). `transferEntry(entryRef)` returns `R` for every form, `transferMemo(entryRef)` the sender memo; disclosure reads `R` from state and `verifyTransferAmount` / `transferCiphertext` lose the `bundles` argument (`BundlesMismatch` becomes `RecordMalformed`). Cost, measured (BLS12-381, auditor on): commit-reveal +13–16 k regular gas and +1.19 M (M = 1) to +8.04 M (M = 8) EIP-8037 state gas per transfer. Status: **done** (review2 T5, branch `review2-fix`; no `proofSystemId` change: the mode is in `opTag`, the statement is unchanged).

Change (2026-10-27): owner ruling 2026-10-27, C0-1 (ii) — the multi-recipient bundle is `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j ‖ D_aud_j` (5 points, 640 B per leg on BLS12-381; BUNDLE ≈ +486 k gas per audited leg, measured); the single format's record keeps `Y_t ‖ C_out ‖ D_out ‖ C_aud` (`16 + 4P` bytes, never a multi-recipient or commit-reveal length). Status: **done** (review2 T3, branch `review2-fix`; `proofSystemId` / `proofSystemIdMulti` = `keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"[ ‖ "/multi"])`, `…/v2` refused).

Change (2026-10-11): owner — `zetherTransfer` stores the full record on a BUNDLE token and is commit-reveal on a COMPACT token (CTR-ZTH-48); `zetherTransferCompact` is commit-reveal on both; `zetherTransferNoBundle` is BUNDLE-only; `zetherTransferBundle` goes. Salt and memo travel inside `payload`. Built (P3b; P3's `zetherTransfer` = HASH and `zetherTransferBundle` = BUNDLE are superseded): `zetherTransfer` = BUNDLE on a BUNDLE token, commit-reveal on a COMPACT token; `zetherTransferCompact` = commit-reveal; `zetherTransferNoBundle` = NONE. Source add: owner, 2026-10-11.

**Why.** Disclosure storage is the per-transfer cost the sender should choose: the full record (the BUNDLE token's default), only `keccak256` of it plus the sender memo (commit-reveal, the COMPACT token's default; bundles in an event), or nothing (off-chain disclosure from calldata). The mode is in the statement `opTag`, so a relayer cannot switch it.
**Cost if wrong.** Always storing the full bundle costs ≈ +375 k gas (BLS) per leg; storing nothing makes on-chain disclosure impossible.
**Source.** `history/specs/2026-10-08-zether-multi-recipient-design.md` §2 (Z4, Z6), §5.

### CTR-ZTH-39 — No on-chain attestation of a disclosed amount
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-39 · superseded-by: —

**Why.** `attestTransferAmount` and `AmountAttested` are removed; `verifyTransferAmount` stays a view that any contract can call, and a contract that needs an on-chain trace records the result itself.
**Cost if wrong.** An attestation event is a public, irrevocable record that a party disclosed an amount; keeping it forces that trace on every user of the check.
**Source.** `history/specs/2026-10-08-zether-multi-recipient-design.md` §2 (Z9), §5.

### CTR-ZTH-40 — SENDER_CP opening; leg index in every disclosure challenge
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-40 · superseded-by: —

Change (2026-10-27): review C0-4 — strong Fiat–Shamir: `e = hashToScalar(keccak256(pre ‖ G ‖ K ‖ B ‖ M ‖ A1 ‖ A2))`, the statement points in the token's G1 encoding, so a sender cannot choose `s` after `e` (`s = k1⁻¹(k2 + e(v − a))`) and open a false amount with the key holder. Not a `proofSystemId` change; every Chaum–Pedersen opening and the disclosure vectors changed (the old ones are refusal fixtures). Status: **done** (review2 T4, branch `review2-fix`).

Change (2026-10-27): owner ruling 2026-10-27, C0-1 (ii) — the `AUDITOR` opening of a multi-recipient leg `j` is the DLEQ `K = Y_a`, `B = D_aud_j`, `M = C_aud_j − [v]G` and opens that leg alone (the single format: `B = D_out`); `transferCiphertext` returns `C_out ‖ D_out ‖ C_aud ‖ D_aud`. The challenge formula and the `bundles` argument are unchanged here (review C0-4 / C0-3 follow). Status: **done** (review2 T3, branch `review2-fix`; `proofSystemId` / `proofSystemIdMulti` = `keccak256("scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"[ ‖ "/multi"])`, `…/v2` refused).

**Why.** Handing `s` over opens every leg of a multi-recipient transfer, decoys included; a Chaum-Pedersen proof opens leg `j` only. The challenge binds `j` for every kind, so an opening of one leg never verifies for another.
**Cost if wrong.** A sender proving one payment reveals its decoys, so the decoys stop hiding the real recipient.
**Source.** `history/specs/2026-10-08-zether-multi-recipient-design.md` §5.1.

### CTR-ZTH-41 — Auditor key should be a k-of-n threshold key
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-41 · superseded-by: —

**Why.** A single auditor secret `x_a` reads every transfer of the token; splitting it off chain by a DKG (company, audit firm, regulator) needs k parties to decrypt or open, with no contract change since `Y_a` stays one public key.
**Cost if wrong.** A single auditor key is one point of compromise or coercion for all transfer amounts.
**Source.** `history/specs/2026-10-08-zether-multi-recipient-design.md` §2 (Z11).

### CTR-ZTH-42 — The sender may leave the auditor out of one transfer
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-42 · superseded-by: —

Change (2026-10-11): owner — only under `auditorMode = OPTIONAL` (CTR-ZTH-49); NONE forces every `C_aud = O`, FULL every `C_aud ≠ O`. Built (P3): open on every token with an auditor key. Source add: owner, 2026-10-11.

**Why.** On a token whose auditor is on, the sender may set every `C_aud_j = O` and the statement `Y_a = O`; a mix reverts. The owner accepted that the auditor then reads nothing for that transfer and that the opt-out is publicly visible.
**Cost if wrong.** Without it the auditor-on token forces every transfer into the auditor's view; with a mix allowed a proof could verify under either choice.
**Source.** `history/specs/2026-10-08-zether-multi-recipient-design.md` §2 (Z12), §5.

### CTR-ZTH-43 — Disclosure in a stateless ZetherDisclosure
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-43 · superseded-by: —

Change (2026-10-27): owner ruling 2026-10-27, C0-3 — `ZetherDisclosure` reads `R` from the token's state (`transferEntry`) for every entry; `verifyTransferAmount(token, entryRef, index, amount, kind, opening)` and `transferCiphertext(token, entryRef, index)` take no `bundles`. Status: **done** (review2 T5, branch `review2-fix`; no `proofSystemId` change: the mode is in `opTag`, the statement is unchanged).

**Why.** `verifyTransferAmount` and `transferCiphertext` move out of the token into one stateless contract (no admin, no upgrade, every token and curve); the token keeps `transferEntry` and the implementation-immutable `disclosure()`. It takes 2,972 B off `ZetherToken`; the challenge binds the token address.
**Cost if wrong.** Left in the token, disclosure keeps it further over EIP-170 (still 4,363 B over after the split); a mutable disclosure contract could change what an opening proves.
**Source.** `history/specs/2026-10-08-zether-multi-recipient-design.md` §2 (Z13), §5, §7.

### CTR-ZTH-44 — Zether is a layer over the public balance; no underlying of its own
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-44 · superseded-by: —

**Rule.** `ZetherLayer` (storage `scaas.zether`, stubs) plus `ZetherLib` (logic) sit on `MetaTokenBase`; shielded value is taken from the public balance (`zetherShield`) or from an underlying leg through `UnderlyingLib` (`zetherWrapShield`), and `UNDERLYING_ZETHER` keeps `Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply() + totalShielded·shieldScale`. The minter never mints shielded value. A leg may be the native coin (CTR-TOK-26).
**Why.** One base, one underlying implementation and one invariant instead of a second escrow inside `ZetherToken`; a Zether token is an ordinary token whose balance can also be shielded.
**Cost if wrong.** A layer-owned underlying duplicates `UnderlyingLib` and its audit surface, and the supply and reserve checks diverge.
**Source.** `history/specs/2026-10-08-token-tree-design.md` T4, T5, §6.1, §6.3.
Change (2026-10-27): **review C3-8 (controller proposal, owner may override)**: since plan 5h D19 the shielded value is held in `SHIELD_POOL` and counted in `totalSupply()`, so the reserve invariant is `Σ_i ⌊reserve_i · num_i / den_i⌋ ≥ totalSupply()` (zether.md and `UnderlyingLib` already say so); the rule's `+ totalShielded · shieldScale` double-counts the pool. The entry points are `mtxShield` / `mtxWrapShield` (CTR-ZTH-45 change of 2026-10-20), not `zetherShield` / `zetherWrapShield`. `gov-inventory.md` (the rate step's collateral check) is corrected the same way. Status: **done** (review2 T8, branch `review2-fix`; documentation only).

### CTR-ZTH-45 — Zether entry points are `zether*` (`pqz*` for PQZ); no register function
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-45 · superseded-by: —

**Rule.** `zetherShield`, `zetherWrapShield`, `zetherTransfer` (+`Bundle`, `NoBundle`, `Single`), `zetherUnshield`, `zetherUnshieldUnwrap`, `zetherRollOver` (+`Batch`, `Signed`), `zetherSetRollOverMode`; events follow the names; there is no `zetherRegister` / `pqzRegister` because the registry's `register` is relayable.
**Why.** The old names `fund` / `burn` read as ERC-20 operations on a token that now has both; the prefix says which balance an entry point touches.
**Cost if wrong.** `burn` on a token with `BURNABLE` means a holder burn of the public balance, so a clash with the Zether `burn` would be silent.
**Source.** `history/specs/2026-10-08-token-tree-design.md` T5, T6, §6.2.

Change (2026-10-20, owner): **one name for both confidential layers: `mtxShield` / `mtxUnshield`**, with the siblings on the same scheme (wrap-shield, unshield-unwrap, rollover, transfers, events) as one interface shared by the Zether and PQZ tokens; replaces the `zether*` / `pqz*` prefixes of this rule. Built with plan Task 5h (the PQZ ABI changes there anyway; test chains, no migration). The reserved `*_ZETHER_PQZ` kinds are dropped (CTR-TOK-21 change 2026-10-20), so no layer argument. Status: decided; built in 5h.

Change (2026-10-20, owner, 5h plan review Q3): the `mtx*` name table of the 5h design (D20) is approved; confidential transfers are **`mtxConfidentialTransfer…`** (not `mtxZKTransfer`; a wallet may label it "Secure Transfer"); one selector per shared function across Zether and PQZ. Status: decided; built in 5h.

Change (2026-10-20, controller record; shared signature is a controller ruling, owner may override): **the `mtx*` interface (plan 5h D20) in full.** One interface `IConfidentialToken` (`src/confidential/IConfidentialToken.sol`) is implemented by the Zether and the PQZ tokens with **one selector per shared function across both layers**; layer-only functions sit in `IZetherToken` / `IPqzToken` on the same scheme. Names: `mtxShield(bytes32 toUA, uint256 amount)` (Zether resolves `Y` from the registry by UA id, CTR-UA-30), `mtxWrapShield(address underlying, uint256 amountIn, bytes32 toUA)`, `mtxConfidentialTransfer`, `…Compact`, `…NoBundle` (Zether only), `…Single`, `…SingleCompact` (PQZ only), `mtxUnshield`, `mtxUnshieldUnwrap`, `mtxRollOver(bytes32 ua, uint256 n)` (Zether: one aggregated pending, any `n ≥ 1` rolls it), Zether-only `mtxRollOverBatch` / `mtxRollOverSigned` / `mtxSetRollOverMode`, PQZ-only `mtxPrepareAcc`; events `Shielded(bytes32 indexed toUA, address indexed from, uint256 amount, uint64 index)` (Zether `index` = `pendingSeq`), `ConfidentialTransfer` / `ConfidentialTransferMulti`, `Unshielded` (refresh: `amount = 0`), `RolledOver(bytes32 indexed ua, uint64 rolled, uint32 accUnits, bytes32 accHash)` (Zether `rolled` = `accSeq`), `Credited`, `Debited`; `TransferBundles` and `RollOverModeChanged` unchanged; **views keep their names**. Proof-taking signature `(bytes payload, bytes proof, bytes auth, bytes32 beneficiary, bytes accHint[, trailing])`: PQZ `auth` = the signer's signature (was `authSig`) and `beneficiary` must equal the payload's; Zether `auth` and `accHint` must be empty (UA-6: the proof alone authorizes). `mtxUnshield(…, uint256 amount, bytes32 recipient)` serves native and UA recipients (CTR-ZTH-51 change); PQZ refresh is `amount = 0, recipient = 0`. `mtxUnshieldUnwrap` takes the five common arguments, then the leg as one calldata struct `Unwrap(address underlying, bytes32 recipient, uint256 amount, uint256 minOut)` (a flat form is stack-too-deep on the legacy code generator). Allow-lists list the new selectors; Zether roll-overs and `mtxPrepareAcc` stay off them. No old name is kept (all chains are test-only). Status: decided (Q3 names: owner; signature: controller ruling); BUILT on branch `pqz-state-b` (plan 5h Task 3b, D20, UA-5c (a)(b); commits 61c60089..82793a58, docs reconciled in 1dcd8657).

### CTR-ZTH-46 — Prover views in a stateless ZetherStatements
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-46 · superseded-by: —

**Why.** The prover-only views (`transferStatement*`, `unshieldStatement`) read the token's `accountState` and move to one stateless contract, pairing with `ZetherDisclosure`; it takes the views out of a token that is over EIP-170.
**Cost if wrong.** The views stay in the token and its size budget (CTR-TOK-24) is spent on code no transaction runs.
**Source.** `history/specs/2026-10-08-token-tree-design.md` T14, §6.1.

### CTR-ZTH-47 — Regulated flags are refused on confidential kinds
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/zether.md#CTR-ZTH-47 · superseded-by: —

**Why.** Flags 5–8 (`FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST`, CTR-AS-17) are refused on `NONE_ZETHER` / `UNDERLYING_ZETHER`; valid flags are `PAYABLE`, `MINTABLE`/`BURNABLE` (`NONE_ZETHER`), `RATE_ADJUSTABLE`/`WRAP_DISABLEABLE` (`UNDERLYING_ZETHER`). A confidential balance can be frozen but not seized on public chains.
**Cost if wrong.** Every control combination on a confidential kind would need its own audited implementation.
**Source.** `history/specs/2026-10-08-token-tree-design.md` T11, §6.3.

### CTR-ZTH-48 — disclosureMode BUNDLE or COMPACT, chosen at initialize
- old: — · status: current · owner: yes · date: 2026-10-11 · normative: contracts/zether.md#CTR-ZTH-48 · superseded-by: —

Change (2026-10-27): owner ruling 2026-10-27, C0-3 — both modes keep `R` in state (BUNDLE inline, COMPACT by SSTORE2); `…NoBundle` is retired, so the rule no longer lists it, and a `disclosureMode` above COMPACT (the retired NONE position included) reverts `BadDisclosureMode` at `init`. Status: **done** (review2 T5, branch `review2-fix`; no `proofSystemId` change: the mode is in `opTag`, the statement is unchanged).

**Rule.** Owner decisions of 2026-10-11, in one place: (1) `disclosureMode ∈ {BUNDLE, COMPACT}` at `initialize`, immutable: on BUNDLE `zetherTransfer` stores the full bundle (default) and a caller may save gas with `zetherTransferCompact` or `zetherTransferNoBundle`; on COMPACT only commit-reveal, the no-bundle entry reverts typed (CTR-ZTH-38). (2) `auditorMode ∈ {NONE, FULL, OPTIONAL}` at `initialize`, immutable; FULL refuses opt-outs, OPTIONAL keeps CTR-ZTH-42 (CTR-ZTH-49). (3) `s` from the seed with a fresh published 16-byte salt per build (CTR-ZTH-30). (4) Commit-reveal stores a sender memo (salt ‖ amounts and recipients XOR an HKDF keystream) so the sender opens from seed + storage alone (CTR-ZTH-50). (5) A who-can-open table per storage (zether.md §14). (6) PQ Zether follows the same rules (CTR-PQZ-19, CTR-PQZ-23, CTR-PQZ-24). Built in P3b (PQZ: spec only).
**Why.** The creator, not each sender, decides whether a token keeps its disclosure data on chain. COMPACT is a subset of BUNDLE, so one implementation per kind serves both and the kinds stay `NONE_ZETHER` / `UNDERLYING_ZETHER` (CTR-TOK-21); separate implementations per mode were rejected, to be revisited only if EIP-170 forces smaller bytecode.
**Cost if wrong.** A per-sender choice leaves no on-chain guarantee of where disclosure data lives; a separate implementation per mode doubles the audit surface.
**Source.** owner, 2026-10-11; background `research/zether-disclosure.md` §4, §6, §7, §9.
Change (2026-10-27): **review C3-8 (controller proposal, owner may override)**: the names in the rule are the `mtx*` ones (CTR-ZTH-45 change of 2026-10-20): `zetherTransfer` is `mtxConfidentialTransfer`, `zetherTransferCompact` is `mtxConfidentialTransferCompact`; `…NoBundle` and the NONE position are retired (owner ruling 2026-10-27, C0-3, above). Status: **done** (review2 T8, branch `review2-fix`; documentation only).

### CTR-ZTH-49 — auditorMode NONE, FULL or OPTIONAL, chosen at initialize
- old: — · status: current · owner: yes · date: 2026-10-11 · normative: contracts/zether.md#CTR-ZTH-49 · superseded-by: —

**Why.** A regulated token needs coverage the sender cannot opt out of (FULL: every transfer from creation, balances reconstructible by bookkeeping); others want the auditor optional per transfer (OPTIONAL) or absent (NONE). The factory refuses FULL/OPTIONAL without a key, NONE with one, and unknown values. One implementation: the token-side difference is a few checks, E6 lives in the shared verifier, and the immutable public config gives the same assurance.
**Cost if wrong.** Without FULL an auditor-enabled token proves no coverage (research finding R3); a key under NONE would be a dead key the public reads as coverage.
**Source.** owner, 2026-10-11; background `research/zether-disclosure.md` §4, §6, §7, §9.

### CTR-ZTH-50 — Commit-reveal stores a sender memo; the sender recovers from storage alone
- old: — · status: current · owner: yes · date: 2026-10-11 · normative: contracts/zether.md#CTR-ZTH-50 · superseded-by: —

Change (2026-10-27): owner ruling 2026-10-27, C0-3 — the memo now sits next to `R` itself, not a 32-byte hash: `transferEntry` returns `R`, `transferMemo` the memo; the prover's `openMemo` / `recoverTransfer` take both (`entry`, `memo`), need no registry key lookup (`R` carries every `Y_tj`) and compare the sender's rebuilt `R` with the stored one; the commitment-only entry form and `recover_transfer_with` / `keys` are gone. Status: **done** (review2 T5, branch `review2-fix`; no `proofSystemId` change: the mode is in `opTag`, the statement is unchanged).

**Why.** Commit-reveal kept only a 32-byte hash, so the sender needed logs or calldata to open its own transfer. Storing `salt ‖ (flags ‖ (v_j ‖ toUA_j)) XOR keystream` (17 + 40·M bytes, `flags` bit0 = auditor included, so recovery needs no guessing; flags byte and keystream label: controller ruling, pending the owner; ≈ 3 slots with the commitment at M = 1 against ≈ 9 for a full bn254 bundle) lets the sender rebuild every bundle from its seed and storage; `s`, the key and `Y_a` are recomputed. No MAC: a wrong decryption fails the commitment. The memo hash is in the signed statement, so a relayer cannot alter or drop it. Receiver and auditor still need `TransferBundles` logs or calldata (R6 open).
**Cost if wrong.** Without the memo a sender whose logs are gone cannot open its own commit-reveal transfers.
**Source.** owner, 2026-10-11; background `research/zether-disclosure.md` §4, §6, §7, §9.

### CTR-ZTH-51 — The Zether public side from and to the UA ledger
- old: — · status: current · owner: yes · date: 2026-10-13 · normative: contracts/zether.md#CTR-ZTH-51 · superseded-by: —

**Why.** Only the public side (units a shield burns, units an unshield mints, the outer fee) may be a UA; the confidential account stays a Zether kind. Without it a PQ UA holder would need a classical key to use a Zether token — what PQZ's UA path exists to avoid. A distinct UA envelope tag (`SCAAS-ZETHER-UA-ENVELOPE-V1`) keeps a proof from moving between address and UA envelopes; the unshield recipient word carries a `bytes32` id, so one proof binds one recipient id with no new op tag.
**Cost if wrong.** A new binding and two `…ToUA` entry points per Zether kind; the prover takes a 32-byte recipient.
**Source.** owner, 2026-10-13 (Q7); `history/specs/2026-10-13-ua-parity-design.md` §4.11, O5.

Change (2026-10-20, owner): **shielded value sits in a `SHIELD_POOL` sentinel instead of being burned** — `SHIELD_POOL = address(uint160(uint256(keccak256("scaas.shield.pool.v1"))))`, for the PQZ and the Zether kinds alike. Shield moves `amount · shieldScale` from the signer to `SHIELD_POOL` (`Transfer(signer, SHIELD_POOL)`, no burn); unshield / burn-unwrap moves it out to the recipient (no mint); a fee paid from a hidden balance (beneficiary fee, the per-credit fee of every leg) moves out of `SHIELD_POOL` to each fee recipient's public balance. So `totalSupply()` never changes on shield / unshield and stays the true total, `Σ balanceOf == totalSupply` holds, `balanceOf(SHIELD_POOL) == totalShielded · shieldScale`, and the escrow invariant becomes `reserve ≥ totalSupply()`. `SHIELD_POOL` is not payable and cannot spend (as `UA_POOL`, `UAPoolNotPayable`); the token's own address is not used (CTR-MTX-18). Relations and proofs unchanged. Status: decided; built in plan Task 5h for both kinds.

Change (2026-10-20, owner / controller proposal (owner may override)): UA-6 — the confidential account is the Zether UA itself, which is also a SIGNING UA on the UA ledger (Q1 / U8), so its public and confidential balances share one id; CTR-ZTH-51's statement that a PQ UA holder needs no classical key to use a Zether token still holds for the **public** side (a PQ UA may pay a shield into any Zether account), while the confidential side of classical Zether is classical by nature. **U9, `authSig` leaves the Zether entry points**: with `authRef` gone the argument could only be empty, so `zetherTransfer`, `…Compact`, `…NoBundle`, `…Single`, `zetherUnshield`, `zetherUnshieldUnwrap` and the `…ToUA` forms drop it (an ABI break either way), as do the prover API, `authDigest` and the `SCAAS-ZETHER-AUTH-V1` digest; the token checks `kindOf(from) == ZETHER_BLS12381` and verifies the proof (the `_authRef` read and the `authSig` calldata saved per spend). `zetherRollOverSigned` and `zetherSetRollOverMode` go through `requireAuthorized(ua, PURPOSE_ZETHER_OWNER, …)` with the same Schnorr bytes. Spec §5. Status: decided (Q1) / proposal (U9); built in UA-6 (branch `ua6`, commits c4ece459, 97fe4778; prover 93c5ead2, 1e961aea, 67ef75bc; the `…ToUA` forms are specified, UA-5c).

Change (2026-10-20, controller record; owner may override): **UA-5c (a)(b) move into plan 5h part A** (owner: (a) confidential ops via the UA envelope and (b) unshield to a UA ride with the `mtx*` rename; (c)(d) follow as step 5c′ before the node relay). (b): **no separate `zetherUnshieldToUA` / `zetherUnshieldUnwrapToUA`** — `mtxUnshield(…, uint256 amount, bytes32 recipient)` carries the recipient as a `bytes32`: a native address is its zero-padded id (statement word unchanged, vectors unchanged), a derived UA id (non-zero top bits) must be a registered SIGNING UA and is credited on the UA ledger by a pool move `SHIELD_POOL → UA` (`_poolMove`; no mint), the pools are refused as recipient; unshield-unwrap to a UA pays a SCaaS ledger leg through `transferToUA` (`UALegNotLedger` otherwise); one proof binds one recipient id. This supersedes the two `…ToUA` entry points, the event `ZetherUnshieldedUA` and their allow-list rows in this rule's earlier text. (a): `mtxConfidentialTransfer*`, `mtxUnshield`, `mtxUnshieldUnwrap` join the Zether UA allow-list and `uaExecute` stores `SCAAS-ZETHER-UA-ENVELOPE-V1` bindings in the ticket (tested in both directions). Pool trust boundary as CTR-PQZ-15 change. The Zether pool path is built (Task 3z `7733910e`, merge `f8715b65`: shield / unshield / beneficiary fee through the pool, `_uaMove` refuses the pool); the rename, the one-function unshield and (a) are plan 5h Task 3b. Status: decided; BUILT on branch `pqz-state-b` (pool: Task 3z `7733910e`; rename, one-function unshield, (a) and (b): Task 3b, commits 61c60089..82793a58; docs reconciled in 1dcd8657).

### CTR-ZTH-80 — Range bits 32 and DECRYPT_BOUND 2^40
- old: R34(params) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CTR-ZTH-18, CTR-ZTH-19

**What it said.** An earlier ruling used range bits 32 and a decryption bound of 2^40.

### CTR-ZTH-81 — Zether registry with eight auth schemes and PoP
- old: R34(registry) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CTR-UA-02, CTR-UA-16, CTR-UA-22

**What it said.** The built Zether-only registry with eight auth schemes and a PoP bound to `msg.sender` (Transitional, BUILT on dev chains; replaced by the UA registry).

### CTR-ZTH-82 — PQ_COMMITMENT verified like SELF_SCHNORR
- old: RS2-10 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-UA-23, CTR-UA-16

**What it said.** An earlier rule verified `PQ_COMMITMENT` exactly like `SELF_SCHNORR`.

### CTR-ZTH-83 — Built registry PoP does not bind authority
- old: RS2-22 · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: CTR-UA-07

**What it said.** A note that the built registry PoP does not bind an authority.

### CTR-ZTH-84 — Permissionless rollOver proposed as D17
- old: UD:§12.7.3 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A proposal for permissionless rollOver as a separate decision.

### CTR-ZTH-85 — SDK must store every s
- old: UD:§12.7.4 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-30

**What it said.** A proposal that the SDK store every sender randomness `s`.

### CTR-ZTH-86 — Implicit rollOver open to everyone
- old: UD:§13.3 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A proposal for implicit rollOver open to everyone.

### CTR-ZTH-87 — Curve D1 = BLS12-381 after preflight
- old: UD:§14 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling setting the curve to BLS12-381 after a preflight.

### CTR-ZTH-88 — D1 and D2 settled on BLS12-381
- old: UD:§14:consequences · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling settling two curve decisions on BLS12-381.

### CTR-ZTH-89 — Curve D1 = bls12_381
- old: UD:§15:D1 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling setting the curve to bls12_381.

### CTR-ZTH-90 — Keep implicit rollOver plus public entry points
- old: UD:§15:D17 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling keeping implicit rollOver plus public entry points.

### CTR-ZTH-91 — Curve D1 = bn254 for the private phase
- old: UD:§19 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** A ruling setting the curve to bn254 for the private phase.

### CTR-ZTH-92 — Keep bn254 verifiers and chain 9000 as is
- old: UD:§19:unlocked · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01, NET-EVM-02

**What it said.** A ruling keeping the bn254 verifiers and the private chain unchanged.

### CTR-ZTH-93 — When to reopen the curve decision
- old: UD:§19:reopen-conditions · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-ZTH-01

**What it said.** Conditions under which the curve decision would reopen.

## 24. Contracts — Universal Account

### CTR-UA-01 — Refuse BLS keys and signatures at infinity
- old: RS2-18 · status: current · owner: no · date: 2026-10-03 · normative: contracts/accounts.md#CTR-UA-01 · superseded-by: —

**Why.** BLS keys and signatures at infinity make the pairing trivial; refusing them prevents a fake BLS custody that lets `x` alone spend.
**Cost if wrong.** Accepting infinity lets anyone pass a BLS check.
**Source.** `history/specs/2026-10-03-zether-design.md:618`

### CTR-UA-02 — UA is a key-derived identifier, not a contract
- old: R290 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-02 · superseded-by: —

**Why.** A UA is an identifier derived from key data, like an EOA for every scheme: free, deterministic, the same on every chain, with nothing to deploy.
**Cost if wrong.** A contract per account costs a deploy per user per chain and is upgradeable state.
**Source.** `history/specs/2026-10-06-universal-account-design.md:93`

### CTR-UA-03 — 32-byte kind-tagged ids in canonical form
- old: R291 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-03 · superseded-by: —

**Why.** 32-byte kind-tagged ids never collide with 20-byte native ids; a 20-byte truncation would allow a 2^80 grind between an EOA and a multisig policy.
**Cost if wrong.** 12 more calldata bytes per id (192 gas).
**Source.** `history/specs/2026-10-06-universal-account-design.md:100`

### CTR-UA-04 — keccak256 for ids in every family
- old: R292 · status: current · owner: no · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-04 · superseded-by: —

**Why.** One hash (keccak256) with native support in every family gives the same id on every chain.
**Cost if wrong.** Different hashes per family would give different ids for one key.
**Source.** `history/specs/2026-10-06-universal-account-design.md:113`

### CTR-UA-05 — Fixed kind table per registry generation
- old: R293 · status: current · owner: no · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-05 · superseded-by: —

**Why.** The kind table is fixed per registry generation; a mutable table would be an admin key over every account.
**Cost if wrong.** New schemes wait for a new generation and new token implementations.
**Source.** `history/specs/2026-10-06-universal-account-design.md:117`
Change (2026-10-19): controller proposal (owner may override) — **gen 1 starving behind gen 2 is `UAVerifyGas`, never a verdict** (the second code review, on-chain part (plan Task 5g, branch `rev2-chain-sol`; triage W-A…W-S in `pqz-core/research/code-review-2026-10-19/U-agy-chain.md`, row W-M; report `V2-claude-ua-account-wallet.md` V2-5). `_viaPredecessor` / `_zetherViaPredecessor` turned every gen-1 revert except a 4-byte `UAVerifyGas` into `false`, so gen 1 running out of gas before its own hold (its pre-hold work: record SLOAD, `abi.decode(auth)`, `uaOf` / `uaMessage` keccaks, `SSTORE2.read`) came back `UAUnauthorized`: fail-closed, but a relayer is told "bad signature" instead of "more gas" (T-AUTH-4). Now both read `g = gasleft()` before the call and also re-raise `UAVerifyGas` for a revert with no data while `gasleft() < g / 63` (gen 1 used up all it was given, i.e. ran out of gas; any other gen-1 revert returns its unused gas and stays a failed check). Deviation from the triage's wording ("a minimum-gas guard before the hand-off"): a constant guard must cover gen 1's pre-hold work, which grows with the caller's `auth` (an `msig` with PQ member signatures), so no constant is sound; the check after the call needs none. Edge: an `auth` whose decoding alone exceeds the gas supplied reads `UAVerifyGas` too (still fail-closed). Tests: `test_W_M_gen1OutOfGas_isUAVerifyGas_aCheapRevertIsAVerdict` (a gen 1 that burns all its gas behind gen 2: `UAVerifyGas` on both hand-offs, `UAUnauthorized` on the old code; a gen 1 that reverts at once with no data stays `UAUnauthorized`); `test_W_M_gen1StarvedBeforeItsHold_isUAVerifyGas` (a 5 k–300 k gas sweep with the real p256 path never yields `UAUnauthorized`; it passes on the old code too: there the gas gen 2 keeps is too little to finish any verdict, so the misclassification needs a gen 1 whose pre-hold work is large, e.g. a big `auth`). Deployed bytecode: `UARegistry` (only a gen 2 takes the path; none is deployed). Status: **done** (`17c72d62`).

### CTR-UA-06 — Native kinds unregistered; derived kinds register first
- old: R294 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-06 · superseded-by: —

Change (2026-10-17): owner — kinds are the same on every chain, so **every derived kind is registrable on every chain whose registry has its verifier, also where the key is a native account**; the native key's registered id is the derived `keccak256(TAG(kind) ‖ key_data)`, separate from its native id and the same on every chain (`ed25519` 0x0102 no longer "native elsewhere"). New derived kind **`secp256k1` 0x0108** (owner 2026-10-17, controller design): `x ‖ y` (64), ECDSA over the 32-byte `ua_msg`, sig `r ‖ s ‖ v`, low-s, `v ∈ {27, 28}`, keyHash group `secp256k1` over x (one key, one purpose with `bip340` / MuSig2 / FROST), `Secp256k1Verifier` (cap 50 k), enabled on every chain's gen-1 registry; registry slot 19; vectors appended (kinds.json, signatures.json, metatx3.json, uatrade_kat.json); all six clients. Native kinds stay without records and outside the per-kind list (CTR-UA-29).

**Why.** Native kinds need no registration; derived kinds register once per chain, which is where PoP and one-key-one-purpose are enforced and typos revert.
**Cost if wrong.** One registration per chain (~75 k gas on bn254).
**Source.** `history/specs/2026-10-06-universal-account-design.md:125`

### CTR-UA-07 — PoP binds chain, registry, UA and the PQZ key hash
- old: R295, UA:Q10 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-07 · superseded-by: —

**Why.** Every record field follows from signed data (PoP over chain, registry, UA and `authRef`; the authority co-signs), so registration is relayable and front-running yields the same record or a revert.
**Cost if wrong.** A field taken from `msg.sender` or left unsigned would turn front-running into capture.
**Source.** `history/specs/2026-10-06-universal-account-design.md:133`, `history/specs/2026-10-06-universal-account-design.md:1407`

Change (2026-10-20): controller proposal (owner may override) — UA-6 (U4): the last word of the PoP digest is the PQZ key hash (`0` without a PQZ key), no longer `authRef`; no authority co-signs (purpose `authref` removed). The signer's PoP covers the hash, so a front-runner cannot strip or swap the PQZ key; every other record field is implied by the signed key data. See CTR-UA-30. Status: proposal; built in UA-6 (branch `ua6`, commit 9c2cbc5c).

### CTR-UA-08 — Rogue-key defence chosen per aggregate kind
- old: R296, UA:Q3 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-08 · superseded-by: —

**Why.** Each aggregate kind uses its native rogue-key defence, checked on chain: per-member PoP for `msig`, KeyAgg for MuSig2, DKG PoKs for FROST.
**Cost if wrong.** Off-chain facts (share distribution, distinct parties) stay attestation-only and must be shown as such.
**Source.** `history/specs/2026-10-06-universal-account-design.md:148`, `history/specs/2026-10-06-universal-account-design.md:1391`

### CTR-UA-09 — Structures commit to members; one nesting level
- old: R297 · status: current · owner: no · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-09 · superseded-by: —

**Why.** Structures commit to sorted members and nest one level, which bounds gas and avoids cycles.
**Cost if wrong.** Two-level governance uses `SmartKeyAccount` or Safe as a member.
**Source.** `history/specs/2026-10-06-universal-account-design.md:159`

### CTR-UA-10 — One key one purpose: registry, tags, EOAs
- old: R298(2-3-4) · status: current · owner: yes · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-10 · superseded-by: —

Change (2026-10-13): owner — new purpose `trade` (`scaas.ua.purpose.trade.v1`) for the `UATradeOrder` digest, the `CancelOrder` digest over a UA order hash and the `UAInvalidateNonces` digest (CTR-DEX-25); the registry is unchanged (it takes any purpose tag), the constant joins `UAKinds` and the six UA libraries. SPECIFIED (UA-5b). Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.6, O4, Q4.

**Why.** One key = one purpose in four layers (derivation, registry `keyOwner`, tagged messages, EOA rules) prevents cross-scheme nonce leaks and signing oracles.
**Cost if wrong.** A foreign wallet reusing an EOA key for `bip340` remains undetectable on chain.
**Source.** `history/specs/2026-10-06-universal-account-design.md:166`

Change (2026-10-20): controller proposal (owner may override) — UA-6: purpose `authref` is removed (with `PURPOSE_AUTHREF`, `scaas.ua.purpose.authref.v1` and the co-sign step); purpose `pop` wraps `popDigest(ua, pqzKeyHash)`; purpose `zether-auth` keeps its bytes and covers only the PQZ `authDigest` (classical Zether spends by its proof alone); purpose `zether-owner` is signed by Schnorr with `x` through `requireAuthorized` (the Zether UA is a SIGNING UA). One key = one purpose gains the PQZ key: it decrypts and proves, the signer's key authorizes. Spec §5. Status: proposal; built in UA-6 (branch `ua6`, commits 9c2cbc5c; clients 294a4688..8b93de4e).

### CTR-UA-11 — keyHash per curve group, not per kind
- old: R299 · status: current · owner: no · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-11 · superseded-by: —

**Why.** `keyHash` per curve group makes all kinds over one group share a namespace, so the same key cannot register under two kinds.
**Cost if wrong.** A per-kind keyHash allows the same key under two kinds.
**Source.** `history/specs/2026-10-06-universal-account-design.md:173`

### CTR-UA-12 — Tagged message for every derived-UA signature
- old: R301 · status: current · owner: no · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-12 · superseded-by: —

**Why.** Every derived-UA signature is over a tagged message with kind and purpose, so cross-kind and cross-purpose replay die at the hash; native signers sign EIP-712 `UAAuth`, never a raw hash.
**Cost if wrong.** One extra keccak (~60 gas).
**Source.** `history/specs/2026-10-06-universal-account-design.md:188`

### CTR-UA-13 — No key rotation inside a UA
- old: R302, RS2-9, UA:Q1 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-13 · superseded-by: —

**Why.** A UA is immutable: new key data is a new UA; rotation moves funds. A rotatable policy kind was rejected for v1 because it brings back an admin-like mutable record.
**Cost if wrong.** Membership changes of a corporate `msig` require moving funds.
**Source.** `history/specs/2026-10-06-universal-account-design.md:202`, `history/specs/2026-10-03-zether-design.md:597`, `history/specs/2026-10-06-universal-account-design.md:1385`

### CTR-UA-14 — Each function accepts only the kinds it needs
- old: R303, UA:Q4, UA:Q5, UA:Q7 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-14 · superseded-by: —

Change (2026-10-13): owner — UA parity (CTR-UA-27): the DEX, `MandateWallet` and (when built) regulated tokens open to registered SIGNING UAs through UA forms; the address-typed ABI is unchanged; the earlier plan of a UA-ledger allowance `uaApprove` and an `SCaaSDex` v2 with `bytes32 maker` is dropped (no UA ever grants or holds an allowance, Q2; UA orders are `UATradeOrder`s in the one `SCaaSDex`, CTR-DEX-25/26); the role and admin functions stay as they are, their holders gasless through their own contract account (Q1). Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §6 Q1, Q2.

**Why.** Each function accepts exactly the kinds it needs; native-address functions keep their ABIs and Zether UAs can neither receive on v3 nor sign through `requireAuthorized`.
**Cost if wrong.** UA holders need v3 tokens; deployed v1/v2 clones stay native-only.
**Source.** `history/specs/2026-10-06-universal-account-design.md:207`, `history/specs/2026-10-06-universal-account-design.md:1394`, `history/specs/2026-10-06-universal-account-design.md:1396`, `history/specs/2026-10-06-universal-account-design.md:1400`

Change (2026-10-20, owner; UA-6 Q1 / U8): **the Zether kind joins the SIGNING set, not MEMBER**: `requireAuthorized` accepts `zether-bls12381` for every purpose (verifier `ZetherSchnorrBls12381Verifier`, `auth.keyData` empty as a stored kind), `_checkTo` accepts it as a UA-ledger receiver, and parity (CTR-UA-27) applies; it stays out of MEMBER (a hot key the wallet holds in software for every balance read) and out of the PQZ holder set. Domain separation unchanged: Schnorr hashes `"SCAAS-ZETHER-SCHNORR-V1" ‖ R ‖ Y ‖ uaMessage(kind, purpose, digest)`, proofs have their own transcripts. The closed sets are now ZETHER = {0x0141}, SIGNING = every derived kind including 0x0141, MEMBER = SIGNING single-key kinds except 0x0141 plus the native kinds; the clauses "Zether `authRef`" and "a Zether UA can never be a v3 receiver nor sign through `requireAuthorized`" are deleted. Status: decided; built in UA-6 (branch `ua6`, commits 9c2cbc5c, c4ece459).

### CTR-UA-15 — Registry is monotonic and admin-free
- old: R304 · status: current · owner: no · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-15 · superseded-by: —

**Why.** A monotonic, admin-free registry lets tokens rely on a record forever and nobody can repoint a key. Rejected: the early shared-registry sketch (`SchnorrPublicKey {x, y}`, `register(x, y, sig)`, `schnorrAddress = keccak256(abi.encodePacked(x, y))`) — corrected to kind-tagged ids, a PoP with domain tag, chain and registry, on-curve and subgroup checks, and no upgrade path.
**Cost if wrong.** A compromised derived key is handled like a compromised EOA: move funds.
**Source.** `history/specs/2026-10-06-universal-account-design.md:215`

### CTR-UA-16 — The Zether key is the UA; the PQZ key is an attribute of a PQ signer
- old: R305, UA:Q2 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-16 · superseded-by: —

**Why.** Zether kinds bind only the encryption key; authorization is an immutable `authRef` (self, native or SIGNING UA), so spend authority stays separate from decryption.
**Cost if wrong.** `authRef` cannot rotate; a timelocked rotation was rejected.
**Source.** `history/specs/2026-10-06-universal-account-design.md:219`, `history/specs/2026-10-06-universal-account-design.md:1389`

Change (2026-10-20, owner): **the Zether key is the UA and the PQZ key is an attribute of a PQ signer** (CTR-UA-30): the immutable `authRef`, its co-signature and the rule "a BLS UA on the curve of `Y` is refused" are removed; classical Zether spends by its proof alone and signs every other write by Schnorr with `x` (a leaked `x` is a full loss, accepted); a PQZ holder is a single-key `mldsa44` / `mldsa65` / `fndsa512` UA or a PQ-eligible `msig`, the key is given once in `register` and cannot be added later. UA-6 U3, holder set (controller proposal, owner may override): `slhdsa128s` is **not** a direct holder (not in the owner's list; a 7,856-byte signature and a ≈ 1.4 M gas cap on every spend) but counts as PQ weight inside an `msig`, as built; every other kind, Zether included, reverts `UAPqzHolder`. The same-curve-BLS DDH concern becomes a wallet derivation rule (separate trees, already true). Spec §2–§5. Status: decided (owner rulings) / proposal (U3); built in UA-6 (branch `ua6`, commit 9c2cbc5c).

### CTR-UA-17 — Verify through registry; large keys stored once
- old: R306 · status: current · owner: no · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-17 · superseded-by: —

**Why.** The registry does lookup and check in one call; small keys travel in calldata, large keys (PQ, MuSig2/FROST group keys) are stored once.
**Cost if wrong.** No token-side cache in v1: one cold call (~2.6 k) per check.
**Source.** `history/specs/2026-10-06-universal-account-design.md:229`

Change (2026-10-20): controller proposal (owner may override) — UA-6 (U1, U6): the optional PQZ key of a PQ signer is stored as a separate SSTORE2 pointer beside the record (returned by `recordOf`), not as `keyPtr`; the `Record` keeps one slot; `keyOf(ua)` keeps returning the signer's own stored key (ML-DSA `pk`, Zether `Y`, …). Zether `Y` is stored so that `keyOf` serves storage-only recovery and its signed writes carry only the signature. Status: proposal; built in UA-6 (branch `ua6`, commits 9c2cbc5c, 8889a21b, a01ed25e).

### CTR-UA-18 — Derived-UA balances in a separate bytes32 ledger in the base
- old: R308 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/accounts.md#CTR-UA-18 · superseded-by: —

**Why.** Derived-UA balances live in a separate `bytes32` ledger, shown to ERC-20 tools as the `UA_POOL` sub-ledger, keeping `Transfer` replay equal to `balanceOf`; the ledger lives in the one base, so every tier has it.
**Cost if wrong.** Naive indexers see one large `UA_POOL` holder.
**Source.** `history/specs/2026-10-06-universal-account-design.md:243`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-9.

### CTR-UA-19 — UAMetaTransaction has its own typehash in the token domain
- old: R309, UA:Q11 · status: current · owner: yes · date: 2026-10-08 · normative: contracts/accounts.md#CTR-UA-19 · superseded-by: —

**Why.** `UAMetaTransaction` has its own struct and typehash because `from` is `bytes32`; it is signed in the token's one salted domain (version `"1"`, `chainUid` the implementation's immutable) and keeps explicit shapes (transfer, `pay`, `unwrap`), since a `bytes32` sender cannot run a self-call.
**Cost if wrong.** Clients build two struct shapes; a separate domain version would add a second salt source.
**Source.** `history/specs/2026-10-06-universal-account-design.md:255`, `history/specs/2026-10-06-universal-account-design.md:1410`; `history/specs/2026-10-07-metatx-generic.md` §3 MG-9, §7 (CTR-UA-19 row).
Change (2026-10-08): both UA structs (`UAMetaTransaction`, `UAMetaTransfer`) share the token domain; the split is CTR-UA-26. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G8, §3 GC-9.

### CTR-UA-20 — Optional VC layer; on-chain anchor deferred
- old: R310 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-20 · superseded-by: —

**Why.** The credential layer is optional; contracts consume only `ComplianceRegistry` flags. The on-chain anchor is deferred because nothing reads it and it would leak metadata.
**Cost if wrong.** No public holder/issuer co-statement in v1; the evidence bundle carries it privately.
**Source.** `history/specs/2026-10-06-universal-account-design.md:264`

### CTR-UA-21 — Holder binding by account-signed presentation
- old: R311, UA:Q14 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-21 · superseded-by: —

**Why.** Holder binding is a presentation signed by the account under purpose `vp` (SD-JWT VC + KB-JWT `alg: scaas-ua`), ideally by a dedicated identity UA.
**Cost if wrong.** External SD-JWT verifiers accept these presentations only if they implement `scaas-ua`.
**Source.** `history/specs/2026-10-06-universal-account-design.md:271`, `history/specs/2026-10-06-universal-account-design.md:1415`

### CTR-UA-22 — Breaking dev-only migration from Zether registry
- old: R312 · status: current · owner: no · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-22 · superseded-by: —

**Why.** Migration from the built Zether registry is breaking and dev-only: the old registry and `AuthScheme` leave the build (backed up in `smartcontracts/evm/legacy/ua3/`, UA-3), Zether accounts re-register.
**Cost if wrong.** Dev balances are recreated by scripts; no production data exists.
**Source.** `history/specs/2026-10-06-universal-account-design.md:278`

### CTR-UA-23 — PQ and ed25519 kinds on every EVM chain
- old: R313, UA:Q9 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-23 · superseded-by: —

Change (2026-10-11): owner — (1) ML-DSA signs `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the empty FIPS 204 context instead of `ua_msg` with `ctx = kind_tag`: EIP-8355 always uses the empty context and EIP-8051 takes a 32-byte message, so only a 32-byte digest carrying the tag fits both; key data and UA ids unchanged, vectors change in P6; chain 7622's `MLDSA65` becomes EIP-8355's layout. (2) New kind `slhdsa128s` (0x0133, SLH-DSA-SHA2-128s, FIPS 205, pk 32 B, sig 7,856 B, same `pq_msg`), the hash-based backup if lattices fall: pure Solidity on SHA-256 `0x02` (no SLH-DSA precompile EIP), enabled on public chains only after P6 measures its gas against the per-transaction cap and `UA_VERIFY_BUDGET`. Both SPECIFIED (P6). Source add: owner, 2026-10-11; `research/pq-eips-vs-scaas.md` Q1, Q4.

Change (2026-10-15): controller proposal (owner may override) — P6f D3 / D5: on the SCaaS testnet the UA ML-DSA kinds verify through `MLDSA44` at `0x5caa500000000000000000000000000000000012` and `MLDSA65` at `0x5caa500000000000000000000000000000000013` (EIP-8355 layout, empty context, gas 49,000 / 68,000 + 6 per message word); on the copy `UAMldsaVerifier(0x0130 / 0x0131, …)` picked the precompile (`PRECOMPILE()` = the address) and verified the `pq_signatures.json` rows. The gen-1 registry on the SCaaS testnet is redeployed with them in P6g.

**Why.** PQ signing kinds and ed25519 are enabled on every EVM chain (owner), verified by precompile where probed or pure Solidity, each within a measured per-chain cap; an over-budget kind is disabled, never registrable-but-unusable.
**Cost if wrong.** PQ checks cost real money on public L1s (≈ $36–240 per ML-DSA-65 check at 10 gwei).
**Source.** `history/specs/2026-10-06-universal-account-design.md:281`, `history/specs/2026-10-06-universal-account-design.md:1404`

### CTR-UA-24 — EIP-7702 EOAs are native; classify by code
- old: R331 · status: current · owner: no · date: 2026-10-07 · normative: contracts/accounts.md#CTR-UA-24 · superseded-by: —

**Why.** An EIP-7702 delegated EOA keeps its base key as root, so ECDSA is accepted and ERC-1271 through the delegate is a fallback; classification is by code at verify time.
**Cost if wrong.** If a future EIP lets 7702 accounts disable the base key, a new registry generation must follow it.
**Source.** `history/specs/2026-10-06-universal-account-design.md:355`

### CTR-UA-25 — No on-chain registration gate in v1
- old: UA:Q8 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/accounts.md#CTR-UA-25 · superseded-by: —

**Why.** No on-chain registration gate in v1: node sponsorship limits bound spam; self-paid spam pays its own gas.
**Cost if wrong.** An immutable `IRegistrationPolicy` per generation is the fallback if spam becomes a problem.
**Source.** `history/specs/2026-10-06-universal-account-design.md:1402`

### CTR-UA-26 — The UA path splits into UAMetaTransaction and UAMetaTransfer
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/accounts.md#CTR-UA-26 · superseded-by: —

Change (2026-10-13): owner — the UA allowlist grows with parity: `unwrapToUA` and `burn` (UA-5a), `zetherShield` and the confidential ops under the UA envelope binding (UA-5c); `approve`, `mtxTrade` and `uaTrade` stay refused in every `ua*` function — a UA trades by a signed `UATradeOrder`, not by a UA-ledger allowance. SPECIFIED. Source add: owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §4.1, UP-8, UP-10.

**Why.** The UA ledger carried the same token-shaped `to`/`value`/`data` struct as the address path; splitting it the same way (owner G8) gives one model everywhere: a generic call for the UA allowlist and a typed transfer/payment, sharing the one nonce map.
**Cost if wrong.** Two meta-tx models — split on the address path, mixed on the UA path — for clients, node and vectors.
**Source.** `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G8, §3 GC-9.
Change (2026-10-19): controller — **a cancel is not bound to the nonce it cancels: recorded, no change** (the second code review, on-chain part (plan Task 5g, branch `rev2-chain-sol`; triage W-A…W-S in `pqz-core/research/code-review-2026-10-19/U-agy-chain.md`, row W-P; report `V3-claude-common-metatx-dex.md` V3-02). `uaCancelDigest` covers `(chainid, chainUid, token, ua, batch, validUntil)` and `uaCancelNonce` bumps the lane from whatever it is (the native `cancelNonce` meta-tx likewise), so a relayer that withholds a cancel can submit it later and void the next envelope on that lane (`MetaTxBadNonce`). Griefing only — nothing moves, the signer re-signs — and conformant to accounts.md ("each signature cancels once"). Binding the nonce (`uaCancelDigest(…, nonce)` with `_nonce == nonce`, `cancelNonce(batch, expected)`) changes the `metatx-cancel` digest, six clients and the KAT vectors; not done. Wallets: a cancel's `validUntil` no later than the envelope it targets, shown as "bump this lane once", not "cancel envelope n". Status: **recorded** (owner may order the binding).

### CTR-UA-27 — Parity: every native-id operation is open to a registered SIGNING UA
- old: — · status: current · owner: yes · date: 2026-10-13 · normative: contracts/accounts.md#CTR-UA-27 · superseded-by: —

**Rule.** Owner decisions of 2026-10-13 on the UA parity design: a derived UA of any SIGNING kind, PQ included, can do every operation a native id can — as a subject through a signed UA form (`ua*`, the UA allowlist, `UATradeOrder`, the generic UA pipeline of `MetaTxBase`) and as a receiver through a `bytes32` form credited in the UA ledger. Q1: the role and admin functions (token owner and role holders, DEX `admin`, factory creator and `TokenConfig.owner`/`roles`/`initialHolder`, `SmartKeyAccount` keys and guardian, `addReserve`, a one-call UA-source `zetherWrapShield`) stay as they are, with no UA counterpart — their holders still act gaslessly through their own contract account (`SmartKeyAccount` / `MandateWallet` `execute`, fee `NONE`, NODE-JOB-01, NODE-JOB-19). Q2: no UA ever grants or holds an allowance. Q10: regulated tokens key compliance by `bytes32` when built. Phases UA-5a / 5b / 5c.
**Why.** A UA never sends a transaction, so without a UA form for every subject and a `bytes32` form for every receiver a PQ-key UA could not trade, wrap in one step, receive from a mandate or use a Zether token without keeping a classical key — the reason UAs exist. Separate structs and events keep every address-typed ABI, vector and indexer unchanged; the allowlist/dedicated-function split reuses the self-call where the body needs only `_msgSender()`. Role functions stay off every allowlist because a signature check would skip a minter contract's caps or a Safe's guards (CTR-MTX-19); the owner keeps them as they are since their holders are gasless already through their own contract account. An allowance for UAs was rejected: an EOA has none on a SCaaS token (CTR-TOK-01), and every pull already has a signed, named intent.
**Cost if wrong.** Each operation has two forms to build, test and vector (code size grows; owner: no size work before Glamsterdam); a UA cannot hold a role directly, so a UA-only holder who needs a role deploys a contract account.
**Source.** owner, 2026-10-13; `history/specs/2026-10-13-ua-parity-design.md` §1–§6 (UP-1…UP-6, UP-8, UP-10; Q1, Q2, Q10).

### CTR-UA-28 — A native caller credits a derived UA in one call
- old: — · status: current · owner: yes · date: 2026-10-13 · normative: contracts/accounts.md#CTR-UA-28 · superseded-by: —

Change (2026-10-13): built as ruled (UA-5a): `_uaMint`, `wrapToUA`, `unwrapToUA`, `mintToUA`, `payWithFeeToUA`, `burn` and `unwrapToUA` on the UA allowlist (CTR-UA-26) and `uaPayReceiverFee` (CTR-MTX-05) are BUILT; the spike's controller rulings C5a-1…C5a-14 settle build details (task split, one wrap body, check order, fixtures, gas method, vector parameters) and change no rule. Source add: plan `superpowers/plans/2026-10-13-ua5a-receivers-wrap.md`.

**Why.** Every `address` receiver of a direct path gets a `bytes32` form (`wrapToUA`, `unwrapToUA`, `mintToUA`, `payWithFeeToUA`, beside `transferToUA`), each crediting through `_uaMove` (a mint is a move from 0), so a wrap reaches a UA in one call instead of `wrap` + `transferToUA` and a mandate can pay a UA payee. `wrapToUA` is on the address allowlist only (a UA holds no outside underlying); `unwrapToUA` pays a SCaaS ledger leg by `transferToUA` and is on both allowlists. The `UnwrappedToUA` event and the ERC-165 test for a ledger leg were controller rulings, accepted by the owner on 2026-10-13.
**Cost if wrong.** Four more entry points per kind; a leg that falsely reports `IUALedger` can only cheat the unwrapper who chose it (the exact balance delta still holds the wrapper's reserve).
**Source.** owner, 2026-10-13 (Q9); `history/specs/2026-10-13-ua-parity-design.md` §4.2, §4.3, §4.5 (UP-9).

## 25. Contracts — Post-quantum Zether

### CTR-UA-29 — The registry keeps an on-chain list of the UAs of each kind
- old: — · status: current · owner: yes · date: 2026-10-17 · normative: contracts/accounts.md#CTR-UA-29 · superseded-by: —

**Why.** Wallets choose decoys for PQZ and classical Zether multi-recipient transfers among the UAs of the token's kind; event logs may be pruned on a long-running chain, the registry state is not, and a UA serves many tokens, so the list lives in the registry (`uaCount`, `uaAt`, `uaPage`, `uaIndex`; every kind including `msig` (owner 2026-10-17); native ids are not listed). Controller design accepted by the owner: the index in the record's free 40 bits, ≈ +27 k gas per registration, gen 2 forwards gen-1 kinds.
**Cost if wrong.** ≈ 27 k gas on every registration and 25,602 B of registry code (over EIP-170; test chains allow 64 KiB) for a list wallets could otherwise rebuild from logs while the logs exist.
**Source.** owner, 2026-10-17 (TODO.md "UA Registry: on-chain index of UAs per kind"); branch `ua-index`.

Change (2026-10-19): controller proposal (owner may override) — on-chain review W-C (`pqz-core/research/code-review-2026-10-19/U-agy-chain.md`, V2-1): **a decoy selection rule for wallets** — decoys only from UAs active in the token within the look-back window, weighted by recency, never registered after the wallet's last sync point, at most a fixed share per `authRef` group; threat S30 in accounts.md. Spec only, no bytecode. Status: written (`66654e3`); wallet code in P6h.

Change (2026-10-19): owner rulings on the on-chain review (both proposals accepted): **W-J** the `secp256k1` kind (0x0108) verifies ECDSA over the raw digest, so an EOA-held key signs it only through `eth_sign` (against S23) — recorded as a residual risk in the S23 row; an EIP-191 `personal_sign` variant (new verifier, vectors, six clients) after P6. **W-K** `MandateWallet.isValidSignature` / `HederaMandateWallet` accept the owner's ECDSA over any digest (ERC-7739 class) — documented beside `SmartKeyAccount`'s limitation in accounts.md; no wrapping. Status: recorded in the spec.

Change (2026-10-20): controller proposal (owner may override) — UA-6 U11, **the PQZ-capable list**: each UA stays in its kind's list (`msig` included); a PQZ holder is also appended to the list of key `0x0142`, read with the same `uaCount(0x0142)`, `uaAt(0x0142, i)`, `uaPage(0x0142, …)`, so PQZ decoy legs come from one anonymity set of recipients that all have a PQZ key (a per-kind filter would leak which kind the real recipient is); no reverse index, `Record.index` stays the kind-list position; ≈ +27 k gas per holder registration; it lives in the generation that enables 0x0142. Classical Zether decoys keep the `0x0141` list. **The decoy rule of the 2026-10-19 Change loses its `authRef` clause** (no on-chain grouping is left to cap with one key per UA): it keeps "active in the token within the look-back window, weighted by recency, never registered after the wallet's sync point"; threat S30 now records that a sybil decoy set costs one PQ registration per decoy (≈ 5 M gas, free on the SCaaS testnet, bounded by node sponsorship quotas, CTR-UA-25). Status: proposal; built in UA-6 (branch `ua6`, commit 9c2cbc5c).

### CTR-UA-30 — A UA is one signature-verifying entity; a PQZ key is an attribute of a PQ-signing UA
- old: — · status: current · owner: yes · date: 2026-10-20 · normative: decisions.md · superseded-by: —

**Rule.** Owner rulings 2026-10-20 on the research note `docs/research/ua-identity.md`: (1) **a UA is one entity that
can verify signatures** (a native account, a single key of any kind, BLS, a multisig m-of-n, …); ids keep the current
derivation (CTR-UA-02 / -03: native ids as-is or zero-padded, derived ids `keccak256(keccak256(tag) ‖ key_data)`).
(2) **Classical Zether: option (A) — the Zether key is itself the UA** (as the zether-dev `ZetherAccount.register(y, c,
s)` with `yHash`, in SCaaS form `keccak256(keccak256(tag) ‖ Y)` with the kind tag): the key signs by Schnorr with `x`,
the Zether proof authorizes a spend ("self" mode kept); its public balance and its confidential account share that id.
(3) **PQZ: the PQZL public key is an attribute of a PQ-signing UA only** (`mldsa65` / `mldsa44`, later `fndsa512`, or a
`msig` whose non-PQ members' weight is below the threshold — the CTR-PQZ-12 rule; classical signers may not carry a PQZ
key), **supplied in `register`** (no separate attach function), with the `R_REG` proof of knowledge bound to chain,
registry and the UA id; immutable. (4) **An encryption key belongs to one UA only**, multisig included (the existing
`keyOwner[keccak256(GROUP ‖ key)]` map, `UAKeyInUse`). Consequences: the `pqz-mlwe` UA kind (0x0142) and its `authRef`
go (the id 0x0142 stays as the PQZ scheme id); the PQZ account, its fees (CTR-PQZ-06 change) and its public balance live
under the signing UA's id; for a multisig the PQZL secret is a single view / prove key, spends need the m-of-n
signature. The research note's option to drop Zether "self" mode is withdrawn by (2).
**Why.** One identity per holder for public and confidential balances; the PQZ key cannot sign compactly (an `R_REG`
proof is ≈ 40 KB), so it rides on a PQ signer; Zether keys can sign, so the single-key account stays simple.
**Cost if wrong.** Registry, verifiers, the `R_REG` message, the PQZ token state keys and every UA client change
(test chains only; the `R_REG` change rides the 16k `proofSystemId` bump).
**Source.** owner, 2026-10-20 (chat rulings on `docs/research/ua-identity.md` §8: PQ signers only, keys in `register`, Zether option (A)). Status: decided, not built (UA-6, before plan Task 5h).

Change (2026-10-20, owner): **definition — a UA is the actor (person, organization, device or group) that signs and is accountable for a write to a smart contract, tokens included**. Reads need no UA. Consequence (controller reading, consistent with rulings (2)–(4)): anything that cannot sign a write is not a UA but an attribute of one — the PQZ key (attribute of a PQ signer); a classical Zether key is a UA because it signs (Schnorr by `x`) and its proof authorizes the spend. Recorded in README §6. Status: decided.

Change (2026-10-20, owner): **the Zether `authRef` is removed entirely** (no optional spending co-signer): a Zether key UA authorizes its spends by its proof alone and signs its other writes (`zetherRollOverSigned`, `zetherSetRollOverMode`, `pop`) by Schnorr with `x`; a leaked `x` is a full loss (funds and privacy), accepted (analysis `research/shield-and-key-reuse.md` §1). Removed in UA-6 with the PQZ `authRef`: the record field, `authPop`, purpose `authref`, `UAAuthRef`, `survivesEncKeyLeak` for Zether. Status: decided, built in UA-6.

Change (2026-10-20, owner; UA-6 design question Q1): **a Zether key UA may sign every write**, like any signing UA (follows the UA definition above: the actor that signs and answers for a write) — its Schnorr signature by `x` authorizes UA-ledger transfers, trades and every other `requireAuthorized` path, and its public balance is spendable that way; `zether-bls12381` joins the SIGNING set (not an `msig` member, cannot hold a PQZ key). UA-6 spec decision U8 (`docs/superpowers/specs/2026-10-20-ua6-encryption-key-attributes.md`, branch `ua6-spec`). Status: decided; built in UA-6 (branch `ua6`, commits c4ece459, 97fe4778).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U1, **record and storage**: the `Record` keeps its one slot (kind, registeredAt, keyPtr, index); the PQZ key is a second SSTORE2 pointer in a new mapping `_pqzKey[ua]`, written once inside `register`, never in the id; the PQZ key claims `keccak256(GROUP("pqz-mlwe") ‖ pqzKey)` in the existing `_keyOwner` map for every holder, `msig` included (`UAKeyInUse`, ruling (4)); the registry hard-codes no key length (`UAPqzVerifier.verifyPop` refuses any key that is not exactly `PqzCt.PK` bytes with every coefficient `< q`). Removed: the `_authRef` mapping, the `authPop` argument, the `recordOf` second return value as `authRef`. Source: UA-6 spec `superpowers/specs/2026-10-20-ua6-encryption-key-attributes.md` §2. Status: proposal; built in UA-6 (branch `ua6`, commit 9c2cbc5c).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U2, **`register` shape**: one function `register(kind, keyData, pop, pqzKey, pqzPop)`, the pair empty for every UA but a PQ holder (`pqzPop` empty iff `pqzKey` empty); same selector for every kind, the argument slots of the removed `(authRef, authPop)` pair reused; a separate `registerWithPqzKey` rejected (two entry points for one record). Steps (cheap first): kind enabled, key data, id, single-key keyHash or `msig` members and gas bound, PQZ attribute (`UAKindDisabled(0x0142)`, `UAPqzHolder`, `UAKeyInUse`), the signer's PoP, `R_REG`, store. Spec §3. Status: proposal; built in UA-6 (branch `ua6`, commit 9c2cbc5c).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U4, **one digest for both proofs**: `popDigest(ua, pqzKeyHash) = keccak256(abi.encode(POP_TAG, chainKeyHash, chainUid, registry, ua, pqzKeyHash))`, the built function with its last word renamed from `authRef`; `pqzKeyHash = keccak256(GROUP("pqz-mlwe") ‖ pqzKey)`, or `0` without a PQZ key (so every UA without one keeps today's PoP bytes and every classical vector stays valid). The signer's PoP and the `R_REG` proof use it under the kind tags `TAG(kind)` and `TAG(0x0142)`: a front-runner can neither strip nor swap the key, and a proof made for another UA fails. Spec §3. Status: proposal; built in UA-6 (branch `ua6`, commit 9c2cbc5c).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U5, **a PQ-eligible `msig` signs its registration**: an `msig` whose non-PQ weight is below its threshold always registers with its m-of-n `abi.encode(MemberSig[])` over `uaMessage(MSIG, POP, popDigest(ua, pqzKeyHash))` (purpose `pop`), with or without a PQZ key, because an unsigned registration would let anyone fix the structure first without the key, forever. A classical-dominant `msig` can never hold a PQZ key, so its `pop` stays empty (no change). Spec §3. Status: proposal; built in UA-6 (branch `ua6`, commit 9c2cbc5c).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U6, **interface after UA-6**: `UARegistered(ua, kind, keyData, address pqzKey)` carries the 20-byte pointer, not 16 KB of log data (≈ 0.13 M gas saved); `recordOf(ua)` returns `(Record, address pqzKey)` (0 = none; a gen-2 registry forwards it), wallets read the key with `eth_getCode` minus the leading `STOP` byte; new error `UAPqzHolder(ua)`; removed `UAAuthRef`, `requireZetherAuthorized`; `kindEnabled(0x0142)` and `verifyCap(0x0142)` answer for the `R_REG` verifier; no `pqzKeyOf` view. Spec §3.2. Status: proposal; built in UA-6 (branch `ua6`, commit 9c2cbc5c).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U12, **UA ledger and public balances**: the PQZ public balance, the fees of CTR-PQZ-06 (2026-10-20), the source of `pqzShield` and the target of an unshield to oneself live under the signing UA's id in the token's UA ledger, spent by that UA's ML-DSA / `msig` signature; a Zether account's public balance sits under its Zether UA id, spendable by Schnorr with `x`. `_checkTo` needs no change beyond `UAKinds.isSigning`; the sentence "a Zether kind never receives" is deleted. Spec §8. Status: proposal; built in UA-6 (branch `ua6`, commits 9c2cbc5c, 8889a21b, a01ed25e).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U13, **`R_REG`, `proofSystemId` and the 5h dependency**: `R_REG` absorbs a 32-byte message; the relation, the statement layout, `UAPqzVerifier`, the precompile and `statement_register.json` do not change, only the pre-image of the message (the signer's id and the key hash instead of the PQZ id and `authRef`). The change has no `proofSystemId` of its own: it rides the 5h bump (the "16k" id with the B-1 transcript fix, K_MAX = 16,384, q = 2^50 − 42,310,535, owner rulings 2026-10-20) in the roll-out of plan fs3 Task 13; until then the SCaaS testnet keeps today's registry. Spec §9. Status: proposal (the q value and the 5h bump: owner rulings); built in UA-6 / 5h (branch `ua6`, commit 9c2cbc5c; the 5h bump rides plan Task 5h).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U14–U16, **clients, node, vectors**: the ten client libraries (`ua-rs`, `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb`, `ua-dart`, `ua-py`, `ua-go`, `ua-cs`, clientkeys `ua.js`) move rows 0x0140 and 0x0142 out of `KINDS` (0x0142 stays in a `SCHEMES` table so `tag`, `ua_msg`, `key_hash` work while `ua_of` refuses it), `is_zether(k) = k == 0x0141`, `is_signing` adds 0x0141, new `is_pqz_holder` and `msig_pqz_eligible`, `authref` leaves `PURPOSES`, `pop_digest` takes `pqz_key_hash`, new `pqz_reg_message`; the clientkeys register flow builds `(pqzKey, pqzPop)` from the sealed PQZ leaf; `clients/zether-prover` drops `authSig`/`authDigest` and the bn254 build. Node (spec only, nothing built reads the registry): the route body becomes `{chain, kind, keyData, pop, pqzKey?, pqzPop?}`, the node recomputes the key hash and never verifies `R_REG` locally, the route body limit rises from 64 KiB to 160 KiB (a PQZL holder registration is ≈ 49 KB binary, ≈ 100–108 KB as hex), the record cache reads `recordOf → (Record, pqzKey)`. Vectors: `kinds.json` (0x0140 out, 0x0142 to `schemes`, `authref` out, holder and `pqz_reg_message` rows), `structures.json` (PQ-eligible `msig` rows), `signatures.json` / `pq_signatures.json` / `groups.json` (`authRef` fields dropped: every one is zero, so PoP bytes do not move; holder PoP rows over a non-zero hash), `metatx3.json` (a Zether-UA row); PQZ statement vectors unchanged. Spec §10. Status: proposal; built in UA-6 (branch `ua6`, commits bf68718a, c12a38e9 [e2e]; 93c5ead2, 1e961aea, 67ef75bc [prover, clientkeys]; 1d24da92 [vectors]; 35036846, c159cf56, 40a8f2ba, 7e2016ef, 7419d7ef [ua-py, ua-go, ua-cs, ua-dart]; 294a4688, a0a66940, da649535, fc0a9a21, 26d9775c, 8b93de4e [ua-rs, ua-c, ua-cxx, ua-qt, ua-dart-frb]; final fix wave 872a6251).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U17–U19, **size gate, gas, tests**: `scripts/size_gate.py` on `UARegistry` (over EIP-170 since CTR-UA-29; allowed on the 64 KiB test chains) and the Zether / PQZ implementations and libraries, expected to shrink, no size work (owner: wait for Glamsterdam), the baseline ratchets down where it shrinks. Gas measured with forge `--isolate` and logged in `smartcontracts/evm/runs/<date>-ua6-gas.txt` (registrations with and without a PQZ key, a PQ-eligible `msig`, `requireAuthorized` on a Zether UA, the Zether and PQZ spends without the registry auth call). Tests `test_UA6_*`: holder registration with and without a key; strip / swap (`UAPoP`); `R_REG` over another UA's digest; the same PQZ key on two UAs (`UAKeyInUse`); non-holders (`UAPqzHolder`); PQ-eligible `msig` without `pop`; `pqzKey` where `0x0142` is disabled; gen-2 forwarding; `uaCount(0x0142)` order; a Zether UA signing, receiving, refused as a member; Zether spends with no `authSig`; the PQZ transfer from an ML-DSA and an `msig` holder; a leg or auditor without a key. The `authRef` suites go to `legacy/ua6/`. Spec §10. Status: proposal; built in UA-6 (branch `ua6`, commits 740fbe06, 872a6251).

Change (2026-10-20): controller proposal (owner may override) — UA-6 U20, **migration**: none (all chains test-only; mainnet 22776 not launched). The registry ABI, the Zether entry points and every client change at once; the SCaaS testnet gets the new gen-1 registry (with `UAPqzVerifier` in slot 0x0142 on the 16k id), the PQZ and Zether tokens and the e2e accounts by `smartcontracts/evm/script/pqz/e2e.py` in plan fs3 Task 13 (back up, reset, deploy; controller may do this on the SCaaS testnet); other dev chains redeploy on their next reset; no record is carried over. Spec §10. Status: proposal; built in UA-6 (branch `ua6`, commit 740fbe06 for the docs).
Change (2026-10-20): controller ruling (owner may override) — UA-6 in-branch rulings, recorded in full (branch `ua6`, ledger `.superpowers/sdd/2026-10-20-ua6-encryption-key-attributes/progress.md`). (1) **`uaExecute(zetherShield)` is allowed on both Zether kinds**: scope addition, the brief's test requires it; it is the first bullet of CTR-ZTH-51; small ABI surface to revisit in UA-5c (commit c4ece459). (2) **Rollover and mode changes accept a registered Zether UA only** (owner ruling 2026-10-20, replacing the controller ruling that accepted any id passing `requireAuthorized`, commit c4ece459): `zetherRollOverSigned` and `zetherSetRollOverMode` revert `AccountNotRegistered(ua)` for any other kind or an unregistered id, before `requireAuthorized`, even with a valid signature; asserted in `test_ownerOpsZetherUaOnly` (the commit after 47515612 titled "owner ops accept a Zether UA only"). (3) **ua-c ABI version stays 1**: the kind rows 0x0140 / 0x0142 and the purpose `authref` are removed, which is binary-compatible; the behaviour change is accepted on the test chains (commits a0a66940, da649535, final fix wave). (4) **The deciding `slhdsa128s` msig vector case**: a PQ-eligible `msig` with an `slhdsa128s` member is decided by a generated vector row and test, so its PQ weight is no longer undecided (commit 67ef75bc, vectors 1d24da92). (5) **`UAKinds.uaOf` refuses 0x0142** with `UAKindNotDerived` in code (it calls `_requireDerived`; `tag()` and `groupName()` keep `_requireTagged`), matching accounts.md, CTR-PQZ-13, the spec and all ten clients; `UARegistry` +9 B, baseline ratcheted; asserted in `test_UA6_pqzNotAKind` (commit 872a6251). (6) The Zether UA no longer signs the purposes `member` and `zether-auth` in the clients: no contract accepts them from a Zether UA (final fix wave). Status: controller ruling; built in UA-6.
Change (2026-10-20): review dispositions of the UA-6 reviews (CTR-UA-30, plan Task 10). Per-task reviews: Task 1 clean (minors folded into Tasks 4/9); Task 2 clean (verifyPop key-length check confirmed; minors deferred to Task 9); Task 4 clean; Task 5 one Important (bare `expectRevert` in `test_v3FeeUA`), fixed in a01ed25e; Task 3 one Critical (`e2e.py` NameError on a deleted dict), fixed in c12a38e9; Task 6a two Important (the `slhdsa128s` PQ weight undecided, `zether-read-balance` bn254-only) plus minors, fixed in 67ef75bc; Task 8, Task 6b (native and Rust) and Task 9 clean. Final whole-branch review (988e15f8..7524be45): 0 Critical, 4 Important (the e2e `uaIndex` check on the 0x0142 list; stale `authSig` selectors in zether.md CTR-ZTH-34 and the metatx.md allowlist; `uaOf(0x0142)` accepted; these decisions lines without commits and rulings) and minors 1–8; fixed in the final fix wave (872a6251 and following) except: gas optimisation of registration (owner: no size or gas optimisation now), the `isDerived` simplification and the `_CFG13` rename, which are skipped. Residuals kept open: `ua-qt` and `tst_ua.qml` uncompiled (no Qt6 on the host), no evm test exercises a real `R_REG` proof (the verifier is a stand-in in `UARegistryPq`: cover with the 16k regeneration or the fs3 Task 13 e2e), `script/pqz/e2e.py` first real run on a PQZ chain in fs3 Task 13. Status: done.

### CTR-PQZ-01 — Separate PQZ class gated to private chains
- old: R270 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-01 · superseded-by: —

Change (2026-10-15): owner — the name: **PQZ = Post-Quantum Zero-knowledge** (the proof engine: PQZL lattice + PQZH hash, one precompile); the confidential token in the Zether model is its first application and "PQ Zether" is the historical name. Code identifiers, opTags, `proofSystemId` strings and directory names keep `pqz` (they are hashed into proofs and vectors). The spec file `contracts/pq-zero-knowledge.md` is renamed `contracts/pq-zero-knowledge.md` together with the pqz-core layout move (after the WIP branches merge; links rewritten by script, `docs/history/` left as recorded).

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D2: `PqzSafety` is a library with the hard-coded allowlist {31337, 1337, 7622} (a new chain is a code change and a new deploy, as `ZetherSafety`) and `selfTest(pqz)`: a STATICCALL to `0x5caa500000000000000000000000000000000f01` with the input exactly `06 00000000` must succeed and return exactly 32 bytes equal to the frozen `0xed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205` (P6e D13); it runs in `UAPqzVerifier`'s constructor, in `OpenFactory.setPqzEnabled(true)` and in `UAPqzVerifier.isSupportedOnThisChain()`, which every `*_PQZ` token creation calls.

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D5: the SCaaS testnet has `maxCodeSize` 0x10000 from block 0; no size-reduction work for the PQZ contracts (owner: optimise after Glamsterdam); every new contract over its limit gets its measured runtime / init size as a ratchet entry in `smartcontracts/evm/size-baseline.json`, and `NoUnderlyingPqzToken` / `UnderlyingPqzToken` join the token set of `scripts/size_gate.py`.

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D6: the forge tests mock the `PQZ` precompile with `vm.mockCall` (op 6 answers the frozen self-test hash, ops 1–5 the word 1, or 0 / a short answer where a test needs it) and keep everything else real: `PqzCt` on the P6e vectors (`enc.json` Enc + Trivial(1000) and back by `ct_keccak`), the token-built statement body compared byte for byte with `statement_transfer.json`, the real `UARegistry` with `UAPqzVerifier` and `UAMldsaVerifier` (its ML-DSA precompile candidate mocked as well).

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D7: the e2e uses real proofs: a `pqz-ffi` example `pqz_prove` (feature `prove`; reads `op`, `stmt`, `wit`, `rnd32` as hex lines on stdin, writes the proof) is the only addition to `pqz-core/ffi` (P6-ANON S3 is in flight there); statements come from the token's own views, keys / Enc / witnesses from `pqz_kat.py`, ML-DSA signatures from `@noble/post-quantum` 0.7.1, transactions are signed by P6f's `eth.py` (legacy EIP-155, gas price above the base fee: clients pay baseFee + tip).

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D15: the SCaaS testnet deploy does not use `forge script`: forge's EVM has neither `PQZ` nor `MLDSA*`, so the simulation of `UAPqzVerifier`'s constructor and of every token op fails; the e2e driver deploys the forge artifacts with raw transactions and links the libraries itself. Registry generation 1 on the SCaaS testnet enables `mldsa44` and `mldsa65` (`UAMldsaVerifier` with the precompile candidates `…0012` / `…0013`, probe from `pq_signatures.json`), `pqz-mlwe` (`UAPqzVerifier`, PQZL v2) and `msig`, budget 12 M; the classical kinds are not enabled in this generation (the SCaaS testnet is the resettable testnet; a full-stack deploy is `Deploy.s.sol`'s, which needs the CREATE2 deployer the chain no longer has since the reset).

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D16: the e2e tokens prove with PQZL (smaller calldata, the registry's PoP system); a second `UAPqzVerifier` with the PQZH id serves one PQZH token where time allows, to measure the PQZH debit paths.
Change (2026-10-19): controller proposal (owner may override) — **on-chain review W-B (plan Task 5g, branch `rev2-chain-pqz`, commit `af47304e`; finding V1-02, P2): the token pins the `PQZ` precompile.** Before: `PqzLib.init` took `PRECOMPILE` / `PROOF_SYSTEM_ID` from the creator's verifier without any check, so a factory-listed wrapper could be bound to an "always valid" contract and drained. Now `PqzSafety.requirePqz(pqz, psid)` (precompile `== PqzSafety.PQZ`, `psid` PQZL v3 `0x8079d65b…` or PQZH `0x0a47a768…`, then `OP_SELFTEST == SELFTEST`; error `NotPqz(pqz, psid)` / `SelfTestFailed`) runs in `PqzLib.init` and in `UAPqzVerifier`'s constructor; the constructor also pins its `R_REG` probe: `keccak256(psid ‖ message ‖ pk ‖ proof)` must be `PROBE_PQZL` `0x6c4573ab…5b04` or `PROBE_PQZH` `0x36c3b5f3…5160` (the self-test's REGISTER vector, `statement_register.json` row 0 with `proof_pqzl.json` / `proof_pqzh.json` row 4), else `UAPqzProbe`. Deviation from the spec text kept on purpose: `PqzToken.initialize` takes no probe vector (bound to `PQZ`, whose self-test already folds in the REGISTER verdicts of both ids, the 45–200 KB argument adds nothing); the spec now says so. The factory's listing is unchanged (`_checkPqz` still asks the verifier; a foreign verifier object is harmless once the token pins the precompile); creator-chosen basket legs stay as disclosed (token-wrappers.md §2.2). The new ids are a code constant: a future PQZL id change edits `PqzSafety`. Bytecode: `PqzLib`, `UAPqzVerifier`. Tests `test_initPinsThePrecompile`, `test_constructorPins`. Status: **done** (`af47304e`, merged `734b9c76`).

**Why.** PQZ is a separate token class gated by a hard-coded allowlist, a constructor precompile self-test and the registry `chain_uid`, with two release gates before any production or commercial use (owner): the licence/patent gate **G-LIC** and the independent audit.
**Cost if wrong.** Without the self-test a chain with the same id but another client would accept PQZ deployments.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:208`
Change (2026-10-08): owner — PQZ is meant for public chains too; the route is a lattice-verification precompile on that chain, which SCaaS waits for (rejected: a Solidity verifier split over transactions, a STARK-wrapped proof, a SCaaS appchain). Until then the allowlist and self-test stay. Source add: owner chat 2026-10-08.
Change (2026-10-27): **review C2-8 (controller proposal, owner may override)**: the D2 text above names `OpenFactory.setPqzEnabled(true)` and calls `UAPqzVerifier.isSupportedOnThisChain()` "`OpenFactory`'s PQZ gate". Since 5g-Z2 there is no `setPqzEnabled` (the kind switch is `setKindEnabled`, with no chain gate); the on-chain gate is `PqzStateLib.init` (`PqzSafety.requireAllowedChain`, `requirePqz`, the self-test). `isSupportedOnThisChain()` stays as a view for off-chain callers. The §7.8 event list no longer names a `PqzRegistered` event: the PQZ key is in the registry's `UARegistered(…, pqzKey)`. Status: **done** for the documents (review2 T8, branch `review2-fix`); the `UAPqzVerifier` NatSpec follows in review2 T8b (comments only, no pin moved).

### CTR-PQZ-02 — Additive-only MLWE with BFV-style encoding
- old: R271 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-02 · superseded-by: —

**Why.** Additive-only MLWE with BFV-style encoding gives exactly Enc/Add/Dec with a provable decryption relation; full FHE stacks bring relinearization keys and failure probabilities.
**Cost if wrong.** A failure-prone scheme gives an attacker a key-recovery oracle.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:225`

### CTR-PQZ-03 — Lattice parameters at or above Kyber-512
- old: R272 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-03 · superseded-by: —

Change (2026-10-15): owner — β 446 accepted for the shared-randomness hints of the multi-recipient transfer `R_TXM` (op 7): with 4 legs and the auditor copy, 80 hints on one `(r_g, e1_g)` give β 446.0 (DDGR20 worst case, pinned lattice-estimator `53da598` + leaky-LWE-Estimator `0a9caf8`; core-SVP 2^130.2 / 2^118.2), below the self-imposed 450 margin and above the Kyber-512 floor (406). Hence groups of 4 legs per randomness with or without the auditor (P6-ANON D4 as planned; the 3-leg grouping proposed after S1 is withdrawn) and PQZH `R_TXM` M = 4 is built with and without the auditor. All other instances keep β ≥ 450. Source: `pqz-core/pqzl/params/anon/hints-anon.txt`, `research/pqz-anonymity.md`.

Change (2026-10-15): owner — `R_TXM` (op 7) noise bound: **each e2 vector of each leg is bounded by 64 in ℓ2 (‖e2_j‖² ≤ 4,096, per vector), as §4.3 states for the single-recipient forms**, not one block bound 64·√M over the M legs' e2 together. Both tracks implement the same rows: PQZH (`p6-anon-h`) already bounds each e2 by 64; PQZL (`p6-anon-l`) changes its block bound to per-vector bounds. Raised by the P6-ANON L/H pre-review (finding X-1); the per-vector bound is the stricter one, so the noise budget and the 4.1× mint margin stand. Status: owner.

Change (2026-10-16): owner — P6-ANON L-3, op 7 memory: the node verify arena (`ARENA_SMALL`, today 144 MiB for the six forms) becomes **512 MiB** when op 7 lands in pqz-ffi (S3); measured verify peak with all 14 relations loaded 193.8–253.4 MiB, so 512 MiB is ≥ 2× the peak. Controller proposals with it (owner may override): the native client prove arena (`ARENA_BIG`, 448 MiB) becomes 1 GiB (R_TXM8 prove peaks 590–656 MiB); in the browser (wasm, 256 MiB reference) PQZL `R_TXM` is offered for M ≤ 4 only, M = 8 on native / desktop clients (M ≤ 8 stays the PQZL limit, D20); the multi-group Enc wrapper and its vectors land in S3 / S4.

Change (2026-10-13): owner — the noise budget (§4.3) states that it needs each norm bound proven per block, and records that PQZL v1 did not enforce them (all exact-ℓ2 equations shared one Schwartz–Zippel domain, lazer#25): attacker-controlled accounts could reach ≈ 44,001 noise per credit, ≈ 45.0 M over `K_MAX`, mint margin ≈ 1.12× instead of 4.1×; v2 restores the per-block bounds, so the budget, the 4.1× margin (threat T5) and `K_MAX = 1024` stand unchanged. Source add: `research/pqz-l2-domain.md`.

Change (2026-10-13): owner — the parameters section records (dated note) that the v2 verifiers, generic and specialised, did not bound `z21` (lazer#26), so the proof's MSIS instances as enforced were β 286–311 (core-SVP classical 2^83.5–2^90.8) instead of β ≥ 450; both verifiers now check `‖z21‖² + ‖w − γ·w1‖² ≤ B²` (LNP22 Fig. 18), honest proofs and the transcript unchanged, parameters and β stand; threat T2 names the check; `proofSystemId` stays v2 pending the owner's decision (recommendation: no bump). Source add: `research/pqz-z21-norm.md`.

Change (2026-10-26): controller record (R0 review fix part b, finding F-6) — **the exception's figures restated** after the owner's rulings of 2026-10-25 (CTR-PQZ-04 Change of 2026-10-25): at `n2048-kmax1024` the audited `R_TXM` uses groups of `s_aud = 2` (2 legs + 2 auditor copies at their own windows) and the unaudited one groups of 4, both 64 hints per `(r_g, e1_g)`: DDGR20 451.92 (≥ 450), dual_hybrid − offset 443.92 classical / 444.92 quantum [estimate: dual_hybrid on LWE(n − h) minus the primal offset uSVP(n − h) − DDGR20(h); the lattice-estimator has no hints, so no hinted dual estimate exists] — the exception is the dual figure ≈ 444, not "β 446.0 at 80 hints, dual_hybrid not measured" (the pre-fix primal figure; the hint study measured dual 437.97 / 438.97 at those 80 hints). `n2048-kmax1024` is documented as **not recommended** (owner 2026-10-25: the frozen set, lower margins than the other sets). Corrected in the spec (CTR-PQZ-03 / -04, the security table, threat T21), `pqz-core/params/sets/n2048-kmax1024/SET.md` and `params/sets/README.md`. Status: owner rulings (2026-10-25); text by the controller.

**Why.** Parameters at or above Kyber-512 under classical and quantum core-SVP (β ≈ 476) with worst-case noise bounds, so an accepted state never fails to decrypt.
**Cost if wrong.** Any change needs a new `proofSystemId` and a recomputed noise budget.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:230`

### CTR-PQZ-04 — Shared encryption randomness with split fallback
- old: R273 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-04 · superseded-by: —

Change (2026-10-14 → 2026-10-15): P6-ANON plan D4, randomness groups of `R_TXM`, after Task S1 (branch `p6-anon-s`): DDGR20's leaky-LWE-Estimator (`0a9caf8`) beside lattice-estimator `53da598` in the pinned Sage image (`pqz-core/pqzl/params/anon/hints.sage`, `run_hints.sh` → `hints-anon.txt`) gives, for worst-case orthogonal maximal-norm mixed hints, β 463.9 / 457.9 / 451.9 / 446.0 at 32 / 48 / 64 / 80 hints (16 per recipient key, 16 for the auditor copies); single-recipient `R_TX` keeps 463.9. The controller's interim proposal (3 legs per group with the auditor, 4 without, to stay ≥ 450) is **withdrawn**: the owner accepted β 446 on 2026-10-15 (CTR-PQZ-03 Change line), so **status: owner — 4 legs per `(r_g, e1_g, u_g)` with or without the auditor, `G = ⌈M/4⌉`, leg j in group `⌊j/4⌋`, the sender's `v_f` in group 0** (D4 as planned).

Change (2026-10-25): **review finding R0-1 (P1, Codex, confirmed by the controller)** — in `R_TXM` with the auditor, all auditor copies of a randomness group use the same `pk_a`, `r_g` and 16 coefficients, so `v_{a,j} − v_{a,k}` cancels the mask and reveals every digit difference of the group's legs (decoy legs identifiable, one known amount gives the others), at all four parameter sets, in PQZL and PQZH. **Owner ruling: fix direction 2** — leg `j` of a group of `s` legs uses coefficients `[16·(j mod s), 16·(j mod s) + 16)` of one `pk_aᵀ r_g` (sizes unchanged; worst-case hints per group `32s` instead of `16s + 16`), with `s` per parameter set the largest that keeps DDGR20 and dual_hybrid ≥ 450; direction 1 (own randomness per leg, ≈ +20 M state gas per extra `u` at n2304-kmax4096) rejected. Status: hint study done 2026-10-25 (all 80-hint values reproduce; DDGR20 and dual_hybrid at 32·s hints per set, `pqz-core/pqzl/params/anon/hints-s.txt`): largest s with both ≥ 450 — n2304-kmax4096 3, n2560-kmax16384 4, n2816-kmax65536 4, n2048-kmax1024 none ≥ 2 (and today's n2048 R_TXM is already below 450 on dual_hybrid at 64 / 80 hints, newly measured); **owner 2026-10-25: s changes only with the auditor on (without it groups stay 4); n2048-kmax1024: the exception widened to dual_hybrid ≈ 444 (443.92 / 444.92 at 64 hints, DDGR20 451.92), so s_aud = 2 there** — s_aud = 2 / 3 / 4 / 4 (n2048 / n2304 / n2560 / n2816), 4 without the auditor; next the relation fix with one proofSystemId bump per set (after the Fable review of R0 and the fix design). Source: `pqz-core/research/code-review-2026-10-25/R0-1-auditor-shared-randomness.md`, `codex-R0.md`.

Change (2026-10-26): controller record (R0 review fix part b; Fable's required addition 3, `pqz-core/research/code-review-2026-10-25/fable-R0.md`) — **`s_aud = 3` at `n2304-kmax4096` rests on the dual_hybrid − offset heuristic with a 3-β margin**: 96 hints give DDGR20 463.04 and dual_hybrid − offset 453.04 classical / 456.04 quantum, while `s = 4` (128 hints) would give 443.21 / 445.21; no hinted dual estimate exists (the lattice-estimator has no hints; the study runs `LWE.dual_hybrid` on LWE(n − h) and subtracts the primal offset). The heuristic's direction is conservative and the smaller `s` was chosen; `n2560-kmax16384` / `n2816-kmax65536` keep `s = 4` with dual − offset 458.60 / 475.09. Built in part a (PQZL v5 / PQZH v3 per set); the contracts and the spec follow in part b (CTR-PQZ-26 Change of 2026-10-26). **F-4** (Fable, P3): with the auditor copies on, the auditor's own key as the sender or a recipient meets the copy in window 0 under the same `r` and cancels the mask, before and after the fix — the token refuses it (CTR-PQZ-26 Change of 2026-10-26). Status: s_aud owner (2026-10-25); the margin statement and F-4 as recorded.

**Why.** One shared `(r, e1)` per transfer saves two 16 KB `u` vectors; security against malicious recipients is a stated hint-leakage assumption with a split-randomness fallback.
**Cost if wrong.** If the assumption fails, a colluding receiver and auditor could open the sender's new balance.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:239`

### CTR-PQZ-05 — Every debit re-encrypts the remaining balance
- old: R274 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-05 · superseded-by: —

**Why.** Every debit re-encrypts the remaining balance fresh, resetting noise and digit growth.
**Cost if wrong.** Homomorphic subtraction would accumulate noise until decryption fails.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:250`

### CTR-PQZ-06 — Credit cap and public plainPending amounts
- old: R275 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-06 · superseded-by: —

**Why.** Public amounts go to `plainPending` and only proven credits take slots under `K_MAX = 1024`, so dust cannot lock an account.
**Cost if wrong.** Counting dust as slots let `fund(victim, 1)` × 4096 lock a victim.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:254`

Change (2026-10-19): **owner ruling — `K_MAX = 1024` is too small and must be raised**: in practice one wallet is picked as a decoy many times (op 7 / Z-multi), and every decoy credit counts against its cap, so a popular or targeted account would hit `RefreshRequired` and stop receiving until its owner refreshes. Today the cap comes from the noise budget (`K · 11,872 < 2^24`, digit sums `K · 15 < 2^14`) under q ≈ 2^42; spec option A (n = 2560, q = 2^50, +25 % key / ciphertext size) gave 4096. Status: **decided; design pending** together with the ciphertexts-in-state ruling (CTR-PQZ-07, plan Task 5h): larger parameters (new `proofSystemId`), credit accounting that keeps decoy credits from blocking real ones, or both.

Change (2026-10-19): **owner choice — A' plus B**, possibly in that order. **A'**: larger lattice parameters (q ≈ 2^54, `K_MAX` ≈ 65k; sizes and security margin to be measured with the pinned lattice-estimator; new `proofSystemId`, PQZL and PQZH). **B**: credits are never refused (no `RefreshRequired` on a credit), the pending queue is unbounded, rollovers proceed strictly in order and never lose or skip an entry; a rollover stops before `acc` exceeds the cap, and the owner's refresh (a debit re-encrypting the balance) resets it. Controller analysis: keep strict order — skipping would let an owner drop exactly the zero-valued decoy credits and so reveal, to anyone watching, which ring members of other people's past transfers were decoys; the costs are head-of-line delay (decoys before a real credit must be rolled first), rollover gas borne by keepers or the owner, state held by the unrolled queue (ciphertexts are in state, CTR-PQZ-07) and a periodic owner refresh every ≈ `K_MAX` units; mitigations: the decoy selection rule (CTR-UA-29), a minimum per-credit fee on the SCaaS chains, a higher `ROLL_MAX` if gas allows, keeper rollovers. Status: decided; design in plan Task 5h (B and the state layout first, then A'), before plan Task 6 and Task 13.

Change (2026-10-20): **owner ruling — `K_MAX = 16,384` instead of 65,536** (supersedes A' n = 2816 / q = 2^54 and ruling O2 of the 5h design). With the 5h budget formulas: digit sums 15·K = 245,760 < 2^18 (m = 18), noise K·B ≈ 2.40·10^8 < 2^28 (E = 2^28), so q ≥ 2^(m+4)·E = 2^50: the spec's option-A set n = 2560 (k = 40), q = 2^50 − 71, Δ = 2^30 − 1. Measured earlier for that (n, q) (aprime.txt / spec §6.2): encryption β 508 / 497.3 / 482.4 at 0 / 32 / 80 worst-case hints (≥ 450 everywhere, the β 446 exception no longer needed), 2^145.7 / 2^132.7; mint margin ≈ 3.36×; key / ciphertext 20,608 B (+25 % vs today, −9 % vs n = 2816). Trade-off accepted: an owner refreshes about every 16k units instead of 65k. Still to measure: LaZer codegen proof sizes, rollover gas and `ROLL_MAX` (estimate ≈ 210–220), op 7 M = 8 under 2^24, and whether n = 2304 also clears 450 at 80 hints. Status: decided; regeneration in plan Task 5h after B and the v4 transcript fix.

Change (2026-10-20, owner): **`plainPending` is removed.** Fees (`confidentialFee` to the beneficiary, the per-credit fee to every credited leg) are paid straight into the recipient's **public UA-ledger balance**, spendable at once (no prover, no withdraw path); which id holds it follows the UA identity rework (research `docs/research/ua-identity.md`; owner 2026-10-20: a UA is one signature-verifying entity and an encryption key is an attribute of it, never shared between UAs). **`pqzShield` becomes a proven debit** (as `REFRESH`) whose `plainUsed` is funded by burning the signer's public balance in the same transaction, so a shield lands in `acc` in one call; any transfer may top up the same way. Shielding into another account is gone (send publicly or confidentially instead), so only proven credits touch another account. The relation is unchanged (`Trivial(plainUsed)` already in `T`); the payload field `plainUsed` is renamed `shieldIn` (the public amount moved from the signer into `SHIELD_POOL` in the same call). Removed in 5h: the `plainPending` state field, its views, events and spec rows (`IPqzToken`, `PqzLib`, `PqzLayer`, `UnderlyingPqzToken`, pq-zero-knowledge.md). Status: decided; built in plan Task 5h.

Change (2026-10-20, owner, later the same day): **all four transfer flows are allowed on both confidential layers (classical Zether and PQZ)**: public → public, public → anyone's confidential balance (shield into another account, back again), confidential → anyone's public balance (unshield with a recipient), confidential → confidential (`R_TX`, `R_TXM`). **Shielding needs no proof on either layer**: Zether as today (`pending += [amount]G`); PQZ folds public amounts into one per-account accumulator (or one trivial queue entry) that the permissionless rollover adds to `acc` as `Trivial(sum)` — zero noise, one `K_MAX` unit — and a debit may still take it inline as `shieldIn`. This supersedes, in the 2026-10-20 change above, "`pqzShield` becomes a proven debit" and "shielding into another account is gone"; `plainPending` stays removed as a debit-only field. Design (ordered position of the fold so an in-flight debit neither loses it nor is griefed, D4) in plan Task 5h. Analysis `research/shield-and-key-reuse.md` §2–§3. Status: decided; built in 5h.

Change (2026-10-20, owner, 5h plan review): **two fees.** `txFee` (today `confidentialFee`): per transaction, any op, to the beneficiary. `decoyFee` (today `multiLegFee`): op 7 only — op 1 has no decoys and never pays it — the same amount to every leg, real recipient included, so it reveals no decoy; the token sets an immutable `minDecoyFee` at `initialize` (may be 0) and the sender chooses the per-leg amount `d ≥ minDecoyFee` (public, in the payload, bound by the statement: `fee = txFee + M·d`); no chain-level floor (supersedes the 5h design's D10 per-credit fee on op 1 and the O4 floor). Applies to both layers (Zether may set a non-zero `minDecoyFee`, default 0). A shield into another account is free (gas only; tx fee only when relayed). Status: decided; built in 5h.

Change (2026-10-20, controller record, owner may override where marked "proposal"): **plan 5h part A as built** (branch `pqz-state-b`; today's parameters, no relation or `proofSystemId` change, statement bytes identical, `test_transferStatementMatchesVector` green; reports `.superpowers/sdd/2026-10-20-pqz-state-redesign/task-{1,2,3z,3}-report.md`; docs sync `pqz-state-docs`). Commits: Task 1 `b978cf89`, Task 2 `85680d55` + `133b7303` + `f4d367c4`, Zether pool Task 3z `7733910e` + `171d4884` (merge `f8715b65`), Task 3 `ff4e6948` + `3cbc5f5e`. Decision by decision:
(D7, owner B) a credit of op 1, op 7 or a shield is never refused: `RefreshRequired` and both cap checks are gone, `pendingCount` is a uint64 and unbounded. Status: built.
(D8, owner B) `pqzRollOver(ua, n)` (name `mtxRollOver` after 3b): anyone, strictly in order, `1 ≤ n ≤ ROLL_MAX`, `n' = min(n, K_MAX − 1 − accUnits)`, `CapReached(ua)` at 0, `AccNotPrepared` until both halves of `acc` are prepared, a rollover past the queue reverts `RollOverRange` (no clamp), the slots below `rolled − INLINE_MAX` are deleted. **`ROLL_MAX = 256`** measured 12,134,236 gas = 72.3 % of 2^24 (fit 2,850,548 + 36,264 per entry; 272 would be 12,714,466, over the 0.75 · 2^24 rule), pinned by `PqzStatePinGasTest`. Final review I1 (commit `595296b6`): every stored `acc` word is `ACC_MARK | word` (bit 255, masked on read; `accHash` over the unmarked bytes) — a TRIVIAL-only first rollover had written `u = 0` into 515 of 516 slots, so the next rollover of 256 credits cost 20,888,499 gas (> 2^24); now 12,088,219 (`PqzStateTrivialRollGasTest`); `ROLL_MAX` 256 re-measured cold 12,148,307. `pqzPrepareAcc(ua, half)` (name `mtxPrepareAcc`): permissionless, idempotent, PQZ holders only, `half > 1` reverts `BadPayload`, 5,757,946 gas per half (5,757,911 before the `ACC_MARK` fix `595296b6`). Two accepted choices beyond the design text: a rollover raises `floor` together with `cleared` (keeps `cleared ≤ floor`; harmless since `p ≥ rolled − INLINE_MAX`), and prepare refuses non-holders. Status: built.
(D9) `accUnits` is uint32; `unitsOf(T) = accUnits + (p − rolled) + 1 ≤ K_MAX`, a TRIVIAL entry counts one unit. Status: built.
(D24, controller) a debit whose shared `u` (any `u_g`, a burn's `u'`) is all zero reverts `ZeroU` (Codex T2 CHAIN-01: such a credit would leave `acc` unchanged while `rolled` advances); TRIVIAL entries are contract-made and exempt. Status: built.
(D18, controller proposal; owner ruling "shield needs no proof" of the 2026-10-20 changes above) the proof-free shield is a **TRIVIAL queue entry**: `blob = 0` and the amount in the low 64 bits of the pending slot, one slot per account and block, a later shield of the same block **merges** into the tail entry when it is TRIVIAL, of this block and its index is `≥ max(floor, rolled)` (never into an entry a debit of the block already spent); rollovers and debits add each entry as its own `Trivial(digits(amount))` (one unit, zero noise); `shieldIn` (was `plainUsed`, header word 480) is the same-call top-up from the signer's public balance; a wrap-shield mints to the pool and writes the same entry. Measured 88,221 gas first entry, 73,942 append, 51,776 merge. Rejected: a per-account integer accumulator outside the queue (breaks the exact un-roll rebuild; `plainPending`'s flaw) and folding a run of entries as one normalised term (digits are not normalised under addition, the un-roll could not subtract part of a run). Documented residual, tested (`test_trivial_sameBlockResidual`): a debit whose window holds an entry of its own block can be made to revert by a merge before it; wallets use `shieldIn` for "shield and spend now". Status: built.
(Owner ruling 2026-10-20, fees; replaces D10's per-credit fee on op 1 and op 7 and O4's chain floor) two fees, both out of `SHIELD_POOL` to public UA-ledger balances. **`txFee`** = `confidentialFee`, per transaction on any op that names a beneficiary (the old code path, now paid to the beneficiary's public balance). **`decoyFee`**, op 7 only: an explicit payload word `d` (after `M`, before the salt; `PqzCore.M_OUT = 240`), `d ≥ token minDecoyFee`, `d < 2^64` else `DecoyFeeOutOfRange(d, min)`, the same `d` to every leg including the real recipient, the header `fee` word `= txFee + M·d` so the proof binds `d`; `minDecoyFee` is immutable at `initialize` (`ConfidentialConfig.multiLegFee` renamed; init requires `minDecoyFee < 2^64` and `confidentialFee + 8·minDecoyFee < 2^64` and `< cap`; no chain floor). Op 1 never pays a decoy fee. Shields are free (gas only; a tx fee only when relayed; owner Q2). The libraries return what the debit moved (`PqzCore.Paid` for PQZ, `fee` / `ZetherLib.Paid` for Zether) and the token pays exactly that (Task 3 fix 1: the fee was computed twice before). **Zether** (final review I2, commit `ee4ba31f`): the same rule on the multi-recipient format — payload `… ‖ be32(M) ‖ be32(decoyFee) ‖ Y_f …` (`M_PTS = 144`), `IZetherToken.DecoyFeeOutOfRange(d, min)`, the header fee word `txFee + M·d` (`≥ 2^64` ⇒ `AmountOutOfRange`; statement layout and relation unchanged), init `minDecoyFee < 2^64` and `confidentialFee + 16·minDecoyFee < 2^64` and `< cap` (16 legs), `minDecoyFee()` view, `ZetherLib.Paid {txFee, decoyFee, legs}` paid from `SHIELD_POOL` (`d` to every leg); the single format never pays it; zether-prover builds the word (`decoyFee`, `minDecoyFee` request fields; `DECOY_LEG_GAS` 32 k per leg in its gas check, measured 28,663). Status: built.
(Owner Q1, for part B) the 16k modulus is **q = 2^50 − 42,310,535** (prime; q − 1 = 2^3·19·43·431·5659·70627 keeps today's Ligero radices), Δ = 2^30 − 41, replacing 2^50 − 71 (no FFT domain for PQZH); PQZL and PQZH share q. Status: decided; built in part B (not in part A, which keeps q = 2^42 − 215, `K_MAX = 1024`).
(D16, D17) parameters as the 16k Change above, order: B + state + shield / pool / names / kinds on today's parameters first (part A), then the 16k regeneration with B-1, A-2 and `R_REG` as one id bump (part B; see CTR-PQZ-09), then plan fs3 Task 12, 6, 13. Status: decided; part A built, part B pending.
Superseded by this Change: the first 5h design's `ROLL_AGE = 24` (owner 2026-10-20: **`ROLL_AGE = 5` blocks**, see CTR-PQZ-08), D10's per-credit fee and the O4 floor, and "`pqzShield` becomes a proven debit". Status: decided; part A built.
Change (2026-10-22): controller proposal (owner may override) — **gas under Amsterdam in the clients and the node**
(TODO "Node / relayer on the Amsterdam gas model", branch `amsterdam-node`). zether-prover `DECOY_LEG_GAS` 32,000 →
**120,000** (a leg's payout measured 116,698 under Amsterdam, F185 `ZetherDecoyFee.test_gas_decoyFeePerLeg`; the bound
the contract test pins). zether-prover kept the Osaka `gas_limits` table as the bound on a transfer's **regular** gas
(EIP-7825's 2^24 under EIP-8037; F185 re-ran every edge cell under Amsterdam and each settles; total 21.4–31.2 M; re-measured on 2026-10-27, CTR-ZTH-34) and
`TX_GAS_CAP` 2^24 as that regular cap; the transaction's gas limit comes from `eth_estimateGas`, never from the table;
per-`M` regular gas not re-measured (a gas run on the owner's go). The node (`scaas-node` `guard::gas`): refuses a
calldata floor (15,000 + 64 per byte) over 2^24 before simulating, reads "out of gas" / "gas required exceeds allowance"
of its simulation as a refusal (regular gas over 2^24, measured on Nethermind 2.2.0), and bounds the gas limit
(`eth_estimateGas` + 20 %, regular + state) by `max_gas_per_tx`, the chain's current block gas limit read from
`latest` and 2^32 − 1 — no longer by 2^24 on an Amsterdam chain (the fork is read per chain from the `latest`
header's `blockAccessListHash`; before Amsterdam the whole limit stays ≤ 2^24, the first review fix, `d88b0e1c`); a job
rebuilt after a restart keeps its sent transaction's gas limit; never a zero gas price (fees from `eth_feeHistory`, ≥ 1 wei). SCaaS
testnet `max_gas_per_tx` 16,000,000 → **64,000,000** (op 1 ≈ 41.7–43.4 M with state gas, Task 7b). Normative:
[node/submit-lanes.md#amsterdam-gas](node/submit-lanes.md#amsterdam-gas). Status: built on branch `amsterdam-node`
(not merged).

Change (2026-10-21, owner rulings, controller record): **Amsterdam re-plan** (spec `superpowers/specs/2026-10-20-pqz-state-redesign.md` §12; plan 5h Task 8 split 8a → 8b → 8c → 8d). (1) Option (b): the SCaaS chains run Ethereum's Amsterdam rules — EIP-7976 calldata floor (≈ 261,909 B of calldata per transaction), EIP-8037 state gas, EIP-8038 storage-write costs; measured in Task 7b (`9c2f53ef`). Status: decided; measured. (2) The precompile may be deployed for customers: budgets are judged against Ethereum-like limits (2^24 regular gas per transaction, the EIP-7976 floor, a 60 M mainnet-like block), never against a zero gas price or the testnet's 200 M target. Status: decided. (3) op 7 M = 8 on chain is decided in 8d by a measurement at set (a) (regular gas ≤ 2^24 under Amsterdam, the total against a 60 M block); the first ruling "M ≤ 4 on chain" is withdrawn (the token builds the precompile input in memory; op 7 M = 8 G = 2 relayed calldata ≈ 124 KB < 261,909); no G = 1 relation; the cores keep M = 8 with G = 2 (specs regenerated at set (a) in 8b). Status: cores decided; on-chain M = 8 open until 8d. (4) PQZH backup only: its debit inputs exceed one transaction's calldata; 8c moves it to the new q; `MAX_PROOF_PQZH` stays 262,144. Status: decided. (5) **Set (a) replaces the 16k set** of the 2026-10-20 Change above (n-study candidate E): n = 2304 (k = 36), `K_MAX` = 4,096, q = 61,275,424,977,257 (≈ 2^45.80, q ≡ 9 mod 16, q − 1 divisible by 2^3·19·43·431), Δ = ⌊q / 2^18⌋ = 233,747,196, β_s / β_e 38 / 173, `M_i` 16 bits, carries 13, `e_T` / `e'` + 2^26 in 27 bits, proof MLWE rank 36, mint margin 3.08×; DDGR20 β 468.5 at 80 hints (dual_hybrid − offset 458.5). Status: decided; cores built in 8b (`pqz-core/pqzl/params/pa/`), 8c / 8d pending. (6) `ROLL_MAX` re-pinned in 8d (≈ 96 at set (a), estimate). Status: open until measured. (7) `MAX_INPUT` stays 512 KiB (O8; the input is built in memory); Task 7b's 261,120 proposal is dropped. Status: decided. (8) Precompile addresses → 32-bit `0x…5caa0f01` / `0x…5caa0012` / `0x…5caa0013` (CTR-PQZ-10's 2026-10-15 addresses superseded in 8d). Status: decided; 8d. (9) Op blobs stay in contract state (owner: a ciphertext must never be lost): calldata and events may be pruned by EIP-4444, so ciphertexts never leave state (CTR-PQZ-07 Change 2026-10-19 holds); the state gas (≈ 30 M per debit at 16k, ≈ 27–29 M at set (a), estimate) is real money on a customer chain and accepted. Status: decided. (10) Foundry 1.8.5 with Amsterdam profiles (task F185, branch `foundry-185`, `d4c24678`). Status: built on its branch, not merged. (11) A spike on tight coefficient packing of the stored blobs and `acc` (≈ −28 % state gas, estimate) runs before 8d and may change the stored blob format. Status: pending. Superseded: the 16k set (n = 2560, `K_MAX` 16,384, q = 2^50 − 42,310,535), O9's G = 1 for M = 8, `ROLL_MAX` 208 / 192, PQZH on chain.

Change (2026-10-27): **review C0-7, option (1) (controller proposal 2026-10-27, owner may override)**: the fee beneficiary of a PQZ debit is any registered UA-ledger receiver (`kindOf(ua) ≠ 0`); it needs no PQZ key (the `txFee` is a public pool → UA-ledger credit, as this entry, the UA-6 spec and the pq-zero-knowledge.md §7.10 say). The PQZ holder rule still applies to the sender, the credited legs and the auditor. Status: **done** (review2 T1, branch `review2-fix`; `PqzGuards.t.sol` `test_beneficiary_anyRegisteredUA`).

### CTR-PQZ-07 — Ciphertexts in calldata, hashes in storage
- old: R276 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-07 · superseded-by: —

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D13: the statement is built once in memory; for the precompile call the 5-byte prefix `u8(op) ‖ be32(len)` is written into the low bytes of the statement's length word and the proof is copied right after it, so the up to 345 KB input is never copied a second time (the length word is restored after the call); the verdict is a successful call returning exactly 32 bytes equal to 1, anything else reverts `ProofRejected`.

**Why.** Ciphertexts live in calldata and events with hashes in storage; storage of a 16 KB ciphertext would cost 2.6–8.8 M gas per write.
**Cost if wrong.** Indexers must rebuild state from events; clients check hashes.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:265`

Change (2026-10-19): **owner ruling — PQZ ciphertexts are kept in contract state**, superseding "bytes in calldata + events". Reason (owner question on data permanence): with only hashes in state, the ciphertext bytes live in history, which EIP-4444 history expiry may prune; an account that lost its local copy could then no longer debit or roll over (funds stuck behind a valid hash). Status: **decided; design pending** (plan Task 5h: storage layout — slots vs SSTORE2 vs a hybrid, one shared `u` per operation under CTR-PQZ-04, pending cleanup at rollover, gas and state-growth budget — then build before the SCaaS testnet reset of plan Task 13).

Change (2026-10-20): controller proposal (owner may override) — **plan Task 5h design** (spec `superpowers/specs/2026-10-20-pqz-state-redesign.md`, plan `superpowers/plans/2026-10-20-pqz-state-redesign.md` D1–D17; measured with the forge prototype `smartcontracts/evm/test/research/PqzStateGas.t.sol`, log `smartcontracts/evm/runs/2026-10-20-5h-state-gas.txt`, and `pqz-core/pqzl/params/aprime/`). (D1) every debit operation stores its `out` once as an SSTORE2 op blob (`salt ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖ UA_j)_{j<M} ‖ v_f`, = today's bundle `R` plus `v_f`; burn / refresh `u' ‖ v_f`): one shared `u` per group stored once (CTR-PQZ-04), 3.49 M gas for op 1 with its credit, 7.45 M for op 7 M = 8 with the auditor; storage slots (11.4 M per ciphertext) and one SSTORE2 per credit (op 7 M = 8 ≈ 27 M) rejected. (D2) a pending credit is one slot `blob ‖ g ‖ G ‖ j ‖ block` (26.3 k), `pendingHash` removed. (D3) `acc` after a debit is a reference to the debit's blob (`u_0`, `v_f`); rollovers materialise it in `CT/32` slots, rewritten in place (never zeroed), with `accHash`; the zero → non-zero first write (11.4 M; 15.8 M under A') is split out into a permissionless two-half `pqzPrepareAcc`. (D4) every debit leaves `acc` fresh, `accUnits = 1`, `rolled = floor = p` (a debit with `p < rolled` un-rolls `[p, rolled)`: pending again, nothing lost or skipped). (D5) debits read `acc` and the inline credits from state; an optional calldata hint replaces the 516 cold SLOADs (1.23 M) when it hashes to `accHash`, else is ignored; the `acc` / `inline` arguments go. (D6) W-E's base (`baseHash` / `baseRolled` / `baseUnits`) is removed; `ROLL_AGE = 24` blocks is enforced on rollovers, so a debit submitted within 24 blocks of its proof never sees `rolled > p`. (D7, D8) B: no `RefreshRequired` on credits; `pqzRollOver(ua, n)` strictly in order, clamped to `K_MAX − 1 − accUnits` (`CapReached` at 0), deletes the slots below `rolled − INLINE_MAX`; measured 2.78 M + 36.3 k per entry, so **`ROLL_MAX = 256`** (12.11 M, 72.2 % of 2^24); under A' (n = 2816) 3.81 M + 46.6 k, `ROLL_MAX = 176` (target 256 missed, owner question O9). (D9) `accUnits` uint32. (D10) `multiLegFee` becomes a per-credit fee on op 1 and op 7, paid to every credited UA, non-zero required on the SCaaS chains. (D11) storage modes kept; BUNDLE's entry is the op blob, HASH adds the memo, COMPACT / NONE now cost ≈ +3.4 M. (D12) events carry the blob pointer instead of bytes, new `PqzDebited`. (D13) views for restore-from-state. (D14, controller 2026-10-20) `PqzLib` splits into `PqzStateLib` / `PqzTransferLib` / `PqzBurnLib` / `PqzViewLib` (today's code 4,041 / 13,723 / 7,340 / 12,220 B), every token ≥ 4 KiB under 65,536 B. (D15) the transfer mode is folded into the relayed binding (review L1). (D16) A': n = 2816 (k = 44), q = 2^54 − 327, Δ = 2^32 − 1, `K_MAX = 65,536`, `e_T ∈ [−2^30, 2^30)`, `M_i < 2^20`: encryption β 520 (DDGR20 496.8 at 80 hints, so the β 446 exception lapses), mint margin 3.08×, sizes +37.5 %, R_TX codegen proof ≈ 57.1 KB; the proof MLWE rank must rise (dual_hybrid 447). (D17) order: B + state on today's parameters first, then A'. Open questions O1–O9 in the spec (O1: is A' still wanted once B removes the liveness problem). Status: **proposal, pending the owner's review** (Task 5h design step; nothing built).

Change (2026-10-20): **owner rulings on the 5h design** (spec `superpowers/specs/2026-10-20-pqz-state-redesign.md`, open questions O1–O9; the controller's recommendations accepted): O1 B first with today's parameters, then A' (kept: K_MAX 1024 still forces an owner refresh about every thousand credits, often with decoys); O2 n = 2816, q = 2^54 − 327 (β 520, 496.8 at 80 hints — the β 446 exception is no longer needed); O3 the 3.08× mint margin accepted, to be re-checked by review B (plan Task 11); O4 a per-credit fee with a floor of at least the state cost of one pending slot (≈ 26.3 k gas at the chain's gas price), the figure set per chain profile; O5 the NONE storage mode retired (no gas saving left; fewer entry points; simpler W-A binding); O6 `ROLL_AGE = 24` blocks enforced (replaces W-E's base); O7 refresh ≈ 3.3 M gas dearer accepted (direct cost of ciphertexts in state); O8 `MAX_INPUT` raised to 512 KiB, the A' verify-time budget measured on a quiet host when the owner frees it; O9 under A' `ROLL_MAX` = 176 accepted, op 7 M = 8: measure one randomness group (144 hints) first, else M ≤ 4 on chain. Status: decided; implementation per plan `superpowers/plans/2026-10-20-pqz-state-redesign.md` after the 5g-Z Z1 merge (D1–D17 above now read as accepted except where an O-ruling changes them).

Change (2026-10-20, controller record): **the state layout as built** (plan 5h part A, branch `pqz-state-b`, Task 1 `b978cf89`, Task 2 `85680d55` / `133b7303` / `f4d367c4`, Task 3 `ff4e6948` / `3cbc5f5e`). Decision by decision:
(D1) every debit stores its `out` once as an SSTORE2 **op blob**: transfers `R ‖ v_f` (op 1: `salt ‖ u ‖ v_t ‖ [v_a] ‖ toUA ‖ v_f`; op 7: the bundle plus `v_f`), burn and refresh `u' ‖ v_f`; credits and `acc` point into it. In BUNDLE mode `entryPtr[ref]` already is the op blob (no second SSTORE2, no 3.4 M paid twice). Status: built.
(D2, deviation from the design text, accepted) a pending entry is one slot `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`: **byte offsets** `(uOff, vOff)` instead of `(g, G, j)`, because the position of `v_j` in `R` also depends on `auditorOn`, which the tuple lacked; TRIVIAL: `vOff = 0`, the amount in the low 64 bits of the blob field. Status: built.
(D3) `Account`: slot 0 `pendingCount ‖ rolled ‖ floor ‖ cleared` (4 × u64), slot 1 `accBlob ‖ accU ‖ accV ‖ accUnits(u32) ‖ flags`, slot 2 `sendCounter`, slot 3 `accHash`, `pending` mapping, `uint256[516] accWords` (never zeroed). Flags 1 MATERIALISED, 2 / 4 the prepared halves. `plainPending`, `pendingHash` and W-E's base are gone. After a debit `accHash` stays stored (stale) and the hint path checks the MAT flag first. Status: built.
(D4) a debit leaves `acc` = a fresh reference, `accUnits = 1`, MAT cleared, `rolled = floor = p`, `[cleared, p)` deleted; `p < rolled` un-rolls `[p, rolled)` (their slots survive: rollovers delete only below `rolled − INLINE_MAX`). Status: built.
(D5) a debit reads `acc` and its inline window from state; the entry points lose `acc` / `inline` and take an optional `accHint` (used when `keccak256(hint) == accHash` and MAT is set, else ignored; a stale hint never reverts); statement views `(payload, binding)`. Measured: op 1 BUNDLE with a fresh reference 4,000,294 gas, materialised + hint 4,131,335, materialised without hint 5,357,164, 16 inline credits 4,843,937 (≈ 36 k each). Status: built.
(D11, owner O5) NONE retired on PQZ: `pqzTransferNoBundle` / `pqzTransferSingleNoBundle` removed (entry points, `_isPqzOp`, both `mtxSelectors`: 19 → 17 and 11 → 9), both remaining modes store the blob (HASH adds the memo; the `entryHash` map is gone), COMPACT op 1 costs 4,072,031 gas. Zether keeps NoBundle. Status: built.
(D12) events carry pointers under PQZ names until Task 3b (`PqzShielded`, `PqzDebited`, `PqzTransfer`, `PqzTransferMulti`, `PqzBurned`, `PqzRolled`, `PqzCredit`), then the shared names (CTR-ZTH-45 change). `PqzPlainCredit` is gone. Status: built (Task 3), renamed in 3b.
(D13) views: `pqzAccount` (counters, `accBlob`, `accUnits`, flags, `sendCounter`, `accHash`), `pqzAcc`, `pqzPending` (the raw slot word, not a decoded tuple), `pqzPendingCt`, `pqzEntryBlob`, `minDecoyFee()`; disclosure reads `R` from the blob, so `disclosureStatement(ref, leg, amount, kind)` has no bundle argument and `verifyTransferAmount(ref, leg, amount, kind, proof)` takes the proof alone as the opening (the W-I canonical-opening check is moot). Status: built.
(D14, controller) `PqzLib` is split into four DELEGATECALL libraries over the internal `PqzCore` (`PqzStateLib` 6,378 B, `PqzTransferLib` 13,194 B, `PqzBurnLib` 7,633 B, `PqzViewLib` 12,111 B, each < 24,576), the release's `Env.libs` (plan 5g-Z2). The split does not shrink the tokens; the state work did (UnderlyingPqzToken 60,907 B, NoUnderlyingPqzToken 48,412 B at Task 3 fix 1). **Owner rulings 2026-10-20 supersede two parts of D14:** no view `fallback` (views stay direct token functions) and no 4 KiB margin (tokens must fit the hard 65,536 B limit only; the size ratchet baseline still applies; code size is otherwise not optimised until Glamsterdam). Status: built.
(D15) the transfer mode is folded into every relayed binding (see CTR-PQZ-25). Status: built (Task 3).
Estimates replaced by measurement: ≈ 2.8 M + 36 k per rolled entry, 12.13 M for 256 (spec §5.3). Status: part A built; the permanent costs are the blobs (16,816 B to 35,216 B per operation, never deleted).

Change (2026-10-25): **owner ruling P46 (2026-10-21) built, and the contracts wired to the generated parameter set** (plan 5h Task 8d part 2a with its review fix round, squash-merged into `pqz-16k` as `19f3135e`; research note `research/pqz-pack.md`). (1) **P46, the stored form** (owner 2026-10-21, after the packing spike: "P46" chosen over today's 64-bit lanes and P51 — 51-bit lanes, five coefficients per 256-bit word with unreduced sums of up to 36 terms, measured at `n2304-kmax4096` in the spike and rejected: a cheaper rollover per credit but ≈ 2.5 M less state gas saved per op — for its state-gas saving): what a PQZ token stores — every op blob (SSTORE2) and a materialised `acc` — holds each coefficient in `PACK_BITS = ⌈log2 q⌉` bits (42 / 46 / 50 / 54 at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`), four coefficients (one 64-bit-lane word) per `PACK_BITS / 2` bytes, the coefficients' fields concatenated big-endian; `acc` slots store `not(packed word)` (never 0 for a reduced `acc`, D3), `accHash` = keccak256 of the packed bytes, the calldata hint is those bytes, `transferCiphertextHash` = keccak256 of the packed `R`, `ZERO_HASH` = keccak256 of the packed `Trivial(0)`; a rollover sums the stored credits as loaded into two accumulators with a `PACK_BITS`-bit carry gap per field and spreads once, a debit expands its window on the fly. Calldata, the statement, `pqz-stmt`, the precompile and the proofs keep `be8` (no id change for the packing). Stored `ct` / `acc` slots per set: 10,836 B / 339, 13,340 B / 417, 16,100 B / 504, 19,116 B / 598 (64-bit lanes: 16,512 / 18,560 / 20,608 / 22,656 B). Headroom: lanes stay `< 2^64` while `(ROLL_MAX + 1) · q < 2^64` (≤ 1,023 terms at 54 bits; the carry gaps hold 2^PACK_BITS terms), so the scheme fits every set; `K_MAX` (up to 65,536) does not enter (each rollover reduces). Status: built. (2) **One set per build, the contracts' set** (owner 2026-10-21): every PQZ contract reads its set from `smartcontracts/evm/src/pqz/PqzSet.sol`, generated by `gen_set.py` (sizes, q, Δ, `K_MAX`, `PACK_BITS`, the statement lengths, `PQZL_ID`, `HAS_PQZH` and `PQZH_ID` — the zero word, refused, at a set without PQZH: review 8d1b M7, the same form as `pqz-stmt` —, `ZERO_HASH`, and from the set's vectors the precompile's `SELFTEST` hash and `UAPqzVerifier`'s R_REG probe hashes); the committed file is `n2304-kmax4096`'s; `smartcontracts/evm/script/pqz/at-set.sh <set>` builds and tests another set. `PqzSafety` accepts exactly the set's ids (retired and other sets' ids refused) at the 32-bit address `0x…5caa0f01`. Status: built; every forge suite passes at all four sets (1,358 passed, 9 skipped each; logs `smartcontracts/evm/runs/2026-10-25-t8d2a-forge-<set>.txt`, size gate `2026-10-25-t8d2a-sizes.txt`). (3) **`ROLL_MAX` provisional per set** — 96 / 80 / 64 / 48, the P46 spike's 80 at `n2304-kmax4096` scaled by the per-entry cost — under the existing pin tests; part 2b measures and pins it. Status: provisional (controller), pending 2b. Superseded: the 64-bit-lane stored layout (`ACC_MARK | word`, `accHash` over the unmarked words, 516 `acc` words) of the Change (2026-10-20) above.

Change (2026-10-26): controller proposal, owner may override — **plan 5h Task 8d part 2b: `ROLL_MAX` pinned per set and the gas measured** (branch `pqz-8d2b` from `main` `d14fe16f`, commits `f9b0fd5c`, `3ce752be`, `1494d66f`, `4a49df11`, `6027eff5`, `950c646a`, `f5abd77f`, and the review fix round `9afdd17b`, `c7e784a9`, `43c0ab39` with the docs commit after them; forge 1.8.5, Amsterdam; logs `smartcontracts/evm/runs/2026-10-26-t8d2b-*`). (1) **`ROLL_MAX` per set** in `set.toml` `roll_max` → `gen_set.py` → `PqzSet.ROLL_MAX` (checked: a positive multiple of 16, below `K_MAX`, `(ROLL_MAX + 1) · q < 2^64`); `PqzCore.ROLL_MAX` reads it, the provisional per-set expression and the test-only `AMS_ROLL_MAX` / `ROLL_CEILING` ceiling are deleted. Values **96 / 80 / 64 / 32** at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536`: the largest multiple of 16 whose rollover, as a relayed full transaction on **either relay path** (`mtxExecute`, the ECDSA envelope, and `uaExecute`, an `mldsa65` fee UA with ML-DSA-65 at 68,006 [estimate]; outer fee FIXED) on a prepared account with every entry from its own cold blob, stays under 0.75 · 2^24 = 12,582,912 regular gas. `uaExecute` binds (157,115–157,139 gas more per rollover): 11,860,959 / 12,268,273 / 12,567,631 / 11,238,795 at `ROLL_MAX`, 13,021,439 / 13,539,505 / 13,950,047 / 12,732,731 at `ROLL_MAX + 16`; on `mtxExecute` 11,703,832 / 12,111,158 / 12,410,516 / 11,081,668 and 12,864,324 / 13,382,390 / 13,792,932 / 12,575,616 (a build with a larger constant, `runs/2026-10-26-t8d2b-fix-rollscan-<set>.txt`). The first pin (commit `3ce752be`) measured `mtxExecute` only and gave `n2816-kmax65536` 48 (12,575,616, 7,296 under); the review fix round (review `task-8d2b-review.md` I1, 2026-10-26) measured both paths, and on `uaExecute` 48 is 12,732,731, over the cap: **`n2816-kmax65536` 48 → 32** (controller proposal, owner may override; the owner may instead define the rule for `mtxExecute` only, which gives 48). `PqzStatePinGasTest` asserts both paths (`ROLL_MAX` fits on each, the linear fit at `ROLL_MAX + 16` is over the cap on the costlier; the fit equals the scan's measured value). Margins on `uaExecute`: 721,953 / 314,639 / **15,281** / 1,344,117 gas (`n2560-kmax16384` is tight: re-run the scan after any contract change). The lane assertion of Review Focus 5 holds (`PqzCt.t.sol`, and now `gen_set.py`). (2) **`mtxPrepareAcc` halves** 2.18–3.75 M regular as relayed full transactions through `mtxExecute`, 2.32–3.90 M through `uaExecute` (state gas 16.8–29.6 M per half): under 0.75 · 2^24 at every set on both paths. (3) **Gas per relation per set** (`PqzStatePinGasTest.test_gasTable_*`: real proof lengths, the `PQZ` precompile at its provisional testnet row; summary in `contracts/pq-zero-knowledge.md` §9.3): every built PQZL form fits 2^24 at every set (asserted), op 1 8.70–9.55 M regular / 17.5–30.3 M state, op 7 M = 8 with the auditor 12.17–13.10 M / 54.0–70.5 M; PQZH debits fit one transaction only at `n2048-kmax1024` (not op 7 M = 4 with the auditor, not with the hint), on both relay paths: 0.30–0.39 M of headroom via `mtxExecute`, 0.09–0.18 M (1,361–2,769 B) via `uaExecute` (3,360 B more calldata); every PQZL form fits 2^24 on both paths. (4) **The hint path under the packed layout** is the packed `acc` (`CTP` bytes); the gas tests had passed the unpacked `pqzAcc` and so measured the ignored-hint path (fixed: the test now checks the hint's execution is cheaper and that an unpacked hint is ignored); under the EIP-7976 floor the hint saves gas only on a transaction that is not floor-bound. (5) **Findings for the owner, no rule changed:** op 7 M = 8 carries more EIP-8037 state gas than a 60 M mainnet-like block holds at `n2048-kmax1024`, `n2304-kmax4096` and `n2816-kmax65536` (spec `superpowers/specs/2026-10-20-pqz-state-redesign.md` §12 item 3 left that test to this measurement); the `R_REG` verify call (3.62–5.03 M at the provisional rows) is above the 3,000,000 PQZ verify cap `script/pqz/e2e.py` configured the registry with before 2026-10-26 (now 4,500,000, which covers PQZL only; a PQZH registry needs ≥ 5.1 M); PQZH against the per-transaction cap: options and a proposal in the research note `research/pqzh-calldata-cap.md` (owner decides, nothing built). The research prototype `test/research/PqzStateGas.t.sol` stays the pre-P46 record (marked research-only); `test/research/PqzPackGas.t.sol` measures the real token and holds the `ROLL_MAX` scan. Status: values proposed and built on the branch; the findings in (5) wait for the owner.

Change (2026-10-27): **owner ruling — `ROLL_MAX` is bounded on both relay paths** (the 2026-10-26 controller proposal of the 8d part 2b fix round, confirmed): the largest multiple of 16 whose relayed full rollover stays ≤ 0.75 · 2^24 regular gas through `mtxExecute` **and** `uaExecute` (the costlier, ML-DSA-65 fee UA, +157 k gas): **96 / 80 / 64 / 32** at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536` (n2816 was 48 on the `mtxExecute` path alone); `PqzStatePinGasTest` asserts both paths; `n2560-kmax16384` keeps only 15,281 gas on `uaExecute` (logs `smartcontracts/evm/runs/2026-10-26-t8d2b-fix-rollscan-<set>.txt`).
Change (2026-10-27): **review C0-10 (controller proposal (1), owner may override)**: PQZL op 7 `M = 8` is accepted at every set, but its EIP-8037 state gas (70.45 / 65.66 / 54.02 / 63.44 M with the auditor) is more than a 60 M block holds at all sets but `n2560-kmax16384` with the auditor. The dependence on the chain's block gas limit is accepted; the client rule is `M ≤ 4` where the block limit is 60 M. No cutoff in code: a flag would hard-code one chain's block limit (the other option, a generated per-set shape table next to the PQZH `M = 8` refusal, was not taken). Written into pq-zero-knowledge.md §9.3 (findings for the owner) and CTR-PQZ-07. Status: **done** (review2 T8, branch `review2-fix`; documentation only).

### CTR-PQZ-08 — Public rollover with race-free debits
- old: R277 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-08 · superseded-by: —

Change (2026-10-19): controller proposal (owner may override) — **on-chain review W-E (plan Task 5g, branch `rev2-chain-pqz`, commit `af47304e`; finding V1-03, P3): a debit on the account's base survives anyone's rollover; T8 and this rule restated.** Before: the proof survived a rollover (same `T`) but the calldata `acc` did not (`AccMismatch`), contrary to T8's "impossible by construction"; on the relayed path the user had to re-sign. Fix (small and sound): `Account` gains `baseHash`, `baseRolled`, `baseUnits` = the state the last debit left (initially `Trivial(0)`, 0, 0; rollovers never touch it); `_total` accepts `acc` hashing to the current `accHash` or to `baseHash` (then `rolled`, `accUnits` are the base's); `_debit` works from that `rolled`, so a debit on the base undoes the rollovers since (their credits pending again; every slot `≥ floor` is kept) and writes the new base. Why sound: between two debits only rollovers change `acc`, each moving `pending[rolled..rolled')` into it, so `base + Σ pending[baseRolled..p)` is the same `T`, and `accUnits + unrolled` is preserved. Rejected: a one-slot "previous accHash" (two rollovers defeat it); owner-only rollover (a design change). Residual (spec, griefing only): a debit built on an intermediate rolled `acc` (needed with > 16 credits since the last debit) can still be forced to rebuild calldata (relayed: re-sign the envelope), and to re-prove only after > 16 further credits are rolled past `p`. Cost: one more storage slot per account; ≈ 22k gas on an account's first debit (`baseHash` 0 → non-zero, a cold SSTORE set), ≈ 5k gas per debit after that (`baseRolled` / `baseUnits` share the slot `_sent` already dirties, ≈ 100 gas); to be measured with plan Task 13's gas run (review 5g L3). Tests `test_rolloverRace_debitOnTheBase`, `test_rolloverRace_belowBaseRolled`, and from the 5g integration `test_rolloverRace_baseRolledBelowPBelowRolled` (`baseRolled ≤ p < rolled`: `rolled` goes back to `p`, review L2); `_total` hashes `acc` once (review N1, PqzLib −18 B). Status: **done** (`af47304e`; L2 / N1 `427729f4`; merged `734b9c76`).

**Why.** Public rollover cannot disturb a debit because the contract rebuilds the same `T` either way; at most 16 inline credits.
**Cost if wrong.** A griefer with > 16 proven credits can force one re-prove.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:269`

Change (2026-10-19): **owner ruling — raise `ROLL_MAX`** (today 16). The bound is gas, not arithmetic (64-bit lanes hold ≈ 2^22 additions of values < 2^42 before the one `mod q`): 16 ciphertexts in calldata cost ≈ 8.3 M gas against the 2^24 transaction cap. With the ciphertexts in state (CTR-PQZ-07) a rollover reads them instead of taking calldata: ≈ 10–25 k gas per entry with SSTORE2 or one shared `u` per operation, ≈ 1.1 M with storage slots — a second reason to prefer SSTORE2 / shared `u` in plan Task 5h. Status: decided; Task 5h sets `ROLL_MAX` from measurement as the largest batch under 2^24 gas with ≈ 25 % margin (target ≥ 256 if the layout allows), pinned by a gas test.

Change (2026-10-20, controller record; owner ruling for the number): **no base, `ROLL_AGE = 5`** (plan 5h D6, built in Task 2 `85680d55`, review fix `f4d367c4`). W-E's base (`baseHash`, `baseRolled`, `baseUnits`, the base branch of `_total`) is removed; its "rolled moves backwards" survives only as the un-roll of a debit with `p < rolled`. **Owner: `ROLL_AGE = 5` blocks** (was 24 in the first design, D6 / O6; ≈ 25 s at 5 s blocks), enforced per rolled entry (`RollTooYoung(index)`), TRIVIAL entries too; a debit takes young entries inline. Race wording corrected (spec §5.6): the residual is more than `INLINE_MAX` *old* entries above a capped `p` (a rollover can roll them past `p` at once; harm bounded: `InlineTooFar`, re-prove at a new `p`, nothing lost) — and the same-block merge residual of CTR-PQZ-06; the down-direction `InlineTooFar` is defence in depth since every rollover keeps `floor ≥ rolled − INLINE_MAX` (`PendingRange` fires first; PQZH op 7's limit 10 still applies). Regression tests: the three W-E races as "a rollover between prove and submit still settles", the un-roll at `p = rolled − INLINE_MAX` right after a `ROLL_MAX` rollover, `RollTooYoung` at `block_i + ROLL_AGE − 1`. Status: decided (number: owner); built.
Change (2026-10-27): **owner ruling 2026-10-27, review C0-6 option (3): accept** — rollover against an in-flight debit. `ROLL_AGE` counts from each entry's own creation block, not from the proof, so 17 entries (`INLINE_MAX + 1`; 11 for PQZH op 7) appended above `p` and rolled after `ROLL_AGE` (two `mtxRollOver`) raise `floor` to `p + 1` and the debit reverts `PendingRange` before any state change. The cost to the attacker is 17 units to the victim per attempt (`mtxShield(victim, 1)`, about 74 k gas each); a sustained flood blocks any prover slower than about 22 blocks. It is liveness only: nothing is lost, wallets re-prove on `PendingRange`. Not taken: (1) a timestamp `ROLL_AGE` of at least 120 s, (2) never raising `floor` past an entry younger than that horizon (the controller's proposal; code change and a cost on every rollover). The spec's claims that a griefer cannot force a re-prove and that a client with a short queue never meets the race were wrong; corrected in pq-zero-knowledge.md CTR-PQZ-08 (a), T7, T8 and the test-plan line, and in the redesign spec §5.6. Status: **done** (review2 T8, branch `review2-fix`; documentation only, no code change).

### CTR-PQZ-09 — LNP22 proofs through rewritten LaZer fork
- old: R278 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-09 · superseded-by: —

Change (2026-10-13): owner — `proofSystemId` v1 → v2 for the two LaZer `tbox` Schwartz–Zippel fixes (lazer#24: λ × M evaluation challenges instead of one pair reused, soundness ≈ 2^-84 → the stated 2^-127; lazer#25: one challenge domain per exact-ℓ2 equation); v1 retired. Source add: `research/pqz-tbox-soundness.md`, `research/pqz-l2-domain.md`.

Change (2026-10-13): owner — §8 states that a v2 verifier bounds the whole `z2 = (z21, z22)` (lazer#26, P6-Z21): an accepted-set change only (no transcript, format or honest-proof change, nothing deployed); `proofSystemId` stays v2 for now, bump or not is an open owner decision. Source add: `research/pqz-z21-norm.md`.
Change (2026-10-14): owner — no `proofSystemId` bump for the z21 fix: v2 stays `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")`, and every v2 verifier must check ‖z21‖² + ‖w − γ·w1‖² ≤ Bsq (merged `a8b5b66`). Source: `research/pqz-z21-norm.md` §6.3.
Change (2026-10-14): owner — the verify limit is raised from 50 ms to 60 ms p99 (adversarial, chain host; also the bound for wasm32 verify), so the PQZH Ligero backend passes (`R_TX` proven wasm32 p99 55.9 ms, native 10.5 ms; `docs/research/pqzh-ligero.md`). Applies to both proof systems (PQZL, PQZH). Gas figures quoted at the 50 ms threshold are recalibrated on measured p99 in P6f.
Change (2026-10-14): controller proposal (owner may override) — the relations stay hand-built on LaZer's `tbox` (P6e decision D1): each relation is a LaZer spec `pqz-core/pqzl/params/<rel>_params.sage` whose header LaZer's own codegen generates, the statement → equation builders stay in `pqz_rel.c` / `pqz_sv.c`, pinned by the KATs and the generic-vs-specialised differential test; no generator for the builders. Evidence: rerunning the codegen (pinned image, `params/regen.sh`) reproduces all five checked-in headers byte for byte (`params/codegen-tx0.txt`). Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D1, Task 2; branch `p6e-a2`.
Change (2026-10-14): controller proposal (owner may override) — one statement codec, the Rust crate `pqz-core/stmt` (`pqz-stmt`: `no_std`, no dependencies, wasm32), shared by the precompile decoder, the clients' statement builder, the Ligero relations and the vector generator (P6e ruling R2); every decoder accepts exactly one encoding (decision D15): fixed lengths per form, coefficients `< q` as `be8`, `fee` and `amount` `< 2^64` on every debit form (controller 2026-10-14: the decoder at the trust boundary may be stricter than the core, whose relations read `amount` only for BURN), the `salt` word = 16 zero bytes ‖ 16-byte salt (CTR-PQZ-19, §7.7; controller 2026-10-14; pqz-core only hashes the word, so the precompile decoder is where it is enforced; the C bench statements now use that form, so the `R_TX`, `R_TX0`, `R_BURN` test proofs changed once), `auditorOn` as the length says, the header words §7.7 / §7.5 fix to 0 for the form (controller 2026-10-14, after review: a transfer's `amount` and `recipient` (§7.7 "amount (burn; else 0)", "recipient (burn; else 0)"), a burn's `toUA`, `auditorOn` and whole `salt` word, a refresh's `toUA`, `amount`, `recipient`, `auditorOn` and `salt`; checked in header order after the scalars, the salt form and `auditorOn`; a burn's `amount > 0` stays a contract check, not an encoding rule), the op's opTag, a known `proofSystemId` (PQZL v2 `0x2e07e6ed…`, PQZH Ligero v1 `0x0a47a768…`, D2 / D3), and `encode(parse(x)) = x`; byte-equal with the C core's statements and `pqz_kat.py` (`stmt/runs/stmt1-*`). The C core keeps its own parser. Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` R2, D15, Task 5; branch `p6e-a2`.
Change (2026-10-14): controller decision (owner may override) — gate-B measurement of the 60 ms verify limit for wasm32: p99 over ≥ 1,000 honest verifies per relation, run under `scripts/capped` (no other heavy job), proven preset; a p99 above 60 ms or within 5 % of it requires the wasm32-specific F_q multiply. Applied on branch `p6e-b1`: proven `R_TX` 59.7 ms with u128 products → the multiply on 21-bit pieces (wasm32 only, proofs byte-identical with native) → every PQZH relation ≤ 19.9 ms p99 in wasm32. Source: `research/pqzh-ligero.md` §12.3.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D11, first part (branch `p6e-b1`): the PQZH Ligero crate `pqz-core/pqzh/ligero/` no longer depends on the Plonky3 crate `pqz-core/pqzh/` (it carries copies of that crate's ring helpers, statement constants and test client as `ring.rs`, `stmt.rs`, `client.rs`; its only dependency is `sha3`); the Plonky3 crate is unchanged and kept as backup. The reference presets (conjectured, proven without radix 431, Johnson) are behind the default feature `bench`; without it only THE preset `Params::proven()` exists, and production users depend with `default-features = false`. Still to do under D11: replace `stmt.rs` / `ring.rs` by `pqz-stmt` (plan Tasks 5 / 6) and put `soundness()` behind `bench`. Source: `superpowers/plans/2026-10-14-p6e-relations.md` (D11, Task 6), `research/pqzh-ligero.md` §12.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D3 (branch `p6e-b2`, Task 9): PQZH's `proofSystemId` is `keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")` = `0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4` (Ligero over F_q, radix-431 domains, Keccak-256 Merkle tree and transcript, zero knowledge by the modified construction, the proven unique-decoding preset; parameters fixed per id and op, never read from the proof). Every PQZH statement carries it at bytes 32..63 and the PQZH verifier (and prover) reject a statement with any other id. The STARK's provisional id `keccak256("scaas/pqz/pqzh/stark-d1-goldilocks5-fri-keccak256-zk/v1")` = `0xaa1f92dd…` is retired unused. Frozen at gate B. Source: `superpowers/plans/2026-10-14-p6e-relations.md` (D3, Task 9), `research/pqzh-ligero.md` §13.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D11, second part (branch `p6e-b3`, Task 6; completes R2 for PQZH): the PQZH Ligero crate decodes every statement with `pqz-stmt` (`cs::parse` = `pqz_stmt::parse`, so every D15 / R6 rule applies to the Ligero prover and verifier, then PQZH's own `proofSystemId` check, D3); its own statement constants and codec (`stmt.rs`, the codec half of `ring.rs`) are removed; the test client, the reference presets, the float parameter model and `soundness()` / `breakdown()` are behind the default feature `bench`, and `Params::proven()` is a constant. Without `bench` the crate depends on `sha3` and `pqz-stmt` only and has no float code (`pqz-core/pqzh/ligero/runs/l14-deps.txt`). Honest proofs are byte-identical to the base commit's; the Ligero accepted set tightens to `pqz-stmt`'s before any deployment (no id change, D4). Source: `superpowers/plans/2026-10-14-p6e-relations.md` (R2, D11, Task 6), `research/pqzh-ligero.md` §14.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D9 (branch `p6e-a4`, Task 11): the PQZ known-answer vectors live in one canonical directory, `smartcontracts/vectors/pqz/` (as `smartcontracts/vectors/ua/`), read in place by every consumer (precompile and fuzz targets, forge tests, clients); the copies of pq-zero-knowledge.md §14 to `smartcontracts/evm/test/vectors/pqz/` and `clients/zether-prover/vectors/pq/` are dropped (copies drift), and so are `pqz-ffi`'s `selftest/*.hex`: its `build.rs` compiles the self-test's `R_REG` proofs in from the REGISTER rows of `proof_{pqzl,pqzh}.json`. One generator writes them, `pqz-ffi`'s `pqz-vectors` binary (feature `prove`, plan R4): every value from the crate's API, every expected output from `pqz_precompile` and `selftest()`; `--check` = regenerate and compare byte for byte; every file has an independent checker in `pqz_kat.py` (a file without one fails). `worstcase_noise.json` stores seeds, sparse vectors, each credit's `ctHash` and the aggregate `T`, not the 1,023 ciphertexts (≈ 34 MB of hex); its bound case is the worst the verifier accepts (an attacker-registered key at the norm bounds: `T` noise 1,023 · 11,872 = 12,145,056, the plain unit has noise 0). Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D9, Task 11; `smartcontracts/vectors/pqz/README.md`.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D2 (recorded with Task 12, branch `p6e-a6`): PQZL's `proofSystemId` stays v2, `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")` = `0x2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f`, frozen at gate A; v2 covers the auditor-off transfer `R_TX0` (an added statement form, existing proofs unchanged; CTR-PQZ-24) and the hedged prover (prover-only; CTR-PQZ-19), on the precedent of the owner's z21 ruling above (no bump for a change that leaves the honest proofs and the transcript of existing forms unchanged). If overridden: the string `…/v3`, one constant and the vectors. Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D2.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D4, the bump rule (recorded with Task 12, branch `p6e-a6`; pq-zero-knowledge.md §8 Versioning): after a deployment, any change to the parameters, presets, relation rows or statement layout of an existing form, to the transcript, the proof encoding or the accepted set ⇒ a new `proofSystemId`. Prover-only changes must keep the frozen vectors' proof bytes (`pqz-vectors --check`, the `proofs_fnv` lines fail on any byte change); adding a statement form before the first deployment and tightening the accepted set before any deployment need no bump and are recorded case by case (as the `R_TX0`, salt / zero-word and Ligero `pqz-stmt` lines here). The precompile may implement several ids; retiring one is a chain activation (P6f), never silent. Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D4.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D7 (gap G3; branch `p6e-a6`, Task 12): pq-zero-knowledge.md §5's transcript text is amended to what v2 implements, no code change: PQZL `hash0 = SHAKE128("SCAAS-PQZ-TRANSCRIPT-V1" ‖ u8(op) ‖ be32(len(stmt)) ‖ stmt)` (32 B) seeds LaZer's tbox transcript unchanged (each prover message, coder-encoded, absorbed as `hash ← SHAKE128(hash ‖ message)`; challenges expanded from `hash`); PQZH a Keccak-256 chain seeded with `keccak256("SCAAS-PQZH-LIGERO-V1" ‖ u8(op) ‖ be32(len(stmt)) ‖ stmt)`. The former text (a labelled SHAKE256 transcript with a label and `be32` length per message) was never implemented; changing the code to it would be a `proofSystemId` bump and a rewrite of LaZer's transcript. Strong Fiat–Shamir holds in both: `op` and the whole statement come first. Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D7, G3.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D15, proof half, and pq-zero-knowledge.md §8.1 "Serialization v1" (branch `p6e-a6`, Task 12): §8.1 records every frozen byte layout (precompile framing, both ids and `MAX_PROOF(id)`, the 640-byte header word by word with the decoder's rule per form, every statement body with offsets, objects, bundle, opening, `entryRef`, `authDigest`, the prover-API witness layouts, both proof formats, `OP_SELFTEST`), checked against `pqz-stmt`, `pqz.h` / `pqz_rel.c`, the Ligero crate and the vectors. Proof rules: a PQZL proof is LaZer's coder grammar (`tB`, `h`, `tA1`, `c`, `hint`, `z1`, `z21`, `z3`, `z4`, then a 1 bit and zero bits to the byte boundary) consumed exactly with no trailing byte (`pqz_decproof`), ≤ 98,304 B; a PQZH proof has every F_q element `< q` in 6 bytes, the opened columns in increasing index order without repeats (indices from the transcript, none in the proof), the multiproof in its canonical order, consumed exactly within the exact per-form bound. The precompile decoder is stricter than the C core, which does not check `opTag`, `proofSystemId`, the salt form or the zero words (it only hashes them). Where the older spec text disagreed (transcript, C API, compile-time arena, one proof format and one `MAX_PROOF`, vector directories), the code and the vectors were taken (§8.1 lists the changes). Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D15, serialization v1, Task 12.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D14, gate staging (recorded with Task 12, branch `p6e-a6`): gate A (PQZL: Tasks 1–5, 7, 10–12 for PQZL) freezes the PQZL id and vectors and unblocks P6f / P6g / P6h on PQZL; gate B (PQZH: Tasks 6, 8, 9 and the PQZH parts of 10–12) freezes the PQZH id and format after the Ligero Solidity-verifier measurement (its format wishes come before the freeze) and after a Claude-subagent review of the modified ZK argument (`research/pqzh-ligero.md` §4.1); an external review of that construction comes before PQZH is used with real value (owner step). PQZL does not wait on PQZH. Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D14.
Change (2026-10-16): controller proposal (owner may override) — P6-ANON Task S4 (branch `p6-anon-s4`, plan D15, run `pqz-core/ffi/vectors/runs/s4a-*`), the op 7 `R_TXM` vectors in `smartcontracts/vectors/pqz/`: (1) **one new file and appended rows, no new proof file**: `statement_transfer_multi.json` (11 statements: every built `(M, auditorOn)` of each id, PQZL M ∈ {1, 2, 4, 8} and PQZH {1, 2, 4}, with one real leg at a position that varies by shape, plus a two-real-leg, an all-decoy and a group-boundary row; each row's `ids` lists the ids that build its M), the `R_TXM` rows **appended** to `proof_pqzl.json` (11) / `proof_pqzh.json` (8) and 342 op 7 rows appended to `negative.json` (rows carry `form` `TRANSFER-MULTI` and a `case`); the P6e rows stay byte-identical, so the only rewritten frozen bytes are the two `negative.json` rows `TRANSFER: under op 7` (pqzl, pqzh), whose reason changes `Op` → `OpTag` because op 7 decodes since S3 (an op 1 statement under op byte 7 now fails at its opTag; output `…00` and input bytes unchanged); the self-test hash `ed910a2c…d205` is unchanged; (2) **the memo vectors of CTR-PQZ-23's op 7 memo** (S3's labels `"PQZ/memo/ks/v1"` and the `u8(M)` byte) live in the same file: each row's sender memo and its `memoHash`, and 9 `memo_open` rows (the canonical memo, another key seed, wrong lengths, flipped flags / M / amount / salt bytes) with `memo::open`'s result; `pqz_kat.py` recomputes them with stdlib HMAC-SHA256; (3) **wasm32 replays PQZL M = 8 verify-only**: wasm32 does not prove PQZL op 7 above `WASM_PQZL_MAX_LEGS` = 4 (S3's one-arena proposal, CTR-PQZ-10), so `replay_wasm.mjs` verifies the native M = 8 proofs through the wasm32 precompile (3 rows) and proves every other row byte-equal; (4) **no op 7 disclosure-bundle vectors yet**: plan §5.4's bundle `salt ‖ u_0…u_{G−1} ‖ (toUA_j ‖ v_j ‖ v_{a,j})_j` has no `pqz-stmt` codec (only op 1's `Bundle`), so its rows and the per-leg `opening` vectors wait for the codec (proposed for S7 / P6g, which writes the contract side of §5.3 / §5.4). LH-2 (C ↔ Rust op 7 statements, `pqzh-ligero.md` §15.5) done with the vectors: `pqz-core/ffi/vectors/lh2.sh` (pqz_bench.c's and Ligero's `setup_multi` statements through `pqz-stmt`, both provers and verifiers, and `pqz_kat.py`), run `s4a-lh2.txt` 50 cases, 0 failures. Source add: plan `superpowers/plans/2026-10-14-p6-anon.md` Task S4; `smartcontracts/vectors/pqz/README.md`; `pqz-core/STATUS.md` §"Op 7 vectors".
Change (2026-10-17): controller (gate A / gate B, owner mandate 2026-10-14) — **gate A (PQZL) and gate B (PQZH) passed** with op 7 in the frozen set: `pqz-core/gate.sh 2026-10-17` (KAT 19/19; `check_tbox_fixes`, `check_sv_fixes` ok; differential 6,486 cases, 0 mismatches; z21 differential 406, 0; `pqz-vectors --check` 16 files byte-identical; `pqz_kat.py --check` ok; tamper 191 / 191; wasm32 replay 53 cases, 0 fails; `pqz-ffi`, `pqz-stmt`, Ligero tests green; STARK-backup cross-check equal; fuzz smoke 3 × 60 s, no finding); every built PQZH op ≤ 236,196 B and p99 ≤ 10.9 ms native / 20.4 ms wasm32 (S6 multi-bench); the Ligero ZK review done (`research/pqzh-ligero.md` §12: sound and zero-knowledge in the classical ROM). Both `proofSystemId`s — PQZL v2 `0x2e07e6ed…798c2f` and PQZH `0x0a47a768…fead4` — are **frozen**: any change to parameters, transcript or accepted set takes a new id. Open (owner): a 128-bit post-quantum (QROM / Grover) target for PQZH would need a new parameter set and id (§5.1).
Change (2026-10-18): owner — **the production PQZL core for the `PQZ` precompile is the Rust crate `pqzl`** (`pqz-core/pqzl/rust/`, the byte-for-byte port of the C core, plan `superpowers/plans/2026-10-17-pqzl-rust-port.md`), once the port is verified: the frozen vectors re-proved byte-equal, `pqz-vectors --check` and the self-test hash unchanged through `pqz-ffi`, the 2 h fuzz differential (Rust verdict = C verdict) clean, and the whole-branch review passed. `pqz-ffi` then builds the Rust backend by default (port Task 11) and the node image loads that library; the C core stays in the repository as the reference and the differential oracle (kept, less maintained). No `proofSystemId` change: the proofs and the accepted set are the same. Until the switch, the precompile on the SCaaS testnet runs the C core.
Change (2026-10-18): owner — the PQZL C core (the reference for the Rust crate `pqzl`) is hardened on branch `pqzl-c-hardening`; the three latent defects the Rust port found (signed-overflow UB and one out-of-bounds write) are fixed, and the C now computes what the Rust port computes. The fixes: (1) `lazer/poly.c` `poly_auto_self` in the NTT domain reverses the one residue vector it holds and no longer writes 64 words past it (never reached by a relation); (2) `pqz_fixexp.h` `pqz_exp_fp` clamps in 128 bits, saturating as intended outside [−64, 64), and `rejection.c` wraps in unsigned arithmetic on dishonest-size exponents (prover only); (3) `pqz_rel.c` `rd_poly` reads a non-canonical word in [2^63, 2^63 + q) without signed overflow, and `lazer-in2.h` `int_set_i64` handles `INT64_MIN`. No `proofSystemId` change: honest proofs, the transcript and the accepted set are unchanged, and no verifier computes anything different. `int_set_i64` (both verifiers) and `rd_poly` (the generic `pqz_verify` only; `pqz_verify_fast` parses with its own code) are called by a verifier, but give the same bits for every input. Evidence: `pqz-core/STATUS.md` "C core hardening (2026-10-18)".
Change (2026-10-18): owner — the 128-bit post-quantum (QROM / Grover) soundness target for PQZH stays open and is **not pursued now**; the frozen PQZH id and its 127.2-bit classical proven preset are unchanged (revisit before PQZH carries real value). Owner 2026-10-18, again: decide later — the cost estimate (about twice the query term t ≈ 121 → ≈ 240, possibly a 384-bit hash; proof ≈ 235 KB → ≈ 420–480 KB [estimate], above `MAX_PROOF` 262,144 and `MAX_INPUT` 393,216; calldata alone ≈ 7 M gas against ≈ 3.8 M today) is too much gas; a half-day parameter search for the real proof size comes first when it is revisited.
Change (2026-10-18): owner — follow-ups of the C core hardening review, in the C core and the Rust crate `pqzl` alike (Rust port Task 10b, branch `pqzl-rust`): (1) `lazer/poly.c` `poly_auto_self` in the NTT domain (reached by no relation) now computes X → X⁻¹ through the coefficients (`_fromcrt`, then the coefficient automorphism, as `poly_auto`), replacing a residue reversal that is not the automorphism in the fork's incomplete NTT; Rust `poly.rs` likewise; (2) `rejection.c` / `rejection.rs` saturate `t2 − 2·t1`, `t − ln M` and `a − |y| − ln M` instead of wrapping (`pqz_sat_sub64` / `pqz_sat_sub128` in `pqz_fixexp.h`, Rust `saturating_sub`), so an exponent below −2^63 rejects and fails closed through the `PQZ_REJ_MAX` retry cap instead of accepting, while `t2 − 2·t1` above 2^127 accepts, as before (through a double wrap) and as the exact value (prover only; every saturated verdict is the exact one). No output changes: honest proofs, `proofs_fnv`, `proofSystemId`, the vectors and the self-test hash are unchanged, and C = Rust on the oracle tests. Evidence: `pqz-core/STATUS.md` "C core hardening (2026-10-18)", follow-ups (`ub_test` t10b, gate t10b PASS).
Change (2026-10-18): controller (owner ruling of the same day, Rust port Task 11, branch `pqzl-rust`) — **`pqz-ffi` builds the Rust PQZL core by default**: feature `pqzl-rust` (the crate `pqzl`) is the default; the C core is opt-in (feature `pqzl-c`; `--no-default-features --features pqzl-c`, or `PQZL=c` for `ffi/run.sh` / `ffi/vectors/run.sh`), and the default build compiles no C (`cc` is an optional build-dependency). With both features `pqzl::` is the Rust core and `pqzl::c` the C core, which the fuzz mode `pqzl-diff` links into one binary. One boxed `pqzl::Ctx` for the process behind the existing lock and worker thread (the node calls the precompile from several threads; one warm cache set, verify times independent of the calling thread). Checks: `PQZL=rust ffi/run.sh rust1` (every test, self-test `ed910a2c…d205`, native = wasm32, digest lines byte-equal to the C core's `gate-t10b`), `PQZL=rust ffi/vectors/run.sh rust1` (`pqz-vectors --check` 16 files byte-identical), the C backend alone `rust1-c`; fuzz in mode `pqzl-diff`, 2 h per target, no finding: `precompile` 1,252,401 inputs (177,740 PQZL verdicts C = Rust), `mutate` 134,348 (82,916 verdicts, 47,556 `pqz_test_mutate` re-encodings C = Rust), `codec` 517,545 (398,196 `pqz_test_mutate` decode / re-encode results C = Rust); the default build again: `ffi/run.sh rust1b`, `ffi/vectors/run.sh rust1b`, `pqz-core/gate.sh rust1` PASS. Out of memory inside the Rust verifier is a node fault (status 4, `pqzl::Ctx::try_verify_fast`'s `Error::Memory`), as the C core's arena exhaustion, never `…00`. No `proofSystemId`, format or accepted-set change. Not yet deployed: the SCaaS testnet keeps the C-backed image until the live roll-out (the node image's Docker inputs now include `pqz-core/pqzl/rust`).
Change (2026-10-18): controller proposal (owner may override) — Rust port plan (`superpowers/plans/2026-10-17-pqzl-rust-port.md`) D1, dependencies (recorded with Task 12, branch `pqzl-rust`; in force since Tasks 1–3, `109dda5`, `6dca40b`, `bd9539d`): the crate `pqzl` (`pqz-core/pqzl/rust/`, `no_std` + `alloc`, `#![forbid(unsafe_code)]`, no floating point, Rust 1.97.1) has two run-time dependencies, `sha3 =0.10.8` (SHAKE128 / SHAKE256, Keccak; already in `pqz-ffi`'s lock) and `aes =0.8.4` (fixslice, constant time; AES-NI where detected) with the crate's own AES-256-CTR loop; `cc` is a build dependency of the dev / test feature `c-oracle` only, and `serde_json` a dev-dependency. The C core's `shake128.c` and bitsliced AES are standard algorithms, so any correct implementation gives the same output (checked by the arithmetic KAT 19 / 19, the keys KAT and byte-equal proofs).
Change (2026-10-18): controller proposal (owner may override) — Rust port plan (`superpowers/plans/2026-10-17-pqzl-rust-port.md`) D2, memory (recorded with Task 12; in force from Task 2 on, controller ruling R2; tested by Task 10, `5e3ebbb`, and Task 11, `3e4da45`): no arena. Every buffer that scales with the input is a `Vec` reserved with `try_reserve`; an allocation failure is `Error::Memory` (prove, `try_verify`, `try_verify_fast`) or the verdict false (`verify`, `verify_fast`), never a panic or an abort, and the `Ctx` stays usable. `tests/memory.rs` measures the heap peak per operation with a counting allocator and denies allocations one by one across every relation and operation. Through `pqz-ffi` an `Error::Memory` inside a verifier is a node fault (status 4), as the C core's arena exhaustion.
Change (2026-10-18): controller proposal (owner may override) — Rust port plan (`superpowers/plans/2026-10-17-pqzl-rust-port.md`) D3, API (recorded with Task 12; Task 1 `109dda5`, extended by Tasks 10–11): safe methods on one `Ctx` value that holds what the C core keeps in static storage (keys per relation, SV tables; no globals, re-entrant, no lock), mirroring `pqz.h`: `prove`, `verify`, `verify_fast`, `try_verify`, `try_verify_fast`, the key and encryption functions (free and as `Ctx` methods reusing the cached matrix), all returning `Result<_, Error>` with `Error { Internal, Input, Reject, Memory }` = the C codes 1 / 3 / 4 and arena exhaustion. `pqz-ffi` swaps the backend behind its existing functions without touching callers.
Change (2026-10-18): controller proposal (owner may override) — Rust port plan (`superpowers/plans/2026-10-17-pqzl-rust-port.md`) D4, the C core (recorded with Task 12): the PQZL C core stays in the repository as the reference: the test oracle of the crate (feature `c-oracle`, dev only) and, since Task 11 (`9de6c3a`), the opt-in `pqz-ffi` backend `pqzl-c` (the fuzz mode `pqzl-diff` links both). The port changed no C file; the only C changes are the owner-ordered hardening (branch `pqzl-c-hardening`) and its follow-ups (Task 10b), recorded above.
Change (2026-10-18): controller proposal (owner may override) — Rust port plan (`superpowers/plans/2026-10-17-pqzl-rust-port.md`) D5, formats (recorded with Task 12): no change. The crate is a second implementation of the same proof system: the same `proofSystemId` v2 `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")`, statements, witnesses, proofs (serialization v1) and accepted set. Evidence: the frozen vectors re-prove byte-equal (Task 8), `pqz-vectors --check` and the self-test hash unchanged through `pqz-ffi` on the Rust backend, the 2 h fuzz differential (Task 11), and the package's "Rust = C" stage (`artifact/reproduce.sh`: the prover's `proofs_fnv` native and wasm32 and the keys KAT against `expected-results.json` `rust`).
Change (2026-10-18): controller proposal (owner may override) — Rust port plan (`superpowers/plans/2026-10-17-pqzl-rust-port.md`) D6, performance (recorded with Task 12): measured and reported, not a gate: run `d6` (`pqz-core/pqzl/rust/d6.sh`, `pqzl/rust/runs/d6/results-d6.md`) measures the C core and the crate in one session on one machine (prove / verify / verify_fast p50 / p99 native and wasm32, prove peak memory: C arena against Rust heap and wasm32 linear memory, `ffi_bench` on both `pqz-ffi` backends). Run `d6` (2026-10-18; loop steps t = 9..11, `R_TXM8`, `R_TXM1_0`, `R_TXM2_0`, re-run on a quiet machine after external load, owner ruling; the first-pass files kept): every `proofs_fnv` Rust = C and every bench `fails 0`. Native, the crate is faster on every relation (prove 1.6–2.5×, `R_TX` 529 against 983 ms; generic verify 2.0–2.9×; verify_fast 1.2–1.6×, `R_TX` p99 8.9 against 11.4 ms) and needs 4–6× less memory (heap peak `R_TX` 60.0 MiB against the C arena's 290.1 MiB). In wasm32, prove is about level (0.8–1.4×) and generic verify 1.3–1.9× faster, but verify_fast is 1.7–2.0× slower (`R_TX` p99 32.0 against 17.5 ms; the largest, `R_TXM8`, 51.0 ms against the 60 ms limit, about 15 % margin on the reference CPU). Likely cause: `pqzl/rust/src/arith/ntt.rs` multiplies 64 × 64 → 128 bits (`mulq`, `red128`, the basemul `u128` accumulator) on every target and wasm32 has no wide multiply, while the C core uses a 21-bit-limb path on wasm32; neither build uses simd128. Follow-up, not done in the port: a `cfg(target_arch = "wasm32")` limb path in `ntt.rs` (`pqz-core/STATUS.md` "Open", item 10). Through `pqz-ffi` (`ffi_bench 200`) the Rust backend verifies every PQZL form faster (`R_TX` p99 9.27 against 11.72 ms, op 7 M = 8 14.86 against 21.42 ms).
Change (2026-10-18): controller proposal (owner may override) — Rust port plan (`superpowers/plans/2026-10-17-pqzl-rust-port.md`) D7, publication (recorded with Task 12): `publish = false`; crates.io only on an owner ruling (licence: the repository's Vegan Community License 1.0; LaZer's MIT notice travels in `pqzl/rust/NOTICE` and `LICENSE-lazer`).
Change (2026-10-18): controller proposal (owner may override) — Rust port plan (`superpowers/plans/2026-10-17-pqzl-rust-port.md`) D8, params (recorded with Task 12; Task 6, `d652273`): the 14 generated `pqzl/params/pqz_*_params.h` become `pqzl/rust/src/params/*.rs` through one converter, `pqzl/params/to_rust.py` (stdlib only), checked in; `pqzl/params/regen.sh` and `pqzl/rust/run.sh` run `to_rust.py --check` (the Rust params equal the converter's text from the checked-in headers) (no hand-copied constants; `tests/oracle_params.rs` compares every field with the C headers).
Change (2026-10-18): controller (owner ruling of the same day "if it is enough, raise it", Rust port Task 12, branch `pqzl-rust`) — **the wasm32 op 7 prove limit is M = 8 on the Rust backend**: `pqzl::WASM_MAX_LEGS` and `pqz-ffi`'s `WASM_PQZL_MAX_LEGS` (Rust backend, the default) are 8; the C backend (opt-in) keeps 4, the limit that came from the C core's one client arena (M = 8 peaks at 495.3 MiB there). Criterion ("enough"): the Rust wasm32 M = 8 prove peak within the 255.6 MiB (268,012,304 B) that the C core's wasm32 M = 4 prove already takes (`artifact/runs/s6-docker-multi`), and native = wasm32 on the M = 8 vector proofs. Measured in run `d6` (bench build, feature `wasm-m8`): linear memory 123,076,608 B = 117.4 MiB (auditor on, prove p50 2,393 ms) and 111,017,984 B = 105.9 MiB (auditor off, 2,827 ms), one relation per process; a `Ctx` that keeps every relation's keys (all the vectors, M = 8 included) reaches 229,638,144 B = 219.0 MiB, still under 255.6 MiB; native = wasm32 on all 374 vector digest lines, the three M = 8 rows proved in wasm32 byte-equal. The wasm32 replays (`pqzl/rust/wasm/run_vectors.mjs`, `pqz-ffi` `vectors/replay_wasm.mjs`) now prove the three M = 8 rows instead of verifying the native proof (on the C backend they still verify it); `pqz-ffi`'s digest lines keep their frozen M ≤ 4 set (`expected-results.json` unchanged). No format, `proofSystemId` or accepted-set change: verify takes every M on every target, as before.
Change (2026-10-19): controller proposal (owner may override; Rust port whole-branch review, branch `pqzl-rust`; the owner had said "the D6 table decides whether gas needs re-calibration") — **the live `PQZ` gas rows stay as they are** for the Rust backend. Evidence: run `d6` (2026-10-18, `pqz-core/pqzl/rust/runs/d6/c-ffi-bench.jsonl` and `rust-ffi-bench.jsonl`, `ffi_bench 200`, verify through the C ABI, both backends in one session on the reference machine): the Rust backend is faster on every PQZL row, p50 / p99 ms Rust against C: Transfer 6.48 / 9.27 against 8.34 / 11.72 (p50 −22 %), Transfer0 6.24 / 9.23 against 8.15 / 11.26, Burn 6.28 / 9.12 against 8.09 / 11.05, Refresh 6.07 / 8.85 against 10.79 / 12.70, Register 3.36 / 5.66 against 4.22 / 7.17, DiscloseSender 3.39 / 5.92 against 4.54 / 7.35, DiscloseReceiver 3.67 / 6.41 against 4.71 / 7.08, DiscloseAuditor 3.73 / 6.57 against 4.86 / 6.84, TransferMulti1 / 2 / 4 / 8 6.37 / 8.80, 6.65 / 9.43, 7.19 / 9.70, 10.76 / 14.86 against 8.72 / 12.10, 9.09 / 12.30, 9.96 / 13.81, 14.83 / 21.42, TransferMulti1_0 / 2_0 / 4_0 / 8_0 6.31 / 9.81, 6.43 / 10.10, 6.88 / 9.77, 9.71 / 13.39 against 9.03 / 12.96, 9.31 / 12.89, 9.80 / 13.14, 13.89 / 18.62. That is a difference above the 15 % re-calibration rule (CTR-PQZ-10, owner 2026-10-15), but in the safe direction: the rows were calibrated on the C core, so they over-price the Rust backend. Ruling: keep the live rows; re-calibrate with the calib image on the chain host (P6f Task 6 method) at the live roll-out of the Rust-backed image on the SCaaS testnet, before or with the image switch, per the 15 % rule.
Change (2026-10-19): owner — the Rust-backed roll-out on the SCaaS testnet (image `scaas/nethermind-pqz:1.39.0-pqz3`, library `libpqz_ffi.so` sha256 `16dd99ce77d05a9bea9f54142979bc21511240aeff6d4442d784470a428c9caf`, self-test `ed910a2c…d205`; a third `engine.Pqz` schedule with re-calibrated PQZL rows) **stopped before going live** (owner ruling: stop and roll back) because of the PQZL Fiat–Shamir finding: a whole-code review found a P0 soundness break inherited from LaZer, in the C and the Rust core alike, whose fix changes the `proofSystemId`. The SCaaS testnet was never touched (no stop, backup or edit); **live stays `pqz2`** with its two schedules (schedule 1 from T = 1792205116). Kept as record for the next roll-out (branch `p6-rust-rollout`, `pqz-core/nethermind/runs/2026-10-19-*`): (1) two calibration runs `calibrate.sh pqz3 --ops 1,2,3,4,5,7`, both noisy: host load before / after 4.02 / 5.75 (run 1) and 2.96 / 3.65 (run 2), two external processes holding about two of the eight cores (`iii` 100 %, `gnome-shell` 83 %); the unchanged PQZH rows drifted up to +38 % / +29 % and ML-DSA +39 % / +75 % against the live values, and the PQZL p99s moved ±25 % between the runs while every PQZL p50 but one was 12–46 % below the C core's (D6). (2) Controller rule for the live PQZL rows (owner may override): per PQZL row, new = min(live, max(run 1, run 2)). The max of two noisy runs is an upper estimate of the true cost, and the result is never above live because D6 measured the Rust core faster on every PQZL row. The same rule applies to `selftestGas` (PQZL-led); PQZH rows and the ML-DSA prices stay unchanged, with no third run. Result: op 1 PQZL 83,072 B 5,409,000 → 3,454,000 (−36.1 %), op 1 PQZL 66,560 B 5,223,000 → 3,848,000 (−26.3 %), op 5 PQZL 2,567,000 → 2,406,000 (−6.3 %), op 7 PQZL M = 2 auditor off 3,827,000 → 3,331,000 (−13.0 %), `selftestGas` 2,567,000 → 2,406,000; every other row = live. Script `runs/2026-10-19-pqzl-rows.py`; `chain/add-schedule.py` gained `--id` (pqzl / pqzh / id prefix) and `--selftest`, with `--check`. (3) Copy rehearsal (`runs/2026-10-19-rust-copy-*`): pqz2 → pqz3 with the data kept, probe 388 ok before T (schedule 1) and after T, e2e 86 ok, then the final rows as a fourth schedule, probe 388 ok (`OP_SELFTEST` at 2,406,000). The next roll-out needs a new image and a new calibration under the new `proofSystemId`. Source: `pqz-core/nethermind/runs/2026-10-19-calib-rust-compare.md`.
Change (2026-10-19): controller proposal (owner may override) — PQZL Fiat–Shamir fix (plan `superpowers/plans/2026-10-19-pqzl-fs3.md`, [lazer#28](https://github.com/lazer-crypto/lazer/issues/28), check P6-FS) **F1, where z3 and z4 are absorbed**: in the prover right after `_lnp_tbox_compute_z34`, in the verifier right after a successful `_lnp_tbox_check_z34` (after its norm checks), `hash ← SHAKE128(hash ‖ enc(z3) ‖ enc(z4))` (encoding F2) before the existing `memcpy (hash0, hash, 32)`, so LaZer's `hash0` becomes `hz`; the matrices V4 (domain `M + 2(d−1) + 2 + Z`) and V3 (`+ 256`) and the tg round chain from `hz`, and the JL rows R / R' stay derived from `cseed` (the hash of `ty3 ‖ ty4 ‖ tbeta`). **Deviation** from the plan's "no further edits" (Tasks 2 / 3, recorded in the plan at `b49bd66`): `__schwartz_zippel_accumulate_z3` / `_z4` drew V and the R / R' rows from one seed; because the prover builds z3 / z4 from R / R' and `hz` depends on z3 / z4, they now take V's seed (`hz`) and a separate `rseed` (`cseed`); the specialised verifiers fold the JL rows on `cseed` (PRG `gr`) and V3 / V4 on `g0 = hz`, C and Rust alike. Why: V must follow z3 / z4 and R must precede them (LNP22's interactive order); the smallest change that reaches every consumer of `hash0` (`sz_z3`, `sz_z4`, the tg round, the SV's `g0`). Status: implemented in the C prover, generic and specialised verifiers `6d83208` (review fix `2789314`) and in Rust `420f409` (doc comment `13a8f8e`); evidence under F6.
Change (2026-10-19): owner (plan `superpowers/plans/2026-10-19-pqzl-fs3.md` Task 0, recorded `2fff733`) — PQZL Fiat–Shamir fix **F2, the encoding of z3 and z4**: one coder session `coder_enc_grandom3 (z3, log2stdev3)`, `coder_enc_grandom3 (z4, log2stdev4)`, `coder_enc_end` over centred copies (`fromcrt`, `mod`, `redc`), exactly as `encproof` writes them into the proof. Copies in the generic code (the verifier's `accumulate_z3` still reads z3); in the specialised verifiers `F.z3` / `F.z4` are not read again. Why: the spec rule that each prover message is absorbed in its proof encoding; injective (the decoding is bijective, one pad bit). Rejected: fixed-width `urandom3(z mod q)` (contradicts that rule). Status: implemented `6d83208` (C), `420f409` (Rust, `Coder::grandom` on the same `split` / `nones` as the proof codec).
Change (2026-10-19): controller proposal (owner may override) — PQZL Fiat–Shamir fix **F3, buffer sizing for F2**: `grandom_bits` moved from `pqz_rel.c` to `lazer/coder.c` as `coder_grandom3_nbits (v, log2o)` (`encproof` uses it too); `_lnp_tbox_hash_z34` takes `nbits/8 + 2` bytes from the arena and skips the coder when the arena is exhausted (the call then fails through the sticky error; review fix `2789314`); the C specialised verifier sizes its transcript buffer as `max(nfin, nty, proof_len + 1) + 64`, because z3 ‖ z4 is a bit range of the proof and the buffer is allocated before the norm checks; Rust's `Coder` is a growing `Vec`, the bit count summed first and reserved with `try_reserve` (`Error::Memory`, no panic). Why: LaZer's coder writes without bounds checks; exact sizing removes the overflow surface. Status: implemented `6d83208`, `2789314` (C), `420f409` (Rust).
Change (2026-10-19): controller proposal (owner may override) — PQZL Fiat–Shamir fix **F4, where h is absorbed**: right before `lnp_quad_many_prove` / `lnp_quad_many_verify` (`_lnp_tbox_hash_h`; Rust `hash_h` before `quad::many_prove` / `many_verify`), `hash ← SHAKE128(hash ‖ urandom3(h mod q ∈ [0, q), q, log2q))`, the proof's own encoding of h (`encproof`), on a copy reduced with `redp`; μ (`lnp-quad-many.c`) and the final challenge's seed `SHAKE128(hash ‖ t ‖ v ‖ w1)` (`lnp-quad.c`) receive this `hash2` with no edit to the quad files; the specialised verifiers draw μ from `g2 = PRG(hash2)` and run the final round over `hash2`; the Schwartz–Zippel γ challenges stay on `hash1`. Why: the same pattern as F1, and it removes the γ / μ domain overlap of review C (settled point 1). Status: implemented `6d83208` (C), `420f409` (Rust); evidence under F6.
Change (2026-10-19): controller proposal (owner may override) — PQZL Fiat–Shamir fix **F5, labels**: none. Why: the existing rounds have none, the h encoding has a fixed length per relation and the z3 / z4 encoding is self-delimiting (F2), consistent with the documented v2 chain (P6e D7). Status: in force with F1 / F4 (`6d83208`, `420f409`).
Change (2026-10-19): controller proposal (owner may override; the removal of v2 follows the owner's F9) — PQZL Fiat–Shamir fix **F6, the new id**: PQZL `proofSystemId` v3 = `keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v3")` = `0x8079d65b5e5c15e330f7e65c875776dfc1b0f6c93ced90c045e83865d116baef` (computed with `pqz_kat.py`'s `keccak256`); v2 (`0x2e07e6ed…798c2f`) is **removed** from the accepted set (forgeable). Why: the bump rule (P6e D4: a transcript change ⇒ a new id). Status: **done**. The id in `pqzl/src/pqz.h` (`6d83208`) and `pqzl/rust/src/lib.rs` (`420f409`); every other pin in `8af584b` (plan Task 5): `pqz-stmt` `PQZL_ID` (no v2 constant kept; a new test asserts `max_proof(v2) == None`), `pqz_kat.py`, the Nethermind `Harness/Program.cs` and `VectorFiles.cs`, `chain/engine-pqz.json` (all 20 PQZL rows, the id only; their gas is re-calibrated in Task 13) and `chain/add-schedule.py`, `PqzRegistryBase.sol`, and `pqzh/stark-backup/src/rel.rs` (not on the plan's list, but an input of the gate step `xcheck`, which compares its statements byte for byte with `pqz_bench.c`'s). Vectors regenerated with `pqz-vectors`: every PQZL proof, the statements (the id word; same sizes), `fee0.json`, `negative.json`, `worstcase_noise.json`, `selftest.json` (only the PQZL REGISTER `proof_keccak`); PQZH proofs byte-unchanged. `negative.json` 731 → 744 rows: **16 new rows "retired PQZL v2 proofSystemId"** (each of the 8 PQZL forms and 8 op 7 shapes, `expect 0`, reason `ProofSystemId`; the v2 id computed as keccak of the v2 string, no literal), and 3 "coder padding bit 7" rows dropped because the generator adds that row only when a proof's last byte is < 0x80 (existing generator behaviour). **Self-test hash unchanged** `ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205` (it covers `kat_digest` and the verdicts, not proof bytes), verified on both backends (`pqz-core/ffi/runs/fs5-*`, `fs5-c-*`), so no self-test pin moves. The fuzz input `regress/valid/crash-b9881…` (a valid v2 `DISCLOSE-RECEIVER` input) is re-proved under v3 as `fixture-disclose-receiver-rnd33` (honest set kept at 44). Checks (`8af584b`): `ffi/vectors/run.sh fs5` (`pqz-vectors --check` 16 files byte-identical, `pqz_kat.py --check` ok, tamper 191 / 191, wasm32 replay 53 cases, 0 fails), also with the C backend `fs5-c` (every file regenerated byte-identically, so C = Rust on every vector proof); `ffi/run.sh fs5` / `fs5-c` (native = wasm32, 29 digest lines, C backend = Rust backend); `pqzl/rust/run.sh fs5` (19 test binaries, 0 failed; the six `fnv … equal` lines; native = wasm32 387 digest lines); `stmt` 11 + 1, `pqzh/ligero` 13 + 17 + 8, `xcheck` equal, Nethermind 41 / 41, `forge test` `test/pqz` 37 / 37, KAT 19/19. Measured so far: (1) P6-FS binding test (F10), before the fix (`pqz-core/pqzl/runs/fs1-before.txt`, `fs1-review-fix.txt`; Rust `pqz-core/pqzl/rust/runs/fs1-test.txt`): 10 of 12 checks FAIL in both cores (the μ seed of the h-changed proof and the V3 / V4 seeds of the z3- and z4-changed proofs equal the honest proof's, in `verify` and `verify_fast`), the honest proof verifies; after (`pqz-core/pqzl/runs/fs2-tbox.txt`; Rust `pqz-core/pqzl/rust/runs/fs3-test.txt`): 0 of 12, `check_tbox_fixes: ok` with P6-SZ, P6-L2, P6-Z21 and P6-FS. (2) Specialised verifier (`pqz-core/pqzl/runs/fs2-sv-fixes.txt`, `fs2-sv-diff.txt`): `check_sv_fixes` ok; generic = specialised on 4,328 + 2,158 cases, 0 mismatches, PRG mismatches 0; the z21 differential 406 cases, 0 disagreements (its exit 1 is the both-verdicts flag, as in every gate since 2026-10-17). (3) `relfix.sh fs2` (`pqz-core/research/pqzl-measure/runs/fs2-*`): KAT 19/19, `fails 0` native, wasm32 and ASan + UBSan (the four UBSan notes of the v2 runs at the same sites, none new), native = wasm32 `proofs_fnv` on the six forms; new `proofs_fnv` (bench `5 5 63`: `R_REG`, `R_TX`, `R_BURN`, `R_DS`, `R_DR`, `R_TX0`) `b76964d5 78417d42 6c959845 ba3698fc 619971bf 25062de9` (v2: `8bd69f2d b9bbf854 0a5976da b4aa2e26 c800f2c6 a29a5747`), wasm32 `3 1 63` `df9c238e 27653466 5850b6d7 6a168a2c 85759c97 78ed03a7` (v2: `e70b5dc4 9304299b 0ea1c7a6 f39a8e64 96a6e906 a0afafc7`): Task 2 / 3 values, which change again with Task 4 (F7, F8). (4) C = Rust (`rust/run.sh fs3`, `41c708b`): `fs_bind` ok; the Rust bench `proofs_fnv` equal the C values above, native and wasm32, generic and `verify_fast`, `fails 0`; `oracle_prove` proof bytes C = Rust on all 14 relation codes (with its assert on the committed v2 vector proof disabled locally). At `41c708b` these were red until Task 5: every test against the v2 vectors or digests (`prove_eq_c`'s v2 assert, `ctx_eq_free`, memory peaks, `oracle_smoke`, the negative digests, `vectors.rs`, `run.sh`'s FNV lines), and until Task 4 the `norm_honest` cheating fixtures (`cheating_proofs_reject`, those rows of `oracle_verify` / `sv_diff`); all green since (`rust/run.sh fs4`, `fs5`). (5) Final v3 `proofs_fnv`, with F7 and F8 (`relfix.sh fs4`, C, = Rust `rust/run.sh fs5`): bench `5 5 63` `b935013d 258418fb 85ab8aa8 cd5eccf7 b3cb29a2 06c6a4a5`, native = wasm32; op 7 bench `2 2 16320` `e839a31e 4c63cef7 e88b6a9f 62e81d1d 40131675 ad7a159c 024ffaf8 f22cc134` (v2: `ee87e7a4 4294a892 4ff8974f cd21b056 bba9cd96 2fef961b 74c6be73 90c8fc70`); wasm32 `3 1 63` `c5d0e8c6 da580d8a 581fda3e 12c24f8f 1fc860f7 3ff37043`; full table `pqz-core/STATUS.md`, section "PQZL v3".
Change (2026-10-19): owner (plan `superpowers/plans/2026-10-19-pqzl-fs3.md` Task 0, recorded `2fff733`) — PQZL Fiat–Shamir fix **F7, D-2 (z2 rejection, prover-side zero knowledge)**: LaZer's `lnp-quad.c` ran `rej_bimodal` for z2 with `stdev1sqr` and no random sign (review D-2, `pqz-core/research/code-review-2026-10-19/D-lazer-fork.md`); it is replaced by **Rej1**, the one-time-commitment rejection of LNP22 / LNS21: with v = c·s2, reject if ⟨z2, v⟩ < 0, otherwise accept with probability exp((‖v‖² − 2⟨z2, v⟩)/(2σ2²))/M2, using `stdev2sqr` and the existing `scM2`. `rej_onetime` (C `lazer/rejection.c`, Rust `rand/rejection.rs`) always draws one `u`, as `rej_standard`, and ORs the sign test, so C and Rust consume the rng alike; `rej_bimodal` stays for z3 / z4. **No parameter regeneration.** Why: the codegen already computes `M2 = exp(1/(2γ2²))` for `rejs2 = 2`, commented "one-time commitments ([1], chapter 7)"; LaZer called the wrong test with σ1. Cost about 2× the expected z2 attempts; `PQZ_REJ_MAX` 1000 still fails with probability ≈ e^-42.5 ≈ 2^-61 at worst (R_TXM M = 4: 2·M1·M2 ≈ 24 expected z1 / z2 tries; Task 4 review; a liveness bound only, a cap hit is a prove retry). Rejected: (a) standard rejection `rejs2 = 1` (γ2 ≈ 12, σ2 ≈ 17× larger: all 14 `*.sage` regenerated, the estimator, `e_s1_proof` and `z21_msis` re-checked, new sizes and gas); (b) a random sign on z2 (no protocol slot in ABDLOP's `A1 z1 + A2 z2 − c·tA`). Status: **done** in `c57381b` (plan Task 4; review notes `0dc869d`): C `rej_onetime` (`lazer/rejection.c`, sign taken without a branch, then `rej_standard`, which draws one `u`) called from `lnp-quad.c` for `rej2 == 2` with `scM2` / `stdev2sqr` (the inline comments keep the file at 548 lines, so the `336,$` anchors of `sv/review/review.sh` still apply); Rust `rand/rejection.rs` and `proof/quad.rs`. Unit tests (C `pqzl/test/pqz_ub_test.c` `test_onetime` under ASan + UBSan, `pqzl/test/runs/ub-fs4.txt`, PASS; Rust `rand::rejection::tests::onetime_rej1`, ok, asserting the same counts): on 2^16 samples at `R_REG`'s `scM2` / `stdev2sqr`, `rej_onetime` = `rej_standard` OR (⟨z, v⟩ < 0) on every sample (5,438 with ⟨z, v⟩ < 0, of which `rej_standard` alone accepted 5,417, so the sign test is exercised), the same rng offset afterwards, acceptance 11,624 / 65,536 = **0.17737 against 1/(2·M2) = 0.17628** (M2 = 2.8364453; 0.7 standard errors; the old test accepted ≈ 1/M2 ≈ 0.35). Rejection attempts per proof (both loops, `relfix.sh fs4`): `R_REG` 14.0–16.2, `R_TX` 18.5–19.6, `R_TX0` 22.2–23.0, about twice the v2 / Task 2 runs. Parameters unchanged (`params/to_rust.py --check`: 15 files equal; `params/regen.sh` not rerun: it needs the LaZer checkout and the sage image, and its inputs are untouched). `relfix.sh fs4` `fails 0` native, wasm32 and ASan + UBSan (only the known UBSan notes); cheating fixtures re-exported (`rust/runs/fs4-export.txt`: every production verifier rejects them). Open: the M2 formula against LNP22 §2 / LNS21 and the extended-MLWE assumption for the one revealed sign bit, review B (Task 11).
Change (2026-10-19): controller proposal (owner may override) — PQZL Fiat–Shamir fix **F8, D-3 (β sign bits, prover-side)**: in the tbox sign sampler β3 reads bit `8 − nrbits` and β4 the next unused bit, a refill when `nrbits < 2`, and `rbits` (a secret sign) is cleared at the end. Why: the old indices made β4 read bit 8 of a `uint8_t` on every fourth attempt (β4 = +1) and β3 reuse β4's bit of the previous attempt (review D-3; leakage ≲ 3·10^-6 nats per proof, but a deviation from LNP22). Status: **done** in `c57381b` (plan Task 4), C `lazer/lnp-tbox.c` `_lnp_tbox_compute_z34` (refill when `nrbits < 2`, β4 at bit `8 − nrbits` after β3's decrement, `rbits` cleared with `explicit_bzero`, since `bytes_clear` is not in the library) and Rust `proof/tbox.rs` `compute_z34` (`crate::wipe`). `z34poc.sh`'s sed still makes its 5 edits, `l2dom/build.sh` its 1, `sv/review/review.sh` its three `336,$` controls 1 each. No separate unit test: pinned by the `proofs_fnv` lines and C = Rust proof bytes (`rust/runs/fs4-oracle-prove-noassert.txt`: 14 relation codes; then `fs5` with the vector assert). Not changed, by choice (Task 4 review): the Rust `rbits` wipe on the `PQZ_REJ_MAX` / error exits (stack only, the proof is discarded).
Change (2026-10-19): owner (plan `superpowers/plans/2026-10-19-pqzl-fs3.md` Task 0, recorded `2fff733`, also under CTR-PQZ-26) — PQZL Fiat–Shamir fix **F9, chain 7622's history**: **path B**, the SCaaS testnet is reset from genesis at the v3 roll-out (backup first, as on 2026-10-15/16), so v2 is dropped entirely, from the accepted set and from `pqz-stmt`. Rejected: path A (keep the data; it would keep a forgeable v2 verifier for blocks before the activation and v2 in `pqz-stmt`, plus a transcript switch in both specialised verifiers). Either way the deployed PQZ tokens and `UAPqzVerifier` hold v2 immutably and are redeployed. Status: decided; executed by plan Task 13 after the merge (new image, gas re-calibration, `patch-chainspec.py`, probe, `chain/e2e.py`, `smartcontracts/evm/script/pqz/e2e.py`); until then the SCaaS testnet stays on image `pqz2`, which accepts forgeable v2 proofs (a test chain; owner ruling).
Change (2026-10-19): controller proposal (owner may override) — PQZL Fiat–Shamir fix **F10, the mutate hook for the binding tests**: `pqz_test_mutate` / `test_mutate` kind 14 "z3 coefficient ±1" (test-only: `PQZ_TEST_HOOKS` / feature `test-hooks`), because the binding test needs a z3 change within Bz3 (kind 6, +2^20, exceeds it); the fuzz targets' `% 14` is unchanged, `oracle_codec` loops `0..15` (C = Rust on kind 14). The binding tests replace the earlier ruling "cheating-prover PoC first" (owner 2026-10-19, under CTR-PQZ-26): `pqz-core/pqzl/sz/fs_bind.c` (the fourth check of `check_tbox_fixes.sh`) and `rust/tests/fs_bind.rs` (`fs_trace_take`) only observe which seed each challenge is derived from; no forging or cheating-prover tooling is added. Why: the smallest test-only addition. Status: **done**, implemented in Task 1, `c5b2c99` (review fixes `c0bd890`, Rust run `b3cc772`); green on the final v3 code: `check_tbox_fixes` P6-FS 0 failed checks of 12 in `relfix.sh fs4` (`pqz-core/research/pqzl-measure/runs/fs4-tbox-fixes.txt`), `tests/fs_bind.rs` `VERDICT … ok (0 failed checks of 12)` in `rust/run.sh fs4` and `fs5`.
Change (2026-10-19): owner — **review G/H fixes A–E before the merge of `pqzl-fs3`** (plan `superpowers/plans/2026-10-19-pqzl-fs3.md` Task 4b; findings `pqz-core/research/code-review-2026-10-19/G-codex-pqzl-rust.md`, Codex, and `H-agy-pqzl-rust.md`, agy, triage table A–E). Rule: none of them may change proof bytes or the verdict on any valid input. (A, Codex G-3 + agy H-4) **Exact statement length and proof cap before any work**: `verify` / `verify_fast` / `prove` hashed the statement and built the relation keys (and the SV tables) before the statement's length was checked, so an oversized statement cost work proportional to its length (bounded in production by pqz-ffi's `MAX_INPUT`). Now `rel_of` (C `src/pqz_rel.c`, Rust `rel.rs`, the one function every entry calls) returns no relation unless the statement has exactly that relation's length (`stmt_bytes`), and both verifiers reject a proof over `MAX_PROOF` before the keys, the tables and the hash; Rust `stmt_hash` takes `u32::try_from(len)` (`Error::Input`, unreachable after the check) instead of a silent `as u32`. Same verdicts as before (those inputs were rejected later); only the order changed. Tests: `rel.rs` `bad_length_refused_before_caches` (no `Ctx` cache built), `pqz_sv_diff.c` `bad_length_before_keys` (the arena mark does not move), `tests/oracle_verify.rs` `bad_length_eq_c` (C = Rust, both verifiers). (B, Codex G-2 + agy H-2) **Rust prover wiping on every exit**: a drop guard `Wiped` (`lib.rs`, over `crate::wipe`, `no_std`, no dependency) now holds `s1`, `s2`, `m`, `t_a2`, the seeds `wh` / `ex0` / `ex1` (`rel.rs`), the 96-byte expanded mask seed and the copy `sv` (`proof/tbox.rs`), `s`, `yseed`, `c·s1`, `c·s2` (`proof/quad.rs`), so a `?` exit clears them too; `wipe`'s doc and STATUS Open item 8 state the platform boundary (plain stores + `black_box`: no volatile write without `unsafe`, no `zeroize`; compiler copies are not cleared). The C core has the same gap (`expseed`, `yseed`, the arena copies): recorded under Open item 8, not fixed here. (C, agy H-1) **`keys.rs` `canonical()`** uses `chunks_exact(8)` and requires an empty remainder (unreachable today: 16,384 and 16,512 B are multiples of 8); test `canonical_short_chunk`. (D, agy H-3) **C SV `|x|` without signed overflow**: `pqz_sv.c` `uabs64` negates after the cast to `uint64_t` (INT64_MIN → 2^63, no UB), used in `l2_sum`, the z4 norm check and the hint bound (the same pattern at all three sites; unreachable through the decoder); regression only: `check_sv_fixes.sh` and the differential show no change, neither feeds INT64_MIN. (E, Codex G-1) **constant-time prover arithmetic** (`set_upsilon` / `binexp`, `Int` add / sub; inherited from C `lazer/int.c`): branch `pqzl-fs3-ct`, commits `e847bec` and `7659e56`, recorded in the next Change line. Status A–D: implemented on branch `pqzl-fs3-fixad` (commit `d12bfe6`; `tests/memory.rs` exhaustion and peak tests green on locally re-proved v3 rows, `rust/runs/fixad-memory-v3local.txt`), checks `check_tbox_fixes` ok, `check_sv_fixes` ok, `sv/diff.sh fixad` 0 mismatches, `relfix.sh fixad` fails 0 with the Task 4 fnvs, `rust/run.sh fixad` green except the v2-vector tests that Task 5 regenerates; not merged.
Change (2026-10-19): owner — **review fix E, constant-time secret arithmetic in the prover, C and Rust** (Codex G-1; owner ruling: before the merge, both cores; branch `pqzl-fs3-ct`, commits `e847bec` (prover) and `7659e56` (keys, review notes), rebased on `cd881a6`; inventory, method and limits `pqz-core/research/code-review-2026-10-19/E-constant-time.md`). Rule: control flow only, proof and key bytes unchanged. (a) Fixed, no branch or address on witness-derived values: `int_add` / `int_sub` / `Int::add` / `sub` (sign and borrow branches, conditional negate → masked sign-magnitude select), `int_redc` (variable-time compare), the masked selects of `limbs_cnd_select` and the mpn restoring division (clang compiled them to a cmov of pointers plus a load; LLVM turned Rust's `Int::redp` mask into a branch → value barriers `pqz_ct_barrier` / `ct::mask`), `int_mul_sgn_self`'s assert on the secret β sign, `int_binexp` / `Poly::binexp` (the slack bits), dcompress decompose / power2round / make_ghint, `_int2i128`'s bound checks, the witness code (`dec_w`, `debit_witness`, `dr_witness`: branches, short-circuit checks, and the divisions by q, Δ, 16 that wasm32 keeps as `i64.div_s` / `rem_s` → `ct_sdiv` on the fixed-step restoring division), `_urandom_i64`'s asserts on accepted values; keys: `pqz_dec` / `dec` (division by 2Δ, the same way), `pqz_enc_seed` / `enc_seed` (per-digit check). (b) Public by design, the only declassifications: rejection verdicts (observable by design through the prove time; they leak only what the Fiat–Shamir-with-aborts / extended-MLWE analysis allows), each try's transcript messages at the hash sites (the coder stays checked), the accepted proof fields, witness-valid, self-check and resample verdicts, the samplers' try counts, the rejection-input abort. Check: `pqz-core/pqzl/test/ct.sh` (ctgrind: valgrind memcheck, witness / rnd32 / seeds / digits / s marked secret; C `-DPQZ_CTGRIND`, Rust test-only feature `ctgrind`); memcheck contexts before / after: prover C 135 / 0, Rust 141 / 0 (seven relations), keys C 18 / 0, Rust 21 / 0; final run on the committed tree with R_TXM M = 4 and three proofs per relation 0 / 0. Limits: executed paths, x86-64, branches and addresses only; wasm32 read from the generated code. Timing (controller, 2026-10-19, idle host, `pqz-core/pqzl/rust/runs/ct-timing/`): p50 new / `0dc869d` — verify_fast 1.00–1.02 native / 1.00–1.01 wasm32 (gas basis unchanged), generic verify 1.11–1.16, prove 1.04–1.09 native / 1.02–1.06 wasm32; no variable-time verifier copies needed.
Change (2026-10-19): controller proposal (owner may override) — **the second code review of the PQZL C core (2026-10-19), fixes Q-A…Q-H, Q-I recorded** (plan `superpowers/plans/2026-10-19-pqzl-fs3.md` Task 5e, branch `rev2-pqzl`; reports `pqz-core/research/code-review-2026-10-19/L-codex-pqzl-c.md` (Codex), `M-agy-pqzl-c.md` (agy, with the controller's triage table Q-A…Q-I), `N-claude-pqzl-c.md` (Claude); no P0 / P1 on the verifier path, no C = Rust verdict divergence). Rule: proof bytes and verdicts of valid inputs unchanged. (Q-A, N-1) **No 128-bit shift by a secret amount**: `pqz_bernoulli_fp` (`pqz_fixexp.h`) and Rust `bernoulli_fp` (`rand/fixexp.rs`) computed `mant << (sh & 1)` with `sh` from the Gaussian sampler / rejection exponent; on wasm32 that is a `__ashlti3` libcall, and compiler_builtins' version (every Rust wasm32 build) branches on the amount; now `mant + (mant & −(sh & 1))`, equal values; the C wasm helpers (`pqz_wasm_rt.c`, `ffi/csrc/wasm_ti3.c`) are branch-free already and no other variable 128-bit shift on secret data remains (`pqz_div_q56` shifts by its public loop counter, `_lnM_q56` works on the public `scM`). (Q-B, L C2-2, M C2-1, N-2; Open item 8) **Wipe on every exit, as Rust fix B**: `pqz_arena_wipe_release` (`pqz_arena.c`) zeroes, before releasing to the mark, every byte above the mark up to the high-water mark since the last wipe and the payload of every freed block below the mark (a block recycled from a free list may have held a secret; a listed block keeps its 16 link bytes); `pqz_prove` and the three client helpers (`pqz_keypair_from_secret`, `pqz_encrypt`, `pqz_decrypt_raw`, so `pqz_keygen` / `pqz_enc_seed` / `pqz_dec` too) use it, the verifiers keep `pqz_arena_release`; `wipe_vec` clears `s1`, `s2`, `m`, `tA2`, the secret key and the encryption randomness (and their NTT copies) wherever they were allocated; `explicit_bzero` (volatile `pqz_zeroize`) of `expseed[96]` (`lnp-tbox.c`), `yseed` (`lnp-quad.c`), the sampler's per-try `buf` / `w` and the masks' uniform parts `out` (`grandom.c`), the `debit_witness` / R_DR witness stack arrays, and `pqz_dec`'s `w` on its error exit. Boundary: what the compiler copies into registers or spills is not cleared (as in Rust). (Q-C, C-F2, L C2-1, M C2-3, N-3; Open item 2) **No write after a failed allocation — fail-stop**: `pqz_arena_alloc` (LaZer's `_alloc`, whose results LaZer never checks) traps (`__builtin_trap`: SIGILL on x86-64, `unreachable` on wasm32) when a block does not fit; the 1 MiB shared sink and the unused `pqz_arena_realloc` are removed; the specialised verifier's own allocations, which check, use `pqz_arena_try_alloc` (NULL and `PQZ_ERR_ARENA`, the call returns 0 and `pqz-ffi` reports status 4 as before). Alternatives considered: (a) a sink at least as large as the largest single allocation (a static bound from the parameter headers, e.g. `R_TXM8`'s 13–14 MB `A1`) — rejected: every later failed allocation still aliases the same sink, so structures and their element arrays overwrite each other and a pointer read back from the sink can be proof data, i.e. writes do follow a failed allocation; (b) `setjmp` / `longjmp` from the allocator back to the entry point — rejected: libc symbols in the libc-free library (`check_symbols.sh`) and no `setjmp` on freestanding wasm32; (c) a check at every entry point against the call's measured peak — rejected: not a static bound, larger. Consequence: the opt-in C backend stops the process (instead of a NodeFault) when LaZer itself runs out of arena (A, a relation's keys, the prover, the generic verifier); not reachable from input (the specialised verifier's sizes are input-independent; `ARENA_SMALL` 512 MiB against a measured peak of 268,297,200 B, a 2.0× margin, `ffi/runs/rev2-c-summary.txt`), and `tests/fault.rs`'s graceful 18 MiB band (exhaustion in the SV tables) still gives status 4. (Q-D, L C2-3) **The entropy decoders stop at the first failed read** (`coder.c` `coder_dec_ghint` / `coder_dec_grandom` return before advancing `in` past the buffer; `pqz_decproof` stops through `err`): source-level pointer UB on truncated proofs, verdicts unchanged (they rejected and still reject). (Q-E, N-4) **The bounds asserts return**: `spolyvec_insert_elem` / `spolymat_insert_elem` past `nelems_max` hand out a scratch poly (sticky error set) instead of writing past `elems`; `coder_dec_urandom5/6` refuse a header above `nelems_max` before their input-sized buffer (latent: no PQZ path reaches them). (Q-F, M C2-4…C2-7; Open item 4) `aes256ctr.c` no `NULL + 0`; `INTVEC_T` and the `Z`-sized pointer arrays of `lnp-tbox.c` are never zero-length (M = 0, nbin = 0, Z = 0); `pqz_keys.c` `canonical()` requires `n % 8 == 0` (Rust fix C's twin); `pqz__div` refuses `nn < dn` or `dn < 1` (`PQZ_ERR_INTERNAL`). (Q-G, N-5) **Masks through the value barrier**: `pqz_ct_barrier` on the masked selects of `pqz_int_set_centred` (`pqz_glue.h`), `dec_w` (two) and `debit_witness`'s rounding sign (`pqz_rel.c`); `test/ct.sh`'s summary lines name the compiler and `ffi/build.rs` writes the C compiler and its version into the build script's log. Deviation: `pqz_csubq` (`pqz_ntt.h`) gets no barrier: its mask feeds an add (no select of two operands, no pointer), it runs in every NTT butterfly of the verifiers, where an `asm` barrier would block vectorisation, and memcheck (fix E) sees no branch there with clang 18; the owner may order it (and a timing run). (Q-H, N-6) `check_symbols.sh` refuses test-hook symbols (`pqz_test_*`, `pqz_sv_test_*`, `pqz_sz_trace*`, `pqz_l2dom_poc`; a ctgrind build adds none) in library objects, `test/check_symbols_neg.sh` checks it on the `-DPQZ_TEST_HOOKS` objects; `pqz_stmt_hash`'s comment (statements up to 215,936 B). (Q-I, M C2-8; Open item 6) global mutable state: recorded, no code (the node uses the Rust crate; `pqz-ffi` serialises every C call). Tests: `pqzl/test/ub_test.sh` parts d–h (`pqz_ub_test.c`; ASan + UBSan with pointer-overflow back on: d Q-A equality, e Q-D, f Q-E / Q-F, g Q-B on the arena, h Q-C undersized arenas trap with no ASan report); the same tests on the pre-fix core fail (`pqzl/test/runs/ub-before-rev2*.txt`: UBSan `NULL + 0`, the M = 0 VLA, ASan heap- and global-buffer-overflow, the decoder pointer past the buffer, non-zero arena after keygen / enc / dec / prove). Status: **done** (`ea4b00d` Q-A, `d08e3f9` Q-B…Q-H); evidence in `pqz-core/STATUS.md` "Second code review: the PQZL C core (2026-10-19)". **Owner rulings 2026-10-19 (both proposals accepted):** (1) the Q-C fail-stop on the opt-in C backend is accepted (consensus-neutral: a stopped process and a node fault both give no verdict; production uses the Rust core; if the C backend ever becomes a node default, build every key and table at start-up so an undersized arena fails at boot); (2) the fuzz builds re-enable the `vla-bound` and `pointer-overflow` sanitizer checks (`ffi/build.rs`, `pqzl/sv/fuzz.sh`; Q-F removed the only reasons for the exclusions), done at plan Task 7 with the campaigns that validate it, `-fno-sanitize-recover` kept, STATUS Open item 4 updated then. **Open (owner, needs a timing run asked for first):** value barriers on `pqz_csubq` (every NTT step of the verifiers; a barrier would block vectorisation; memcheck clean with clang 18) and on the select in `pqz_int_modq` (`pqz_glue.h:46`), left without one in Q-G.
Change (2026-10-19): controller proposal (owner may override) — **the deferred minors of the PQZL Rust port** (TODO "PQZL Rust port follow-ups" item 5; port plan `superpowers/plans/2026-10-17-pqzl-rust-port.md`, ledger Tasks 10, 10b, 11, branch review C-M5), branch `rev2-pqzl`: (1) `pqz-ffi` `tests/fault.rs` (Rust backend) with a denying allocator in the test binary: the fallible `Ctx` allocation of `ffi/src/pqzl/rust.rs` denied → status 4, `out` untouched; end to end through the precompile, a fresh `Ctx` whose cache allocations (≥ 1 MiB) are denied → `Error::Memory` → status 4; the panic path through the new test hook `TEST_PANIC` → `…00`, status 3, the `Ctx` dropped and rebuilt; afterwards each time VALID (hooks `TEST_PANIC`, `drop_ctx`, feature `test-hooks` only); (2) `tests/verify_only.rs` (C-M5): on the Rust backend the process heap (a counting allocator) stays within 4 KiB of its value before the 5,000 mixed calls after every one of them and their peak at or below the warm-up's; (3) the two-limb rejection case S3 is compared C = Rust (`pqz_shim_rej_limbs`, `c_rej_limbs` / `rand_rej_limbs`, `oracle_rand::rejection_saturation_eq_c`, 200 random seeds); (4) `tests/memory.rs` prints its `PQZL_MEM_*` settings; (5) `gate.sh` writes its summary and PASS / FAIL line to `runs/gate/<label>-summary.txt`. Status: **done** (`d5bcc33`).

**Why.** LNP22 via a LaZer fork with six rewritten layers runs portably and deterministically in the node, the prover and WASM; one implementation, no Solidity verifier; kill criterion on size and verify time.
**Cost if wrong.** We own a C fork; upstream fixes are merged by hand.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:277`

Change (2026-10-20): **review B finding B-1 (P0)** (`pqz-core/research/code-review-2026-10-19/X-review-b-transcript.md`): the Schwartz–Zippel challenges V3 / V4 of the z3 / z4 JL accumulators are drawn from hz (`hash0`), after z3‖z4 but BEFORE the commitment `tg` to the mask g, while the β4 / υ / bin / l2 accumulators use the post-`tg` hash; all feed the accumulators whose coefficients 0 and d/2 of `h = g + acc` must vanish, so a prover who knows V before committing g could cancel a z3 / z4 error (all four implementations and both provers; upstream LaZer the same; confirmed in code by the controller; **confirmed by review A** (`W-review-a-pqzl-rust.md`, A-1): a patched prover's z3 / z4 errors cancelled through `g` were accepted by the Rust `verify` and `verify_fast` on all 14 relation codes, the same tamper without cancellation rejected; a mint path through the exact-ℓ2 row is a hypothesis, not built). Fix: draw V3 / V4 from the post-`tg` hash (same domains; R / R' stay on cseed), plus a `tg`-mutation case in the P6-FS binding tests; a transcript change. **Owner ruling 2026-10-20: fold the fix into the `K_MAX` = 16,384 parameter regeneration (one `proofSystemId` bump for both)**, not a separate v4 now; nothing deploys v3 meanwhile (the SCaaS testnet stays on v2 until plan Task 13). The lazer#28 comment draft gains this finding before posting. **Owner 2026-10-20, after review A's confirmation: keep the fold-in (b)** — the fix ships with the 16k parameter regeneration, not as a separate v4 (all chains are test-only; the SCaaS testnet holds no real value). Review A's A-2 (P3: the last β4 row and the υ row share one Schwartz–Zippel challenge, harmless because B4² = −1 forces the freed pair to zero) is renumbered in the same bump. Status: decided; built with the 5h A' step. **Built (5h Task 8a, 2026-10-21, on today's n = 2048 / q, branch `pqz-16k`; the id bump is Task 8d's):** V3 / V4 from the hash after `tg` in `lnp-tbox.c` (prover and verifier), `pqz_sv.c`, `proof/tbox.rs`, `sv.rs`; A-2: υ, binary, exact ℓ2, V4, V3 one domain up (υ at M + 2(d − 1) + 1); review A's cheating prover as `pqz-core/pqzl/rust/tests/cheat_b1.rs` (before the fix modes 1 / 2 were accepted by all four verifiers on all 14 codes, C included; after it all rejected), `test_mutate` kind 15 (tg) in both `fs_bind` tests (4 of 18 checks failed before, 0 after), A-2 as a fifth check of `check_tbox_fixes.sh`; vectors, cheating fixtures, the fuzz `regress/valid` input and `UAPqzVerifier.PROBE_PQZL` regenerated, the self-test hash unchanged (pqz-core/STATUS.md, "Transcript B-1 / A-2").

Change (2026-10-20, owner, 5h plan review Q1): **the 16k modulus is q = 2^50 − 42,310,535** (prime; q − 1 = 2^3·19·43·431·5659·70627 keeps the Ligero subgroup of today's PQZH; 2^50 − 71 has q − 1 = 2^3·17·p and no usable Ligero domain, nor had A''s 2^54 − 327), Δ = 2^30 − 41; K_MAX 16,384, the mint margin and the security estimates unchanged; PQZL and PQZH share q. Rides the one `proofSystemId` bump of plan Task 5h (16k + B-1 + A-2 + R_REG). Status: decided.

Change (2026-10-20, controller record): **the one `proofSystemId` bump is part B of plan 5h, not part A** (D23): part A (state, B, shield, pool, fees, names, kinds) changed no relation, vector or id (`shieldIn` is a rename of header word 480); part B carries, under PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k40-q50l4/v4")` and a PQZH Ligero v2 id, the 16k parameters (n = 2560, q = 2^50 − 42,310,535 by owner Q1 / D25, Δ = 2^30 − 41, `K_MAX = 16,384`), **B-1** (V3 / V4 from the post-`tg` hash in all four implementations and both provers, the `tg`-mutation test, review A's cheating prover as the regression fixture), **A-2** (the last β4 row and the υ row get distinct Schwartz–Zippel challenges) and the **`R_REG` message bound to the UA id** (UA-6; controller ruling 2026-10-21 for Task 8a: by UA-6 §9 / U13 the 32-byte message stays opaque to the relation, the statement layout, the verifier and the vectors; its pre-image `uaMessage(0x0142, POP, popDigest(ua, keyHash(0x0142, pk)))` is the registry's and the clients' (built in UA-6), so 8a documents it on `pqz-stmt`'s `Register` and re-pins `UAPqzVerifier.PROBE_PQZL` for the new proof bytes, the probe's message staying `keccak256("SCAAS-PQZ-SELFTEST-V1")`; no PQZ vector is bound to a real UA id, no copy of UA-6's hashing in `pqz-vectors`); a new `UAPqzVerifier`, a new `Env` version and new PQZ releases; v3 and PQZH v1 are retired at the SCaaS testnet reset (plan fs3 Task 13), nothing deploys v3 meanwhile. Status: decided (owner: fold B-1 into the 16k regeneration; Q1 modulus); pending (part B).

Change (2026-10-23): controller proposal (owner may override; P6 mandate) — **plan 5h Task 8d part 1: the one `proofSystemId` bump of Task 8, one id per parameter set and proof system** (D23: B-1, A-2, the `R_REG` message binding of 8a and each set's parameters; a proof of one set never verifies under another set's id). The labels are written once, in each set's `pqz-core/params/sets/<set>/set.toml` (`pqzl_id`, `pqzh_id`); `gen_set.py` hashes them (Keccak-256) into `pqz_set.h` (`PQZ_PROOF_SYSTEM_ID`, `PQZ_PQZH_ID`), `rust/set.rs` (`PQZL_ID` / `PQZH_ID` and the labels; `pqz-stmt` and the `pqzl` crate read them), `set.json` (`pqz_kat.py`) and `PqzSet.sol`. Scheme: PQZL `scaas/pqz/lnp22/mlwe-d64k<k>-q<log2q>l4/v4` (k = n / 64, log2q = ⌈log2(q − 1)⌉; `n2560-kmax16384`'s is D23's `mlwe-d64k40-q50l4/v4`), PQZH `scaas/pqz/pqzh/ligero-fq<log2q>-n<n>k<k>t<t>-keccak256-zk-proven/v2` (the field and the Ligero preset of `[pqzh_preset]`). Ids: `n2048-kmax1024` PQZL `…/mlwe-d64k32-q42l4/v4` = `0x19fad50a2dfdd6351dd0d52203ad440d7e6d5b345641f877bfcd7382079a326d`, PQZH `…/ligero-fq42-n32756k817t121-keccak256-zk-proven/v2` = `0x9d945089e2a5c39b287888bcd87974934d20181176465b1ab099b5cd1ca7dca4`; `n2304-kmax4096` PQZL `…/mlwe-d64k36-q46l4/v4` = `0x15d16d775baed2374e6e41fd153eb6d0cfc75b3b59a7057943be2338e0cb608a`, PQZH `…/ligero-fq46-n45752k952t120-keccak256-zk-proven/v2` = `0xe4bc6d17ac1395670158d149b01898476ea32ffa482ce3f4c3f495d6b9885730`; `n2560-kmax16384` PQZL `…/mlwe-d64k40-q50l4/v4` = `0xa3db21fc14c959e7e48b795b0819c0e856a0689765c80bda291602b6ff70262d`, PQZH `…/ligero-fq50-n32756k817t122-keccak256-zk-proven/v2` = `0xe83ad1daa5aab5ebf86d484b303e607d76233c680ce87dd0b627021c48109851`; `n2816-kmax65536` (core only) PQZL `…/mlwe-d64k44-q54l4/v4` = `0x9d23a0de6403d1a37aefcf61821fcfb46dc53021d12a9232467b570ac3bd53a3`. `gen_set.py` refuses a label that does not name its set's k / log2q (PQZL) or field / preset (PQZH), two equal ids across all sets and a retired id. **Retired, refused as unknown ids:** PQZL v2 `0x2e07e6ed…798c2f`, PQZL v3 `0x8079d65b…16baef`, PQZH v1 `0x0a47a768…2fead4` (`pqz-stmt` test `retired_ids_refused`; a negative vector row per retired id and form / op 7 shape in every set's `negative.json`). Every set's vectors regenerated: at `n2048-kmax1024` the statements differ only in the id word (bytes 32..63), every proof (the transcript hashes the statement), the hashes / digests over them and `negative.json`'s rows that depend on proof bytes and lengths; the self-test hash is unchanged (it covers verdicts, not proof bytes). Status: built on branch `pqz-8d1` (8d part 1, off chain); the contracts (`PqzSafety`, the tests' ids, the EVM Ligero fixtures) follow in 8d part 2. Source add: plan 5h Task 8d, `.superpowers` ledger `task-8d-report.md`.

### CTR-PQZ-10 — Native never-crash precompile on the SCaaS testnet
- old: R279 · status: current · owner: yes · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-10 · superseded-by: —

Change (2026-10-14): owner — the one `PQZ` precompile verifies BOTH proof systems, PQZL (`keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")`) and PQZH Ligero (`keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")`), dispatching on the statement's `proofSystemId` through `pqz-ffi` (`pqz-core/ffi/`); same address, same input framing, `OP_SELFTEST` covers both ids. P6f: gas priced per id from each system's measured p99 adversarial verify (CTR-PQZ-11), node limits sized for the PQZH input (`MAX_INPUT` 393,216 B; `TxPool.MaxTxSize` and the block byte limit must admit it). PQZH is not offered on chains without the precompile (owner 2026-10-14).

Change (2026-10-14): controller proposal (owner may override) — P6e plan D5 (branch `p6e-b2`, Task 9): per-id `MAX_PROOF` is 98,304 B for PQZL (unchanged) and 262,144 B for PQZH; the precompile's `MAX_INPUT` rises from 262,144 to 393,216 B, because the largest input, a PQZH transfer of `u8(op) ‖ be32(len) ‖ stmt ‖ proof` = 5 + 83,072 + 262,144 = 345,221 B, did not fit the old value. The PQZH verifier's length bound is the exact largest parseable proof per relation (at THE preset `R_TX` 235,470 B, `R_BURN` 234,744 B, `R_REG` / `R_DS` / `R_DR` 190,458 B, all under 262,144 B), checked before the statement or the proof is parsed; it rejects nothing the parser would accept, it only rejects early. If a proof exceeded the bound the prover would prove again with fresh randomness drawn further from the same hedged SHAKE256 output (at most 16 attempts), a guard only: every proof is within the exact bound by construction. Consequence for P6g (not decided here): a PQZH transfer's proof costs ≈ 9.2 M gas of EIP-7623 calldata floor, so `INLINE_MAX` per proof system (≈ 8 for PQZH) is a P6g question. Source: `superpowers/plans/2026-10-14-p6e-relations.md` (D5, Task 9), `research/pqzh-ligero.md` §13.
Change (2026-10-14): controller proposal (owner may override) — the D15 / R6 rules and the D5 limits above are enforced by `pqz-stmt` `decode_input` before any proof code (P6e Task 5; SELFTEST exactly `06 00000000`). Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D5, D15, Task 5; branch `p6e-a2`.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D10 (branch `p6e-a3`, Task 7): one Rust crate `pqz-core/ffi` (`pqz-ffi`) is the only way into either verifier: C ABI `int pqz_precompile(input, len, out, out_len)` (`pqz_ffi.h`; status 0 ok, 1 revert = input over `MAX_INPUT`, 2 bad arguments, 3 a caught panic in the decode / verify logic, input-caused, output `…00`, 4 a node fault, below; a failed Rust heap allocation or an OOM kill still aborts the process) for the node, the same as a Rust API, and a `prove` feature (keygen, enc, dec, prove of both systems; wasm32 proofs byte-equal with native) for the clients; decode by `pqz-stmt`, dispatch on `proofSystemId`, PQZL to the specialised verifier only (R5), PQZH to Ligero without its bench feature; one process-wide lock around every libpqz call (`STATUS.md` Open 6), run on one worker thread with a fixed 16 MiB stack (the core's stack use never depends on the caller's thread), `catch_unwind` on every entry, arenas allocated once and sized from measurement (verify-only 144 MiB ≥ 1.5 × the adversarial-corpus peak 95.2 MB, prove 448 MiB). Faults split (controller 2026-10-14, answering this branch's open question): an input-caused panic is status 3 with `…00` (the same on every node); a fault of the node, not of the input (arena exhaustion, worker or core unavailable, failure to reserve the arena, a failed self-test computation; anything not certainly input-caused), is status 4 = no result, `out` untouched, and P6f aborts block processing instead of treating the input as invalid; pq-zero-knowledge.md CTR-PQZ-10 says so. Source add: `pqz-core/ffi/README.md`, `pqz-core/STATUS.md` §"`pqz-ffi`".
- **Change 2026-10-15 (owner):** the SCaaS testnet (resettable): the controller runs P6f Task 10 itself — after the copy gate (T7–T9) passes it backs up the current SCaaS testnet data, then resets the SCaaS testnet with a fresh genesis carrying the PQZ and ML-DSA precompiles from block 0 — and later makes the P6g / P6i deploys on the SCaaS testnet without a per-step owner approval. Chain 22776 (mainnet) changes stay the owner's. Status: owner.
- **Change 2026-10-15 (owner):** P6f Task 6 gas calibration is **one run**, not two runs on different days; re-calibrate before chain 22776 or when a later measurement differs by more than 15 %. Plan `superpowers/plans/2026-10-14-p6f-precompiles.md` Task 6 updated.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D13 (branch `p6e-a3`, Task 7): `OP_SELFTEST` returns `keccak256(kat_digest ‖ u8(pqzl_valid) ‖ u8(pqzl_invalid) ‖ u8(pqzh_valid) ‖ u8(pqzh_invalid))` with `kat_digest = keccak256(A digest ‖ keccak256(pk) ‖ keccak256(u ‖ v) ‖ M ‖ keccak256(fft) ‖ u8(fft_ok))` (A as `pqz_kat.py` writes it, KeyGen and Enc / Dec from fixed seeds, one Ligero FFT round trip) and one compiled-in `R_REG` proof per id, valid and under a statement with one message bit flipped; today `0xed910a2c…1333d205`, frozen with the vectors (`selftest.json`, Task 11). Source add: `pqz-core/ffi/src/selftest.rs`.
Change (2026-10-14): controller proposal (owner may override) — P6e plan D12, fuzzing set-up (recorded with Task 12, branch `p6e-a6`; implemented by Task 10 on its own branch): clang 18 libFuzzer on stable Rust — the C core with ASan + UBSan, `pqz-ffi` and Ligero instrumented with `-C passes=sancov-module`, panics turned into aborts in the fuzz build; no nightly / `cargo fuzz` unless the stable flags do not link (then an owner step to install nightly). Targets: `pqz_precompile` on raw input, edit scripts over an honest input of every form and both ids (PQZL also generic vs specialised verifier), the codecs (`encode(decode(x)) = x`, D15). Corpora: only small structure-aware inputs committed, minimized, under `pqz-core/fuzz/corpus/<target>/` (≤ 4 MB per target), large seeds rebuilt from the vectors at run time, crash inputs committed as regression cases. Continuous = long runs per target on the owner's machine under `scripts/capped` with text logs, plus a CI job `pqz` (build, KATs, vectors `--check`, symbol scan, 60 s per fuzz target, no artifacts). If the owner's "no CI workflow for now" (session 4) covers this job, the local runs alone stay. Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D12, Task 10.
Change (2026-10-15): controller proposal (owner may override) — P6e plan D12 implemented (Task 10, branch `p6e-a5`): **no CI workflow for now** (controller 2026-10-14: the plan's CI job `pqz` is not built; fuzzing is local runs only, `scripts/capped pqz-core/fuzz/run.sh <target> <seconds>`, text logs in `pqz-core/fuzz/runs/`, one campaign at a time). Stable Rust 1.97.1 sancov (`-C passes=sancov-module` + coverage `llvm-args`) links with clang 18's libFuzzer, so no nightly and no owner step. Panics abort through a panic hook rather than `panic = "abort"` (which `pqz-ffi` refuses natively): this also turns the panics `pqz-ffi` (status 3) and Ligero would catch into findings; overflow checks and debug assertions are on. Targets `precompile` (raw bytes into the C ABI), `mutate` (edit scripts over the 24 honest inputs of `smartcontracts/vectors/pqz/`, PQZL decoded-field mutations, SV vs generic verifier on every 256th mutated PQZL input that decodes), `codec` (D15 round trips of `pqz-stmt` and of the PQZL proof coder); every input: no panic, no status 3 / 4, deterministic, `…01` only for the unmodified honest inputs, verify-only arena peak ≤ 96 MiB (= 144 MiB / 1.5). Seeds rebuilt at run time from the vectors (`seeds.py`); committed corpora are the minimized inputs ≤ 512 B. PQZH proofs have no separate encoder (Ligero reads them exactly), so their D15 property is covered by `mutate` (any accepted modified proof is a finding) instead of a codec round trip. Source add: `pqz-core/fuzz/README.md`, `pqz-core/STATUS.md` §"Fuzzing".

Change (2026-10-15): controller proposal (owner may override) — P6f D1 (plan `superpowers/plans/2026-10-14-p6f-precompiles.md`, branch `p6f`): the precompiles come from a Nethermind **plugin** `Nethermind.Pqz.dll` in `/nethermind/plugins` (registers `IPrecompileProvider` = the Ethereum table + 3 addresses and `ISpecProvider` = `PqzChainSpecBasedSpecProvider`, the Taiko pattern), compiled against the pinned image's own DLLs; enabled iff the chainspec has `engine.Pqz`; no Nethermind patch. Built and tested: 36 / 36 unit tests, 1-h P/Invoke harness clean (6,955,371 inputs), probes and e2e on the copy of the SCaaS testnet.
Change (2026-10-15): controller proposal (owner may override) — P6f D3: addresses outside EIP-1352 — `PQZ` = `0x5caa500000000000000000000000000000000f01`, `MLDSA44` = `0x5caa500000000000000000000000000000000012`, `MLDSA65` = `0x5caa500000000000000000000000000000000013` (above `0xffff`, outside RIP-7587's `0x100`–`0x1ff` and the OP / Taiko / Arbitrum system ranges; low bytes = the old `…0F01` and EIP-8355's 0x12 / 0x13); the same on 22776. Checked empty (code, balance, nonce) before activation on the copy. Closes pq-eips-vs-scaas.md Q6.
Change (2026-10-15): controller proposal (owner may override) — P6f D4: status mapping — `pqz-ffi` 0 ⇒ the 32 bytes; 1 ⇒ failed call (all gas); 3 ⇒ `…00` + warning `PQZ-INPUT-PANIC keccak(input)`; 2, 4, any other ⇒ critical `PQZ-NODE-FAULT` and `Environment.Exit(120)` (the block is never sealed or imported, nothing marked invalid, a restart re-processes); also from `eth_call` and the prewarmer.
Change (2026-10-15): controller proposal (owner may override) — P6f D5: ML-DSA-44 / -65 by .NET 10 `MLDsa` on the pinned base image's OpenSSL 3.5 (`MLDsa.IsSupported` checked at start-up; false ⇒ refuse to start), EIP-8355 exactly (empty context); no fallback needed (every ACVP / EIP-8355 / UA vector agrees).
Change (2026-10-15): controller proposal (owner may override) — P6f D13: image `scaas/nethermind-pqz:1.39.0-pqz1` built locally by `pqz-core/nethermind/build-image.sh`, never pushed: every `FROM` pinned by digest, `libpqz_ffi.so` release (no `prove`, no `test-hooks`, `--locked`), labels `scaas.pqz.commit` / `scaas.pqz.ffi.sha256` / `scaas.pqz.selftest`; `pqz1` = `sha256:c53359a69bfae32a48412940fa98c744d06f55ab3e8da41e0b5ac82d2e8bea4f` (library `12495e8b…7d87`, no test-hook or GMP / MPFR / HEXL names, exports only `pqz_precompile`).

Change (2026-10-16): owner decision L-3 implemented + controller proposals (owner may override) — P6-ANON Task S3 (branch `p6-anon-s3`, run `pqz-core/ffi/runs/s3a-*`): op 7 is in `pqz-ffi` (no new dispatch code: `pqz_stmt::decode_input` returns it, PQZL `pqz_verify_fast(7, …)`, Ligero `verify(7, …)`); **`ARENA_SMALL` = 512 MiB (owner)**, measured verify-only peak over the whole adversarial corpus with every form's and every built op 7 shape's keys and SV tables kept = 268,240,256 B (honest + self-test 268,113,792 B), margin 2.00 ×, `arena_used` constant after every call, 8-thread and 1 MiB-stack runs equal to serial, status 3 / 4 never. Proposed: (1) **`ARENA_BIG` = 1 GiB native** (was 448 MiB): the prove arena with every relation loaded peaks at 853,679,872 B (after `R_TXM8_0`), margin 1.26 × (`R_TXM8` alone 836 MB in L3); (2) **wasm32 has one arena, `ARENA_BIG` = `ARENA_SMALL` = 512 MiB**, so linear memory never holds two (the wasm32 prove run of all six forms and every op 7 shape with M ≤ 4 of both ids: 594,739,200 B of linear memory, was 631 MB with 144 + 448 MiB); (3) **wasm32 `prove` refuses PQZL op 7 with M > 4** (`pqzl::WASM_PQZL_MAX_LEGS`) as `ProveError::Statement(Reject::Legs)` before any core work (L3: wasm32 `R_TXM8` prove peaks at 646–669 MB, `R_TXM4_0` all-loaded 432.7 MB); verify has no such limit; M = 8 is for native clients, M ≤ 8 stays the PQZL limit (D20).

Change (2026-10-19): controller proposal (owner may override) — **second whole-code review of 2026-10-19 (PQZH Rust, reports I / J / K), fixes P-D, P-E, P-F, P-H, P-I** (plan `superpowers/plans/2026-10-19-pqzl-fs3.md` Task 5c, branch `rev2-pqzh`; triage `pqz-core/research/code-review-2026-10-19/J-agy-pqzh-rust.md`). No PQZH proof byte or verdict changes. (P-D) **PQZH verifier out of memory is a node fault, not an abort**: `pqzh_ligero::try_verify` returns `Err(Oom)` when a buffer sized by the parameters and the relation (the decoded w / q / h, the opened columns, the domains H_k and H_n, the challenges, the linear test's own vectors, the per-column evaluation buffers, `batch_inv`'s) cannot be reserved (`try_reserve_exact`); `verify` stays the bool (false on `Oom`); pqz-ffi's `pqzh::verify` maps `Oom` to `NodeFault` (status 4), as PQZL's `Error::Memory`. Not covered, still an abort: the decoded statement (no larger than the input the caller holds), the layout tables (a few KB), the shared A matrix (512 KiB, built once per process at first use) and allocations inside std / sha3; this paragraph's text in pq-zero-knowledge.md and `ffi/README.md` says so. Test `pqzh/ligero/tests/oom.rs` (an allocator that refuses allocations above a limit: `Ok(true)` at 1 MiB, `Err(Oom)` at 200 / 50 / 20 kB, never a verdict, never an abort). (P-E) `#![forbid(unsafe_code)]` in `pqzh-ligero` (`deny` only under the test-only `ctgrind`); the raw-pointer exports of the bench / test wasm harnesses are `unsafe extern "C"` with `# Safety` contracts (`pqzh/ligero/wasm` `step_load`; `ffi/wasm` `prove_v`, `precompile_v`, `sl`), the harnesses documented as trusted-caller only; JS callers unchanged. (P-F, `stark-backup`, not live) the proof decoder rejects non-minimal varints (a final `00` after a continuation byte), so `01` and `81 00` no longer both decode; test `varints_minimal`. (P-H, `stark-backup`) the MV layout's candidate selection is structural (statement candidates always used), so the preprocessed commitment depends only on (op, Params), the cache key; test `mv_layout_statement_independent`; default-preset proofs unchanged. (P-I, `stark-backup`) **a gate before the backup is ever promoted**, no code now: a reviewed hiding preset, a size bound that admits hiding proofs, `pqz-stmt` decoding with the op tag / id / auditorOn / zero-word checks, a distinct `proofSystemId`, every relation (STATUS Open item 12). Status: P-D, P-E implemented `7373006`; P-F, P-H `50e5dbc`; P-I recorded. **Owner ruling 2026-10-19 (both proposals accepted): P-D accepted as a partial fix as recorded (the decoded statement, the fixed tables, the 512 KiB matrix A built once per process at first use, std / sha3 internals still abort on allocation failure); P-I gate accepted, extended after the branch review with: a verifier that rejects non-hiding configurations and a preset at 128-bit proven soundness, the salt-form check, the prover hygiene (constant time, wiping), the verifier fault handling (OOM as `NodeFault`, panic containment), vectors / KAT / tamper / xcheck / fuzzing / gas rows and its own review round (STATUS Open item 12).**

Change (2026-10-19): controller proposal (owner may override) — **on-chain review fixes, plugin side** (plan `superpowers/plans/2026-10-19-pqzl-fs3.md` Task 5g, branch `rev2-chain-neth`; triage rows W-D, W-G, W-H, W-R in `pqz-core/research/code-review-2026-10-19/U-agy-chain.md`, details U NETH-02 / NETH-03 and V1-05 / V1-06 in `V1-claude-plugin-pqz-zether.md`). (W-D) **Refuted: a block-number transition does not drop the precompiles.** The finding read `ApplyToReleaseSpec(spec, startBlock, null)` ⇒ `ScheduleAt(null)` = null. Nethermind 1.39.0 (decompiled from the pinned image's `Nethermind.Specs.dll`) never passes null: `ChainSpecBasedSpecProvider.CreateTransitions` builds every block-number release with the genesis timestamp and every timestamp release at the last block transition, and `SpecProviderBase.GetSpec` looks releases up by timestamp alone from the first timestamp transition on; `CreateTransitions` is the only caller of `CreateReleaseSpec`, which is the only caller of `ApplyToReleaseSpec`. So a block-number release carries the schedule in force at genesis (none when the first schedule is later), which is the schedule in force for every block before the first timestamp transition. The test `SpecTests.A_block_number_transition_keeps_the_schedule` resolves the spec with the test genesis' `maxCodeSizeTransition` 6432 and a timestamp schedule at T1, at blocks and timestamps before and after both (a genesis schedule plus T1, and T1 alone), and asserts the schedule, the three addresses and that the release is the block-number one (EIP-170 on). No code change; status: **refuted, test kept** (`4407935`). (W-R) **ML-DSA never reverts on a `CryptographicException`**: `MlDsa.Verify` catches `CryptographicException` (only that) from the key import or the verify and returns 32 zero bytes with the warning `MLDSA-CRYPTO-EXCEPTION`, per EIP-8355; any other exception stays a failed call. No real input is known to raise one (every public-key bit pattern decodes, a malformed signature is false; the 1-h harness reached none), so the test raises it through a seam (the verify function is a parameter). Residual, for the owner: a `CryptographicException` that a node-local OpenSSL fault raises would also become `…00`, a verdict, where the PQZ precompile would stop the node (D4); none is known. Status: **done** (`5f555db`). (W-G) **The reviewed library hash**: `SelfTest.ExpectedLibrarySha256` (`pqz-core/nethermind/Nethermind.Pqz/SelfTest.cs`, beside the self-test pin) is the SHA-256 of the reviewed `libpqz_ffi.so` from the Dockerfile's `ffi` stage; the plugin refuses to start with any other library (`PQZ-REFUSE`, exit 120); `build-image.sh` reads the constant, stops unless the freshly built library has that hash, and passes the constant (no longer the build's own hash) to the Dockerfile's `sha256sum -c`; `clang` / `clang-14` / `libclang-cpp14` / `libllvm14` are pinned to exact Debian 12 versions (`1:14.0-55.7~deb12u1`, `1:14.0.6-12`). A library change = build, review the printed hash, commit it, build again. The value today is the `pqz3` library (`16dd99ce…9caf`, built 2026-10-19 from `1adbd56`), which no current source produces; plan Task 13 sets the `pqz4` value. Status: **done** (`7d95144`; no image built). (W-H) **Recorded, no code**: a node fault inside `eth_call` / `eth_estimateGas` / tracing exits the process (D4), and the PQZL lock is shared by RPC and block import, so the signer must not serve public RPC (a rule in `pqz-core/nethermind/chain/RUNBOOK.md`); public RPC goes to a rate-limited follower. Found while recording: the live `docker-compose.yml` publishes `8545` / `8546` on every host interface, so an owner step binds them to `127.0.0.1` (or confirms a firewall) at the next node restart (plan Task 13). Status: **recorded**. Tests: `run-tests.sh` (pinned SDK image, OpenSSL 3.5.5) 44 / 44 passed (41 before, plus the W-D, W-R and W-G tests), log `pqz-core/nethermind/runs/2026-10-19-rev2-5g-test.txt`. Source add: `pqz-core/nethermind/README.md`, `pqz-core/nethermind/chain/RUNBOOK.md`, report `.superpowers/sdd/2026-10-19-rev2/task-5g-neth-report.md`. **Owner rulings 2026-10-19:** W-R — a `CryptographicException` in the ML-DSA precompiles returns 32 zero bytes (EIP-8355 "never a revert"; every node runs the pinned image), not a node-fault exit; W-H — the SCaaS testnet signer's RPC ports on every interface are accepted for the testnet (no firewall or binding step); the RPC rule binds mainnet 22776.

Change (2026-10-23): **owner ruling — `MAX_PROOF_PQZH` = 327,680 B (320 KiB) for the parameter set `n2560-kmax16384` only**; every other set keeps 262,144 B. Reason: at `n2560-kmax16384` the PQZH debit proofs (R_TX / R_TX0 / R_BURN, op 7) are bounded at ≈ 301.9–303.6 KB [model, `pqz-core/params/sets/n2560-kmax16384/PQZH.md`; `pqz-core/params/sets/README.md`], above 262,144; a set-specific Ligero preset is not available there (q − 1 = 2^3 · 19 · 43 · 431 · 5,659 · 70,627 has no other small radix; the preset search finds nothing below ≈ 299.6 KB) and re-proving under the limit cannot close a 37–41 KB gap, so the per-set raise (option C of the three options in `pqz-core/params/sets/README.md`) applies. Headroom: 327,680 − 303,590 = 24,090 B over the largest bound (op 7 M = 4 with the auditor; t = 121 — 22,560 B at the built t = 122); largest precompile input 5 + 165,760 + 327,680 = 493,445 B ≤ `MAX_INPUT` 512 KiB (owner 2026-10-21). For `n2304-kmax4096` the owner chose the radix-7/17 preset on 2026-10-22 (debits 251,608–253,048 B under 262,144). Status: decided; **built (8c part 2, merged into `pqz-16k` as `6f0c0b03` (2026-10-23); gates of the three PQZH sets PASS at `e458ec63`; review approved after one fix round)**: `set.toml` `[pqzh_preset] max_proof` → generated `MAX_PROOF_PQZH` in the set's `rust/set.rs` → `pqz-stmt` `max_proof(PQZH_ID)` and the prover; owner 2026-10-23 also: t = 122 at this set (THE preset's n / k; 127.55 bits; bounds 303,412–305,120 B, 22,560 B headroom; honest proofs ≤ 302,112 B) and `pqz-stmt` `MAX_INPUT` per set (393,216 at `n2048-kmax1024`, 524,288 at the other sets); the node's input limit (`pqz_ffi.h`, Nethermind, 393,216) and the PQZH id per set stay Task 8d. A PQZH debit at `n2560-kmax16384` still needs a per-transaction regular-gas cap ≥ ≈ 21.3 M (EIP-7976 calldata floor, `PQZH.md`).

Change (2026-10-23): controller (owner rulings of 2026-10-21, spec 2026-10-20 §12 items 7 and 9) — **plan 5h Task 8d part 1, the node side off chain:** (1) `pqz-ffi`'s default parameter set (its default cargo feature, hence the node library `libpqz_ffi.so`, the Dockerfile's `ffi` stage, the Nethermind tests' library and corpus) is `n2304-kmax4096`, the default set on chain; (2) the node's precompile input limit comes from the library: `pqz-ffi` exports `size_t pqz_max_input(void)` = pqz-stmt's `MAX_INPUT` of the set it was built for (524,288 B at `n2304-kmax4096` / `n2560-kmax16384`, 393,216 B at `n2048-kmax1024`); `pqz_ffi.h` drops the literal `PQZ_FFI_MAX_INPUT` 393,216 and the Nethermind plugin's `PqzNative.MaxInput` calls it (the C smoke test checks it against `set.json`); (3) the precompile addresses in the 32-bit form `PQZ` `0x000000000000000000000000000000005caa0f01`, `MLDSA44` `…5caa0012`, `MLDSA65` `…5caa0013` in the plugin (`PqzAddresses`), the chain scripts (`patch-chainspec.py`, `e2e.py`), `smartcontracts/evm/script/pqz/e2e.py` and the docs (supersedes P6f D3's addresses above for every new image; chain 7622's live image `2.2.0-pqz3` keeps them until its next roll-out). Not changed: `chain/engine-pqz.json` and `add-schedule.py` keep the live chain's rows and ids (rows for the new ids and statement lengths need the calibration of plan 5h Task 9), `SelfTest.ExpectedLibrarySha256` stays the reviewed `pqz3` value until the next image is built and reviewed. Status: built on branch `pqz-8d1`; Solidity constants and contract tests in 8d part 2.

Change (2026-10-24): **owner ruling — `n2816-kmax65536` is made a full PQZL set** (owner: "PQZL n2816-kmax65536: core only … ⇒ it must be done fully, for customers if they need it": deployable for a customer like the other sets), plan 5h Task 8d part 1b. `set.toml` `core_only = false`, `pqzh = false`, `max_input` 524,288 (512 KiB, the other non-frozen sets' value; its largest input at the limits is 5 + 295,808 + 98,304 = 394,117 B, R_TXM M = 8 with the auditor, above the frozen set's 393,216); `MAX_PROOF_PQZL` stays 98,304 (largest proof in its vectors 79,199 B, margin 19,105 B). Built: pqz-stmt for the set (a set without PQZH knows no PQZH id: `HAS_PQZH` false, `PQZH_ID` the zero word, refused as an unknown id; generated by `gen_set.py`), pqz-ffi without PQZH (a compile-time check refuses feature `pqzh` there), `pqz_max_input()` = 524,288, vectors `smartcontracts/vectors/pqz/n2816-kmax65536/` (PQZL only; self-test hash `0x0aa1dfe2…491882`), the Nethermind plugin per set (MSBuild `-p:PqzSet=<set>` selects `SelfTest.ExpectedHash`; default `n2304-kmax4096`), the full gate (Ligero / cross-checks skipped: no PQZH). **No PQZH at this set** (the ruling stands). The reason as first given (controller, said to the owner 2026-10-24: "no Ligero evaluation domain exists") overstated it; **corrected reason (8d part 1b review M1, 2026-10-25):** q − 1 = 2^3 · 3 · 1,789 · 419,563,967,521 has no power-of-two part beyond 2^3 and a smooth part of only 24, none of the radices the current Ligero presets use (19 / 43 / 431; 7 / 17 at `n2304-kmax4096`). F_q^* does have subgroups of order 1,789 and 42,936 (= 24 · 1,789), so PQZH here would need a radix-1,789 FFT step and a new preset at a different rate (k = 1,789, n = 42,936: rate 1/24 against ≈ 1/40 today, more column queries, a fresh soundness and size analysis) — unexplored work, not in scope — or another q, i.e. another set. Its contracts follow in 8d part 2 with the other sets. Status: built on branch `pqz-8d1b` (8d part 1b). Source add: `.superpowers` ledger `task-8d-report.md` "Part 1b — Result", `pqz-core/params/sets/n2816-kmax65536/SET.md`.

Change (2026-10-25): owner 2026-10-24 ("run it on the SCaaS testnet yourself", "no backup of chain 7622 needed") — **the SCaaS testnet runs the plan 5h Task 8d part 1 node**: image `scaas/nethermind-pqz:2.2.0-pqz4` (Nethermind 2.2.0 + the reviewed library `0894d191…64772`, set `n2304-kmax4096`, per-set proofSystemIds, `pqz_max_input()` 524,288, the 32-bit addresses), reset on path B without a backup (genesis block unchanged, `0xa17faef4…2ac2`), `engine.Pqz` = one schedule of **provisional** rows for the new ids (the live rows × 1.3, `pqz-core/nethermind/chain/provisional-rows.py`; testnet only, plan 5h Task 9 calibrates). Probe 398 ok, 0 failed (`pqz-core/nethermind/runs/2026-10-25-pqz4-live.txt`; RUNBOOK "Image 2.2.0-pqz4"). The testnet has no PQZ contracts until plan 5h Task 8d part 2 and their redeploy. Status: **executed**.

Change (2026-10-25): **owner ruling — no PQZH at `n2816-kmax65536`, the radix-1,789 preset not pursued** (owner: no spike; "write down clearly why PQZH is not done at 65K"). **Not pursued (owner ruling 2026-10-25: no spike, write the reason down).** Controller estimate from the cost model of `pqz-core/pqzh/ligero/ligero_params.py` (`fft_cost(n) = n · Σ (r + 1)` over the radices of n; computed by hand, not run): (1) a radix-r stage costs ≈ r + 1 products per point, so the largest FFT at n = 42,936 = 2^3 · 3 · 1,789 is ≈ 77.4 M products against ≈ 3.7 M at `n2304-kmax4096`'s n = 45,752 (≈ 21×); k = 1,789 about halves the row count, so the prover's work is ≈ 10× `n2304-kmax4096`'s, most likely over the prover budget (`PMAX` 4e9 base products), and the prover runs on the client (wasm32 in the browser). (2) A fast 1,789-point DFT (Rader) needs a cyclic convolution of length 1,788 = 2^2 · 3 · 149, which has no NTT in F_q (149 does not divide q − 1); an extension field does not help (q + 1 = 2 · 31 · 109 · 409 · 6,517,458,439 is not smooth either); only nested Winograd-style convolutions remain — several days of work with an uncertain result. (3) The verifier (the precompile) would not be the problem: it evaluates at the t opened columns (Lagrange), with no size-n FFT. A chain that needs PQZH with `K_MAX` 65,536 needs another parameter set whose q − 1 is smooth like the other sets' (2^3 · 19 · 43 · 431 divides q − 1), with a full parameter and estimator run. Status: decided (docs only: `pqz-core/params/sets/n2816-kmax65536/SET.md`, `pqz-core/params/sets/README.md`).

**Why.** A native never-crash precompile on the SCaaS testnet verifies at ≈ 0.12 M gas per ms; a Solidity verifier would exceed the per-transaction cap.
**Cost if wrong.** Every node of the SCaaS testnet must run the PQZ client build; a crash would halt the single-signer chain.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:290`

Change (2026-10-25): **owner ruling — raise the PQZH limits for the R0 review fix** (owner: "option 2: raise the limits, keep the audited R_TXM M = 4 in PQZH at n2048 / n2304"; values: controller, as `n2560-kmax16384`'s approved 320 KiB). With the R0-1 group sizes (`s_aud` 2 at `n2048-kmax1024`, 3 at `n2304-kmax4096`, auditor on) PQZH's audited R_TXM M = 4 has G = 2 randomness groups and the exact proof bounds 279,756 B (n2048) and 296,248 B (n2304), above 262,144; no Ligero preset of these sets' radices fits (smallest 277,628 / 294,782 B at the preset's query soundness; `pqz-core/research/code-review-2026-10-25/r01a-limits/`). (1) `MAX_PROOF_PQZH` = 327,680 B at `n2048-kmax1024` and `n2304-kmax4096` (every PQZH set now 320 KiB). (2) `MAX_INPUT` = 524,288 B at `n2048-kmax1024`, as the other sets (its 393,216 held the frozen byte identity, gone with the fix; the audited M = 4 PQZH input is 429,137 B). Margins at the limits (largest exact bound / precompile input at the bound, R_TXM M = 4 audited): n2048 279,756 B (47,924 under) / 429,137 B (95,151 under); n2304 296,248 B (31,432) / 464,061 B (60,227); n2560 unchanged 305,120 B (22,560) / 470,885 B (53,403); the largest input at the limit 5 + 167,808 + 327,680 = 495,493 B (n2304, 28,795 under 512 KiB). PQZL is unchanged (`MAX_PROOF_PQZL` 98,304): largest vector proofs n2048 85,167 B (R_TXM M = 8 audited, G = 4), n2304 80,330 B (G = 3). Stated, no design change: a PQZH proof above ≈ 261,909 B cannot fit one transaction's calldata under EIP-7825's 2^24 regular-gas cap (the EIP-7976 floor; the sets' `PQZH.md`: a PQZH debit needs a larger per-transaction cap), so the raise matters only where the chain's cap allows it; PQZH stays the backup proof system, not offered on chain. `set.toml` `[pqzh_preset] max_proof` / `max_input` → `gen_set.py` → pqz-stmt (`rust/set.rs`), `set.json`, `pqz_kat.py`. Status: decided; built in the R0 fix part a (branch `pqz-r01`).

Change (2026-10-26): controller proposal, owner may override — **R0 review fix part b, the node** (branch `pqz-r01`; review `pqz-core/research/code-review-2026-10-25/claude-R4.md`): (R4-C3) the plugin compiles in its set's PQZL / PQZH ids (`Nethermind.Pqz/PqzSetIds.cs`, written by `gen_set.py` from `set.toml` next to `SelfTest.ExpectedHash`; empty PQZH at `n2816-kmax65536`), and `PqzStartupCheck` refuses with `PQZ-REFUSE` when the schedule in force at the next block (the block-tree head's timestamp + 1; the head is the genesis on an empty database) or any later one has a row with another id; earlier schedules are not checked (the node never executes them again). Owner 2026-10-26: option (a) of the review of fix part b, I-1 — the head, not the wall clock (part b's first version took the wall clock, so a node whose database lay before a switch from foreign ids started and then had to execute the foreign schedule); consequences for an id change on a running chain (new-library nodes start once their head reaches T − 1, in practice after T with a block period, the old-library nodes sealing the first blocks at or after T under the old ids, no PQZ call between T and the swap; old-library nodes are refused at any restart, a fresh node needs a data copy past the switch) in `contracts/pq-zero-knowledge.md` §9.1. (R4-C4) a start-up ML-DSA-44 / -65 known-answer set through `MlDsa.Verify` (the precompile path): from one valid input per level (EIP-8355's wycheproof tcId 1; the mldsa65 UA proof of possession), the valid input, a c̃ bit flip, two hint indices out of order, a non-zero hint padding byte, a hint count over ω, z's first coefficient at γ1, t1 at its maximum and a message bit flip; the SHA-256 of the 16 verdict bytes must equal a compiled-in constant (`MlDsaKat`), else `PQZ-REFUSE`; `PQZ-START` logs the OpenSSL version (`SafeEvpPKeyHandle.OpenSslVersion`; logged, not pinned — the image digest pins it, D5). (R4-C6) a C# test ties `PqzNative`'s status constants to `pqz_ffi.h`'s `#define PQZ_FFI_*` (the panic child-process test not added: fault-hooks exports no panic hook, not cheap). (W-G per set) `SelfTest.ExpectedLibrarySha256` per set, the Dockerfile's `ffi` stage with `--build-arg PQZ_SET=<set>` (`build-image.sh` reads `PQZ_SET` and the set's line). `chain/add-schedule.py --id pqzl|pqzh` resolves to the set's ids (`PQZ_SET`, `set.json`), not v3 / v1; provisional testnet rows per set (`chain/engine-pqz-provisional-<n>.json`, provisional-rows.py over each set's corpus; testnet only, prices × 1.3 of the retired calibration until plan 5h Task 9). Status: the head rule (R4-C3) decided, owner 2026-10-26 (option (a)); the rest proposal.

### CTR-PQZ-11 — Deterministic precompile pricing and chain limits
- old: R280 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-11 · superseded-by: —

Change (2026-10-15): controller proposal (owner may override) — P6f D2 (plan `superpowers/plans/2026-10-14-p6f-precompiles.md`): prices live in the chainspec section `engine.Pqz = {"schedules": [{"timestamp", "pqz": [{op, id, stmtLen, gas}], "selftestGas", "mldsa44Gas", "mldsa65Gas"}]}`, parsed strictly (unknown or missing key, unsorted or duplicate timestamp, first timestamp before genesis ⇒ the node refuses to start); `pqzTransitionTimestamp` = the first schedule's timestamp; a re-price or op 7 is a new schedule.
Change (2026-10-15): controller proposal (owner may override) — P6f D6: `gas = row.gas + 3·⌈len/32⌉`, the row = the active schedule's `(op, id, stmtLen)`; no row ⇒ `…00` at the smallest row's gas without an FFI call (the rows are the allowlist); `row.gas = 1000·⌈6000·t_row / t_ecMul / 1000⌉`; `selftestGas` = the smallest row (not the cold price: cold p99 108.6 ms would be 39.0 M gas, above EIP-7825's cap); ML-DSA `max(EIP-8355 BASE, calibrated) + 6·⌈max(0, L − PK − SIG)/32⌉`.
Change (2026-10-15): controller proposal (owner may override) — P6f D7 (one run, owner 2026-10-15): calibrated inside the calib image on the chain host through `PqzPrecompile.Run`; `t_ecMul` 17 µs ⇒ 0.359 M gas / ms; rows 2,567,000–5,409,000 (max `t_row` 15.05 ms ≤ 60 ms), `selftestGas` 2,567,000, `mldsa44Gas` 49,000, `mldsa65Gas` 68,000; every honest and `MAX_PROOF` input fits a direct transaction (largest honest 11.67 M). Table: contracts/pq-zero-knowledge.md §9.3; log `pqz-core/nethermind/runs/2026-10-15-calib.txt`.
Change (2026-10-15): controller proposal (owner may override) — P6f D8: node limits `TxPool.MaxTxSize` 1,048,576 and `Blocks.TargetBlockGasLimit` 80,000,000, JSON-RPC defaults kept; rehearsed on the copy (direct 315 KB transactions accepted, the ramp to 80 M).

Change (2026-10-16): owner — P6f accepted and live on the SCaaS testnet (Task 10, path B, run by the controller in its session; merge `a243650`): (1) the reset chainspec adds `eip4895TransitionTimestamp` 1, `maximumExtraDataSize` `0xffff` and `maxCodeSizeTransition` 0 (genesis hash unchanged, `0x24e43dcb…c464`); (2) the node config drops `Mining.MinGasPrice` (not a Nethermind key; the real one is `Blocks.MinGasPrice`), so clients pay baseFee + tip; (3) the follower gossip stall seen on the copy is a known issue, not a blocker; (4) the backups `mba-chain-nethermind-backups/pqz-20261016-004736` and `data/nethermind_data.bak-20260831-090830` are kept until the owner deletes them, the copy scratch dirs are deleted; (5) the measured ML-DSA prices 49,000 / 68,000 (EIP-8355 has 6,500 / 9,000) stand on the SCaaS testnet and are measured again before 22776. The P6f D1–D8 and D13 proposals above stand as recorded. Live run: `pqz-core/nethermind/runs/2026-10-16-live.txt` (PQZ-START, probes and e2e all pass).

Change (2026-10-19): controller proposal (owner may override) — review row W-F (V1-04; plan Task 5g, branch `rev2-chain-neth`): `pqz-core/nethermind/chain/add-schedule.py` refuses (1) a calibration file that lacks a row of the replaced ops / id that the last schedule has (that shape would have been a miss from T on: `…00` for every honest proof), (2) a duplicate row in the new schedule (every node would refuse to start), (3) a calibration file with other than one schedule (the others were ignored). A new shape that the last schedule lacks is still accepted (the op 7 roll-out added its rows that way). `add-schedule.py --check` covers the three refusals and the new-shape case; both past roll-out inputs (`runs/2026-10-17-calib-ops7-engine-pqz.json --ops 7` and `runs/2026-10-19-calib-ops123457-run2-engine-pqz.json --ops 1,2,3,4,5,7 --id 0x2e07e6ed`, on the copy's pre-roll-out chainspec) still pass. Status: **done** (`33142e2`; log `pqz-core/nethermind/runs/2026-10-19-rev2-5g-add-schedule-check.txt`).

**Why.** Precompile prices are deterministic, calibrated on p99 adversarial verify time against `ecMul`; the block gas target rises to 80 M within the EIP-7934 byte limit.
**Cost if wrong.** Mispriced verification makes block capacity a DoS surface.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:308`

Change (2026-10-27): **owner ruling — PQZH per-transaction cap: option (A)** of `docs/research/pqzh-calldata-cap.md` §4: PQZH stays the backup proof system and offers on chain exactly the forms that fit one 2^24 transaction under EIP-7976 on both relay paths — at `n2048-kmax1024` every built form but op 7 M = 4 with the auditor, without the `acc` hint; at `n2304-kmax4096` and `n2560-kmax16384` registration and disclosure only — and no PQZH token release is published at a set whose debits do not fit. Rejected: (B) chunked proof upload (≈ 385 M state gas per debit), (C) Ligero parameter cuts (not reachable at the proven soundness), (D) blobs (cannot work), a chain profile without EIP-7976 (breaks the one-rule policy). No core change. With it (owner 2026-10-27, contracts review 2026-10-26 C0-2 / C2-1, P1): at `n2048-kmax1024` a PQZH value token accepts only single-key `mldsa44` / `mldsa65` / `fndsa512` holders (a PQ `msig` holder exceeds the headroom), and `PqzStateLib.init` refuses a PQZH token at `n2304-kmax4096` / `n2560-kmax16384` (`PqzhValueUnsupported`, generated flag `PqzSet.PQZH_VALUE` from `set.toml` `pqzh_value`, true only at `n2048-kmax1024`). Holder rule (controller ruling, owner may override): the kind check (`PqzhHolderKind(ua, kind)`) applies to every entry that creates a holder's pending entry (shield, op 1 credit, op 7 legs); the fee beneficiary receives a public credit and is exempt. Status: **done** (review2 T1, branch `review2-fix`; `PqzGuards.t.sol`).
Change (2026-10-27): **review C0-2 option (2), "a stated fee-UA list" (owner ruling 2026-10-27 for the option; the list is the documentation half)**: measured in review2 T2 (`runs/2026-10-27-review2-t2-holder-gas-<set>.txt`). On `uaExecute` at PQZH `n2048-kmax1024` an `mldsa65` (precompile) or `fndsa512` fee UA fits every built form (burn 1 with an `fndsa512` fee UA: 16,429,976 regular gas); an `slhdsa128s` fee UA does not (burn 1: 16,890,776, over 2^24 = 16,777,216). That is the one excluded fee-UA kind; at every PQZL set and on the `mtxExecute` path every fee-UA kind fits. Stated in pq-zero-knowledge.md §9.3, `docs/research/pqzh-calldata-cap.md`, the sets README and `n2048-kmax1024/PQZH.md`. The earlier client rule "no `fndsa512` / `slhdsa128s` fee signer for a debit near the cap" (the C0-5 / C0-11 Change above) and "no `fndsa512` fee signer for op 7 `M = 8`" are dropped for `fndsa512`: the measurement (14.5–15.4 M plus the 0.2 M cap-priced verify, the verifier cap is 2.5 M) does not support them (controller ruling, owner may override). Status: **done** (review2 T2 measured; review2 T8 documents, branch `review2-fix`).

### CTR-PQZ-12 — Only a PQ signing UA carries a PQZ key, and it authorizes every spend
- old: R281 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-12 · superseded-by: —

**Why.** PQZ authorization is always a separate PQ signing UA (or a PQ-dominant `msig`), so no classical-only key can move confidential value.
**Cost if wrong.** Users need an ML-DSA key in addition to the PQZ key.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:318`

Change (2026-10-20): controller proposal (owner may override) — UA-6 (CTR-UA-30, U3, U5, U7): the rule becomes **only a PQ signing UA carries a PQZ key and it authorizes every spend**: `requireAuthorized(fromUA, PURPOSE_ZETHER_AUTH, authDigest, authSig)` on the signing UA itself, no `authRef` hop; the weight rule of `msig` (non-PQ weight below the threshold) is read from `keyData` and a PQ-eligible `msig` registers with its m-of-n `pop`; `slhdsa128s` is no direct holder; every other kind reverts `UAPqzHolder` (replaces `UAAuthRef`). The auditor and every credited leg must hold a PQZ key (`AccountNotRegistered`). A leaked PQZ secret is a read-only breach, for an `msig` holder one view / prove key (the `survivesEncKeyLeak` wording is dropped). `R_TX`, `R_TX0`, `R_TXM`, `R_BURN`, the disclosure relations and the statement layout do not change (`ua ↔ pqzKey` is one-to-one and immutable); the PQZ statement vectors take ids as input words and stay byte-identical. Spec §4. Status: decided (owner rulings) / proposal (details); built in UA-6 (branch `ua6`, commits 9c2cbc5c, 8889a21b, a01ed25e).

### CTR-PQZ-13 — 0x0142 pqz-mlwe is the PQZ key scheme id, not a UA kind
- old: R282 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-13 · superseded-by: —

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D3: `UAPqzVerifier` is the `IUAPopVerifier` of 0x0142: `verify` = `verifyPop` = the precompile op 3 on `opTag(REGISTER) ‖ PROOF_SYSTEM_ID ‖ message ‖ pk` (16,480 B) with the proof; `PRECOMPILE` and `PROOF_SYSTEM_ID` are immutables (PQZL v2 for 7622's registry); `pk` must be 16,384 bytes with every coefficient `< q`, checked in Solidity before the call (closes P6c C6-10; the precompile decoder checks it again); the constructor requires the allowed chain, the self-test and an `R_REG` probe through its own `verify` (the self-test's valid vector ⇒ true, one proof bit flipped ⇒ false), else it reverts. Registry cap = the measured verify gas plus a margin, `verifyBudget` 12 M above it.

**Why.** PQZ adds one UA kind (`0x0142` `pqz-mlwe`) under the UA rules instead of its own identity scheme.
**Cost if wrong.** The UA kind table, keyHash groups and vectors gain one row each.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:325`

Change (2026-10-20, owner): **`0x0142` `pqz-mlwe` is the PQZ key scheme id, not a UA kind** (CTR-UA-30): its tag, keyHash group `pqz-mlwe` and registry slot stay (so `tag`, `uaMessage(0x0142, …)` and `keyHash` still work and the keyHash bytes are those of today), but no id is derived from it and `uaOf` refuses it; the PQZ account is the signing UA's id; the key sits in a second pointer beside the record and in the registry list `0x0142`. `R_REG` is over `uaMessage(0x0142, POP, popDigest(signerUA, pqzKeyHash))`; relation, statement, verifier and vectors unchanged; the message change rides the 5h `proofSystemId` bump (q = 2^50 − 42,310,535). Status: decided; built in UA-6 (branch `ua6`, commit 9c2cbc5c).

### CTR-PQZ-14 — Disclosure only by zero-knowledge proof
- old: R283 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-14 · superseded-by: —

Change (2026-10-13): owner — the disclosure statement layout is fixed byte by byte (32-byte words; `kind` a word, so `pk` is aligned; 33,184 B), and the `RECEIVER_X` noise bound reads `e'_i ∈ [−2^24, 2^24)`, the range the proof shows; uniqueness is unchanged. Source add: owner, 2026-10-13 (`research/pqz-relations-burn-disclose.md` §5).

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D11: disclosure lives on the token (no separate contract; `ZetherDisclosure` is curve code): the view `verifyTransferAmount(entryRef, amount, kind, opening)` with `kind` = `ITransferDisclosure.OpeningKind` `SENDER_S` 0, `RECEIVER_X` 1, `AUDITOR` 2 (`SENDER_CP` ⇒ false); `opening = abi.encode(bytes bundle, bytes proof)` accepted only canonical (decoded, re-encoded and compared), `keccak256(bundle)` must equal `transferCiphertextHash(entryRef)`; the 33,184-byte statement of §7.9 with `pk` from the registry (the bundle's `toUA`, or the token's `auditorUA` for `AUDITOR`); op 4 for `SENDER_S`, op 5 otherwise.

**Why.** Disclosure is by zero-knowledge proof only; revealing `r` would open the sender's balance and noise must not leak.
**Cost if wrong.** Each disclosure costs a proof (≈ 15–25 KB, estimate).
**Source.** `history/specs/2026-10-06-pq-zether-design.md:333`

Change (2026-10-27): **review C2-5 / C2-6 / C2-7 (controller proposals, owner may override)**: (C2-5) both relay paths pull the payload's `shieldIn · shieldScale` into `SHIELD_POOL` before the authorization and the precompile (a cheap revert for a signer who spent its public balance; no outer-fee pre-check, so `mtxUnshield` may still pay its fee from its output); spec §7.4 / T20 / §7.11 agree: the outer fee is the base's step 6, after the call. (C2-6) `PqzCore.verdict` reverts `UAVerifyGas` when the precompile call fails or returns other than 32 bytes (out of gas, no schedule, input over `MAX_INPUT`): no verdict, never `ProofRejected`; `verifyTransferAmount` maps only the statement's shape errors to false and propagates an empty revert. (C2-7) `IPqzToken` declares `pqzAccount`, `pqzAcc`, `pqzPending`, `pqzPendingCt`, `pqzEntryBlob`. Status: **done** (review2 T1).

Change (2026-10-27): **review C0-5 / C4-2 / C0-11 (controller proposal, owner may override; the owner did not rule C0-5, the README triage's proposal stands)**: (C0-5) `UARegistry._pqzAttr` refuses an `msig` PQZ holder (`UAPqzHolder`) whose worst-case authorization (`_membersWorst`, register step 4) plus `PqzSet.PQZ_DEBIT_MIN_GAS` exceeds 2^24, the EIP-7825 per-transaction cap (never a chain's own limit; one rule for every chain kind). `PQZ_DEBIT_MIN_GAS` = new `set.toml` key `debit_min_gas` through `gen_set.py`: the cheapest built PQZL debit (burn 1), full relayed transaction on the costlier relay path (`uaExecute`): 6,820,062 / 6,991,487 / 7,161,789 / 7,351,418 at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536` (`runs/2026-10-26-t8d2b-fix-gas-<set>.txt`). The constant contains the fee signer and one single-key holder authorization (a 3,309 B ML-DSA-65 signature, 68,006 gas each), not the `msig`'s own calldata; the bound assumes each kind's cap-over-actual slack covers that calldata (measured: the 2-of-2 / 3-of-3 rows of `test_gasTable_holderRows`, +0.04 / +0.16 M over burn 1 at PQZL). The bound adds `w / 63 + SigCheck.GAS_MARGIN` to `w`: a gen-1 `msig` record authorized through a gen-2 registry is forwarded whole (`_viaPredecessor`), which keeps 1/63 of it plus the margin outside gen 1's own bound (checked, not previously counted). Single-key holders are not bounded (cap <= 2.5 M). Consequence: the Solidity-ML-DSA treasury `{mldsa65 x 3}, t = 2` at the 5.921 M cap is no PQZ holder (it still registers without a key; with a precompile cap it is). (C4-2) `UAGas.t.sol` `test_T_GAS_msigPqAtBudget`: 8 x `slhdsa128s` (cap 1.4 M, 7,856 B signatures) + 1 native clone at the exact bound 11,930,873 authorizes with 57 k to spare, so `MSIG_MEMBER_GAS` stays 35,000. (C0-11) the fit claim is now pinned with the costliest enabled holder and fee-UA kinds: `PqzStateGas.t.sol` `test_gasTable_holderRows` (2-of-2 / 3-of-3 `mldsa65` `msig` holders on both relay paths, `slhdsa128s` and `fndsa512` fee UAs on `uaExecute` incl. op 7 M = 8 with the auditor, which fits at all four sets with an `fndsa512` fee UA: the review's +4.4 M is not reproduced; the PQZH `n2048-kmax1024` verdicts of C0-2 asserted); no client rule against an `fndsa512` fee UA (the measurement fits every set); the one excluded fee-UA kind is `slhdsa128s` on `uaExecute` at PQZH `n2048-kmax1024` (the next Change). Status: **done** (review2 T2, branch `review2-fix`; `UARegistryPqzBound.t.sol`).

### CTR-PQZ-15 — PqzToken is ERC-20 plus IERC20MetaTx
- old: R284, owner:2026-10-07:pqz-metatx · status: current · owner: yes · date: 2026-10-08 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-15 · superseded-by: —

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D1: classical Zether's shape one-to-one: `PqzLayer` (abstract, on `MetaTokenBase`) holds the entry points and views, `PqzLib` (external library, ERC-7201 namespace `scaas.pqz`) the state and logic; kinds `NONE_PQZ` = 4 (`NoUnderlyingPqzToken`) and `UNDERLYING_PQZ` = 5 (`UnderlyingPqzToken`) with the flags of the matching Zether kinds; `pqzShield(ua, amount)` burns `amount · shieldScale` public units of the signer exactly as `zetherShield` (pq-zero-knowledge.md §7.3's `transferFrom` of the underlying predates the token tree, in which the public ERC-20 balance is the layer below; §7.3 amended), `pqzUnshield` mints public units to `recipient`, and `UNDERLYING_PQZ` adds `pqzWrapShield` / `pqzUnshieldUnwrap` as `zetherWrapShield` / `zetherUnshieldUnwrap`; `NONE_ZETHER_PQZ` / `UNDERLYING_ZETHER_PQZ` stay reserved; `OpenFactory.pqzEnabled` with the registrar's `setPqzEnabled` (`true` needs `PqzSafety`'s chain and a passing self-test), `KindReserved` above 5.

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D9: `ConfidentialConfig` is reused unchanged: `verifier` = a `UAPqzVerifier` whose `PRECOMPILE` and `PROOF_SYSTEM_ID` the token reads at `init` (the token's proof system is the verifier's, PQZL or PQZH), `auditorKey` = empty or exactly 32 bytes, the auditor's registered `pqz-mlwe` UA (its `pk` comes from the registry); `maxShielded ≤ 2^62` (CTR-PQZ-17), `confidentialFee < 2^64` and `< maxShielded`, `shieldScale ≠ 0` without overflow of `maxShielded · shieldScale`; `disclosureMode` / `auditorMode` as Zether (`BadDisclosureMode`, `BadAuditorMode`).

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D10: a new account's `acc` is `Trivial(0)`, 16,512 zero bytes: a stored `accHash` of 0 stands for the zero ciphertext's hash and `accUnits` starts at 0 (no ciphertext summed yet); clients pass the zero bytes as `acc`.

**Why.** The owner ruled that `PqzToken` follows `IERC20MetaTx` like `ZetherToken`: v1 and v3 envelope paths over one pipeline, wrap/unwrap as direct calls, the envelope `burn` as the gasless exit, authority split between the PQ `authSig` and the envelope signer; both paths now sign in one domain salted with `chain_uid`. Whether its envelope moves to the generic self-call is open.
**Cost if wrong.** A broken v1 envelope key can spend that signer's public float and burn its nonces; it can never move confidential value.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:337`, `history/SCaaS-2026-10-07.md:39`. Owner wording (2026-10-07): "PqzToken => Cái này cũng phải theo MetaTransaction IERC20MetaTx chứ." (PqzToken must also follow IERC20MetaTx); `history/specs/2026-10-07-metatx-generic.md` §3 MG-4.
Change (2026-10-08): `PqzToken` sits on the one token base and relays like `ZetherToken` (CTR-PQZ-21): `PqzMetaTx` and its sliced-argument dispatch are gone; plain public transfers are `MetaTransfer`s. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G11, §3 GC-10.

Change (2026-10-20, owner): **shielded value sits in a `SHIELD_POOL` sentinel instead of being burned** — `SHIELD_POOL = address(uint160(uint256(keccak256("scaas.shield.pool.v1"))))`, for the PQZ and the Zether kinds alike. Shield moves `amount · shieldScale` from the signer to `SHIELD_POOL` (`Transfer(signer, SHIELD_POOL)`, no burn); unshield / burn-unwrap moves it out to the recipient (no mint); a fee paid from a hidden balance (beneficiary fee, the per-credit fee of every leg) moves out of `SHIELD_POOL` to each fee recipient's public balance. So `totalSupply()` never changes on shield / unshield and stays the true total, `Σ balanceOf == totalSupply` holds, `balanceOf(SHIELD_POOL) == totalShielded · shieldScale`, and the escrow invariant becomes `reserve ≥ totalSupply()`. `SHIELD_POOL` is not payable and cannot spend (as `UA_POOL`, `UAPoolNotPayable`); the token's own address is not used (CTR-MTX-18). Relations and proofs unchanged. Status: decided; built in plan Task 5h for both kinds.

Change (2026-10-20, controller record): **`SHIELD_POOL` as built, and its inheritance trust boundary** (plan 5h D19; Zether Task 3z `7733910e` / `171d4884`, PQZ Task 3 `ff4e6948` / `3cbc5f5e`). `pqzShield` and every debit's `shieldIn` move the signer's public units to the pool (a derived-UA signer: its UA-ledger balance); `pqzUnshield` moves them out; `pqzWrapShield` mints `minted` to the pool; `pqzUnshieldUnwrap` burns `amount · scale` from the pool, then the leg pays; `executeRate` checks `totalSupply()` only. A burn or unwrap to `SHIELD_POOL` or `UA_POOL` is refused in `PqzCore.prepareBurn` (the statement views refuse it too; this replaces Zether's `_requirePayee` for PQZ without a shared-base change). **The pool guard lives in the shared base `ERC20MetaTx._uaMove`** (a native `SHIELD_POOL` side reverts `ShieldPoolNotPayable`; covers outer fees, `uaExecute` fee calls and `uaPayReceiverFee`); the layers move the pool only through the internal **`_poolMove`**, which is **unguarded by design** (a guarded move would refuse the pool itself). It is an inheritance trust boundary: only layer code (`PqzLayer`, `ZetherLayer`, the underlying variants) may call `_poolMove`, and any contract that inherits `ERC20MetaTx` and calls it can move the pool; reviewers check new callers. Libraries return what the debit moved and the token pays exactly that. `PqzShielded.from` is `_msgSender()` (`UA_POOL` for a derived-UA signer; the `UATransfer` event names the UA). Invariants tested (`PqzPoolInvariantTest`, Zether invariant handler): pool = `totalShielded · shieldScale`, `Σ balanceOf == totalSupply`, reserve ≥ `totalSupply()`. Status: decided (owner, pool); built; the guard / boundary is a controller ruling, owner may override.

### CTR-PQZ-16 — Direct decryption without BSGS
- old: R285 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-16 · superseded-by: —

**Why.** Decryption is rounding of 16 coefficients: exact and microseconds, no BSGS.
**Cost if wrong.** None found; a balance cache stays a UX convenience.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:361`

### CTR-PQZ-17 — PQZ shielded supply and amount limits
- old: R286 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-17 · superseded-by: —

**Why.** `MAX_TOTAL_SHIELDED = 2^62` and amounts `< 2^64` keep `b' + v + fee < 2^64` for honest states.
**Cost if wrong.** The classical 2^54 rationale (BSGS) does not apply; raising further would break the digit argument.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:364`

Change (2026-10-20, controller record): with `plainPending` removed the limit reads `totalShielded ≤ maxShielded` and `totalShielded · shieldScale == balanceOf(SHIELD_POOL)`; `initialize` also requires `confidentialFee + 8 · minDecoyFee < 2^64` and `< maxShielded`; an op 7 `decoyFee < 2^64` (`DecoyFeeOutOfRange`). Status: built (plan 5h Task 3).

### CTR-PQZ-18 — Native and WASM prover platforms early
- old: R287 · status: current · owner: yes · date: 2026-10-06 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-18 · superseded-by: —

**Why.** Retail provers come early (owner): native x86-64/aarch64, then the WASM prover in the app's Zether worker with a user-run native fallback.
**Cost if wrong.** WASM emulates 64×64→128 multiplication, which may miss phone budgets.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:367`

### CTR-PQZ-19 — Message-bound derived encryption randomness
- old: R288 · status: current · owner: no · date: 2026-10-06 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-19 · superseded-by: —

Change (2026-10-11): owner — the seed is bound to a fresh published 16-byte salt instead of the amounts (CTR-ZTH-30 for PQZ): a re-proof still never reuses `r`, and the sender remembers no amount. Source add: owner, 2026-10-11.

Change (2026-10-13): owner — burn and refresh take fresh CSPRNG randomness (hedging with the key seed allowed), never the counter-derived seed: their salt is 0, so two burns at one `sendCounter` for different balances would reveal `Δ·(b' − b'')`; no disclosure re-derives it. Source add: owner, 2026-10-13 (`research/pqz-relations-burn-disclose.md` §5).
Change (2026-10-14): controller proposal (owner may override) — P6e plan D6, PQZH half (branch `p6e-b1`): the Ligero prover's masking randomness is hedged with the witness, `SHAKE256("SCAAS-PQZH-LIGERO-RNG-V2" ‖ rnd32 ‖ u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ wit)` (was `SHAKE256("SCAAS-PQZH-LIGERO-RNG" ‖ rnd32 ‖ u8(op) ‖ stmt)`), so a repeated `rnd32` with another witness gives unrelated masks; the verifier is unchanged, PQZH proof bytes change once, before the PQZH vectors freeze. The PQZL half (`SCAAS-PQZ-PROVER-RND-V2`) is a separate change. Source: `superpowers/plans/2026-10-14-p6e-relations.md` (D6), `research/pqzh-ligero.md` §12.

Change (2026-10-14): controller proposal (owner may override) — the PQZL prover's masks are hedged as this entry requires (`H(secret ‖ statement ‖ 32 B CSPRNG)`; P6e gap G2, decision D6): `pqz_rel.c` seeds the commitment randomness and every mask from `SHAKE128("SCAAS-PQZ-PROVER-RND-V2" ‖ rnd32 ‖ wh ‖ hash0)` and `…-SUB-V2` with `wh = SHAKE128("SCAAS-PQZ-PROVER-WIT-V2" ‖ wit)` (32 B; the inner tag added after review, controller 2026-10-14, before the gate-A freeze) (was `rnd32` alone, `…-V1`), `hash0` the statement digest; a repeated `rnd32` for two witnesses or two statements no longer repeats the masks. Prover only: verifiers, transcript and proof format unchanged, honest proofs change once (new `proofs_fnv`), `proofSystemId` stays v2 (D2). The Ligero (PQZH) half of D6 is P6e Part B. Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D6, Task 1; branch `p6e-a1`.

Change (2026-10-19): controller proposal (owner may override) — **second whole-code review of 2026-10-19 (PQZH Rust, reports I / J / K), prover fixes P-A, P-B, P-C, P-G** (plan `superpowers/plans/2026-10-19-pqzl-fs3.md` Task 5c, branch `rev2-pqzh`; triage `pqz-core/research/code-review-2026-10-19/J-agy-pqzh-rust.md`, findings I / J / K; inventory and runs `O-pqzh-constant-time.md`). Rule: no PQZH proof byte or verdict changes (the PQZH `proofSystemId`, vectors and gas rows stay). (P-A) **The FFT's sparse path never decides on secret values**: Ligero's radix stage chose a sparse r-point DFT when few of its inputs were zero, by filtering the values, which in the prover's witness interpolation are raw witness slots (zero patterns and magnitudes of the amounts and the CBD bits); now `fft.rs` `Domain::rec` carries the structural zero-padding length and sums only the sub-transforms whose first input index lies inside it, so the forward transform of zero-padded coefficients keeps the speed-up and the inverse transform (the witness) is always dense; outputs identical. (P-B) **Constant-time secret arithmetic, the method of PQZL fix E**: `Fq` conditional subtractions and `Sub` by masks; `Fq::from_i64` and `ring::modq` without `rem_euclid` (wasm32 `i64.rem_s`); `modq`'s centring through a `black_box` mask (`ct::mask`: with a plain mask x86-64's cmov conversion still made a branch, memcheck `ct-rev2-wip`); `dot_int` without the zero skip on the secret operand; round(w / Δ) by sign and magnitude over a fixed 64-step restoring division (no `i64.div_s`); `& 15` / `>> 4` for `% 16` / `div_euclid(16)`; every honest-prover check (norms, keys, ciphertexts, digits, ranges, carries) a branch-free word OR-ed into one verdict per error message; the declassified points are only the root, w, q, h, the finished proof, those verdicts and the samplers' accept bits. Check: test-only feature `ctgrind` (`ct::public` / `verdict` / `secret`, the valgrind client request is the lib's only `unsafe`, allowed only under that feature), driver `src/bin/ct.rs`, `pqzh/ligero/runs/ct.sh`: all twelve relations (six forms, six op 7 shapes), witness and `rnd32` secret, **0 memcheck reports, every proof verifies** (`runs/ct-rev2.txt`); negative control with the old arithmetic 21 contexts (`ct-rev2-control.txt`); wasm32: no 64-bit division left in the prover (`rev2-wasm-div-before.txt` / `-after.txt`). Changed error text only: a witness with several faults now reports "digits" before "carry" across all coefficients. (P-C) **Wiping, as PQZL fix B**: `Wiped` / `Wipe` drop guards (`pqzh/ligero/src/lib.rs`) on every secret buffer of `cs::witness` and `ligero::prove_once` and the FFT's scratch copies, `cs::Wit` wiped on drop, the SHAKE256 reader replaced in place on drop (sha3 0.10.8 has no `zeroize` and no `Drop`; state access would need `unsafe`); platform boundary as fix B plus by-value `rnd32` copies and the hasher state before `finalize_xof` (STATUS Open item 8 names PQZH). (P-G, `stark-backup`, not live) **the backup's hiding masks are hedged** as this entry requires: `rel::mask_seed` = SHAKE256("SCAAS-PQZH-STARK-RNG-V1" ‖ rnd32 ‖ u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ wit), 32 bytes, replaces `rnd32` as the seed of every mask and salt (was `rnd32` alone; the backup's hiding proofs change, its default non-hiding preset does not use it); test `mask_seed_hedged`. Status: implemented `7373006` (Ligero, pqz-ffi), `50e5dbc` (stark-backup); evidence in `pqz-core/STATUS.md` §"PQZH review fixes".

**Why.** Encryption randomness is derived from a message-bound seed, so the sender can re-derive it for disclosure and a re-proof never reuses `r`.
**Cost if wrong.** Reusing `r` across two messages leaks `Δ·(m − m')` up to noise.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:376`

### CTR-PQZ-20 — Classical to PQZ migration by burn then fund
- old: R289 · status: current · owner: no · date: 2026-10-07 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-20 · superseded-by: —

**Why.** Migration is `ZetherToken.burn` then `PqzToken.fund`; the amount is public once, which is acceptable because classical Zether holds no production funds.
**Cost if wrong.** No cross-system equality proof in v1.
**Source.** `history/specs/2026-10-06-pq-zether-design.md:382`

### CTR-PQZ-21 — PqzToken relays through the generic self-call, as classical Zether
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-21 · superseded-by: —

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D4: `ERC20MetaTx._uaExecute` writes a new virtual hook `_uaEnvelopeBinding(m)` (default 0) into the ticket, as the address path writes `_envelopeBinding(m)`; the PQZ layer overrides it with the tag `SCAAS-PQZ-UA-ENVELOPE-V1` and `m.from` as `bytes32`; the PQZ selectors (`pqzShield`, `pqzTransfer`, `pqzTransferCompact`, `pqzTransferNoBundle`, `pqzUnshield`, `pqzRollOver`; on `UNDERLYING_PQZ` also `pqzWrapShield`, `pqzUnshieldUnwrap`) join both allowlists with fee class `ABSOLUTE`; a new hook `_batchable(sel)` (default true) in `mtxBatch` / `uaBatch` returns false for them, which reverts `MtxNotBatchable(sel)`.

Change (2026-10-20, Task R, owner): `mtxRollOver` and `mtxPrepareAcc` are back on both PQZ relay allow-lists (address and UA envelope, `ABSOLUTE`, static 68 B, unbatched), the outer fee may be 0; this supersedes the next Change line. Status: BUILT, commit `b5e61c96` (`PqzShared.t.sol`; the relayed `ROLL_MAX` rollover is 12,185,595 gas, `PqzStateGas.t.sol`).
Change (2026-10-20, plan 5h Task 3b, built; superseded by Task R above): `mtxRollOver` (was `pqzRollOver`) and `mtxPrepareAcc` are off both PQZ relay allow-lists (address and UA path): a meta-tx carrying either reverts `MtxSelectorNotAllowed` / `MetaTxUnknownOp`; anyone calls them directly (no signer authority is involved). Status: built on `pqz-state-b` (commit 61c60089; off-list checks in `test/pqz/PqzShared.t.sol`). The earlier text that listed the rollover as allowlisted is superseded.

**Why.** The owner asked why `PqzToken` should differ from `ZetherToken`; the only reason given for the separate `PqzMetaTx` was ≈ 2 M gas of memory copies, which assumed three copies of `m.data`. One copy for the `CALL` costs ≈ 0.25 M at 340 KB (`3·w + w²/512`), the callee takes `bytes calldata`, and an op stays ≈ 3.25 M, below the EIP-7825 cap. One base and one pipeline then serve every token; PQZ selectors are not batchable.
**Cost if wrong.** ≈ 0.25 M gas more per PQZ op than a sliced-argument dispatch; a second meta-tx implementation to audit otherwise.
**Source.** `history/specs/2026-10-08-metatx-generic-call-design.md` §2 G11, §3 GC-10.

### CTR-PQZ-22 — PQZ entry-point names mirror classical Zether; kinds reserved
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-22 · superseded-by: —

Change (2026-10-14): owner — multi-recipient transfers are ruled for PQZ (P6-ANON plan, owner rulings of 2026-10-14): mode 2A′ = the multi-recipient transfer `R_TXM` (op 7) is a normal SCaaS transfer path beside the unchanged single-recipient op 1 `R_TX` / `R_TX0`, verified for PQZL and PQZH by the one precompile on the SCaaS testnet; D21 — op 7 joins the frozen set, P6e gate A / gate B and the P6-PUB freeze wait for it and freeze once; D20 — no limit raise (`MAX_INPUT` 393,216, `MAX_PROOF` 98,304 / 262,144), built leg counts PQZL M ∈ {1, 2, 4, 8}, PQZH M ∈ {1, 2, 4}; D16 / D17 — no on-chain decoy rule, optional immutable `multiLegFee` (default 0) plus the wallet decoy policy; `fee` = 0 is accepted on op 7 as on op 1 (PQZ and classical Zether).
Change (2026-10-14, revised 2026-10-15 after review): controller proposal (owner may override) — P6-ANON Task S2 (branch `p6-anon-s`), the op 7 statement as built in `pqz-stmt` (`parse_multi`, `Multi::encode`) and `pqz_kat.py` (`build_multi`, `parse` op 7): `opTag = keccak256("SCAAS-PQZ-OP-TRANSFER-MULTI-V1")` (`6f6a773a…`); §7.7 header with word 192 = `recipientsHash = keccak256(word(UA_0) ‖ … ‖ word(UA_{M−1}))` (leg order, each UA as a 32-byte word), word 320 = `M`, `amount` = 0, `fee` may be 0; body `pk_f ‖ pk_0…pk_{M−1} ‖ [pk_a] ‖ T ‖ u_0…u_{G−1} ‖ v_0…v_{M−1} ‖ v_f ‖ [v_{a,0}…v_{a,M−1}]` = 50,048 + 16,640·M + 16,384·⌈M/4⌉ B (auditor on) / 33,664 + 16,512·M + 16,384·⌈M/4⌉ B (off). (1) The decoder enforces the built leg counts **per id**, either auditor mode (PQZL {1, 2, 4, 8}, PQZH {1, 2, 4}, owner D20), not the union; feature `oversize` (bench only) adds M = 8, 16 for both ids, and pqz-ffi refuses to compile with it (`pqz_stmt::OVERSIZE` const assert). (2) The `auditorOn` and `M` words pick the shape and the length must equal it, because the length alone is ambiguous: `(M = 1, on)` and `(M = 2, off)` are both 83,072 B (plan R4 corrected). Rule order: opTag, id, header present (`< 640` B ⇒ length), `auditorOn` ∈ {0, 1}, `M` ∈ the id's set (`Reject::Legs`), length, `fee` / `amount` < 2^64, salt form, `amount` = 0, coefficients < q. `Multi::encode` refuses a header whose `M` / `auditorOn` word disagrees with the objects. (3) `parse` / `decode_input` keep refusing op 7 (`Reject::Op`) until S3 adds `Stmt` / `Form` variants together with pqz-ffi's dispatch and Ligero (their matches are exhaustive); `decode_input` limits unchanged (D8 / D20). PQZH `(M = 4, on)`: 5 + 132,992 + `MAX_PROOF` 262,144 = 395,141 B > `MAX_INPUT`, so a PQZH proof over 260,219 B makes that input exceed `MAX_INPUT` (model: ≈ 232 KB; H2 measures Ligero's exact bound).

Change (2026-10-16): controller proposal (owner may override) — P6-ANON Task S3 (branch `p6-anon-s3`): (1) `pqz_stmt::parse(7, …)` / `decode_input` return op 7 as `Stmt::Multi` (no `Form`: one length per `(M, A)`, `form()` = None; `proof_system_id()` = header word 1), replacing S2's interim `Reject::Op`; an op 1 statement under op 7 and an op 7 statement under op 1 are both `OpTag`. (2) **D3 verdict with measured numbers** (`pqz-core/pqzl/params/anon/anon-sizes-s3.txt`, `anon_sizes.py measured()`; worst-case input = 5 + statement + the id's proof bound): **PQZL built M ∈ {1, 2, 4, 8}** (largest worst-case input M = 8 auditor on 314,245 B with `MAX_PROOF` 98,304; measured proof 61,802 B, verify p99 through the FFI 16.9 ms native, 23.8 ms wasm32 SV); PQZL M = 16 not built: input 474,161 / 449,947 B (on / off) > `MAX_INPUT` 393,216. **PQZH built M ∈ {1, 2, 4}** (largest worst-case input M = 4 on 369,193 B with Ligero's exact bound 236,196 B); PQZH M = 8 not built: bound 281,208 / 279,756 B > `MAX_PROOF_PQZH` 262,144 and input 497,149 / 478,289 B > `MAX_INPUT`; M = 16 also over the gas cap. Equals `built_legs` and the owner's D20; no limit change. (3) Gas by the calldata model with the measured proofs and native p99: PQZL 2.9–4.6 M, PQZH 10.4–10.5 M (floor-bound; the chain's `G_7` is S8's calibration).

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D8: no op 7 (`R_TXM`) entry point in P6g; it follows P6-ANON S3–S8 (the precompile's op 7 and its gas schedule).

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D12: a direct `pqzUnshieldUnwrap` binds its leg and `minOut` through the statement's `envelopeBinding` word, `keccak256(abi.encode(keccak256("SCAAS-PQZ-UNWRAP-V1"), u, minOut))` (Zether's `unwrapBinding`); relayed, the word is the envelope's binding (the envelope signature covers `data`, hence the leg and `minOut`).

**Why.** `pqzShield`, `pqzWrapShield`, `pqzTransfer`, `pqzUnshield`, `pqzUnshieldUnwrap`, `pqzRollOver` follow CTR-ZTH-45; `NONE_PQZ`, `UNDERLYING_PQZ` and `*_ZETHER_PQZ` are reserved kinds (CTR-TOK-21). Open: the disclosure changes Z9/Z10 are not ruled for PQZ (owner review pending); Z12 is CTR-PQZ-24. ~~Multi-recipient transfers are not ruled for PQZ~~ — resolved: owner rulings of 2026-10-14 (Change line below; P6-ANON plan, "Owner rulings").
**Cost if wrong.** Two naming schemes for the same operations across the two classes.
**Source.** `history/specs/2026-10-08-token-tree-design.md` T5, §6.2.

Change (2026-10-20, owner Q3): PQZ and Zether share the `mtx*` names and one interface (see CTR-ZTH-45 change): `pqzShield` → `mtxShield`, `pqzWrapShield` → `mtxWrapShield`, `pqzTransfer*` → `mtxConfidentialTransfer*`, `pqzUnshield` → `mtxUnshield`, `pqzUnshieldUnwrap` → `mtxUnshieldUnwrap`, `pqzRollOver` → `mtxRollOver`, `pqzPrepareAcc` → `mtxPrepareAcc`; views keep their `pqz*` names. Kinds 6 and 7 are dropped (CTR-TOK-21), so the "reserved" part of this rule is closed. Status: decided; BUILT on branch `pqz-state-b` (plan 5h Task 3b, commits 61c60089..82793a58; docs reconciled in 1dcd8657).

### CTR-PQZ-23 — PQZ storage modes and sender memo as classical
- old: — · status: current · owner: yes · date: 2026-10-11 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-23 · superseded-by: —

Change (2026-10-16): owner — op 7 storage mode for PQZL M = 8 on a BUNDLE token: **no automatic COMPACT**; the user chooses the storage mode for each transfer (BUNDLE `pqzTransfer`, COMPACT `pqzTransferCompact`, commit-reveal `pqzTransferNoBundle`) and the contract never switches it. Rejects P6-ANON S9 proposal 3 as written (plan S9 result: SSTORE2 of the 35,088 B M = 8 bundle ≈ 7.05 M gas puts PQZL (8, on) at ≈ 17.4 M [estimate], over EIP-7825). Consequence: a BUNDLE M = 8 transfer that exceeds the per-transaction cap does not fit; the wallet (P6h) shows the estimate and lets the user choose COMPACT or commit-reveal. Open for the op 7 entry points: whether the BUNDLE entry adds an early explicit revert. S9 proposal 2 (PQZH ≤ 10 inline credits) is not affected and stays a controller proposal.

Change (2026-10-16): owner — (1) op 7 BUNDLE entry: **no early explicit revert** for a shape over the per-transaction gas cap (option a); the call simply does not fit, and the wallet (P6h) estimates gas, explains why and lets the user choose the storage mode — the contract carries no rule tied to today's gas prices. (2) **PQZH op 7: at most 10 inline credits per transfer** (S9 proposal 2 accepted: PQZH (4, on) + n inline ≈ 10.67 + 0.52·n M gas, so n ≤ 10 under the node's 16 M) — a contract constant for PQZH in the op 7 entry points (P6g after S8); PQZL keeps `INLINE_MAX` 16 (CTR-PQZ-08). Credits beyond 10 go through `pqzRollOver` or the keeper.

Change (2026-10-16): owner — wallet rule (P6h) for op 7 on a BUNDLE token with the auditor on when the shape does not fit the per-transaction gas cap (PQZL 5–8 real recipients ⇒ M = 8, ≈ 17.4 M gas): M counts legs, not real recipients — any number of real recipients 1…M is sent by filling the other legs with decoys (`a_j = 0`), so an odd count such as 7 is M = 8 with one decoy. The wallet shows the user both options and the user chooses: (a) one transfer with M = 8 in COMPACT or commit-reveal (≈ 10.4 M gas, one transaction, most private) — **the suggested default**; (b) split into transfers that fit BUNDLE, e.g. two M = 4 (≈ 10.7 M each, ≈ 21.4 M total; linkable by sender and timing, fewer decoys per transfer). No contract change (no automatic COMPACT, no early revert, as ruled above).

Change (2026-10-16): controller proposal (owner may override) — P6-ANON Task S3 (branch `p6-anon-s3`), the op 7 sender memo of plan §5.4 as built in `pqz-ffi` (`src/memo.rs`, feature `prove`; HKDF-SHA256 by the `hkdf` 0.12.4 / `sha2` 0.10.9 crates): `key = HKDF-SHA256(IKM = pqzKeySeed, salt = ∅, info = "PQZ/memo/v1" ‖ chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt)` (32 B, the op 7 header's words; `sendCounter` < 2^32), `ks = HKDF-Expand-SHA256(key, "PQZ/memo/ks/v1", 2 + 40·M)`, `memo = salt ‖ ((flags ‖ u8(M) ‖ (be8(a_j) ‖ toUA_j)_{j<M}) XOR ks)` = 18 + 40·M B, `flags` bit0 = `auditorOn`, `memoHash = keccak256(memo)` in header word 19 (no circularity: the key's inputs are other header words). Proposed here: (1) the keystream label `"PQZ/memo/ks/v1"`, the PQZ analogue of classical `"ZTX/memo/ks/v1"` (CTR-ZTH-50; CTR-PQZ-23 names only the key's info); (2) the `u8(M)` byte after `flags` as plan §5.4 writes it (classical has none: its length gives M; op 7 keeps it so a memo read alone names its leg count), so the op 7 memo is 18 + 40·M B, not the classical 17 + 40·M; (3) `open` refuses a length that is not 18 + 40·M, an M byte that disagrees with it and a `flags` byte other than 0 / 1; no MAC, as classical. The op 1 memo (57 B, CTR-PQZ-23) is not built in `pqz-ffi` yet (P6h). Vectors of the memo: S4.

Change (2026-10-16): controller proposal (owner may override) — P6g plan (`superpowers/plans/2026-10-16-p6g-contracts.md`) D14: the bundle is `R = salt ‖ u ‖ v_t ‖ [v_a] ‖ word(toUA)`; on BUNDLE the entry is an SSTORE2 pointer to `R`; on commit-reveal `keccak256(R)` plus the 57-byte memo as given, whose first 16 bytes must equal the payload's salt (`MemoSaltMismatch`) and whose hash is the header's `memoHash`; no-bundle stores nothing and reverts `TransferEntryDisabled` on a COMPACT token. `PqzTransfer` carries the salt (§7.4 says the salt is "in `PqzTransfer`"; §7.8's event gains the field), so `R` can be rebuilt from logs.

**Why.** The owner applies CTR-ZTH-38/48/50 to PQZ: `disclosureMode` at `initialize`, `pqzTransfer` / `pqzTransferCompact` / `pqzTransferNoBundle`, the 57-byte memo for the one recipient. A stored PQZ bundle is ≈ 16.7 KB (SSTORE2, ≈ 3.4 M gas estimate), which is why commit-reveal matters more here.
**Cost if wrong.** Two classes with different disclosure storage semantics for the same entry names.
**Source.** owner, 2026-10-11; background `research/zether-disclosure.md` §4, §6, §7, §9.

Change (2026-10-20, controller record): **storage modes as built** (plan 5h D11, Task 2 `85680d55`, Task 3 `ff4e6948`): every transfer stores its op blob `R ‖ v_f`; `entryPtr[ref]` is the blob in both modes (BUNDLE: `transferEntry = R`; HASH: `keccak256(R) ‖ memo`); `ciphertextHash = keccak256(R)` read from the blob (same value as before, tested against a client-built `R`); the NONE mode and `…NoBundle` are retired (owner O5). Disclosure from the blob: `disclosureStatement(ref, leg, amount, kind)` (no `bundle` argument) and `verifyTransferAmount(ref, leg, amount, kind, proof)` (the opening is the proof alone). Status: decided; built.

### CTR-PQZ-24 — PQZ auditor modes as classical
- old: — · status: current · owner: yes · date: 2026-10-11 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-24 · superseded-by: —

Change (2026-10-14): controller proposal (owner may override) — the auditor-off transfer is built as its own relation `R_TX0` (P6e gap G1, decision D8): `R_TX` without `pk_a`, `v_a`, `e2_a`, row 5 skipped, every other row and norm of `R_TX` kept; statement header ‖ `pk_f ‖ pk_t ‖ T ‖ u ‖ v_t ‖ v_f` = 66,560 B, witness 12,384 B; spec `pqz-core/pqzl/params/tx0_params.sage` → `pqz_tx0_params.h` by LaZer's codegen (MSIS β 457, MLWE uSVP β 470, knowledge error ≤ 2^-127), builder `pqz_rel.c`, specialised verifier `pqz_sv.c`. Rejected: a dummy auditor key with a `v_a` (16.5 KB of calldata per transfer, a fake key in the registry). Op 1 is `R_TX` or `R_TX0` by the statement length, and the `auditorOn` header word (offset 448) must be 1 on the 83,072-byte form and 0 on the 66,560-byte one, any other value rejected (plan ruling R6, checked by both verifiers and the prover; the precompile decoder repeats it). `R_TX0` has its own ABDLOP keys, `SHAKE128("SCAAS-PQZ-ABDLOP-PP-V1" ‖ 0x81)` (0x81 = its internal relation code, never an op on the wire; controller 2026-10-14, after review: distinct domain separation instead of sharing op 1's tag). Accepted-set tightening of `R_TX` and an added form before any deployment: `proofSystemId` stays v2 (D2 / D4). Source add: plan `superpowers/plans/2026-10-14-p6e-relations.md` D8, R6, Task 2; branch `p6e-a2`.
Change (2026-10-14): controller proposal (owner may override) — `R_TX0` in PQZH as well (P6e plan D8, Task 8, branch `p6e-b3`): the Ligero constraint system of `R_TX` without row 5 (no `pk_a`, `v_a`, `e2_a`; every other row, norm and range kept), on the same statement (66,560 B) and witness (12,384 B) bytes as the C core, op 1 told apart by the statement length (R6: `auditorOn` 0 required); THE proven preset as every op (no per-op preset), exact proof bound 234,744 B (≤ 262,144, D5). Measured: proofs 229,672–231,800 B, verify p99 11.1 ms native / 22.3 ms wasm32 over 1,000 verifies (60 ms limit), 960 mutations 0 accepted. Source: `research/pqzh-ligero.md` §14.

**Why.** CTR-ZTH-49 for PQZ: `auditorMode` with `auditorUA`; FULL forces `auditorOn = 1`, OPTIONAL is the per-transfer choice (the Z12 question of CTR-PQZ-22), NONE has no auditor UA.
**Cost if wrong.** A PQZ token could not offer guaranteed audit coverage.
**Source.** owner, 2026-10-11; background `research/zether-disclosure.md` §4, §6, §7, §9.

Change (2026-10-27): **review C2-3 / C2-4 (controller proposal, owner may override)**: `init` requires a registered, usable auditor key whenever the mode is not NONE — 32 zero bytes under FULL or OPTIONAL revert `AccountNotRegistered(0)`; the auditor, `shield` and `mtxPrepareAcc` check the key with `_keyPtr` (registered and of this set's length) as every debit does. Status: **done** (review2 T1; `test_init_zeroAuditorRefused`, `test_valueIn_keyOfAnotherLengthRefused`).

### CTR-PQZ-25 — Two PQZ transfer paths: op 7 multi-recipient and op 1 single, no switch
- old: — · status: current · owner: yes · date: 2026-10-14 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-25 · superseded-by: —

Change (2026-10-17): controller (P6-ANON S7) — written into the spec with the owner's rulings of 2026-10-16: `M` counts legs (decoy padding), the storage mode is the user's per transfer (no automatic COMPACT, no early revert), PQZH op 7 ≤ 10 inline credits (`INLINE_MAX_PQZH`, S9 proposal 2 accepted). Plan decisions recorded as controller proposals (owner may override): D1 scope (mode 2A′ only), D2 both paths (op 1 unchanged), D3 sizes (PQZL {1, 2, 4, 8}, PQZH {1, 2, 4} as built and measured), D12 entry names, D16 decoys a client choice, D17 optional `multiLegFee` (default 0; zero-credit discard and per-window caps rejected), D18 decoy roll-over by keepers, D20 no limit change, D21 op 7 in the frozen set. S9 proposal 1 (node limits unchanged for op 7: `TxPool.MaxTxSize` 1 MiB, `max_gas_per_tx` 16 M, gateway body 1 MiB on the `pqz` profile, block target 80 M) and proposal 4 (plan gas re-based on the live rate; S8's calibration replaces the estimate) recorded as controller proposals; proposal 3 (automatic COMPACT for PQZL M = 8) was rejected by the owner on 2026-10-16 (CTR-PQZ-23).
Change (2026-10-17): owner — `multiLegFee` built with op 7 (D17 accepted; default 0 = no effect): `ConfidentialConfig.multiLegFee`, op 7's fee word `confidentialFee + M · multiLegFee`, `multiLegFee` to every listed leg; Zether kinds refuse a non-zero one. Controller (P6g op 7): the op 7 payload carries `M` and the recipients (`… beneficiaryUA ‖ be32(M) ‖ salt ‖ UA_0 … UA_{M−1} ‖ out ‖ [memo]`), so `pqzTransfer*` keep the single entries' ABI shape (the plan's separate `recipients` / `out` arguments would not compile without via-IR); the multi bundle is `salt ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖ UA_j)_j`, for `M = 1` the single bundle exactly; the statement views run in `PqzLib` by DELEGATECALL (the PQZ tokens shrink to 45,734 / 58,177 B).
Change (2026-10-19): controller proposal (owner may override) — **on-chain review W-A (plan Task 5g, branch `rev2-chain-pqz`, commit `af47304e`; finding T-lead / V1, P2): the storage mode of a direct transfer is bound.** Before: `pqzTransfer` / `pqzTransferNoBundle` (and the Single pair) built byte-identical statements for BUNDLE and NONE (direct `envelopeBinding` 0, the same `opTag`), so a front-runner could replay a BUNDLE call through `…NoBundle`: no entry stored, the sender's on-chain disclosure lost (no theft). Now a direct transfer's `envelopeBinding` is `keccak256(abi.encode(keccak256("SCAAS-PQZ-DIRECT-MODE-V1"), uint8(mode)))` (HASH 0, BUNDLE 1, NONE 2; the `unwrapBinding` pattern), set in `PqzLib.prepareTransfer` / `prepareMulti` when the binding is 0; a relayed call keeps its envelope binding (the envelope signature covers `data`, selector included). The statement views take `binding` 0 for a direct call in the payload's own mode and the NONE binding for a direct `…NoBundle`. Every other entry pair checked: HASH is already distinct (`memoHash`), op 1 vs op 7 (`opTag`), `pqzUnshield` vs `pqzUnshieldUnwrap` (0 vs `unwrapBinding`), Zether (mode in `opTag`, `unwrapBinding`): no other unbound option. No vector changes (the P6e vectors use the synthetic binding `0xE1…`; no client computes a PQZ direct binding; `e2e.py` uses the views with binding 0 and default modes only). Deployed bytecode: `PqzLib` (statement views of both PQZ kinds). Tests `test_directModeBound_single` / `_multi`. Residual (review 5g L1): on a relayed transfer the mode, and on a relayed unshield the unwrap leg / `minOut`, are bound by the envelope signature only, so a broken v1 envelope key can re-sign them (T18 says so); folding the mode into every binding is plan Task 5h. Status: **done** (`af47304e`, merged `734b9c76`); SCaaS testnet redeploy with plan Task 13.

**Why.** Classical Z7 / Z8 (CTR-ZTH-37): one proof for many recipients with decoys, and the single-recipient transfer kept unchanged; the owner chose on 2026-10-14 that SCaaS uses the multi-recipient transfer as the normal PQZ transfer.
**Cost if wrong.** Two code paths per token (size, audit) and decoy load on other accounts' caps (T22).
**Source.** owner, 2026-10-14 and 2026-10-16; `superpowers/plans/2026-10-14-p6-anon.md` §5–§8, D1–D21.

Change (2026-10-20, controller record): **fees and bindings as built** (plan 5h Task 3, `ff4e6948` / `3cbc5f5e`). (1) `multiLegFee` is replaced by the owner's `decoyFee` (CTR-PQZ-06 change): the op 7 payload is `p ‖ validUntil ‖ shieldIn ‖ fromUA ‖ ben ‖ M ‖ decoyFee ‖ salt(16) ‖ UA_0 …` (a 32-byte word before the salt), statement unchanged. (2) D15, review L1 / T18: the mode is folded into every binding — relayed `binding = keccak256(abi.encode(envelopeBinding, uint8(mode)))`, direct `keccak256(abi.encode(TAG_DIRECT_MODE, uint8(mode)))` (value unchanged), a relayed unwrap `keccak256(abi.encode(envelopeBinding, unwrapBinding(u, minOut)))` (direct unchanged; `unshieldUnwrapStatement` uses the same helper), burns keep the envelope binding; a pre-D15 proof of the same envelope and a `…NoBundle`-style proof are both `ProofRejected` (tested). (3) NONE and `…NoBundle` retired (CTR-PQZ-23 change). Status: decided (fee: owner); built.

### CTR-PQZ-26 — R_TXM: the multi-recipient relation and its contract rules
- old: — · status: current · owner: yes · date: 2026-10-14 · normative: contracts/pq-zero-knowledge.md#CTR-PQZ-26 · superseded-by: —

Change (2026-10-17): controller (P6-ANON S7) — spec text written from the built relation (L1 / H1), layout (S2), vectors (S4) and the live precompile (S8, `G_7` per `(id, M, auditorOn)` in §9.3). Plan decisions recorded as controller proposals (owner may override) unless marked: D4 groups of ≤ 4 legs per randomness with or without the auditor (β 446.0, owner-accepted 2026-10-15), D5 one ℓ2 bound per e2 vector (owner 2026-10-15), D6 op 7 and its layout, D7 no `proofSystemId` bump, D8 limits unchanged, D9 one auditor copy per leg (OPTIONAL = whole transfer), D10 disclosure by leg with `R_DS` / `R_DR` unchanged, D11 bundle and memo with `M` legs, D13 group seeds `SCAAS-PQZ-ENC-GROUP-V1` (CTR-PQZ-19), D14 op 7 in the reproduction package (S6), D15 op 7 vectors (S4), D19 the precompile prices op 7 by the header words (S8).
Change (2026-10-19): owner — whole-code review of PQZH Rust, the PQZL C core and the LaZer fork (Codex aborted for lack of credits; four Claude reviewers, reports `pqz-core/research/code-review-2026-10-19/`) found a **P0 soundness break in PQZL**: the toolbox protocol's Fiat–Shamir transcript does not absorb `h` before the challenge `mu` (nor in the final challenge) and does not absorb `z3`, `z4` before their Schwartz–Zippel challenges, in the C generic and specialised verifiers, the Rust core and the provers, inherited from upstream LaZer (controller re-read the transcript facts in Rust and in upstream `b958e24`; no proof of concept run yet). Owner rulings: (1) **fix now**, ahead of the remaining Rust-port follow-ups and the token-family rename: a cheating-prover proof of concept first, then the transcript fix in all four implementations, a new PQZL `proofSystemId`, regenerated vectors / digests / package, spec update, gate; (2) **report upstream as a public issue at once**: filed as lazer-crypto/lazer#28 (2026-10-19); (3) **stop and roll back the Rust-backed roll-out on the SCaaS testnet**: live stays on image `pqz2` until the fix. The frozen PQZL `proofSystemId` and gate A's 2026-10-17 PASS predate the finding (pqz-core STATUS Open item 11). Other findings (PQZH Ligero prover side channels P2/P3; STARK backup preset not zero-knowledge and 71.9 proven bits P1, varint malleability and unhedged masks P2; LaZer z2 rejection variance P2, β4 sign bit P3; C arena sink P3) are recorded in the reports for later rounds.
Change (2026-10-19): owner — rulings for the PQZL Fiat–Shamir fix (plan `superpowers/plans/2026-10-19-pqzl-fs3.md`, Task 0; lazer#28): (F9) **the SCaaS testnet is reset from genesis** at the v3 roll-out (path B; backup first, as on 2026-10-15/16), so the forgeable PQZL id v2 is removed from the accepted set and from `pqz-stmt`, and the PQZ tokens and `UAPqzVerifier` are redeployed; (F7) D-2 is fixed with **Rej1**, the one-time-commitment rejection of LNP22 / LNS21 (reject if ⟨z2, c·s2⟩ < 0, else accept with exp((‖v‖² − 2⟨z,v⟩)/(2σ2²))/M2 using `stdev2sqr` and the existing `scM2`), **no parameter regeneration** (the M2 formula is confirmed against the paper in the plan's Task 11); (F2) z3 and z4 are absorbed with **the proof's own encoding** (one coder session, grandom3 of z3 then z4, on centred copies), h with its urandom3 proof encoding; (PoC) **binding regression tests replace the earlier ruling "cheating-prover PoC first"**: in all four implementations a test that the V3 / V4 seeds depend on z3 / z4 and the μ / final-challenge seed depends on h, failing before the fix and passing after; no forging tooling is written.
Change (2026-10-19): controller — the second code review of the PQZL C core (L Codex, M agy, N Claude; plan Task 5e): no P0 / P1, no C = Rust verdict divergence (op 7 included); the fixes Q-A…Q-H and the Rust-port minors are recorded under CTR-PQZ-09, none changes a proof byte or a verdict on a valid input (the `proofs_fnv` lines, `pqz-vectors --check` and the self-test hash are unchanged). Status: done on branch `rev2-pqzl`, merge with plan Task 12.
Change (2026-10-19): controller proposal (owner may override) — **on-chain review W-I, PQZ part (plan Task 5g, commit `af47304e`; V1-07, P3 hygiene):** `_parseMulti` checks `payload.length ≥ T_OUT + 32·M + memo` before the subtraction (a short payload is `BadPayload`, no longer panic `0x11`; test `test_multi_shortPayloadIsBadPayload`); `verifyTransferAmount`'s doc now matches its behaviour, chosen over a code change (no token bytecode): a non-canonical opening, empty proof, unknown entry, wrong bundle or leg, `kind > 2`, `amount ≥ 2^64` are false, an opening that does not ABI-decode as `(bytes, bytes)` reverts, as `ZetherDisclosure`'s `OpeningMalformed` (test `test_verifyTransferAmount_undecodableOpeningReverts`). Status: **done** (`af47304e`, merged `734b9c76`).

Change (2026-10-26): controller proposal, owner may override — **R0 review fix part b, the contracts** (branch `pqz-r01`): (1) op 7's groups follow the owner's rule of 2026-10-25 in every contract path: `G = ⌈M / S_AUD⌉` and leg `j` in `u_{⌊j / S_AUD⌋}` with the auditor copies, `⌈M / 4⌉` / `⌊j / 4⌋` without (`PqzCore._groups` / `_groupOf`: `_parseMulti`, `multiHasMemo`, the credits, `_legOf`, `_bundleShape`); the payload length fixes `auditorOn` first (the audited `out` is at least `V·M` longer, so the two shapes never share a length), then `G`. (2) `_bundleShape` decodes `(G, M, auditorOn)` from the length of `R`; forge test `test_bundleShape_unique` proves it unique for every `M ≤ 8` at each set through `at-set.sh` (each set's leg blocks stay below `PKP`; all 16 lengths distinct). (3) The disclosure head's kind word is `OpeningKind + 256·w`, `w = leg mod S_AUD` for `AUDITOR` and 0 otherwise, byte-identical to pqz-stmt's `DW_KIND` rule and the vectors' `disclosures` (forge test against the vectors, head words extracted to `smartcontracts/evm/test/vectors/pqz-disclosures/<set>.json`). (4) **F-4:** with the auditor copies on, `fromUA == auditorUA` or a recipient (op 1's `toUA`, any op 7 leg) `== auditorUA` reverts `AuditorAsParty(bytes32 ua)` on every transfer form, relayed and direct, and in the statement views (one check in `PqzCore._receiver` / `_legs`, which every path calls); the alternative (auditor windows off window 0) works only for `s ≤ 3` and was not taken. Tokens unchanged in size (size gate 0 errors). Status: proposal.

**Why.** `R_TX` with M legs and grouped randomness: linear rows, exact norms and digits only, so LaZer's tbox and Ligero serve it unchanged; `M = 1` is `R_TX` exactly.
**Cost if wrong.** A second transfer relation in both proof systems and in the frozen set; the hint budget per group is below the self-imposed 450 margin by the owner's acceptance.
**Source.** `superpowers/plans/2026-10-14-p6-anon.md` §2–§4; `pqz-core/pqzl/params/anon/hints-anon.txt`; P6-ANON S1–S8.

### CTR-PQZ-80 — PqzMetaTx: own mixin with op arguments sliced from calldata
- old: — · status: superseded · owner: yes · date: 2026-10-08 · normative: — · superseded-by: CTR-PQZ-21

**What it said.** `PqzToken` relayed through its own mixin `PqzMetaTx` with an `_executeOp` reading `m.data` as calldata slices (no self-call, `m.to = m.value = 0` else `PqzOpNotCanonical`), nonce spent with the fee after verify.

## 26. Networks — common model

### NET-ALL-01 — Pruning families keep executed lanes for H
- old: CR-PD-4(pruning), CR-R3-8(pruning) · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-01 · superseded-by: —

**Rule.** Families that prune executed lane state keep an executed lane for at least the horizon H after the op's `validUntil`.
**Why.** At-most-once payment per request holds only while the executed lane is remembered: GRAM measures `validUntil` from execution, not from lane creation, so state pruned earlier than the issuance horizon would let a sibling signature on the same lane execute again. The prune delays equal the 30-day horizon today, so ERP-issued terms are safe.
**Cost if wrong.** Issuers that sign terms on a lane beyond H get no pay-once guarantee.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 901; [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 700.

### NET-ALL-02 — Contract-level meta-tx default on every network
- old: R30, UD:§1:eip1776, UD:§21.5 · status: current · owner: yes · date: 2026-10-08 · normative: networks/README.md#NET-ALL-02 · superseded-by: —

Change: on EVM and Hedera the gateway runs a transfer, a payment or an allowlisted self-call of the token itself, never a call to another contract; signature-authorised entry points are named `mtx…`. Source add: §2 A1–A3, §3 MG-1, MG-3.
Change (2026-10-08): `mtxExecute` runs only allowlisted self-calls and token transfers/payments are `MetaTransfer`s (CTR-MTX-23); the non-EVM families sign the same two kinds (NET-ALL-26) and name signed entries `mtx` in their case (NET-ALL-28). Source add: `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-1, NM-2.

### NET-ALL-03 — Head-of-line table and anti-lock test
- old: R62 · status: current · owner: no · date: 2026-10-05 · normative: networks/README.md#NET-ALL-03 · superseded-by: —

**Rule.** Every adapter states how it avoids head-of-line blocking, and every family passes the anti-lock test.
**Why.** A sequence is strictly ordered, so one stuck transaction (fee below the mempool floor, or a nonce gap) blocks everything queued behind it; with a single key that means a dead relayer until someone intervenes, and one key also caps throughput at about one transaction per block.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 535.; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 1538

### NET-ALL-04 — One WebAuthn grammar for every family
- old: CR-R3-1(grammar), RS4-2 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-04 · superseded-by: —

**Rule.** One WebAuthn rule and one bounded `clientDataJSON` grammar for every family.
**Why.** Verifiers had drifted apart: on Cosmos any page that could get an assertion for the rpId (a sibling subdomain, a related origin, a delegated iframe) could sign any operation, GRAM accepted any origin extending the stored one as a prefix, and elsewhere a cross-origin iframe yields assertions that carry the relying party's origin.
**Cost if wrong.** Cosmos dev passkey addresses change.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 630; [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 15.

### NET-ALL-05 — Key lifecycle stated per family
- old: CR-R3-6 · status: current · owner: no · date: 2026-10-08 · normative: networks/README.md#NET-ALL-05 · superseded-by: —

**Rule.** Key rotation and recovery are stated per family; every gap is listed, never implied away.
**Why.** The families do not offer the same lifecycle: a Cosmos passkey account is one key with no rotation, the Soroban guardian is only a seam, and a GRAM passkey cannot rotate and has no guardian, so a single blanket claim would hide real gaps.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 679.
Change (2026-10-08): EVM rotation runs through `mtxExecute` signed by the account (CTR-ACC-10). Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-6.

### NET-ALL-06 — Indexer filters registered contracts; empty stalls
- old: net-aptos:L1, net-solana:L1 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-06 · superseded-by: —

**Rule.** The indexer filters by the registered contracts in the family's own address form, and an empty list never advances the cursor.
**Why.** The Cosmos, Sui and GRAM reviews found indexers reading a static or wrongly formatted contract list; an indexer that advances with an empty or mismatched list moves past ranges it never really scanned.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 37; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 41.

### NET-ALL-07 — e2e fakes return real token ids
- old: net-aptos:L2, net-solana:L2 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-07 · superseded-by: —

**Rule.** End-to-end fakes return real token ids and refuse unregistered emitters.
**Why.** The GRAM and Hedera reviews found end-to-end tests that passed against fakes; a copy of the contract deployed elsewhere emits identical events, and only a fake that returns the real token ids and refuses strangers proves the indexer drops them.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 38; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 42.

### NET-ALL-08 — Payer signs every amount deciding delivery
- old: net-aptos:L3, net-solana:L3 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-08 · superseded-by: —

**Rule.** Every amount chosen by the relayer that decides whether value arrives must be inside the payer's signature.
**Why.** The GRAM review found a relayer-chosen `forwardTon` amount that decided whether a signed payment arrived; any such amount outside the signature hands that decision to the relayer.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 39; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 43.

### NET-ALL-09 — Permanent submit refusals free the lane
- old: net-aptos:L4, net-solana:L4 · status: current · owner: no · date: 2026-10-07 · normative: networks/README.md#NET-ALL-09 · superseded-by: —

**Rule.** A permanent refusal at submit frees the lane at once
**Why.** The Cosmos and Hedera reviews found lanes held by submissions that could never succeed; resending the same bytes after a permanent refusal never passes, so holding the lane only blocks the jobs behind it.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 40; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 44.

### NET-ALL-10 — Crash-safe lanes never equivocate
- old: net-aptos:L5, net-solana:L5 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-10 · superseded-by: —

**Rule.** Lanes are crash-safe: no equivocation, no sequence used twice.
**Why.** The Sui review found that a restart could sign a second transaction on the same gas-coin version (equivocation); every family must show that a crash never yields two different transactions for one lane sequence.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 41; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 45.

### NET-ALL-11 — Multi-key accounts survive origin change
- old: net-aptos:L6, net-solana:L6 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-11 · superseded-by: —

**Rule.** Multi-key accounts with origins and a guardian survive an origin change.
**Why.** The Sui review found a one-key account that was bricked when the portal origin changed; several keys, an origin list and a guardian with a delay let the owner add the new origin or recover instead.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 42; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 46.

### NET-ALL-12 — Coins sent to accounts stay spendable
- old: net-aptos:L7, net-solana:L7 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-12 · superseded-by: —

**Rule.** Coins sent directly to an account or contract address stay spendable.
**Why.** The Sui, Cosmos and GRAM reviews found coins sent straight to an account or contract address that no code path could move, so they were stuck for good.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 43; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 47.

### NET-ALL-13 — No shared object serialises all markets
- old: net-aptos:L8, net-solana:L8 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-13 · superseded-by: —

**Rule.** No shared object serialises all markets.
**Why.** The Sui review found one shared object serialising every market. A hot shared account runs its transactions one after another, hits per-account compute caps, raises local fees and is dropped under congestion, so unrelated operations of one subject end up waiting on each other.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 44; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 48.

### NET-ALL-14 — ERP verifies only keys it can prove
- old: net-aptos:L9, net-solana:L9 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-14 · superseded-by: —

**Rule.** A client verifies a signature only with a key it can prove belongs to the payer
**Why.** The GRAM and Sui reviews found signatures accepted from keys not tied to the payer. A key added later on chain cannot be checked by the ERP without an RPC call, so it answers "unknown" and the node's simulation decides; it never answers "valid" for a key it cannot prove.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 45; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 49.

### NET-ALL-15 — Lane state prunable, storage refunded
- old: net-aptos:L10, net-solana:L10 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-15 · superseded-by: —

**Rule.** Lane and nonce state is prunable and its storage is refunded.
**Why.** The GRAM review found lane and nonce tables that grow forever and keep charging storage; a permissionless prune that returns the storage deposit gives relayers a reason to clean up.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 46; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 50.

### NET-ALL-16 — Never case-fold base58 addresses or ids
- old: net-solana:L11 · status: current · owner: no · date: 2026-10-04 · normative: networks/README.md#NET-ALL-16 · superseded-by: —

**Rule.** Base58 addresses and ids are never case-folded.
**Why.** Base58 is case-sensitive, and the ERP normalised addresses and transaction hashes with `.lower()`, which corrupts Solana addresses; transaction ids are therefore carried as `0x` plus 128 hex digits, which survive lowercasing.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 51.

### NET-ALL-17 — Asset suite on EVM and Hedera
- old: R215 · status: current · owner: no · date: 2026-10-06 · normative: networks/README.md#NET-ALL-17 · superseded-by: —

**Rule.** The asset suite is specified for EVM and Hedera only.
**Why.** EVM and Hedera run the same Solidity, so one implementation covers both; the other families first need their v2 wrapper work (NET-ALL-19) and then map the same rulings onto native mechanisms.
**Cost if wrong.** Nothing to undo.
**Source.** [history/specs/2026-10-06-asset-suite-design.md](history/specs/2026-10-06-asset-suite-design.md) line 184.

### NET-ALL-18 — Tender on EVM and Hedera first
- old: R188 · status: current · owner: yes · date: 2026-10-07 · normative: networks/README.md#NET-ALL-18 · superseded-by: —

**Rule.** The sealed-bid tender ships on EVM and Hedera first
**Why.** The tender verifies no signature, so the same bytecode runs on Hedera's smart contract service without a Hedera child, and Hedera-native bidders are handled by the deposit token; the other families need native designs.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 121.

### NET-ALL-19 — Wrappers v2 on EVM and Hedera only
- old: R145 · status: current · owner: no · date: 2026-10-06 · normative: networks/README.md#NET-ALL-19 · superseded-by: —

**Rule.** Token wrappers v2 are EVM and Hedera only
**Why.** Move and Solana need no wrapper for gaslessness because the subject account already holds any coin or asset; Cosmos, Soroban and GRAM keep their tier-1 tokens until wrappers there are designed with the same rate and reserve rules.
**Source.** [history/specs/2026-10-06-token-wrappers-v2.md](history/specs/2026-10-06-token-wrappers-v2.md) line 152.

### NET-ALL-20 — Per-family UA registries share kind table
- old: R314, UA:Q12 · status: current · owner: yes · date: 2026-10-07 · normative: networks/README.md#NET-ALL-20 · superseded-by: —

**Why.** GRAM calls are asynchronous, and owner consent alone would let a wallet claim someone else's key. Owner-confirmed.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 303; [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 1412.

### NET-ALL-21 — Non-EVM passkey owners = UA id, URN only
- old: R315, UA:Q13 · status: current · owner: yes · date: 2026-10-07 · normative: networks/README.md#NET-ALL-21 · superseded-by: —

**Why.** A 20-byte form is exactly the truncation the UA id space forbids (2^80 collision work against secp256k1 accounts, CTR-UA-03); an account-shaped form invites native sends to a keyless address.
**Cost if wrong.** dev passkey accounts re-open; users copy a URN, not an address. Owner-confirmed.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 311; [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 1413.

### NET-ALL-22 — Chain identified by (chain_key, chain_uid); chain_uid salts every SCaaS domain
- old: R330 · status: current · owner: no · date: 2026-10-08 · normative: networks/README.md#NET-ALL-22 · superseded-by: —

Change: `chain_uid` is a constructor immutable of every SCaaS contract with a signature and the `salt` of every SCaaS EIP-712 domain, also bound into the confidential token's non-EIP-712 digests; CREATE2 deployer stated (addresses per chain for contracts that take `chain_uid`); fork limit stated (NET-ALL-25); Hedera block-0 hash stability check. Source add: §3 MG-4, §7 NET-ALL-22.
Change (2026-10-08): `chain_uid` (or the family identifier) is the `network` field of `MetaCall`/`MetaTransfer` (NET-ALL-26). Source add: `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-1.
Edit note (2026-10-08): `chain_uid` alone is not unique (Ethereum/ETC, Avalanche C-Chain/Fuji share a genesis), so a chain is `(chainId, chain_uid)`; pruned RPCs may not serve block 0, so deploy scripts and the node read `smartcontracts/evm/chain-uids.json`. Not a new id.

### NET-ALL-23 — Sui/Solana wallet signatures readable, passkey-first
- old: CR-WSF-1 · status: current · owner: no · date: 2026-10-08 · normative: networks/README.md#NET-ALL-23 · superseded-by: —

**Rule.** Solana and Sui wallet-key signatures: no blind blobs; origin binding through the passkey path or an opt-in account policy.
**Why.** Solana `signMessage` and Sui `signPersonalMessage` wallets write no requesting origin into the signed bytes, so any origin line a contract checked could have been written by the phishing page itself; a readable text rebuilt on chain at least lets the wallet show what is being paid, as with any wallet transaction on that page.
**Source.** [history/specs/round3-wallet-signing-formats.md](history/specs/round3-wallet-signing-formats.md) line 343.
Change (2026-10-08): the readable text is rebuilt from the `MetaTransfer`; a `MetaCall` renders its function, argument hash, network, expiry and digest, and clients decode the arguments before signing. Source add: `history/specs/2026-10-08-nonevm-metacall-design.md` §4.

### NET-ALL-24 — Chain profile carries chain_uid and the DEX list
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/README.md#NET-ALL-24 · superseded-by: —

**Why.** Every SCaaS domain is salted with `chain_uid`, and the genuine DEXes are known only off chain (the token consults no on-chain DEX registry; the factory's `isDex` is advisory, CTR-DEX-24; owner 2026-10-08); the signer and the relayer need both values from a source they control, not from a server answer.
**Cost if wrong.** Clients sign with the wrong salt (every signature fails) or for a phishing `dex`.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §3 MG-4, MG-6; §4; §13 N-H1.

### NET-ALL-25 — A chain we run that forks becomes a new chain; no shared genesis hash
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/README.md#NET-ALL-25 · superseded-by: —

**Why.** Two branches of a fork share genesis, so `chain_uid` cannot separate them; a PoA chain re-created from the same genesis file repeats its hash. Owner ruling (2026-10-08): a fork of a chain we run gets a new chain id and `chain_key`; every private genesis carries a unique `extraData` nonce and a known genesis hash is refused.
**Cost if wrong.** Signatures made on one branch or one incarnation of a chain replay on the other.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §3 MG-4 (limits), §10 OQ3.

Under "Networks — EVM":

### NET-ALL-26 — Two signed kinds off EVM: MetaCall and MetaTransfer
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/README.md#NET-ALL-26 · superseded-by: —

**Why.** SCaaS meta-transactions pay for any SCaaS function, not only transfers (owner, 2026-10-08); the non-EVM families mirror the EVM split into a generic `MetaCall` (function + hash of its arguments) and a typed `MetaTransfer` (`entry_ref` 0 = transfer, else payment) on one lane space per contract, with no fee field off EVM.
**Cost if wrong.** A closed op byte keeps every new gasless function (and every third-party contract) out of reach, and families drift from the EVM model.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §1, §3 NM-1, §6 Q4.

### NET-ALL-27 — Verify generically, dispatch statically
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/README.md#NET-ALL-27 · superseded-by: —

**Why.** Move has no call by name and Solana declares every account up front, so the shared part is a per-family verifier library; each gasless function is a typed entry that calls it with its own name and argument hash; CosmWasm and GRAM use one `MtxExecute` message with internal dispatch. Owner: OK (2026-10-08).
**Cost if wrong.** One dispatching entry would need dynamic dispatch Move lacks, or a write-set Solana cannot declare.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §2, §3 NM-2, NM-4, §6 Q2.

### NET-ALL-28 — mtx names in every family, typed path at parity with EVM
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/README.md#NET-ALL-28 · superseded-by: —

**Why.** One naming rule everywhere (owner, 2026-10-08, reversing "non-EVM families keep their op names"): `mtx_` snake case in Move, Soroban and Solana, `Mtx` Pascal case for CosmWasm and GRAM; `mtx_transfer`, `mtx_pay` (lane derived from the reference), `mtx_execute_transfer` and batch as on EVM; native-signer entries and chain standards (SEP-41, CW20) keep their names. Nothing is deployed outside test chains.
**Cost if wrong.** Signed and direct entry points look alike, and the node, clients and readers cannot tell them apart.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, NM-5, §6 Q1, Q4.

### NET-ALL-29 — Key management and mandate operations are MetaCall entries
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/README.md#NET-ALL-29 · superseded-by: —

**Why.** `KeyOp`, `ForwardOp`, `MandateInit`, the mandate close/revoke messages, the Cosmos mandate JSON and GRAM `MandatePay`/`set_key` are SCaaS structs, not chain standards (owner, 2026-10-08); as `MetaCall` entries they share the verifier, the lanes and one vector set; native chain-key rotation is untouched; DEX order structs stay, and the `trade` op becomes the token entry `MtxTrade` where a leg is token-signed.
**Cost if wrong.** Each extra struct keeps its own domain, nonce and vectors to maintain in every client language.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-3, §6 Q3.

### NET-ALL-80 — R36-R49 reserved for the third design batch, never used
- old: R36, R37, R38, R39, R40, R41, R42, R43, R44, R45, R46, R47, R48, R49 · status: unused · owner: no · date: 2026-10-03 · normative: — · superseded-by: —

R36-R49 reserved for the third design batch, never used.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 4.

### NET-ALL-81 — MetaOp v1: one payload with an op byte for every non-EVM family
- old: — · status: superseded · owner: yes · date: 2026-10-08 · normative: — · superseded-by: NET-ALL-26

**What it said.** Every non-EVM family signed `"scaas.metaop.v1" ‖ network ‖ contract ‖ op (pay | trade | mandate_pay | revoke) ‖ from ‖ to ‖ amount ‖ payRef ‖ lane ‖ nonce ‖ validUntil ‖ relayer ‖ extra`.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §1, §3 NM-1.

### NET-ALL-82 — Key management and mandates on structs of their own
- old: — · status: superseded · owner: yes · date: 2026-10-08 · normative: — · superseded-by: NET-ALL-29

**What it said.** `KeyOp` (`scaas.keyop.v1`), `ForwardOp`, `MandateInit`, mandate close/revoke messages, the Cosmos mandate JSON and GRAM `MandatePay` were separate signed structs with their own nonces.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-3, §6 Q3.

## 27. Networks — EVM

### NET-EVM-01 — Celo fee currency (CIP-64)
- old: req:blockchain.md:celo-fee-currency · status: open · owner: yes · date: 2026-10-07 · normative: networks/evm.md#NET-EVM-01 · superseded-by: —

**Rule.** Celo fee-currency support (CIP-64) for relayer lanes is an open owner requirement.
**Why.** Celo lets a transaction pay gas directly in an ERC-20 stablecoin, so an enterprise or an open relayer can submit and sponsor transactions without holding native CELO.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 184.

### NET-EVM-02 — Private reference chain id is 7622
- old: CR-PD-6, owner:2026-10-07:chain-7622 · status: current · owner: yes · date: 2026-10-07 · normative: networks/evm.md#NET-EVM-02 · superseded-by: —

**Rule.** The private reference chain is chain id 7622; its identity is the pair (chain id 7622, genesis hash `0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464`), profile `private7622`.
**Why.** Chain id 9000 is also Evmos Testnet, and replay protection is only as good as the chain id; the genesis hash pins the chain beyond the registry convention.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 918; [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 39.

### NET-EVM-03 — First target chain is the private PoA chain
- old: UD:§16, UD:§16:roadmap · status: current · owner: yes · date: 2026-08-30 · normative: networks/evm.md#NET-EVM-03 · superseded-by: —

**Rule.** The first target chain is the private PoA chain; public chains follow, and CI builds the `private7622` profile.
**Why.** Owner decision: the private chain goes first because gas is not a constraint there (minimum gas price 0) and its Prague fork has EIP-2537 BLS12-381 from genesis, which confidential transfers need.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 889; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 929.

### NET-EVM-04 — Single-signer PoA must be named honestly
- old: UD:§16:single-signer · status: current · owner: yes · date: 2026-08-30 · normative: networks/evm.md#NET-EVM-04 · superseded-by: —

**Rule.** A single-signer PoA chain is named honestly.
**Why.** A Clique chain with one signer is not a decentralised blockchain in any sense; it is a database with hashes and signatures, a single point of censorship and of failure, so partners settling on it must know who controls the signer.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 917.

### NET-EVM-05 — CREATE2 deployer with fixed salts; chain_uid from the RPC; deploy gate checks chainUid()
- old: — · status: current · owner: yes · date: 2026-10-07 · normative: networks/evm.md#NET-EVM-05 · superseded-by: —

**Why.** Owner ruling A11: every SCaaS contract is deployed through a deterministic CREATE2 deployer with a fixed salt, so addresses follow from the init code (per-chain for contracts that take `chain_uid`, identical otherwise) instead of from the deployer's nonce; the deploy script reads `chain_uid` from the RPC and the gate checks every `chainUid()` and refuses a known genesis hash.
**Cost if wrong.** Unpredictable addresses across chains, or a contract deployed with another chain's `chain_uid`.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §2 A11; §3 MG-4, MG-6; §6 step 2.

### NET-EVM-06 — Every profile compiles for Amsterdam (Glamsterdam required on every chain)
- old: — · status: current · owner: yes · date: 2026-10-21 · normative: networks/evm.md#NET-EVM-06 · superseded-by: —

**Rule.** Every Foundry profile (default, private7622, zether, gnosis, celo, bsc, polygon, base) uses `evm_version = "amsterdam"` (Foundry 1.8.5, `experimental = true`); every chain that runs these contracts requires Glamsterdam, and a public chain is deployed only after its fork. No contract reads `block.slotnum` (EIP-7843 is off on the SCaaS testnet: Clique has no slot).
**Why.** The SCaaS testnet runs Nethermind 2.2.0 with Amsterdam from block 1, and owner ruling 2026-10-21 makes Glamsterdam mandatory everywhere, so one set of gas bounds priced as the chain prices them is enough.
**Cost if wrong.** Gas bounds pinned for another schedule would pass in CI and fail on the chain.
**Source.** Owner 2026-10-21 (Task F185, "Đồng ý").

**Addendum (review C5-1, 2026-10-27; controller proposal, owner may override).** A release needs a block gas limit of
`runtime × 1,530 + 2^24` (EIP-8037 state gas for the code deposit plus the EIP-7825 regular-gas cap): about 75.8 M for
`NONE`, about 110.9 M for `UNDERLYING_PQZ` (table in [networks/evm.md](networks/evm.md#NET-EVM-06)), from
`size-baseline.json`. The deploy scripts read the chain's `block.gaslimit` and refuse a release deployment below the
kind's need. No code-size work (owner: not before Glamsterdam).

Under "Clients — signers":

### NET-EVM-80 — First chain Gnosis, then Celo
- old: UD:§1:first-chain · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: NET-EVM-03

It said: First chain Gnosis, then Celo; replaced by NET-EVM-03.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 41.

### NET-EVM-81 — Raise the private chain block gas limit
- old: UD:§16:gas-limit · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CTR-PQZ-11

It said: Raise the private chain block gas limit; replaced by CTR-PQZ-11.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 904.

### NET-EVM-82 — Chain 9000 genesis keys silently ignored
- old: UD:§18 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: NET-EVM-02

It said: Chain 9000 genesis keys silently ignored; replaced by NET-EVM-02.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 997.

## 28. Networks — Hedera

### NET-HED-01 — Hedera HCS anchoring
- old: req:blockchain.md:hcs-anchoring · status: open · owner: yes · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-01 · superseded-by: —

**Rule.** HCS anchoring is an open owner requirement.
**Why.** HCS gives an immutable, timestamped audit log for the hashes of important agent decisions; the consensus timestamp is the evidence.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 235.

### NET-HED-02 — Hedera Schedule Service
- old: req:blockchain.md:hedera-schedule · status: open · owner: yes · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-02 · superseded-by: —

**Rule.** The Hedera Schedule Service is an open owner requirement.
**Why.** High-risk agent actions are created as scheduled transactions that execute only once reviewers have added enough signatures.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 242.

### NET-HED-03 — ED25519 owners pay via mtxExecuteAsOwnerRaw
- old: CR-ADW-2 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-03 · superseded-by: —

**Rule.** An ED25519 owner pays from its `MandateWallet` only through `mtxExecuteAsOwnerRaw`.
**Why.** ERC-1271 runs under STATICCALL and the HIP-632 `isAuthorizedRaw` precompile halts there, so `isValidSignature` cannot cover an ED25519 owner; special-casing the token would add one more Hedera-only path to the signature pipeline for a rare case.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 303.

### NET-HED-04 — Hedera = Solidity on HSCS + HIP-632
- old: R63 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-04 · superseded-by: —

**Rule.** Hedera is the EVM family on the Hedera Smart Contract Service: the same Solidity contracts behind a Hedera JSON-RPC relay, plus HIP-632 for ED25519 accounts; the payer-sponsored path is not used.
**Why.** The payer-sponsored path is a transaction from the subject's own Hedera account, which is exactly the subject lock NET-ALL-02 forbids; running the existing Solidity contracts on HSCS reuses all of them unchanged. The first wording of this ruling, "reuse SubjectAccount/pipeline on Hedera", was narrowed by the Hedera design: there is no `SmartKeyAccount` and no EVM pipeline on Hedera, because native Hedera accounts already rotate keys and the relayer runs `lane_runner`.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 536.

### NET-HED-05 — Hedera status code to outcome class table
- old: R6-7 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-05 · superseded-by: —

**Rule.** Each Hedera status code maps to one outcome class; a billed failure is never requeued without limit
**Why.** The adapter sent every known code except `CONTRACT_REVERT_EXECUTED` back to `queued`, including codes billed after consensus, with no attempt cap; a contract wallet whose `isValidSignature` burns almost no gas under estimation and the full cap at consensus then loops until `validUntil`.
**Cost if wrong.** Each loop the lane pays at least 80% of the estimated gas, again and again, for one payment that never lands.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 162.

### NET-HED-06 — v1 HTS wrapper fee check in initialize
- old: R6-8 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-06 · superseded-by: —

**Why.** An HTS underlying with any fixed, fractional or royalty fee breaks a wrapper — `MetaToken.wrap` measures what actually arrived (fine for receiver-side fees) but `unwrap` sends exactly `amount` (`MetaToken.sol:134-139`), so a fixed fee in the same token or a fractional fee with `netOfTransfers = true` is taken from the wrapper again (`balanceOf(this) < totalSupply`, the last redeemer is stuck), and a fixed fee in HBAR makes every `unwrap` revert (the wrapper holds no HBAR), locking the reserve. v2 refuses these; the built v1 `HederaMetaToken` only associates (the permissionless `associateUnderlying()` calling `0x167 associateToken(this, underlying)`), is still registered as `META v1` (`DeployHedera.s.sol:29-30`), and anyone may create it through the open factory (`OpenFactory.createMetaToken`, permissionless, `:91-96`; `deprecate` does not block creation — `_registered` checks only non-zero, `:167-170`). Fix (SPECIFIED): `MetaToken.initialize` calls an `internal virtual _checkUnderlying(u)` hook (empty by default); `HederaMetaToken` overrides it with `HederaHts.checkAndAssociate(u)` and reverts `UnderlyingInvalid` on any fee; `associateUnderlying()` is deleted (association inside `initialize` means a token that cannot associate is never born, and the auto-association slot is no longer a detour); a new implementation is deployed, registered as a new META version on the Hedera factory, and `deprecate(META, 1)` follows. Until then the wizard and the node's token registry refuse a v1 Hedera token whose underlying is an HTS token with custom fees. Forge tests (mock `0x167`): v1 on an underlying with fixed/fractional/royalty fees ⇒ creation reverts; no fee ⇒ associated once, wrap/unwrap conserve the reserve; `isToken` failure ⇒ `HtsQueryFailed`.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 201.

### NET-HED-07 — Wallets warn on HTS issuer keys
- old: R6-9 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-07 · superseded-by: —

**Rule.** Wizards and wallets read every key of the HTS issuer and warn before a wrapper is created.
**Why.** A wipe key can erase the wrapper's underlying balance and a freeze, KYC or pause key can lock every holder; these keys cannot be blocked on chain because real HTS tokens such as Hedera USDC carry them.
**Cost if wrong.** A wrapper loses its backing or locks its holders without anyone having been told.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 215.

### NET-HED-08 — Hedera runs lane_runner, one tx per lane
- old: R6-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/hedera.md#NET-HED-08 · superseded-by: —

**Rule.** Hedera runs `lane_runner` (one transaction in flight per lane), with no pipeline, replacement or gap-fill.
**Why.** Hedera has no mempool: a transaction with a future nonce is refused with `WRONG_NONCE`, so pipelining, replacement and gap-fill have nothing to work with.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 289.

### NET-HED-09 — HederaMetaToken HIP-632 for 64-byte signatures
- old: R6-2 · status: current · owner: no · date: 2026-10-03 · normative: networks/hedera.md#NET-HED-09 · superseded-by: —

**Rule.** `HederaMetaToken` verifies a 64-byte signature from an account without code through HIP-632 `isAuthorizedRaw`; a precompile revert means "not authorised"; everything else is `MetaToken`.
**Why.** A 64-byte signature is never ECDSA here (OpenZeppelin 5.2 `tryRecover` takes only 65 bytes) and the precompile itself classifies by length, so the branch is unambiguous; the precompile binds the key to the account from Hedera state, so a public key sent by the client never grants authority.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 291.

### NET-HED-10 — HashPack signMessage and KeyList are seams
- old: R6-4 · status: current · owner: no · date: 2026-10-03 · normative: networks/hedera.md#NET-HED-10 · superseded-by: —

**Rule.** HashPack `signMessage` and threshold/KeyList accounts are seams.
**Why.** HashPack `signMessage` (HIP-820) signs a prefixed message, which `isAuthorizedRaw` (exactly 32 bytes) cannot check; checking it through `isAuthorized` needs a protobuf `SignatureMap` built in Solidity and a test on a real network, so it is deferred.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 295.

### NET-HED-11 — Call HIP-632 system contract with CALL
- old: R6-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-11 · superseded-by: —

**Rule.** The HIP-632 system contract is called with `CALL`, never `STATICCALL`.
**Why.** The `isAuthorizedRaw` call does not allow a static frame, and the system contract halts inside one; on testnet the same call returned `ok = false` with no data under STATICCALL and a real answer under CALL.
**Cost if wrong.** Every ED25519 signature reads as not authorised.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 298.

### NET-HED-12 — HederaAdapter reports tx_fee and lane_balance
- old: R6-10 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-12 · superseded-by: —

**Why.** As built the adapter implements neither (both default to `None`, `adapter.rs:112-118`; `hedera.rs` implements only `op_consumed/build/sign/submit/tx_status/…`), so neither `gas_budget` nor `min_relayer_balance` ever sees a Hedera sample; only the zero-balance check in `build` (`hedera.rs:163-166`) stops a drain loop. Tests: a failed receipt still adds to `spent`; a balance below the floor stops the lane taking work.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 307.

### NET-HED-13 — Mesh sig_kind hedera_ed25519 verified locally
- old: R6-11 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-13 · superseded-by: —

**Why.** As built, `sig_kind` is only `eoa`/`erc1271` and `check_evm` returns `Ok` for every non-EOA intent (`mesh/digest.rs:193-195`), so garbage intents force every peer to simulate.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 308.

### NET-HED-14 — Hedera v2 wrappers: fail-closed HTS checks
- old: R144 · status: current · owner: no · date: 2026-10-06 · normative: networks/hedera.md#NET-HED-14 · superseded-by: —

**Rule.** Hedera v2 wrappers check every underlying in `initialize`, fail-closed, through the HTS precompile `0x167`.
**Why.** An HTS underlying with any custom fee breaks a wrapper's reserve or makes `unwrap` revert (the hazard of NET-HED-06), and checking inside `initialize` means a token whose legs cannot be checked or associated is never born.
**Source.** [history/specs/2026-10-06-token-wrappers-v2.md](history/specs/2026-10-06-token-wrappers-v2.md) line 149.

### NET-HED-15 — Hedera ED25519 needs a raw signer
- old: CR-WSF-2 · status: current · owner: no · date: 2026-10-07 · normative: networks/hedera.md#NET-HED-15 · superseded-by: —

**Rule.** Hedera ED25519 subjects need a raw signer.
**Why.** The contracts accept raw ED25519 over the 32-byte EIP-712 digest only, and HashPack or WalletConnect `hedera_signMessage` adds the HIP-820 prefix, which `isAuthorizedRaw` cannot verify, so those wallets cannot sign meta-transactions for ED25519 accounts.
**Source.** [history/specs/round3-wallet-signing-formats.md](history/specs/round3-wallet-signing-formats.md) line 363.

### NET-HED-80 — Permissionless associateUnderlying
- old: R6-5 · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-HED-06, NET-HED-14

It said: Permissionless associateUnderlying; replaced by NET-HED-06, NET-HED-14.
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 296.

## 29. Networks — Cosmos

### NET-COS-01 — IBC ICS-20/27 transfers
- old: req:blockchain.md:ibc · status: open · owner: yes · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-01 · superseded-by: —

**Rule.** IBC token transfers (ICS-20) and interchain accounts (ICS-27) are an open owner requirement.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 293.

### NET-COS-02 — Cosmos CW20 + ADR-036, no authz
- old: R66 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-02 · superseded-by: —

**Rule.** Cosmos = a CW20 token with a contract-level meta operation signed through ADR-036; `x/authz` is never used and `x/feegrant` is only a seam.
**Why.** An `x/authz` grantee would be the relayer, an ordinary account, which breaks the owner rule that only contracts are spenders; a contract grantee is unnecessary because the funds already sit in the contract.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 539.

### NET-COS-03 — Cosmos passkey bound to rpIdHash, origin and UV
- old: CR-R3-1(cosmos-binding) · status: current · owner: yes · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-03 · superseded-by: —

**Why.** As built the decoder checks only the UP flag (`ad[32] & 0x01`) and `type`/challenge by substring `contains` (`cosmos/metaop/src/lib.rs:130-148`; `metaop/src/lib.rs:131-144`; no low-s check before `secp256r1_verify`, `cosmos/metaop/src/lib.rs:147`), with no rpIdHash, origin, UV or low-s check, so any page that can obtain an assertion for the rpId (sibling subdomain, related origin, delegated iframe) signs any `MetaOp`. The low-s check closes signature malleability (the digest identity never depended on the signature).
**Cost if wrong.** Cosmos dev passkey accounts change.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 630.

### NET-COS-04 — Cosmos DEX has no Sweep
- old: CR-R3-10 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-04 · superseded-by: —

**Rule.** The Cosmos DEX has no `Sweep`
**Why.** The DEX never holds balances between transactions, as on EVM ("no owner, no sweep"), so an admin `Sweep` has nothing legitimate to move.
**Cost if wrong.** Tokens sent to the DEX directly are lost, as on EVM.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 708.

### NET-COS-05 — Cosmos DEX fill-or-kill, batch all-or-nothing
- old: R9-2 · status: current · owner: no · date: 2026-10-03 · normative: networks/cosmos.md#NET-COS-05 · superseded-by: —

**Rule.** Cosmos DEX orders are fill-or-kill, and a multi-pair batch is atomic as a whole.
**Why.** Each leg is a fixed signed transfer, so a partial fill cannot be expressed on chain; several `MsgExecuteContract` messages in one Cosmos transaction revert together, so per-pair atomicity does not exist and the off-chain book sends single pairs when a failure must be isolated.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 117.

### NET-COS-06 — Post-simulation grief metered; DEX rereads nonces
- old: R9-3 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-06 · superseded-by: —

**Rule.** Subject-caused grief after simulation is metered and throttled, not excluded; the DEX re-reads both legs' nonces before settling.
**Why.** After simulation the subject can still move its own balance, and with an empty relayer field anyone can relay its op first, so the failure cannot be ruled out; before this ruling the breaker counted only mined fees and `Settle` was open.
**Cost if wrong.** Even metered, each new payer can cost the lane up to three failed transactions per 24 hours before it is throttled.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 233.

### NET-COS-07 — instantiate2 genesis salt; duplicate chain-id refused
- old: R9-4 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-07 · superseded-by: —

**Rule.** Cosmos contract addresses differ between chains, contracts are instantiated without an admin, and duplicate chain ids are refused.
**Why.** Chain ids are not globally unique (`testing`, `localwasm`, restarted testnets, forks that keep the id) and a classic wasmd address is a function of code id and instance id, so a `pay` signed on one chain ran on its twin; immutability without an admin follows CTR-GEN-02.
**Cost if wrong.** A signed payment replays on a twin chain.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 238.

### NET-COS-08 — contract and valid_until from signed payload
- old: R9-5 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-08 · superseded-by: —

**Rule.** `contract` and `valid_until` come from the signed payload
**Why.** The adapter took `contract` and `valid_until` from the unsigned job JSON, `op_consumed` asked the JSON's contract and the runner held the lane until that `valid_until` plus grace (NODE-LANE-16).
**Cost if wrong.** A job can hold a lane past any signed expiry, or be reported consumed against the wrong contract.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 243.

### NET-COS-09 — Cosmos passkey checks stored rpIdHash and origins
- old: R9-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-09 · superseded-by: —

**Rule.** The Cosmos passkey verifier checks the stored relying-party hashes and origins.
**Why.** The verifier checked only the UP flag, `type` and `challenge`, with no relying-party hash, origin or UV check, so an assertion made for another site was accepted.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 246.

### NET-COS-10 — Resubmit tx dropped from mempool
- old: R9-7 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-10 · superseded-by: —

**Rule.** A transaction dropped from the mempool is resent
**Why.** CometBFT can evict a transaction at recheck; status then reads `Unknown` while the send was `Ok`, and the runner did not resend, so the lane sat idle until `valid_until` plus grace. Resending the same bytes is idempotent (code 19 means already in the mempool).
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 249.

### NET-COS-11 — extra must be empty outside trade
- old: R9-8 · status: current · owner: no · date: 2026-10-07 · normative: networks/cosmos.md#NET-COS-11 · superseded-by: —

**Rule.** `extra` must be empty outside `trade`
**Why.** The token ignored `extra` on `pay` and `revoke`, so two payloads that differ only in `extra` authorised the same payment; with `extra` empty, the digest is the single key of one business operation.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 252.

### NET-COS-12 — Cosmos target: MetaCall/MetaTransfer JSON, Mtx messages
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/cosmos.md#NET-COS-12 · superseded-by: —

**Why.** The family form of NET-ALL-26 to NET-ALL-29: the encoding of both kinds, the verifier, and the map from each built entry and struct to its `mtx` name; programs are immutable, so it ships as a new deployment.
**Cost if wrong.** Clients, node and contract drift on names and encodings per family.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, NM-3, NM-5.

### NET-COS-80 — Cosmos passkey v1 derived address
- old: R9-1 · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-ALL-21

It said: Cosmos passkey v1 derived address; replaced by NET-ALL-21.
**Source.** [history/specs/2026-10-03-net-cosmos.md](history/specs/2026-10-03-net-cosmos.md) line 13.

### NET-COS-81 — Cosmos passkey v2 20-byte derived address
- old: CR-R3-1(cosmos-address) · status: superseded · owner: yes · date: 2026-10-07 · normative: — · superseded-by: NET-ALL-21

It said: Cosmos passkey v2 20-byte derived address; replaced by NET-ALL-21.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 630.

## 30. Networks — Soroban

### NET-SOR-01 — Soroban native auth as meta-tx; fee-bump
- old: R65 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-01 · superseded-by: —

**Rule.** On Soroban the contract-level meta operation is the native Soroban authorization; a relayer lane is the transaction source, and fee-bump lets one lane pay for all.
**Why.** A Soroban authorization entry already is a contract-level verifier with a non-sequential nonce and a domain-separated preimage, so no second verifier is written and the subject's sequence never orders anything.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 538.

### NET-SOR-02 — Ledger expiry computed without RPC
- old: R8-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/soroban.md#NET-SOR-02 · superseded-by: —

**Rule.** The ledger expiry is computed without RPC as a safe upper bound.
**Why.** The ERP makes no chain RPC (NODE-STO-03), and ledgers close no faster than one per second, so the anchor-based bound never expires before `valid_until`; overshooting only lengthens how long the host keeps the nonce.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 64.

### NET-SOR-03 — Soroban guardian recovery is a seam
- old: R8-2 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-03 · superseded-by: —

**Rule.** Soroban guardian recovery is a seam.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 96.

### NET-SOR-04 — __check_auth checks auth contexts per key
- old: R8-8 · status: current · owner: yes · date: 2026-10-08 · normative: networks/soroban.md#NET-SOR-04 · superseded-by: —

**Rule.** `__check_auth` checks every auth context against the key's `(contract, function)` allowlist.
**Why.** Soroban host authorization is generic (any function that calls `require_auth`), so restriction, not dispatch, is the missing part once every gasless function is an `mtx_` entry (NET-ALL-27); the allowlist aligns with the universal account's key purposes (CTR-UA-10).
**Cost if wrong.** Any one passkey can add an attacker's key to the account.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 97.
Change (2026-10-08): no longer a seam — `__check_auth` checks every auth context against the key's `(contract, function)` allowlist (owner, via NET-ALL-27); Transitional (BUILT): contexts ignored. Source add: `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, §5.

### NET-SOR-05 — One signature settles once
- old: R8-3 · status: current · owner: no · date: 2026-10-03 · normative: networks/soroban.md#NET-SOR-05 · superseded-by: —

**Rule.** One signature settles once.
**Why.** A Soroban auth entry consumes its nonce when used, so a partial fill needs the maker to re-sign the rest; `filled[order_hash]`, whose hash excludes the nonce, stops overfill across the re-signed copies.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 137.

### NET-SOR-06 — No multi-pair batch per Soroban tx
- old: R8-4 · status: current · owner: no · date: 2026-10-03 · normative: networks/soroban.md#NET-SOR-06 · superseded-by: —

**Rule.** No multi-pair batch per Soroban transaction.
**Why.** A Soroban transaction is one host call, so a failure in one pair reverts the whole transaction and per-pair atomicity does not exist; the matcher sends one pair per transaction, in parallel across lanes.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 139.

### NET-SOR-07 — DEX jobs carry two auth entries
- old: R8-5 · status: current · owner: no · date: 2026-10-03 · normative: networks/soroban.md#NET-SOR-07 · superseded-by: —

**Rule.** A relayed DEX job carries two auth entries.
**Why.** `settle` needs both the maker's and the taker's `require_auth`, while a `signed_op` job carried only one signature.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 141.

### NET-SOR-08 — Token address is a per-family string
- old: R8-7 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-08 · superseded-by: —

**Rule.** A Soroban token address is a per-family string.
**Why.** The token list was typed as an EVM address, which cannot hold the Soroban strkey (`C…`) contract address that `getEvents` filters on.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 182.

### NET-SOR-09 — pay_ref one-shot per (from, pay_ref)
- old: CR-R3-3(rule), R8-9 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-09 · superseded-by: —

**Why.** With a global key, a stranger's 0- or 1-unit `pay(attacker, receiver, …, victim_ref)` burns the victim's ref and blocks the victim's signed payment; booking already sums settlements per `entry_ref` and receiver, so a stranger's payment with someone else's ref is only money in (same direction as Cosmos, which never locks `pay_ref`, and the EVM `MetaToken`). SPECIFIED (as built the key is global, `token/src/lib.rs:203-209`, and `check_amount` accepts 0, `:113-117`). Tests: a third party `pay(self, x, 0, victim_ref)` ⇒ `NonPositiveAmount`; `pay(self, x, 1, victim_ref)` does not block the victim's `pay`; the same `from` paying the same `pay_ref` twice (two signatures) ⇒ `RefUsed`; `pay_under_mandate` cannot be burnt by a third party.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 658; [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 224.

### NET-SOR-10 — Soroban orders bind relayer, no open form
- old: R8-10, RS5-15(soroban) · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-10 · superseded-by: —

**Why.** The host only matches `dex.settle(order)` (`dex/src/lib.rs:158-159`); the counter-order and `maker_fill` (`:153`) are the submitter's choice, so anyone who sees a pending `settle` (transactions flood to every peer before the ledger closes) re-submits both auth entries with `maker_fill = 1`: both nonces are consumed for a dust fill, the real `settle` fails (the relayer pays) and both makers must sign again. Binding the settler means only the DEX operator's lane can spend the auth entries; roles and `maker_fill` are chosen by the (trusted) operator. Binding `(order, fill)` into the signature is not possible: a resting order is signed before its fill is known. SPECIFIED (as built `Order` has no relayer, `:35-47`). Test: a third party re-submits both auth entries with `maker_fill = 1` ⇒ fails; the right relayer settles.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 230; [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 438.

### NET-SOR-11 — TTL extension and RestoreFootprint retry
- old: R8-11 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-11 · superseded-by: —

**Rule.** Entries in daily use extend their TTL, and an archived footprint is restored by the lane and retried.
**Why.** Only `save` and `set_payee` extended TTLs, so an account in daily use was archived about 60 days after its last key change and a payee 60 days after it was allowed; a `restorePreamble` from simulation killed the job.
**Cost if wrong.** Payments from an archived account or to an archived payee die as dead jobs.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 233.

### NET-SOR-12 — op_consumed reads host nonce key
- old: R8-12 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-12 · superseded-by: —

**Rule.** `op_consumed` reads the host nonce key
**Why.** An auth entry submitted by someone else, or by the subject itself, consumes the nonce; reading the host nonce key lets the job end as `consumed` instead of `dead` or `reverted`, so the ERP never asks the payer to re-sign an operation that already ran.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 236.

### NET-SOR-13 — Reject crossOrigin true and topOrigin
- old: R8-13 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-13 · superseded-by: —

**Rule.** The Soroban passkey verifier refuses `"crossOrigin":true` and any `topOrigin`
**Why.** The verifier checked only `type`, `challenge` and `origin`, so a relying-party page embedded in a cross-origin iframe (Permissions-Policy `publickey-credentials-get`) yields a valid assertion under an attacker's page.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 238.

### NET-SOR-14 — Soroban adapter reports tx_fee and lane_balance
- old: R8-14 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-14 · superseded-by: —

**Rule.** The Soroban adapter reports `tx_fee` (`feeCharged` from the `resultXdr` of `getTransaction`, for both `SUCCESS` and `FAILED`) and `lane_balance` (native balance of the lane and of the `fee_bump_lane`)
**Why.** Both hooks were left at their `None` default, so the gas-budget and minimum-balance breakers were blind on Soroban, while a `FAILED` transaction still pays inclusion and resource fees that are not refunded (NODE-LANE-13).
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 240.

### NET-SOR-15 — Signed fields read from invocation
- old: R8-15 · status: current · owner: no · date: 2026-10-07 · normative: networks/soroban.md#NET-SOR-15 · superseded-by: —

**Rule.** `build` takes `valid_until` (hence `TimeBounds.max_time` and the runner's expiry) and `contract` from the signed invocation
**Why.** `build` read `valid_until` from the unsigned job JSON, so a job could carry a later expiry than the one signed (NODE-LANE-16).
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 242.

### NET-SOR-16 — Soroban target: host authorizations of mtx_ functions
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/soroban.md#NET-SOR-16 · superseded-by: —

**Why.** The family form of NET-ALL-26 to NET-ALL-29: the encoding of both kinds, the verifier, and the map from each built entry and struct to its `mtx` name; programs are immutable, so it ships as a new deployment.
**Cost if wrong.** Clients, node and contract drift on names and encodings per family.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, NM-3, NM-5.

### NET-SOR-80 — Non-positive pay refused with ZeroAmount
- old: CR-R3-3(error-name) · status: superseded · owner: yes · date: 2026-10-07 · normative: — · superseded-by: NET-SOR-09

It said: Non-positive pay refused with ZeroAmount; replaced by NET-SOR-09.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 658.

## 31. Networks — Sui

### NET-SUI-01 — Sui shared Account<T> + personal message
- old: R64 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-01 · superseded-by: —

**Rule.** Sui = a shared `Account<T>` per subject holding the balance, signed through `signPersonalMessage`; DEX settlement is two signed legs.
**Why.** Owned coins on Sui cannot be spent by anyone else, so the balance must sit in a contract object; a shared object per subject keeps contention within that one subject.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 537.

### NET-SUI-02 — Sui keys per subject in Keys object
- old: CR-R3-5 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-02 · superseded-by: —

**Why.** As built keys live in each `Account<T>` (`meta.move:93-105`), so rotating a key on one coin type leaves the old key alive on another, and `dex::cancel`/`invalidate_nonces` accept any `Account<X>` of the maker (`dex.move:275-294`). A struct-layout change is a fresh package publish, and every publish is fresh and immutable anyway (NET-SUI-15). SPECIFIED. Tests: rotate a key on `Keys` ⇒ the old key fails on `Account<USDC>` and `Account<SUI>` and cannot cancel orders on any market. The `Keys.policy` bit `POLICY_PASSKEY_FOR_VALUE` is defined in NET-ALL-23.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 672.

### NET-SUI-03 — Account and Registry are derived objects
- old: RS7-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-03 · superseded-by: —

**Rule.** `Account<T>` and `Registry<T>` are derived objects.
**Why.** The ERP and the relayer compute the account id offline from the registry id and the payer address; the chain refuses a second claim, so it enforces one account per subject and coin type with no mapping table, and a registry derived per type stops anyone creating a second registry to split accounts.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 272.

### NET-SUI-04 — open_passkey requires an assertion
- old: RS7-2 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-04 · superseded-by: —

**Rule.** `open_passkey` requires an assertion; origin and rpIdHash come from that assertion.
**Why.** If anyone could set the relying-party hash and origin, an attacker could open the unique derived account for a victim's key with a wrong origin first, and that account could never sign.
**Cost if wrong.** Funds deposited into that account are stuck.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 273.

### NET-SUI-05 — Many keys, origins, guardian per account
- old: RS7-3 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-05 · superseded-by: —

**Rule.** A Sui account has many keys, many origins and a guardian with delayed recovery.
**Why.** With one key and fixed origins, losing the key or changing an origin bricks the account, and its derived id cannot be opened again.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 274.; [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 42

### NET-SUI-06 — Sui DEX atomic PTB batch, no relayer fee
- old: RS7-4 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-06 · superseded-by: —

**Rule.** Sui DEX differences from EVM
**Why.** Move has no try/catch, so a batch is one PTB that is atomic as a whole and the relayer dry-runs and drops bad pairs first; new networks carry no relayer fee; balances are held per coin type, so each side needs two accounts.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 275.

### NET-SUI-07 — Relayer builds PTB BCS locally
- old: RS7-5 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-07 · superseded-by: —

**Rule.** The relayer builds the PTB BCS locally and resends the same bytes.
**Why.** Signing bytes built by the RPC (`unsafe_moveCall`) is blind signing that lets the RPC take the lane's gas coin; resending the same bytes never puts a second signed transaction on the same gas coin version.
**Cost if wrong.** A second transaction on the same gas coin version equivocates and locks the coin until the epoch ends.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 276.

### NET-SUI-08 — Indexer filters registered tokens
- old: RS7-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-08 · superseded-by: —

**Rule.** The Sui indexer filters by event type and by the registered tokens.
**Why.** Event type alone does not prove origin: a copy of the package emits the same event shapes, so only events carrying a registered `Registry<T>` id count, and an empty list holds the cursor instead of skipping ranges.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 277.; [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 38

### NET-SUI-09 — One shared Market per pair
- old: RS7-8 · status: current · owner: no · date: 2026-10-03 · normative: networks/sui.md#NET-SUI-09 · superseded-by: —

**Rule.** One shared `Market` per pair.
**Why.** Sui limits transactions per shared object per commit, so one object per pair keeps the settles, cancels and `min_nonce` updates of one market from throttling every other market.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 279.

### NET-SUI-10 — No second tx on one gas coin version
- old: RS7-7, RS7-9 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-10 · superseded-by: —

**Why.** As built the journal is a local directory (`params.lane_journal/<chain>-lane<i>.json`, fsync + rename, written by `sign()` before the signed report and before sending) with **one** entry per lane — job B's `sign` overwrites job A's pending entry (`sui.rs:495-505, 693-707`), a failed resend of A is only logged (`sui.rs:523-527`), coin selection skips only the current entry's coin (`:657, 666`), so a later job can pick coin C1 vN again (the largest) and sign a second transaction on the same version — equivocation, C1 locked until the epoch ends; the directory (`:465-467`) does not follow the owner lock on failover; expiration is `None` (`sui.rs:317`). Tests: A `Unknown` + failed resend, B signed on C2, job C never picks C1 vN; a restart on a fresh disk with the same store ⇒ no equivocation; transactions carry an epoch expiration.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 278; [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 283.

### NET-SUI-11 — forward never returns to removed key
- old: RS7-10 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-11 · superseded-by: —

**Why.** As built `owner` never changes and `forward` is permissionless (`meta.move:257-261`), so after the owner removes a leaked first key (the main reason for key removal and recovery), anyone can forward objects sent to the account id (e.g. a `Coin<U>` of another type) to the leaked key's address. `Mandate.forward` (`mandate.move:118-120`) is not affected: a mandate's owner is the native address that created it. SPECIFIED. Move tests: remove the first key ⇒ `forward` aborts; `forward_signed` with a current key ⇒ sent to the right `to`.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 291.

### NET-SUI-12 — Lane prune with on-chain horizon
- old: RS7-11 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-12 · superseded-by: —

**Why.** As built there is no `prune` in `smartcontracts/move/sui/sources`; every lane is one dynamic field (`meta.move:285-287`) whose storage fee the lane pays and never recovers. SPECIFIED. Move tests: prune before the horizon aborts; after it deletes and rebates; `valid_until` beyond the horizon is refused.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 295.

### NET-SUI-13 — Grief after dry-run via node rules
- old: RS7-12 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-13 · superseded-by: —

**Rule.** Grief after dry-run uses the node rules, no Sui-specific mechanism.
**Why.** The Sui grief (another op drains the account or spends the nonce before the lane's transaction) has the same shape as on other families and is covered by counting failed fees and lane storage per payer (NODE-LANE-13, NODE-LANE-15), with lane storage refunded by `prune`.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 301.

### NET-SUI-14 — Mesh checks sui_op signature first
- old: RS7-13 · status: current · owner: no · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-14 · superseded-by: —

**Rule.** The mesh checks a `sui_op` signature before any dry-run
**Why.** The mesh decoder did not check the `sui_op` signature at all, so any unsigned op reached a dry-run on every peer (NODE-MESH-16).
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 304.

### NET-SUI-15 — Sui package immutable at deploy
- old: RS7-14 · status: current · owner: yes · date: 2026-10-07 · normative: networks/sui.md#NET-SUI-15 · superseded-by: —

**Rule.** The Sui package is immutable from deploy.
**Why.** Owner decision (2026-10-07), the Sui case of immutable contracts (CTR-GEN-02): a fix ships as a new package, and holders move funds by signing a `pay` from the old account, whose code keeps running.
**Source.** [history/specs/2026-10-03-net-sui.md](history/specs/2026-10-03-net-sui.md) line 306.

### NET-SUI-16 — Signed Sui payloads encoded byte-identical in every client language
- old: R261 · status: current · owner: no · date: 2026-10-08 · normative: networks/sui.md#NET-SUI-16 · superseded-by: —

**Rule.** Every signed Sui payload (target `MetaCall`/`MetaTransfer`, built `KeyOp`) is encoded in every client language byte-identical to Move, with the domain as a parameter.
**Why.** One encoding for every language, so clients can check a KeyOp locally before submitting it (CLI-APP-09).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 200.
Change (2026-10-08): the rule covers every signed Sui payload, the target `MetaCall`/`MetaTransfer` (NET-SUI-18) as the built `KeyOp`. Source add: `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-3.

### NET-SUI-17 — One generator run feeds every vector
- old: R262 · status: current · owner: no · date: 2026-10-06 · normative: networks/sui.md#NET-SUI-17 · superseded-by: —

**Rule.** One generator run feeds every language's Sui vectors.
**Why.** ECDSA signatures are random per run, so vectors from separate runs never match; before this the cross-language vector was only a comment.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 208.

### NET-SUI-18 — Sui target: MetaCall/MetaTransfer in BCS, mtx_ entries
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/sui.md#NET-SUI-18 · superseded-by: —

**Why.** The family form of NET-ALL-26 to NET-ALL-29: the encoding of both kinds, the verifier, and the map from each built entry and struct to its `mtx` name; programs are immutable, so it ships as a new deployment.
**Cost if wrong.** Clients, node and contract drift on names and encodings per family.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, NM-3, NM-5.

## 32. Networks — Aptos

### NET-APT-01 — Object code deployment, one address
- old: RS11-13(deploy) · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-01 · superseded-by: —

**Rule.** The Aptos package is deployed as one object code deployment: one address for calls and event types.
**Why.** Only code in the package can emit its event types, so the indexer can filter by type and drop a copy of the package deployed at another address.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 20.

### NET-APT-02 — Aptos Rejected table; scaas abort Reverted
- old: RS11-8(table) · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-02 · superseded-by: —

**Rule.** Aptos outcome classes: validation refusals free the lane; a `scaas` abort is `Reverted`.
**Why.** A validation refusal never enters the ledger and resending the same bytes never passes, so the job goes straight back to the queue; an abort from `scaas` means the subject's operation is wrong or already used.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 21.

### NET-APT-03 — Account keys, origins, three admin paths
- old: RS11-3 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-03 · superseded-by: —

**Rule.** An Aptos Account holds ≤ 8 ed25519 and WebAuthn P-256 keys and ≤ 8 origins; the first key must match the owner's live authentication key; three administration paths.
**Why.** Checking the first key against the owner's live authentication key stops an attacker from opening the victim's Account first with a wrong key. Rotating the native wallet key never touches the Account's keys, so several keys and a guardian with a 2-day delay keep the Account from being bricked.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 22.

### NET-APT-04 — aptos:signMessage envelope parsed strictly
- old: RS11-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/aptos.md#NET-APT-04 · superseded-by: —

**Rule.** The main path is a contract-level meta-tx signed with `aptos:signMessage`, whose `fullMessage` envelope is parsed strictly
**Why.** Aptos sequence numbers queue every transaction of a subject across all modules, and orderless transactions expire within 60 seconds, so neither lets a subject pre-sign queued jobs, mandates or hour-long DEX orders. Wallets self-report every `fullMessage` field and line order is not standardised, so only a strict parse stops a phishing page from injecting a second `message:` line.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 648.

### NET-APT-05 — One derived Account per subject
- old: RS11-2 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-05 · superseded-by: —

**Rule.** One derived `Account` object per subject holds every asset; its balance is the primary fungible store of the Account address — no internal ledger.
**Why.** A primary store is created for any address that receives an asset, so anything sent to the Account address, even before the Account exists, is spendable at once; one Account for every asset also means one key set and one rotation.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 651.

### NET-APT-06 — Lane table prunable after delay
- old: RS11-4 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-06 · superseded-by: —

**Rule.** The lane table is a `Table` with `valid_until`, prunable by anyone after the delay.
**Why.** A `Table` has no length counter, so two lanes are two state keys and Block-STM sees no conflict. The ERP reissues terms on the same lane and nonce, so deleting a lane right after the executed op's deadline would let a later-signed, still-valid op pay twice; the 30-day delay covers the lane horizon.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 656.

### NET-APT-07 — Domain = chain_id, Account, asset
- old: RS11-5 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-07 · superseded-by: —

**Rule.** The Aptos domain is the on-chain `chain_id`, the derived contract address and the explicit `asset`.
**Why.** The on-chain `chain_id` cannot be faked, and the derived contract address differs between two deployments even on two networks that share chain id 4.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 658.

### NET-APT-08 — Relayer lane ed25519 sequence account
- old: RS11-6 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-08 · superseded-by: —

**Rule.** An Aptos relayer lane is an ed25519 account at `m/44'/637'/{i}'/0'/0'` sending sequence-number transactions, one in flight, paying its own fee.
**Why.** A lane's sequence number matches the shared `recover_lane` contract exactly, and one transaction per lane needs no parallel submissions inside a lane; the relayer pays its own fee, so neither fee payer nor orderless transactions are needed.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 659.

### NET-APT-09 — Hand-written BCS, TS SDK vectors
- old: RS11-7 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-09 · superseded-by: —

**Rule.** Aptos transactions are hand-written BCS, hashed before sending, with vectors from the TS SDK.
**Why.** The `aptos-sdk` crate pulls in all of `aptos-core`, a very large dependency tree that risks running out of memory on a shared build machine and pins its own tokio and rustc versions; hashing before sending lets the lane journal the transaction as signed.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 660.

### NET-APT-10 — Finality commit; REST scan by package
- old: RS11-9 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-10 · superseded-by: —

**Rule.** Aptos finality is commit (AptosBFT), indexed by block height; a block with missing transactions fails the range.
**Why.** AptosBFT commits are final and the REST API returns only committed state; a block returned with fewer transactions than its version range is incomplete, and closing that range would skip events.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 662.

### NET-APT-11 — Aptos DEX Market per pair
- old: RS11-10 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-11 · superseded-by: —

**Rule.** Aptos DEX: one derived `Market` per pair, `min_nonce`/`filled` per market, a permissionless `sweep`, one pair per transaction.
**Why.** Per-market state means no global counter is written on the hot path (the lesson of NET-ALL-13), and a market holds no funds between transactions, so anything sent to it can be swept without permission; entry functions take no structs, so one transaction carries one pair.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 664.

### NET-APT-12 — Mandate opened by Account key
- old: RS11-11 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-12 · superseded-by: —

**Rule.** An Aptos mandate is opened by an Account key's signature, funded by an ordinary `pay`, and its `pay_ref` entries are prunable.
**Why.** Opening by an Account key's signature needs no native transaction from the owner, so it costs the owner no gas and takes no subject sequence (NET-ALL-02); a plain `pay` funds it because the mandate's balance is its own primary store.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 666.

### NET-APT-13 — No disk tx journal on Aptos
- old: RS11-12 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-13 · superseded-by: —

**Rule.** No disk transaction journal on Aptos.
**Why.** The chain runs each (lane, sequence) exactly once and Aptos has no version-based object lock like Sui (NET-SUI-10), so two different transactions signed on one sequence after a restart lock nothing: at most one lands, and the contract refuses a used digest.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 667.

### NET-APT-14 — Pure-Move P-256 passkey verifier
- old: RS11-14 · status: current · owner: yes · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-14 · superseded-by: —

**Rule.** Aptos passkeys are WebAuthn P-256 verified by the pure-Move `scaas::p256`.
**Why.** Move has no P-256 verify callable from contracts (P-256 is checked only at the transaction-authenticator layer), and the owner chose a pure-Move verifier over native passkey accounts or no passkeys; it is a separate, unaudited module so a native verifier can replace it.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 672.

### NET-APT-15 — Indexer API as hint, reread fullnode
- old: RS11-15 · status: current · owner: yes · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-15 · superseded-by: —

**Rule.** The Aptos Indexer API is a hint; content is re-read from the fullnode, and the cursor never passes the indexer's processed version.
**Why.** Owner choice of the hosted Indexer API, trusted only for completeness; it has no `events` table, so it can only point at transactions, and content is re-read from the fullnode.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 675.

### NET-APT-16 — pay_check view for unopened Account
- old: RS11-16 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-16 · superseded-by: —

**Why.** Aptos-node 9.6.0's REST `simulate` hangs on a transaction that both creates the Account object and spends from its pre-existing primary store (the real transaction runs normally); reported upstream if it persists. `relay_pay` runs every check (`pay_checked`) BEFORE opening the Account. BUILT; amended by NET-APT-23.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 677.

### NET-APT-17 — Passkey precomputed P-256 table
- old: RS11-17 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-17 · superseded-by: —

**Rule.** A passkey key is stored with its precomputed `p256::table`
**Why.** Precomputing the table once at registration makes each signature about 400 gas cheaper, which lets a `dex::settle` that matches two passkey orders fit the per-transaction execution gas cap.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 679.

### NET-APT-18 — Mandate open, revoke, refund rules
- old: RS11-18 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-18 · superseded-by: —

**Rule.** Mandate open, revoke and refund rules.
**Why.** A named object can be created only once, so opening needs no nonce; letting the delegate or the owner's Account key revoke, and anyone refund after revoke or expiry, means funds never stay stuck in a mandate.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 681.

### NET-APT-19 — Strict BCS orders; unordered pair market
- old: RS11-19 · status: current · owner: no · date: 2026-10-04 · normative: networks/aptos.md#NET-APT-19 · superseded-by: —

**Rule.** DEX orders travel as BCS bytes parsed strictly, and a market is a named object of the unordered pair.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 683.

### NET-APT-20 — Aptos package immutable at deploy
- old: RS11-20 · status: current · owner: yes · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-20 · superseded-by: —

**Rule.** The Aptos package is immutable from deploy.
**Why.** Owner decision: the node's safety arguments assume fixed code, and an upgrade key can rewrite every account's rules; old Accounts stay spendable through the old package.
**Cost if wrong.** Every fix is a new deployment at a new address plus migration (owner accepted).
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 688.; [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 154

### NET-APT-21 — OOG rebuilt once at gas cap
- old: RS11-21 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-21 · superseded-by: —

**Rule.** A committed out-of-gas is rebuilt once at the gas cap, then `reverted`; every committed transaction is metered.
**Why.** A committed out-of-gas is billed in full, and a dispatchable asset hook can read the gas cap and burn gas only in the real transaction, so an unbounded rebuild made the lane pay on every attempt until `valid_until`, unseen by the hourly breaker.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 695.

### NET-APT-22 — Lazy open requires application line
- old: RS11-22 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-22 · superseded-by: —

**Why.** Opt-in was not enough — every client-opened Account starts without origins (`meta.move:345`; `check_envelope` requires `application` only when origins exist, `auth.move:132, 138`), and a phishing page that obtained a `signMessage` can submit `relay_pay` itself (relayer `0x0`) without passing the client.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 698.

### NET-APT-23 — Dispatchable assets refused on unopened path
- old: RS11-23 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-23 · superseded-by: —

**Rule.** Dispatchable assets are refused on the not-yet-opened path.
**Why.** The not-yet-opened path runs the `pay_check` view, which checks the balance but does not run the transfer, so a hook that aborts or burns gas shows up only on chain, at the gas cap.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 700.

### NET-APT-24 — Every signing client honours lane horizon
- old: RS11-24 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-24 · superseded-by: —

**Rule.** Every signing client honours the lane horizon.
**Why.** The chain cannot see when an op was signed: a client that signs two ops on one lane more than 30 days apart lets the later one run after someone prunes the lane, and a run-time check of `valid_until` does not close that gap.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 702.

### NET-APT-25 — chainId line stays optional
- old: RS11-25 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-25 · superseded-by: —

**Rule.** The `chainId:` line stays optional.
**Why.** The digest already binds `chain_id`, so a missing line is no replay risk, and requiring it would refuse standard wallets that omit optional fields.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 704.

### NET-APT-26 — Mesh verifies Aptos signatures locally
- old: RS11-26 · status: current · owner: no · date: 2026-10-07 · normative: networks/aptos.md#NET-APT-26 · superseded-by: —

**Rule.** Mesh and gateway verify Aptos signatures locally before any simulation
**Why.** The mesh decoders checked only domain, network and contract, so every peer paid a simulation or view call for each garbage intent.
**Cost if wrong.** One cached state read per new subject.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 706.; [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 149

### NET-APT-27 — Aptos target: MetaCall/MetaTransfer in BCS, mtx_ entries
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/aptos.md#NET-APT-27 · superseded-by: —

**Why.** The family form of NET-ALL-26 to NET-ALL-29: the encoding of both kinds, the verifier, and the map from each built entry and struct to its `mtx` name; programs are immutable, so it ships as a new deployment.
**Cost if wrong.** Clients, node and contract drift on names and encodings per family.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, NM-3, NM-5.

### NET-APT-80 — Upgrade policy compatible
- old: RS11-13(upgrade) · status: superseded · owner: no · date: 2026-10-04 · normative: — · superseded-by: NET-APT-20

It said: Upgrade policy compatible; replaced by NET-APT-20.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 20.

### NET-APT-81 — Committed OOG requeued without limit
- old: RS11-8(oog) · status: superseded · owner: no · date: 2026-10-04 · normative: — · superseded-by: NET-APT-21

It said: Committed OOG requeued without limit; replaced by NET-APT-21.
**Source.** [history/specs/2026-10-04-net-aptos.md](history/specs/2026-10-04-net-aptos.md) line 21.

## 33. Networks — Solana

### NET-SOL-01 — Solana network = build-time genesis hash
- old: CR-R3-4 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-01 · superseded-by: —

**Why.** Today `initialize(network, admin)` stores any 32 bytes (`account.rs:28-34`), so a Config initialised with another cluster's hash makes that cluster's signatures valid here for the same PDA, for any relayer; our node is protected by the cross-check, third-party relayers are not.
**Cost if wrong.** one build per cluster (already one per program id). SPECIFIED. **Operator invariant until it lands:** never reuse a Solana program id across clusters, and keep the node's genesis cross-check on. Chains are keyed `solana:<genesis hash>`.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 663.

### NET-SOL-02 — Solana Rejected table; scaas errors Reverted
- old: RS12-16(table) · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-02 · superseded-by: —

**Rule.** Solana outcome classes: preflight refusals free the lane; a `scaas` error is `Reverted`; the adapter rebroadcasts.
**Why.** A preflight refusal never lands and resending never passes, so the lane is freed at once; RPC nodes often drop transactions under congestion, so the adapter resends the same bytes while the nonce has not moved.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 24.

### NET-SOL-03 — Program-level meta-tx; native fee payer lane-only
- old: RS12-1 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-03 · superseded-by: —

**Rule.** Solana uses a program-level meta-tx; the subject never sends a transaction on the hot path, and the native fee payer is only ever a relayer lane.
**Why.** A transaction the subject signs lives about 90 seconds, so it cannot be pre-signed for queued jobs, mandates or hour-long DEX orders; stretching it with the subject's own durable nonce would queue every operation of the subject across all programs, and transaction signatures are ed25519 only, so passkeys could not pay.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 697.

### NET-SOL-04 — Write-lock is the real lock
- old: RS12-2, net-solana:L12 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-04 · superseded-by: —

**Rule.** On Solana the write-lock is the real lock: the hot path writes only the operation's own new PDA and the two parties' token accounts, and a write-set disjointness test is mandatory.
**Why.** Write-locks exist only while a block executes, so disjoint write sets give the anti-lock property by construction, while a hot writable account serialises its transactions, hits the per-account compute cap and raises the local priority fee. The owner made the disjointness test mandatory.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 698; [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 52.

### NET-SOL-05 — One SmartKeyAccount PDA per subject
- old: RS12-3 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-05 · superseded-by: —

**Rule.** One SmartKeyAccount PDA per subject holds every mint; its balance is the token accounts owned by the PDA — no internal ledger.
**Why.** Any token account owned by the PDA counts, so tokens sent to an unusual token account of the PDA stay spendable. Keeping funds in the wallet's own token account with an `Approve` to the PDA was rejected: a token account has only one delegate, each re-approval needs a native transaction, and there are no multiple keys or recovery.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 700.

### NET-SOL-06 — Keys, origins, guardian; open needs assertion
- old: RS12-4 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-06 · superseded-by: —

**Rule.** A SmartKeyAccount holds ≤ 8 keys (ed25519 / P-256 WebAuthn), ≤ 8 origins and a guardian with a 2-day delay; a new origin under the same rpId is added by that passkey; `open_passkey` requires an assertion.
**Why.** Browsers let only origins under an rpId create assertions for it, so a passkey adding a new origin under its own rpId keeps a domain change from bricking the Account while a phishing site on another rpId stays blocked; taking the origin from the assertion itself stops anyone pre-opening an Account with a wrong origin (NET-SUI-04).
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 701.

### NET-SOL-07 — BACKUP_REQUIRED policy bit, default off
- old: RS12-5 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-07 · superseded-by: —

**Rule.** The `BACKUP_REQUIRED` policy bit is optional and off by default.
**Why.** Owner decision: the backup rule is only an on/off option, with the same meaning as the client signer's backup policy.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 703.

### NET-SOL-08 — Lane PDA prunable, rent to rent_payer
- old: RS12-6 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-08 · superseded-by: —

**Rule.** A lane is a PDA per (account, lane), prunable by anyone after `valid_until + PRUNE_DELAY_S`, with the rent returned to the stored `rent_payer`.
**Why.** One PDA per lane means no account is shared between two operations. The ERP reissues terms on the same lane and nonce within a 30-day horizon, so the delay ensures every other signed op of that request has expired before the PDA closes; rent goes to the stored payer so a caller cannot take it.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 704.

### NET-SOL-09 — Token-2022 extension policy
- old: RS12-7 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-09 · superseded-by: —

**Rule.** SPL Token and Token-2022 are both supported through `token_interface`; a mint that is `NonTransferable`, has an active transfer hook, or charges a transfer fee is refused at every transfer.
**Why.** A transfer fee makes the receiver get less than was signed (breaking NET-ALL-08), and fees can change after two epochs, so the check runs at every transfer rather than at registration; an active transfer hook runs arbitrary code that needs extra accounts. The owner chose this policy.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 706.

### NET-SOL-10 — Domain = genesis hash, node cross-check
- old: RS12-8 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-10 · superseded-by: —

**Rule.** The Solana domain is the genesis hash held by `Config` and cross-checked by the node, plus the PDA, the op and the asset.
**Why.** A program cannot read the genesis hash on chain (there is no sysvar for it), so it is stored at `initialize` and the adapter checks it at start; the same program keypair deployed on two clusters still gets two domains.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 707.

### NET-SOL-11 — Raw and OCMS v1; passkey b64url digest
- old: RS12-9(formats) · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-11 · superseded-by: —

**Rule.** ed25519 is accepted as a raw message or an off-chain message v1; a passkey challenge is `base64url(digest)`.
**Why.** Off-chain message v1 is the format hardware wallets sign and is recommended when the wallet supports it, with raw messages as the fallback; an 80-byte raw text can never parse as a valid transaction, so the two never collide.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 708.

### NET-SOL-12 — Precompile introspection rules
- old: RS12-10 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-12 · superseded-by: —

**Rule.** Precompile introspection: the instruction is loaded through the checked sysvar, must be the right precompile, every instruction index must be `u16::MAX`, and pk + message are compared byte for byte.
**Why.** The checked loader blocks a fake Instructions sysvar (the class of the 2022 Wormhole exploit), and comparing pk and message byte for byte, with every index pointing at the precompile instruction itself, avoids the improper-introspection flaw of only checking that some ed25519 instruction exists.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 709.

### NET-SOL-13 — Mandate opened by Account key; mref PDA
- old: RS12-11 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-13 · superseded-by: —

**Rule.** A Solana mandate is opened by an Account key's signature; each `pay_ref` is consumed once through a prunable `mref` PDA.
**Why.** Opening by an Account key's signature needs no native transaction from the owner (NET-ALL-02), and an `mref` PDA that can be created only once makes a second payment with the same `pay_ref` fail.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 711.

### NET-SOL-14 — DEX settle checks both signatures
- old: RS12-12 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-14 · superseded-by: —

**Rule.** Solana `settle` verifies both signatures in the same transaction, with one `Fill` PDA per order and a fee vault per market; cancelling creates or closes the `Fill`.
**Why.** Once 4,096-byte v1 transactions reached mainnet, verifying both signatures inline replaced posting orders on chain first and gave one check path close to EVM; a cancel also creates the `Fill`, so an order that never matched can never settle later.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 712.

### NET-SOL-15 — Anchor 1.x with LiteSVM
- old: RS12-13 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-15 · superseded-by: —

**Rule.** The program uses Anchor 1.x, built with `cargo build-sbf` and tested with LiteSVM; no Anchor v2 alpha, no native/Pinocchio.
**Why.** The largest class of Solana program bugs is missing account checks, which Anchor generates from declared constraints; native or Pinocchio code saves compute but every check is hand-written, and the compute budget has room. LiteSVM runs inside `cargo test` without a validator, which keeps memory use low.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 713.

### NET-SOL-16 — Lane ed25519 with durable nonce
- old: RS12-14 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-16 · superseded-by: —

**Rule.** A Solana relayer lane is an ed25519 key at `m/44'/501'/{i}'/0'` with its own durable nonce account; `sequence` = the nonce value; one transaction in flight.
**Why.** A durable nonce changes exactly when a transaction using it lands, which matches the shared `recover_lane` rule as written, while blockhash expiry cannot be expressed by the runner's comparison; every rebuild of a job uses the same nonce, so at most one transaction lands.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 714.

### NET-SOL-17 — Hand-written tx v1, kit vectors
- old: RS12-15 · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-17 · superseded-by: —

**Rule.** Solana transactions are hand-written v1 transactions, with no `solana-sdk` and no new crate; vectors come from `@solana/kit`.
**Why.** `solana-sdk` brings a large dependency tree that risks running out of memory on a shared build machine (as for NET-APT-09); v1 is required because passkey transactions and two-leg `settle` exceed the 1,232-byte legacy and v0 limit.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 716.

### NET-SOL-18 — No disk journal; durable nonce suffices
- old: RS12-17 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-18 · superseded-by: —

**Rule.** No disk journal on Solana: the durable nonce and the shared `recover_lane` suffice.
**Why.** Each nonce value lets at most one transaction land, even a failed one, so a lane sequence equal to the nonce value makes the shared `recover_lane` correct without a disk journal.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 719.

### NET-SOL-19 — Finalized; standard JSON-RPC indexer
- old: RS12-18 · status: current · owner: yes · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-19 · superseded-by: —

**Rule.** Solana finality is commitment `finalized` with the slot as cursor; the indexer uses standard JSON-RPC (`getSignaturesForAddress` + `getTransaction`), events through `emit_cpi!`, filtered by program id, event authority and the registered tokens; missing history is an error.
**Why.** Owner choice: standard JSON-RPC works on the test validator, self-hosted nodes and any hosted RPC with history, while Geyser needs a dedicated RPC node and provider webhooks lock in a vendor with unverifiable completeness. Only our program can sign with its event authority, so a copy at another program id is dropped.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 721.

### NET-SOL-20 — Solana program immutable after initialize
- old: RS12-19 · status: current · owner: yes · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-20 · superseded-by: —

**Rule.** The Solana program is immutable after `initialize`.
**Why.** Owner decision: the node's safety arguments assume fixed code, and an upgrade key can rewrite every account's rules.
**Cost if wrong.** Every fix is a new program id and domain plus migration (owner accepted).
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 726.; [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 154

### NET-SOL-21 — Destination ATA must exist
- old: RS12-20 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-21 · superseded-by: —

**Why.** An ATA owner can `CloseAccount` it at zero balance and recover ~0.00204 SOL of rent (more for Token-2022 with extensions), and `to` is signer-chosen — loop: the SmartKeyAccount holds 1 unit; sign `pay(1, to = W)`; the lane creates ATA(W) (as built, `account.rs:210-218`, `util.rs:55-73`; `mandate.rs:170-178` likewise); W sends the unit back, closes ATA(W), keeps the rent; repeat — ≈ 0.002 SOL profit per round, stopped only by `min_relayer_balance` (the hourly breaker sees only fees, `adapter.rs:270-276`). The ERP path is safe (`to` = a fixed receiving wallet); mesh `pay` and the job API are not. Taking the rent from the SmartKeyAccount's lamports was rejected (gasless subjects hold no SOL). DEX ATAs owned by a SmartKeyAccount PDA (`dex.rs:252-254`) and the fee vault owned by the Market (`:264-265`) cannot be closed (the program has no `CloseAccount` path), so they are a one-time cost per (PDA, mint), metered and bounded by `max_deposit_per_job`, not a drain. SPECIFIED. LiteSVM: `relay_pay` to a missing ATA ⇒ `DestinationMissing`; to an existing ATA ⇒ runs, the lane pays no rent. Rust: missing destination + unconfigured `to` ⇒ `422`; configured `to` ⇒ the transaction carries the ATA creation; the pay → close → pay loop never creates a second ATA on lane money.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 730.

### NET-SOL-22 — On-chain MAX_TTL_S for expiries
- old: RS12-21 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-22 · superseded-by: —

**Why.** `u64::MAX` makes a PDA never prunable (`account.rs:204`, `dex.rs:199, 312`) — one `cancel_signed` for an invented order hash locks a `Fill`'s rent forever. Rent that never returns (lazy SmartKeyAccount open, `account.rs:189`, no close path; KeyOp growth through `util::grow`, `account.rs:365`, bounded by 8 keys + 8 origins and never shrinking, so once per Account; `MinNonce`, `dex.rs:327`; DEX ATAs of the PDA and vaults) stays lane-paid — subjects are gasless — but is metered (NODE-LANE-13) and bounded per job (NODE-LANE-18) and per subject (NODE-LANE-15). SPECIFIED. LiteSVM tests: `cancel_signed` with `expiry = u64::MAX` ⇒ error; `relay_pay` with `valid_until = now + 32 days` ⇒ error; every lane PDA created is prunable ≤ `MAX_TTL_S + PRUNE_DELAY_S` after creation.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 735.

### NET-SOL-23 — Out of CU rebuilt once at max_cu
- old: RS12-22 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-23 · superseded-by: —

**Rule.** Compute exhaustion is rebuilt once at `max_cu`, then `reverted`; lane-side faults retry once without grief.
**Why.** Landed compute exhaustion and lane-side faults went back to the queue without limit, each landing costing the base fee plus a priority fee of up to 2,000,000 lamports, and the subject can steer the compute gap between simulation and the real transaction.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 740.

### NET-SOL-24 — Reject crossOrigin true and topOrigin
- old: RS12-23 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-24 · superseded-by: —

**Rule.** The Solana passkey verifier refuses `"crossOrigin":true` and any `"topOrigin"`
**Why.** The Aptos verifier already refuses both fields, and the review found the Solana verifier did not.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 742.

### NET-SOL-25 — Every signing client honours lane horizon
- old: RS12-24 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-25 · superseded-by: —

**Rule.** Every signing client honours the lane horizon
**Why.** The chain cannot see when an op was signed, so a client that signs two ops on one lane more than 30 days apart lets the later one run after a prune (the gap found for Aptos, NET-APT-24).
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 744.

### NET-SOL-26 — Mesh verifies Solana signatures locally
- old: RS12-25 · status: current · owner: no · date: 2026-10-07 · normative: networks/solana.md#NET-SOL-26 · superseded-by: —

**Rule.** Mesh and gateway verify Solana signatures locally before any simulation
**Why.** The mesh decoders checked only domain, network and contract, so every peer paid a simulation for each garbage intent.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 746.; [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 149

### NET-SOL-27 — open requires the wallet own signature
- old: RS12-4a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-27 · superseded-by: —

**Rule.** `open` requires the wallet's own signature.
**Why.** A permissionless `open(owner)` let anyone pre-open a passkey-first id with an ed25519 key and brick that passkey's Account; opening on someone's behalf is not needed because the first `relay_pay` opens the Account lazily with the owner's signature.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 883.

### NET-SOL-28 — Mandate delegate ed25519; revoke and close
- old: RS12-11a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-28 · superseded-by: —

**Rule.** The mandate delegate is ed25519; revoke only sets a flag; close returns the passed token accounts and closes the PDA.
**Why.** The delegate is a platform service or HSM key and passkeys do not run on servers; splitting revoke from close settled a review finding that the two contradicted each other.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 884.

### NET-SOL-29 — One pair per instruction; sweep rules
- old: RS12-12a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-29 · superseded-by: —

**Rule.** One pair per `settle` instruction; a batch is several instructions in one transaction; `sweep` is permissionless.
**Why.** One pair per instruction keeps every account a typed Anchor account instead of hand-checked `remaining_accounts`, and several instructions in one transaction still settle atomically.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 887.

### NET-SOL-30 — Passkey blob length little-endian
- old: RS12-9a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-30 · superseded-by: —

**Rule.** In the passkey blob the `u16` authenticatorData length is little-endian.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 891.

### NET-SOL-31 — Restart advances nonce; error classes
- old: RS12-16a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-31 · superseded-by: —

**Rule.** On restart the Solana adapter advances each lane's nonce once, and errors are classed by instruction index.
**Why.** Advancing the nonce at restart means old bytes can never land, so `recover_lane` sees the nonce move and requeues the job at once instead of holding the lane until `valid_until`.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 892.

### NET-SOL-32 — block_hash from last produced block
- old: RS12-18a · status: current · owner: no · date: 2026-10-04 · normative: networks/solana.md#NET-SOL-32 · superseded-by: —

**Rule.** `block_hash(s)` is the hash of the last produced block ≤ s within a 2 048-slot window; `Config` is read at `confirmed`.
**Why.** Skipped slots are normal on Solana and a 512-slot window can be empty on an idle cluster, so the window is 2,048 slots; `Config` is immutable after `initialize`, so `confirmed` is enough.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 894.

### NET-SOL-33 — Solana target: MetaCall/MetaTransfer layouts, mtx_ instructions
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/solana.md#NET-SOL-33 · superseded-by: —

**Why.** The family form of NET-ALL-26 to NET-ALL-29: the encoding of both kinds, the verifier, and the map from each built entry and struct to its `mtx` name; programs are immutable, so it ships as a new deployment.
**Cost if wrong.** Clients, node and contract drift on names and encodings per family.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, NM-3, NM-5.

### NET-SOL-34 — Universal Accounts on Solana: rent-exempt PDAs, nothing expires
- old: — · status: current · owner: no · date: 2026-10-19 · normative: networks/solana.md#NET-SOL-34 · superseded-by: —

**Why.** The family form of CTR-UA-06 on Solana: `["ua", U]` record, `["ukey", keyHash]` claim, `["acct", U]` subject Account owning one token account per mint held (NET-SOL-05), lane PDAs; rent-exempt deposits once, no TTL; a transaction of 1,232 B bounds the members of an `msig` one transaction can carry (≈ 5–7 ed25519, ≈ 2 passkey), so a larger `msig` needs an approval PDA (open); bn254 / BLS / Schnorr kinds are not enabled on Solana until their syscalls and CU are verified. Status: SPECIFIED (controller 2026-10-19, owner question; not built).
**Cost if wrong.** A Solana UA layout that cannot carry its signatures, or balances outside SPL that wallets and DEXs cannot see.
**Source.** owner question 2026-10-19 (how UA, msig, BLS and balances are stored and maintained on Solana); storage costs: [research/near-algorand.md](research/near-algorand.md) §5.

Change (2026-10-19): owner request — a **Storage cost** table in networks/solana.md §2.1 with figures checked against the SIMDs, solana.com and mainnet RPC: the live rent-exempt rate is **5,080 lamports per byte** (SIMD-0194 active, SIMD-0437 steps 1–2 active, steps 3–5 to 696 expected in Agave 4.4), so the earlier 6,960-based figures are replaced (≈ 0.0069 SOL per KB → ≈ 0.0051 per 1,000 B; ATA ≈ 0.00204 → ≈ 0.00149 SOL; 16-member `msig` record ≈ 0.005 → ≈ 0.0037 SOL; 10 MiB ≈ 73 → ≈ 53 SOL); rent collection is disabled (SIMD-0084). The `msig` bound is restated for the v1 transactions SCaaS sends (NET-SOL-17): 4,096 B ⇒ roughly 25–30 ed25519 or 8–10 passkey members per transaction (≈ 5–7 / ≈ 2 at 1,232 B); BLS12-381 syscalls (SIMD-0388) are active on mainnet, CU not measured. Status: SPECIFIED, documentation only.

### NET-SOL-80 — Out of CU requeued without limit
- old: RS12-16(cu) · status: superseded · owner: no · date: 2026-10-04 · normative: — · superseded-by: NET-SOL-23

It said: Out of CU requeued without limit; replaced by NET-SOL-23.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 24.

### NET-SOL-81 — Signed text is domain plus hex digest
- old: RS12-9(text) · status: superseded · owner: no · date: 2026-10-04 · normative: — · superseded-by: NET-ALL-23

It said: Signed text is domain plus hex digest; replaced by NET-ALL-23.
**Source.** [history/specs/2026-10-04-net-solana.md](history/specs/2026-10-04-net-solana.md) line 708.

## 34. Networks — GRAM

### NET-TON-01 — GRAM Tact jetton wallet; escrow DEX
- old: R67(core) · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-01 · superseded-by: —

**Rule.** GRAM = a Tact jetton whose custom wallet verifies signed operations; the DEX is an escrow.
**Why.** GRAM's asynchronous actor model has no atomicity across contracts, so the DEX holds the first signed leg in escrow until the second matches or the order expires; Tact was chosen because FunC, one level lower, was not worth it for this scope.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 540.

### NET-TON-02 — GRAM per-wallet domain set on chain
- old: CR-R3-7, reorg:Q3 · status: current · owner: yes · date: 2026-10-07 · normative: networks/ton.md#NET-TON-02 · superseded-by: —

**Rule.** GRAM binds the `signData` domain on chain through a per-wallet domain set.
**Why.** Anyone may relay a `SignedOp`, so an off-chain domain check never runs when a phishing dApp relays its own signed data.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 693; [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) line 1217.

### NET-TON-03 — GRAM bounced payouts claimable by owner
- old: CR-R3-9, reorg:Q4 · status: current · owner: yes · date: 2026-10-07 · normative: networks/ton.md#NET-TON-03 · superseded-by: —

**Why.** As built `bounced<JettonTransfer>` adds to `fees[master]` (`dex.tact:131-136`), which `WithdrawFees` withdraws (`:43,158`). SPECIFIED. Tests (sandbox): a bounced refund lands in `unclaimed`, `WithdrawFees` cannot take it, `Claim` pays the owner.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 703; [history/plans/2026-10-07-docs-reorg.md](history/plans/2026-10-07-docs-reorg.md) line 1218.

### NET-TON-04 — Compact Tact Jetton with meta-tx wallet
- old: R10-1 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-04 · superseded-by: —

**Rule.** The token is a compact Tact rewrite of a TEP-74 Jetton (`ScaasJettonMaster` + `ScaasJettonWallet`) whose wallet adds `pubkey`, `passkey` and a `lanes` table; no off-the-shelf jetton is used.
**Why.** The wallet must verify meta-transactions (NET-ALL-02), and keeping the TEP-74 opcodes and getters lets wallets and explorers read it.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 24.

### NET-TON-05 — TON Connect signData cell envelope
- old: R10-2 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-05 · superseded-by: —

**Rule.** The subject signs with TON Connect `signData` type `cell`; the contract rebuilds the exact envelope around the `MetaOp` cell and checks `CHKSIGNU` over the envelope cell hash; the seed signer builds the same envelope with `m/44'/607'/i'`.
**Why.** One verification path serves both real TON Connect wallets and the seed wallet.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 25.

### NET-TON-06 — Network domain = config 19 global id
- old: R10-4 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-06 · superseded-by: —

**Rule.** The GRAM network domain is the `global_id` read on chain from config parameter 19
**Why.** GRAM addresses are identical across networks (same code and data), so a network id is required, and config parameter 19 cannot be faked.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 27.

### NET-TON-07 — Lazy key bind via SignedOp stateInit
- old: R10-5 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-07 · superseded-by: —

**Rule.** The key binds lazily through the `SignedOp`'s optional `stateInit`.
**Why.** The public key must be proven by the owner's address, and checking the `stateInit` hash against the address does that without the subject sending a transaction.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 28.

### NET-TON-08 — One GRAM passkey set by set_key
- old: R10-6 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-08 · superseded-by: —

**Rule.** A GRAM wallet holds one passkey, attached or detached by `set_key`, which must carry a proof of possession of the attached key; origins match exactly.
**Why.** One passkey is enough for the portal, and many passkeys with a guardian stay a seam because only the EVM subject account has the full lifecycle; the proof of possession comes from NET-ALL-20.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 29.

### NET-TON-09 — GRAM DEX is fill-or-kill escrow
- old: R10-7 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-09 · superseded-by: —

**Rule.** The GRAM DEX is a fill-or-kill escrow.
**Why.** GRAM has no atomic calls between contracts, a deliberate departure from the EVM DEX (CTR-DEX-01).
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 30.

### NET-TON-10 — Relayer lane = W5R1 wallet, one message
- old: R10-8 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-10 · superseded-by: —

**Rule.** A GRAM relayer lane is a W5R1 wallet with its own seqno, one external message in flight, and W5 `valid_until` = the payload's expiry.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 31.

### NET-TON-11 — Node uses TON Center API v3
- old: R10-9 · status: current · owner: no · date: 2026-10-03 · normative: networks/ton.md#NET-TON-11 · superseded-by: —

**Rule.** The node uses TON Center API v3
**Why.** It is available on mainnet, on testnet and in MyLocalTon (indexer profile).
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 32.

### NET-TON-12 — Events authenticated by derived wallet address
- old: R10-10 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-12 · superseded-by: —

**Rule.** GRAM events are authenticated by the derived wallet address.
**Why.** Jettons have no central log; authenticating the emitter by its derived address stops a fake contract from emitting fake events or clogging the indexer, with no RPC per event.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 33.

### NET-TON-13 — No relayer fee; forward GRAM capped
- old: R10-11 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-13 · superseded-by: —

**Rule.** No relayer fee on GRAM; the DEX ppm fee is signed in the order; gas GRAM is attached per message and the excess returns to the lane; forward GRAM is capped.
**Why.** New networks carry no relayer fee by design; the forward cap answers a critical review finding that uncapped forward GRAM could drain a lane (NET-TON-14).
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 34.

### NET-TON-14 — Forward GRAM capped on every path
- old: R10-12 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-14 · superseded-by: —

**Rule.** Forward GRAM is capped on every path (blocking).
**Why.** The adapter attached an uncapped amount, accepted an unsigned `extra.forward_nanoton` from job JSON, and the wallet forwards that GRAM to its owner, while the breaker counted only mined fees (NODE-LANE-17).
**Cost if wrong.** Anyone who can place a job on a GRAM lane can drain the lane's GRAM; the review verdict was BLOCK until fixed.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 225.

### NET-TON-15 — tx_id is TEP-467 normalized hash
- old: R10-13 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-15 · superseded-by: —

**Why.** As built the code returns `ext.hash()` of the message as sent (`ton.rs:743-750`, looked up raw at `:994-997`); for seqno 0 (with `init`) the two hashes differ, and anyone relaying the BOC (TON Center, a proxy, a mesh peer) can re-wrap it (the envelope is not inside the W5 signature), so `follow` reports `dead` while the money moved. SPECIFIED. Test: a seqno-0 message with `init` ⇒ `tx_id ≠ ext.hash()`, a fake API finds it by normalized hash; a re-wrapped copy still yields `Mined`.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 235.

### NET-TON-16 — Node checks GRAM domain at every door
- old: R10-14(node) · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-16 · superseded-by: —

**Rule.** The node checks the TON Connect domain at every door.
**Why.** `SignedOp` is an ordinary message anyone can send, so a `signData` signature collected by a phishing page ran without passing the ERP; requiring a named relayer was rejected because it kills the open relay and the mesh.
**Cost if wrong.** Pinning the domain on chain means a portal domain change needs a new master and new wallet addresses, accepted because domain binding is TON Connect's anti-phishing layer.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 239.

### NET-TON-17 — Simulation reads balance, checks passkey locally
- old: R10-15 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-17 · superseded-by: —

**Rule.** GRAM simulation reads the jetton balance and checks the passkey locally.
**Why.** `build` read neither the jetton balance nor the passkey, so an op certain to fail on chain was still signed and sent.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 245.

### NET-TON-18 — Revoke runs exactly once
- old: R10-16 · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-18 · superseded-by: —

**Why.** As built the wallet accepts `next == nonce` or `nonce + 1` (`jetton.tact:229`) and the first form sets `next + 1`, so a resend of the **same** signature runs again in the second form, consuming `nonce + 1` and sending a `CancelTag`. SPECIFIED. Test: resending the same revoke ⇒ `E_NONCE`, no second `CancelTag`.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 248.

### NET-TON-19 — DEX keeps nothing not its own
- old: R10-17(cancel/fees) · status: current · owner: no · date: 2026-10-07 · normative: networks/ton.md#NET-TON-19 · superseded-by: —

**Rule.** The GRAM DEX keeps nothing that is not its own.
**Why.** Cancelling an unknown order kept the attached GRAM, and bounced payouts were added to fees that the admin can withdraw; a bounce body is cut to 256 bits and carries no destination, so refunds go through an admin call with an event trail instead of a per-owner debt table.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 250.

### NET-TON-20 — GRAM target: MetaCall/MetaTransfer cells, Mtx messages
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: networks/ton.md#NET-TON-20 · superseded-by: —

**Why.** The family form of NET-ALL-26 to NET-ALL-29: the encoding of both kinds, the verifier, and the map from each built entry and struct to its `mtx` name; programs are immutable, so it ships as a new deployment.
**Cost if wrong.** Clients, node and contract drift on names and encodings per family.
**Source.** `history/specs/2026-10-08-nonevm-metacall-design.md` §3 NM-2, NM-3, NM-5.

### NET-TON-80 — GRAM BindKey message
- old: R67(bindkey) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NET-TON-07

It said: GRAM BindKey message; replaced by NET-TON-07.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 540.

### NET-TON-81 — Domain checked only in the ERP
- old: R10-3 · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-TON-16, NET-TON-02

It said: Domain checked only in the ERP; replaced by NET-TON-16, NET-TON-02.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 16.

### NET-TON-82 — domainHash pinned in wallet init
- old: R10-14(contract) · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-TON-02

It said: domainHash pinned in wallet init; replaced by NET-TON-02.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 239.

### NET-TON-83 — Bounced payouts via admin RefundBounced
- old: R10-17(bounced) · status: superseded · owner: no · date: 2026-10-07 · normative: — · superseded-by: NET-TON-03

It said: Bounced payouts via admin RefundBounced; replaced by NET-TON-03.
**Source.** [history/specs/2026-10-03-net-ton.md](history/specs/2026-10-03-net-ton.md) line 250.

## 35. Clients — signers and clientkeys

### CLI-SGN-01 — Ephemeral agent session keys (1-8 h)
- old: req:blockchain.md:session-keys · status: open · owner: yes · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-01 · superseded-by: —

**Rule.** Short-lived agent session keys (1–8 h) are an open owner requirement.
**Why.** Agents must never hold a sponsor or admin private key in plaintext; those keys live in an HSM or MPC, and an agent gets only a short-lived key bounded by a delegation contract and a per-transaction cap.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/blockchain.md](history/blockchain.md) line 328.

### CLI-SGN-02 — Seed vault DEK with passphrase and PRF envelopes
- old: RS4-8(vault) · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-02 · superseded-by: —

**Rule.** The vault encrypts the seed under a random data key wrapped by a passphrase envelope and, when available, a passkey PRF envelope.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 33.

### CLI-SGN-03 — Zether keys derived in clientkeys JS
- old: RS4-9(keys) · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-03 · superseded-by: —

**Rule.** Zether keys are derived in clientkeys JavaScript.
**Why.** Registering a key should not need the prover's WebAssembly; a separate lazy entry also keeps the seed bundle small.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 35.

### CLI-SGN-04 — Random WebAuthn user handle per passkey
- old: RS4-11 · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-04 · superseded-by: —

**Rule.** Each passkey gets a random 16-byte WebAuthn user handle.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 48.

### CLI-SGN-05 — Client rebuilds operation before signing
- old: RS4-13 · status: current · owner: no · date: 2026-10-08 · normative: clients/signers-clientkeys.md#CLI-SGN-05 · superseded-by: —

**Rule.** A client never signs server-built typed data as is; it rebuilds the operation first.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 57.
Change (2026-10-08): `checkPayment` rebuilds a payment `MetaTransfer`; `checkOwnerCall` a `SmartKeyAccount` `MetaTransaction` signed as the account (CTR-ACC-10). Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-6, GC-8.

### CLI-SGN-06 — WalletConnect is a seam behind a flag
- old: R21 · status: current · owner: no · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-06 · superseded-by: —

**Why.** The SDK is ~400 KB, needs a pinned version + SRI, cannot be tested in offline CI, and a third-party script inside a payment page is supply-chain surface.
**Cost if wrong.** mobile wallets need a small add-on that registers the factory (pinned `@walletconnect/ethereum-provider` + SRI) first. The same holds for Hedera HashPack (also a seam) and the TON Connect HTTP bridge.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 192.

### CLI-SGN-07 — Subject-account seed keys use role path
- old: CR-ADW-3 · status: current · owner: no · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-07 · superseded-by: —

**Rule.** New seed keys of subject accounts use the role path.
**Why.** The account accepts a secp256k1 key's signature over a raw 32-byte digest, so a seed key that is also the subject's EOA key lets any raw signer for that EOA produce account signatures; mainstream wallets no longer expose raw signing, so the exposure is custom raw signers.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 310.

### CLI-SGN-08 — checkPayment pins expected token client-side
- old: CR-ADW-4 · status: current · owner: no · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-08 · superseded-by: —

**Rule.** `checkPayment` pins the expected token client-side.
**Why.** The check took the amount and decimals from the caller and only checked that the token was not the account, so a server could substitute another token carrying the expected symbol.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 316.

### CLI-SGN-09 — Portal and mobile subjects sign with passkeys
- old: R31(client) · status: current · owner: yes · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-09 · superseded-by: —

**Rule.** Portal and mobile subjects sign value operations with WebAuthn P-256 passkeys.
**Why.** The client signs and the relayer pays: the server never holds a key to sign for a subject, the only exception being an explicitly delegated, limited custodial or mandate wallet.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 519.

### CLI-SGN-10 — Zether keys from seed, own paths
- old: R33(keys) · status: current · owner: yes · date: 2026-10-03 · normative: clients/signers-clientkeys.md#CLI-SGN-10 · superseded-by: —

**Rule.** Zether confidential keys come from the same seed on their own paths.
**Why.** Signing keys and the ElGamal key are separate custody: leaking a signing key must not reveal balances and leaking the confidential key must not authorise transfers, so the confidential key never shares a scalar with any signing key. Owner ruling.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 521.

### CLI-SGN-11 — Client-side seed vault, multi-key accounts
- old: R32(vault) · status: current · owner: yes · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-11 · superseded-by: —

**Rule.** A non-custodial seed wallet lives on the client, and one subject account holds several keys (passkey + seed).
**Why.** Owner ruling: build both passkeys and seed words; each is the natural recovery key when the other is lost.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 522.

### CLI-SGN-12 — Backup key required is one switch
- old: R250 · status: current · owner: yes · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-12 · superseded-by: —

**Rule.** "Backup key required" is one boolean deployment switch, default off.
**Why.** Owner decision: only a switch, replacing a per-account mode list and its "device_bound refused" rule.
**Cost if wrong.** per-company rules later would need a company field. SPECIFIED.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 77.

### CLI-SGN-13 — Backup predicate: distinct keys or guardian
- old: R251 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-13 · superseded-by: —

**Why.** Duplicates and self-guardians are exactly the false "backed up" state the switch exists to prevent.
**Cost if wrong.** two passkeys in one password manager still count as two (CLI-SGN-16 warns).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 85.

### CLI-SGN-14 — Backup enforced by clients and issuers
- old: R252 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-14 · superseded-by: —

**Why.** The switch protects users from loss and is not a security control.
**Cost if wrong.** a third-party client ignores it, by design.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 99.

### CLI-SGN-15 — Exits are never blocked
- old: R253 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-15 · superseded-by: —

**Why.** Rescue is never throttled.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 112.

### CLI-SGN-16 — Non-blocking BE/BS warnings
- old: R254 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-16 · superseded-by: —

**Why.** The flags are the only sync signal and are self-reported (`attestation: 'none'`).
**Cost if wrong.** a misreporting authenticator mislabels a key; counting is unaffected.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 123.

### CLI-SGN-17 — Vault v2 under non-extractable device key
- old: R255 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-17 · superseded-by: —

**Rule.** Vault v2 is an outer AES-256-GCM layer under a per-origin non-extractable device key, wrapped around the unchanged v1 vault.
**Why.** All of the v1 vault is reused, and a blob leaked on its own (storage dump, log, support export, file sync) becomes useless without the profile's IndexedDB.
**Cost if wrong.** Once the device key is gone (site data cleared, Safari's 7-day eviction) the blob never opens again, and only the phrase recovers the keys (CLI-SGN-20).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 135.

### CLI-SGN-18 — Device binding relaxes nothing
- old: R256 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-18 · superseded-by: —

**Rule.** Device binding relaxes nothing.
**Why.** WebCrypto keys are not hardware-backed on Chromium and Firefox (the key bytes sit in the profile's IndexedDB files), so the gain is narrow and the claims must stay honest.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 144.

### CLI-SGN-19 — Vault storage, precedence and migration
- old: R257 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-19 · superseded-by: —

**Rule.** Vault storage, precedence and migration.
**Why.** No rollback to a stale weaker blob, no silently created new seed, and no second 128 MiB KDF run.
**Cost if wrong.** One more migration path in the portal signer code.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 153.

### CLI-SGN-20 — Device-loss recovery via phrase only
- old: R258 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-20 · superseded-by: —

**Why.** A re-reveal path would undermine "written down" (CLI-SGN-13).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 165.

### CLI-SGN-21 — scrypt N=2^17 for new envelopes
- old: R259, RS4-14 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-21 · superseded-by: —

**Why.** One number in code and docs, and no device locked out by its own upgrade.
**Cost if wrong.** very low-memory phones use a paper backup or an extension wallet. BUILT (parameters and re-wrap); the failure, marker and bounds tests SPECIFIED.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 173; [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 61.

### CLI-SGN-22 — Seed signers sign family envelopes
- old: R263 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-22 · superseded-by: —

**Why.** The seed signs silently. SPECIFIED for Soroban, Aptos, Solana.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 217.

### CLI-SGN-23 — One WebAuthn ceremony, per-family encoders
- old: R264 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-23 · superseded-by: —

**Why.** Verifier maturity.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 227.

### CLI-SGN-24 — Passkey challenge = b64url op digest
- old: R265 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-24 · superseded-by: —

**Rule.** The passkey challenge is base64url (no padding) of the family's op digest.
**Why.** One rule for every family, the same one passkeys already follow (CLI-SGN-09).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 231.

### CLI-SGN-25 — Added seed keys are role keys
- old: R269 · status: current · owner: no · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-25 · superseded-by: —

**Why.** A backup in the same browser profile as the primary key is not a backup.
**Cost if wrong.** one derivation per role; wallets show the role.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 235.

### CLI-SGN-26 — One connector implementation in clientkeys
- old: R266 · status: current · owner: yes · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-26 · superseded-by: —

**Rule.** One connector implementation in clientkeys, shared by the app and every portal.
**Why.** Owner decision; the existing connectors were tested but never wired into a flow.
**Cost if wrong.** clientkeys gains browser glue. SPECIFIED (as built, the portal connectors are seven node-tested scripts that nothing loads; the portal's payment script is EVM only — EIP-6963, EIP-1193 fallback, the WalletConnect seam, `eth_signTypedData_v4`, the `wallet_kind` hint — and reads `start.typed_data.message.validUntil`, which a non-EVM start lacks; the issuer side is already family-ready: `{family, valid_until, payload_hex, digest, …terms}` plus `public_key`).
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 254.

### CLI-SGN-27 — Check, then sign what was checked
- old: R267 · status: current · owner: no · date: 2026-10-08 · normative: clients/signers-clientkeys.md#CLI-SGN-27 · superseded-by: —

**Rule.** Check, then sign exactly what was checked.
**Why.** It closes the gap between checking `payload_hex` and signing a different `text`.
**Cost if wrong.** A terms change must land together with its `fam/*.js` change; shared known-answer tests catch a mismatch.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 263.
Change (2026-10-08): the target `MetaTransfer` is checked like the built `MetaOp`; a `MetaCall` is checked against the contract's allowlist (function, decoded arguments, recomputed `args_hash`). Source add: `history/specs/2026-10-08-nonevm-metacall-design.md` §4.

### CLI-SGN-28 — Signers spec adds no ids or kinds
- old: R268 · status: current · owner: no · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-28 · superseded-by: —

**Rule.** The signer rules add no account id, registry or key kind.
**Why.** The signer rules and the universal-account design stay independent: the backup predicate works unchanged over the universal account's key sets.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 279.

### CLI-SGN-29 — One key one purpose: wallet layer
- old: R298(1) · status: current · owner: yes · date: 2026-10-06 · normative: clients/signers-clientkeys.md#CLI-SGN-29 · superseded-by: —

**Why.** ECDSA and Schnorr over one secp256k1 key leak through nonce relations; a Schnorr signing oracle on an ElGamal key is a decryption-adjacent oracle; untagged digests replay across protocols. Owner decision.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 166.

### CLI-SGN-30 — EOA path EOA-only; role tree m/7622
- old: R300, S4F:Q1, UA:Q6 · status: current · owner: yes · date: 2026-10-07 · normative: clients/signers-clientkeys.md#CLI-SGN-30 · superseded-by: —

**Rule.** The EVM seed path is the EOA only; every subject-account key that is not the native owner and every derived kind comes from the UA tree `m/7622'/0'/<account>'/<kindNo>'/<i>'`.
**Why.** A key that is both an EOA and an account key serves two purposes; the owner chose one chain-independent tree under purpose `7622'`, so a subject has the same UA on every chain.
**Cost if wrong.** One more derivation per role; wallets show the role.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 181; [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 784; [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 1398.

### CLI-SGN-31 — Key oracle keeps no persistent state
- old: UD:§23.10 · status: current · owner: yes · date: 2026-08-31 · normative: clients/signers-clientkeys.md#CLI-SGN-31 · superseded-by: —

**Rule.** The key oracle keeps no persistent state.
**Why.** Answering twice for the same proof commitment with two different challenges reveals the secret key at once, and an enclave that persisted its open-commitment table could be rolled back and made to answer again; forgetting everything on restart fails closed. With a sigma protocol the commit picks `k` and the response is `s = k + c·x`; two answers for one `k` give `x = (s₁ − s₂)/(c₁ − c₂)`. So `zk_response(nonce_id, c)` removes `k` from open_nonces (remove, not get) and rejects an unknown or used nonce_id, and after a restart every old nonce_id is unknown. Losing the replay cache on restart is also safe: with deterministic ECDSA nonces (RFC 6979) re-signing the same payload yields the same signature, so the cache only saves a signing. The audit log of who asked to sign what is written outside the enclave through the custody lane, so a restart loses none of it.
**Cost if wrong.** A restart of the oracle lane breaks every proof being built; they are rebuilt at a CPU cost of 30 to 50 ms each, and no signed transaction is lost.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2356.

### CLI-SGN-32 — Oracle lane only when an organization holds Zether
- old: UD:§23.11, canon:D7 · status: current · owner: yes · date: 2026-08-31 · normative: clients/signers-clientkeys.md#CLI-SGN-32 · superseded-by: —

**Rule.** A server-side key-oracle lane exists only when an organization holds a Zether account.
**Why.** Loyalty and end-user payments prove on the user's device, treasury operations are plain ECDSA, and confidential B2B settlement is optional (owner, 2026-08-31), so only an organization that holds its own confidential account has a server-side key to serve. "Non-custodial" means holding no one else's money; it does not mean no key on a server: a company's own treasury is self-custody and its key still lives somewhere. Loyalty and end-user payments are `on_device` 1-of-1 (the prover runs on the user's device); with confidential B2B on, the platform holds one share of a 2-of-3 split of the key and cannot spend alone. Even a receive-only confidential treasury needs its key to read what it received (the HSM or enclave exposes exactly `ecdh(D) -> compress(D^x)`), so dropping the oracle lane drops reconciliation, which then stays partial instead of clean. A person with a device can run payouts (500 payees × 12 months = 6,000 transfers a year, so 500 proofs a month, 100 to 250 s of compute on a laptop) but not the daily reconciliation.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 2416; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 861.

### CLI-SGN-33 — Every SCaaS domain built with salt = chain_uid from the pinned profile; other salts refused
- old: — · status: current · owner: no · date: 2026-10-08 · normative: clients/signers-clientkeys.md#CLI-SGN-33 · superseded-by: —

**Why.** The contract enforces the salt whichever wallet signs; wallets such as MetaMask check only `chainId`, so the client fills the salt itself and catches a wrong profile or a hostile server before asking the user.
**Cost if wrong.** Signatures that fail on chain, or a user led to sign for another chain's contract.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §3 MG-4 ("who fills it in when signing"), MG-6.

### CLI-SGN-34 — Meta-tx `data` decoded and shown before signing; unknown selectors refused
- old: — · status: current · owner: no · date: 2026-10-08 · normative: clients/signers-clientkeys.md#CLI-SGN-34 · superseded-by: —

**Why.** With a generic self-call, opaque `data` would let a page ask for any allowlisted call; decoding against the published allowlist shows the function, its arguments and the fee class, and the two `batch` lanes are labelled apart.
**Cost if wrong.** A user signs a burn or an unwrap to a stranger while shown a transfer.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §3 MG-6; §4 (opaque `data`); §13 L-12(e).
Change (2026-10-08): transfers and payments are shown by the typed `MetaTransfer` fields; a `transfer`/`pay` selector inside a `MetaTransaction` is refused; the rule covers every contract on `MetaTxBase`. Source add: `history/specs/2026-10-08-metatx-generic-call-design.md` §3 GC-8.

### CLI-SGN-35 — A trade order names a listed DEX, or the client refuses to build and sign it
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: clients/signers-clientkeys.md#CLI-SGN-35 · superseded-by: —

**Why.** Owner decision 2026-10-08: `dex` must only be a contract on chain; the defence against a phishing `dex` is the client refusing by default an order off the profile's DEX list, showing `dex`, `relayer`, `destination` and the effective minimum fill, warning on `destination ≠ from`, and defaulting `relayer` to the venue node.
**Cost if wrong.** The signed amount is taken by a contract posing as a DEX.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §3 MG-6, MG-8.1, MG-8.3; §4; §13 N-H1, L-10, L-11.

### CLI-SGN-36 — No EOA approve of a SCaaS token; a SCaaS underlying is wrapped by signature
- old: — · status: current · owner: yes · date: 2026-10-08 · normative: clients/signers-clientkeys.md#CLI-SGN-36 · superseded-by: —

**Why.** Owner rulings A5, A6, A9: only a contract calls `approve` on a SCaaS token; an EOA may still approve our wrapper on an outside token; wrapping a SCaaS underlying is a `TradeOrder` signed in the underlying's domain with the wrapper as `dex`, relayed as `mtxWrap`. Contract accounts approve through their own call path.
**Cost if wrong.** Clients offer screens the token refuses, or keep standing EOA allowances alive.
**Source.** [history/specs/2026-10-07-metatx-generic.md](history/specs/2026-10-07-metatx-generic.md) §2 A5, A6, A9; §3 MG-7, MG-7b.

### CLI-SGN-37 — Exchange-path orders: listed-pools toggle, cycle label, approve the puller, surplus check
- old: — · status: current · owner: no · date: 2026-10-08 · normative: clients/signers-clientkeys.md#CLI-SGN-37 · superseded-by: —

**Why.** Clients expose the signer's `LISTED_POOLS` choice (default off), label and warn on cycle orders, send outside-token approvals to the `DexPuller` instead of the DEX, and check each `ExchangeLegSettled` against its `limitReceive`.
**Cost if wrong.** An approval to the DEX would reopen the theft path CTR-DEX-22 closes; an unchecked settlement would hide a short payout.
**Source.** `history/specs/2026-10-08-dex-exchange-design.md` §3 DS-8.

### CLI-SGN-80 — Vault PIN scrypt N=2^15
- old: RS4-8(scrypt) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CLI-SGN-21

It said: Vault PIN scrypt N=2^15; replaced by CLI-SGN-21.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 33.

### CLI-SGN-81 — Zether PoP bound to subject account
- old: RS4-9(pop) · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CTR-UA-07

It said: Zether PoP bound to subject account; replaced by CTR-UA-07.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 35.

### CLI-SGN-82 — Per-subject localStorage vault
- old: RS4-15 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: CLI-SGN-19

It said: Per-subject localStorage vault; replaced by CLI-SGN-19.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 65.

### CLI-SGN-83 — Zether on chain stays deferred
- old: R33(deferred) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CTR-ZTH-01, CTR-ZTH-18, CTR-ZTH-19, CTR-UA-02, CTR-UA-16, CTR-UA-22, INT-ERP-11

It said: Zether on chain stays deferred; replaced by CTR-ZTH-01, CTR-ZTH-18, CTR-ZTH-19, CTR-UA-02, CTR-UA-16, CTR-UA-22, INT-ERP-11.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 521.

### CLI-SGN-84 — Zether PoP bound to caller account
- old: R33(pop) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CTR-UA-07

It said: Zether PoP bound to caller account; replaced by CTR-UA-07.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 521.

### CLI-SGN-85 — Account seed keys on EOA path
- old: R32(path) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CLI-SGN-30

It said: Account seed keys on EOA path; replaced by CLI-SGN-30.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 522.

### CLI-SGN-86 — Seed vault scrypt N=2^15 with PIN
- old: R32(scrypt) · status: superseded · owner: yes · date: 2026-10-03 · normative: — · superseded-by: CLI-SGN-21

It said: Seed vault scrypt N=2^15 with PIN; replaced by CLI-SGN-21.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 522.

### CLI-SGN-87 — Custody tier A/B, HSM or MPC
- old: UD:§15:D7 · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: CLI-SGN-32

It said: Custody tier A/B, HSM or MPC; replaced by CLI-SGN-32.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 861.

## 36. Clients — SCaaS app

### CLI-APP-01 — One SPA, two halves, one build
- old: R150 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-01 · superseded-by: —

**Why.** Chain features work without login; one artefact to test and pin.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 104.

### CLI-APP-02 — React, TanStack Query, hash routes
- old: R151 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-02 · superseded-by: —

**Why.** Server state dominates; hash routing removes SPA-fallback rules from every host and from the node.
**Cost if wrong.** deep links look like `/#/…`.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 105.

### CLI-APP-03 — App has no server and no secrets
- old: R152 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-03 · superseded-by: —

**Why.** Machine credentials and admin credentials never cross (NODE-ADM-06).
**Cost if wrong.** public gateways run with auth `none` behind a host proxy with rate limits.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 106.

### CLI-APP-04 — One adapter interface per family
- old: R153 · status: current · owner: yes · date: 2026-10-06 · normative: clients/app.md#CLI-APP-04 · superseded-by: —

**Why.** Family SDKs are most of the bytes.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 107.

### CLI-APP-05 — App builds and decodes every signed byte
- old: R154 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-05 · superseded-by: —

**Why.** Display and bytes cannot diverge silently; one JS implementation is shared with portals.
**Cost if wrong.** clientkeys grows to all families.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 108.

### CLI-APP-06 — App signer set and key paths
- old: R155 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-06 · superseded-by: —

**Why.** One wallet-glue implementation; one key, one purpose.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 109.

### CLI-APP-07 — Relayed submission for Hedera and non-EVM
- old: APP:Q1, R156 · status: current · owner: yes · date: 2026-10-06 · normative: clients/app.md#CLI-APP-07 · superseded-by: —

**Why.** With gateway submission a user needs no native gas on any family.
**Cost if wrong.** until those routes exist, Hedera and non-EVM are self-paid only.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 1029; [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 110.

### CLI-APP-08 — Intent status is chain truth
- old: R157 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-08 · superseded-by: —

**Why.** The node is trusted for liveness, not truth.
**Cost if wrong.** one read per poll.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 111.

### CLI-APP-09 — Signing review from decoded bytes
- old: R158 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-09 · superseded-by: —

**Why.** Extension wallets show hex for most families; the app's review is the only real check.
**Cost if wrong.** non-curated tokens take an explicit-add step.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 112.

### CLI-APP-10 — Static mode config.json and CSP
- old: R161 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-10 · superseded-by: —

**Why.** One build, every host.
**Cost if wrong.** a host without headers runs the weaker meta CSP.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 115.

### CLI-APP-11 — Admin tokens in memory only
- old: R162 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-11 · superseded-by: —

**Rule.** Admin tokens live in memory only, per node.
**Cost if wrong.** built-in users retype the password after a reload.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 116.

### CLI-APP-12 — OIDC public client with PKCE
- old: R163 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-12 · superseded-by: —

**Why.** No hand-rolled OAuth.
**Cost if wrong.** IdPs without SPA refresh tokens bounce the page once per token lifetime.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 117.

### CLI-APP-13 — Zether runs in a session worker
- old: R164 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-13 · superseded-by: —

**Rule.** Zether runs in one session worker.
**Why.** The worker opens the confidential vault itself, so the Zether secret key never enters the main page realm.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 118.

### CLI-APP-14 — Passkeys origin-bound; backup de-duplication
- old: R165 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-14 · superseded-by: —

**Why.** The two deployment modes are two origins.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 119.

### CLI-APP-15 — Pinned supply chain, one dev flag
- old: R166 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-15 · superseded-by: —

**Why.** Every dependency has signing reach.
**Cost if wrong.** upgrades are deliberate.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 120.

### CLI-APP-16 — Risk disclosures English beside translation
- old: APP:Q3, R167 · status: current · owner: yes · date: 2026-10-06 · normative: clients/app.md#CLI-APP-16 · superseded-by: —

**Rule.** English is the default and every string has a Vietnamese translation; risk disclosures show the English original beside the translation until the owner approves the text.
**Why.** Owner choice; the translated risk disclosures are not yet approved by the owner.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 1031; [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 121.

### CLI-APP-17 — Role gating is UI only
- old: R168 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-17 · superseded-by: —

**Rule.** Role gating in the app is UI only
**Why.** The node enforces the roles on its own routes (NODE-ADM-04); the app only reads them to shape the UI.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 122.

### CLI-APP-18 — Contract-held roles receive calldata
- old: R169 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-18 · superseded-by: —

**Rule.** Contract-held roles get calldata, not transactions.
**Why.** `rateAdmin` must be a contract, so an EIP-681 link sent from an EOA would revert.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 123.

### CLI-APP-19 — App dials only allowlisted origins
- old: R170 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-19 · superseded-by: —

**Why.** Network-learned URLs are attacker-chosen, and SDKs issue their own requests.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 124.

### CLI-APP-20 — Metrics are a dashboard link
- old: R171 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-20 · superseded-by: —

**Rule.** Metrics are a dashboard link
**Why.** `/metrics` is not CORS-enabled, and the operations design already provides the dashboard.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 125.

### CLI-APP-21 — Non-EVM DEX books after EVM
- old: APP:Q2, R172 · status: current · owner: yes · date: 2026-10-06 · normative: clients/app.md#CLI-APP-21 · superseded-by: —

**Why.** Only the EVM venue has a book.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 1030; [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 126.

### CLI-APP-22 — Chain identity and metadata verified
- old: R173, R173a, R173b, R173c · status: current · owner: no · date: 2026-10-07 · normative: clients/app.md#CLI-APP-22 · superseded-by: —

**Rule.** Chain identity and token metadata are verified, not trusted.
**Why.** A third-party RPC can forge every read.
**Cost if wrong.** One extra call per token and chain.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 127.

### CLI-APP-23 — approve only on outside tokens, spender allowlist
- old: R174 · status: current · owner: no · date: 2026-10-08 · normative: clients/app.md#CLI-APP-23 · superseded-by: —

Change: the app never offers `approve` on a SCaaS token; spenders on outside tokens are a listed DEX or a cross-checked wrapper. Source add: §2 A5, A6, §3 MG-7.

### CLI-APP-24 — Keys run in a dedicated worker
- old: R175 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-24 · superseded-by: —

**Why.** A compromised transitive dependency in any SDK chunk could otherwise read an unlocked seed.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 129.

### CLI-APP-25 — Account model follows UA spec
- old: R176 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-25 · superseded-by: —

**Rule.** The account model follows the Universal Account design.
**Why.** Owner ruling in the Universal Account design, with the backup predicate taken from the client signer rules.
**Cost if wrong.** two account kinds to explain.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 130.

### CLI-APP-26 — Token kinds decoded from versionOf
- old: R177 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-26 · superseded-by: —

**Rule.** Token kinds are decoded from `versionOf(token)`, values 0–7.
**Why.** The asset-suite and tender designs give wallets duties (regulated kinds view-only with a notice, managed markets unavailable) that a review found the app did not meet.
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 131.

### CLI-APP-27 — Untrusted text sanitised
- old: R179 · status: current · owner: no · date: 2026-10-06 · normative: clients/app.md#CLI-APP-27 · superseded-by: —

**Why.** With an open factory anyone can deploy "USDC".
**Source.** [history/specs/2026-10-06-scaas-app-design.md](history/specs/2026-10-06-scaas-app-design.md) line 133.

## 37. Integration — ERP

### INT-ERP-01 — 24 h cooling-off for new receiving wallets
- old: R22 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-01 · superseded-by: —

**Rule.** A newly approved receiving wallet is usable only after a cooling-off of 24 h
**Why.** Changing the receiving address is the number one fraud vector, and 24 hours is the window in which a second person can notice.
**Cost if wrong.** A new wallet is usable one day later.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 193.

### INT-ERP-02 — Custodial partner payer wallet needs license_ref
- old: R24 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-02 · superseded-by: —

**Rule.** A `custodial` paying wallet of a non-company partner requires `license_ref`.
**Why.** Holding the keys to someone else's money is a custody activity.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 195.

### INT-ERP-03 — Contract wallets: ERP defers to node simulation
- old: R27 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-03 · superseded-by: —

**Rule.** Contract wallets: the ERP defers to node simulation.
**Why.** A contract wallet's ERC-1271 signature cannot be checked by recovering a key, so the ERP stores it unverified and the node's simulation is the arbiter.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 200.; [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 706

### INT-ERP-04 — MandateWallet deployed outside the ERP
- old: R29 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-04 · superseded-by: —

**Rule.** A `MandateWallet` is deployed outside the ERP
**Why.** The ERP makes no RPC calls and holds no deploy key (NODE-STO-03), and a CREATE2 factory would force it to compute the initcode hash.
**Cost if wrong.** Onboarding a delegated wallet needs one operational step.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 204.

### INT-ERP-05 — Outbox call jobs immutable, operator read-only
- old: CR-PD-1(a/b) · status: current · owner: no · date: 2026-10-07 · normative: integration.md#INT-ERP-05 · superseded-by: —

**Rule.** Outbox `call` jobs are immutable and operators are read-only.
**Why.** The node had become a blind signer for ERP-built calldata: one operator session, or a stolen one, became an arbitrary transaction from a lane that holds fee income (dev deployments then also gave lanes admin roles; lane keys never hold roles, owner 2026-10-07, NODE-GEN-01).
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 247.

### INT-ERP-06 — Portal terms fee NONE, relayer restricted
- old: R10 · status: current · owner: no · date: 2026-10-05 · normative: integration.md#INT-ERP-06 · superseded-by: —

**Rule.** Self-service payment terms use fee `NONE` and `MODE_RESTRICT_RELAYER` to the company relayer, `fee = 0`, and a server-chosen validity (default 300 s).
**Why.** Restricting the relayer is the default for money flows and B2B fees are zero; it trades payer self-submission for front-run safety.
**Cost if wrong.** If the company relayer is down, users cannot submit themselves; signatures expire after 300 s, so payment is delayed, not lost.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 696.

### INT-ERP-07 — No FX: token currency equals order currency
- old: R17 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-07 · superseded-by: —

**Rule.** No FX: the token's currency equals the order currency.
**Why.** Quoting an exchange rate needs a price source.
**Cost if wrong.** Only tokens pegged to the order currency can be used.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 730.

### INT-ERP-08 — ERP-held env: custody dev-only, OpenSSL
- old: R50 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-08 · superseded-by: —

**Rule.** The ERP-held `env:` custody is dev-only and signs through OpenSSL.
**Why.** Pure-Python ECDSA is not constant-time, and even around OpenSSL the key sits in the ERP process memory, which is acceptable only for development; production uses a KMS or HSM adapter.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 523.

### INT-ERP-09 — Journal per (company, token); drift A and C
- old: R56 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-09 · superseded-by: —

**Rule.** One journal per (company, token); drift A and drift C.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 529.

### INT-ERP-10 — ERP family-aware addresses and signed ops
- old: R61 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-10 · superseded-by: —

**Rule.** The ERP is family-aware: chains carry a family, addresses are stored in the family's normalised form, and non-EVM payments are signed ops.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 534.

### INT-ERP-11 — ERP confidential requests, disclosure reconciliation, audit keys
- old: R34(erp) · status: current · owner: yes · date: 2026-10-03 · normative: integration.md#INT-ERP-11 · superseded-by: —

**Rule.** Confidential payment requests are reconciled from disclosed amounts, with an audit key per company.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 546.

### INT-ERP-12 — ERP mirrors markets and books DEX fees
- old: R35(erp) · status: current · owner: yes · date: 2026-10-08 · normative: integration.md#INT-ERP-12 · superseded-by: —

Change: no separate relayer fee; bookings from `LegSettled` (received, `dexFee`, relayer and treasury shares). Source add: §3 MG-8.3.
Change (2026-10-08): on the exchange path the record is `ExchangeLegSettled`; the company books `receivedFloor − dexFee + surplus` and shows the surplus as price improvement. Source add: `history/specs/2026-10-08-dex-exchange-design.md` §3 DS-8.

### INT-ERP-13 — ERP verifies ED25519 for long-zero payers
- old: R6-3 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-13 · superseded-by: —

**Rule.** Hedera long-zero payers sign with their native ED25519 key.
**Why.** A long-zero `0.0.N` address is an ED25519 account without an EVM alias, and the precompile's EC branch refuses long-zero addresses; the ERP can check the ed25519 signature locally but cannot tell without chain RPC whether the key belongs to the account, so node simulation through HIP-632 decides (INT-ERP-03).
**Source.** [history/specs/2026-10-03-net-hedera.md](history/specs/2026-10-03-net-hedera.md) line 293.

### INT-ERP-14 — ERP verifies G… ed25519 via OpenSSL
- old: R8-6 · status: current · owner: no · date: 2026-10-03 · normative: integration.md#INT-ERP-14 · superseded-by: —

**Rule.** The ERP verifies Stellar `G…` ed25519 through OpenSSL.
**Why.** `cryptography` is already a dependency of the custody code (INT-ERP-08) and replaces a pure-Python ed25519; a multisig account or a changed signer may make the master signature insufficient, which node simulation decides.
**Source.** [history/specs/2026-10-03-net-soroban.md](history/specs/2026-10-03-net-soroban.md) line 193.

### INT-ERP-15 — Bus scope is a per-tenant client setting
- old: R73 · status: current · owner: yes · date: 2026-10-06 · normative: integration.md#INT-ERP-15 · superseded-by: —

**Rule.** Bus scope is a per-tenant client setting delivered per job.
**Why.** Owner decision; the private window is 120 s rather than 300 s because with a 300 s token `validUntil` a 300 s window would never open.
**Cost if wrong.** A tenant that opts in exposes payer, payee, amount and timing to admitted peers of the matching class.
**Source.** [history/specs/2026-10-05-relayer-mesh-design.md](history/specs/2026-10-05-relayer-mesh-design.md) line 73.

### INT-ERP-16 — One node per company and chain
- old: R97(routing) · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-16 · superseded-by: —

**Why.** One lane journal per signer is the double-spend guard.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 120.

### INT-ERP-17 — Client kills locally only if never pushed
- old: R98(client) · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-17 · superseded-by: —

**Rule.** The client kills a job locally only if it was never pushed; otherwise it cancels on the node, by uid or by origin.
**Why.** The ERP's own veto went away with its journal; a compare-and-set on the node gives the same one-winner guarantee for our lanes, and a published job may already be landed by peers.
**Cost if wrong.** During a node outage a kill switch waits for the node, at most until the job's `valid_until`.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 121.

### INT-ERP-18 — Client push and sync cadence
- old: R101 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-18 · superseded-by: —

**Why.** A client that cannot hold a long poll still sees status within seconds.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 125.

### INT-ERP-19 — Client halts sync on store change
- old: R110(store-loss) · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-19 · superseded-by: —

**Rule.** The client halts sync on a store change.
**Why.** A recreated or rewound store has no record of signed jobs, and a blind re-push can re-sign intents whose old outer transactions are still in a mempool (funds stay safe, gas is lost).
**Cost if wrong.** One manual step after disk loss or restore.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 135.

### INT-ERP-20 — Client status latency bounds
- old: NI:I4 · status: open · owner: no · date: 2026-10-07 · normative: integration.md#INT-ERP-20 · superseded-by: —

**Rule.** INT-ERP-20 — *Open (default applied).* Payment status latency is ≤ ~10 s while jobs are live and ≤ 1 min otherwise, from the cadence of INT-ERP-18. Owner confirmation pending; the default stands.
**Why.** It follows from the sync cadence of INT-ERP-18: a fixed one-minute interval plus a trigger 10 s after each push while jobs are live, without any node-to-ERP call.
**Open.** Owner decision pending; the default stated in the normative text applies.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) line 1613.

### INT-ERP-21 — ERP Sui verify follows lesson L9
- old: R260 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-21 · superseded-by: —

**Rule.** ERP verifiers are three-valued and verify only with a key provably bound to the payer
**Why.** The ERP rejected Sui payments the chain accepts (test cases `a2_pay_sui`, `a3_pay_sui`); settlement is driven only by chain events, so `None` can never mark anything paid.
**Cost if wrong.** A valid signature from a non-member key queues one dead job per request, which needs portal access to the order.
**Source.** [history/specs/2026-10-06-signers-followups.md](history/specs/2026-10-06-signers-followups.md) line 188.

### INT-ERP-22 — Client holds salts; chain only commitments
- old: R195 · status: current · owner: yes · date: 2026-10-06 · normative: integration.md#INT-ERP-22 · superseded-by: —

**Rule.** The client holds every salt and key; the chain holds only commitments; the node holds neither salts nor personal data.
**Why.** Owner decision: the erasure duty then lands entirely in the system of record, where it can be met.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 215.

### INT-ERP-23 — Commitment and Merkle formats
- old: R196 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-23 · superseded-by: —

**Rule.** Commitment and Merkle formats:
**Why.** Domain tags and the leaf/node prefix stop cross-format and second-preimage confusion, and JCS reuses the canonical form of NODE-JOB-04.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 218.

### INT-ERP-24 — Per-subject DEK; erasure destroys it
- old: R197 · status: current · owner: no · date: 2026-10-07 · normative: integration.md#INT-ERP-24 · superseded-by: —

**Rule.** Salts and anchored payloads are encrypted under a per-subject data key (DEK); erasure destroys the DEK.
**Why.** Deleting rows alone leaves them in backups, and a plain hash of a sequential id is reversible; destroying the key makes every copy unreadable, backups included.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 224.

### INT-ERP-25 — References carry no personal data
- old: R198 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-25 · superseded-by: —

**Rule.** References carry no personal data and are not derived from business identifiers.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 234.

### INT-ERP-26 — Disclosure is opening a commitment
- old: R199 · status: current · owner: no · date: 2026-10-06 · normative: integration.md#INT-ERP-26 · superseded-by: —

**Rule.** Disclosure is opening a commitment.
**Source.** [history/specs/2026-10-06-tender-sponsorship-shredding.md](history/specs/2026-10-06-tender-sponsorship-shredding.md) line 238.

### INT-ERP-27 — Payment mode is configuration, not hard-coded
- old: UD:§1:payment-mode · status: current · owner: yes · date: 2026-08-30 · normative: integration.md#INT-ERP-27 · superseded-by: —

**Rule.** The payment mode is configuration, not code.
**Why.** Owner decision: deployments choose among several payment modes, so none is fixed in code.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 45.

<!-- example:odoo -->
## 38. Integration — example connector

### INT-ODOO-01 — Deploy job precedes pay via prerequisite
- old: RS4-6 · status: current · owner: no · date: 2026-10-06 · normative: integration-odoo-example.md#INT-ODOO-01 · superseded-by: —

**Rule.** The deploy job precedes payment through a prerequisite.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 28.

### INT-ODOO-02 — Owner-call nonce from mined jobs
- old: RS4-7 · status: current · owner: no · date: 2026-10-08 · normative: integration-odoo-example.md#INT-ODOO-02 · superseded-by: —

Change: `mtxExecuteAsOwner` name; the nonce and the predicted account address are per chain. Source add: §3 MG-3, MG-4.

### INT-ODOO-03 — First key registered with HMAC challenge
- old: RS4-12 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-03 · superseded-by: —

**Rule.** The first key registers in two steps with an HMAC challenge.
**Why.** A new key must prove possession and its origin before it is stored, which blocks a broken first key at registration; the HMAC challenge needs no server state, and the proof message is domain-separated so a server-chosen challenge is never the digest of a real operation.
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 51.

### INT-ODOO-04 — Deploy job only for payer own account
- old: RS4-16 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-04 · superseded-by: —

**Rule.** A deploy job is created only for the account of the paying partner itself
**Source.** [history/plans/2026-10-03-r3-passkey-seed.md](history/plans/2026-10-03-r3-passkey-seed.md) line 67.

### INT-ODOO-05 — Payment addon depends on account_payment
- old: R28 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-05 · superseded-by: —

**Rule.** `dms_blockchain_payment` depends on `account_payment`
**Why.** Auto-pay reads invoices and leaves reconciliation to `account_payment`.
**Cost if wrong.** The chain payment provider cannot be installed on a database without accounting.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 202.

### INT-ODOO-06 — No idempotency addon; natural UNIQUE keys
- old: R7 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-06 · superseded-by: —

**Rule.** No `bamboo_idempotency` dependency; dedup by UNIQUE natural keys.
**Why.** An optional addon must install on its own, and the idempotency addon adds a column to every table in the database.
**Cost if wrong.** It can be added later as a dependency; the natural keys stay correct.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 682.

### INT-ODOO-07 — Odoo addon split, no account addon
- old: R8, UD:§1:independent-addon · status: current · owner: yes · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-07 · superseded-by: —

**Rule.** The blockchain addons never depend on the DMS core; no accounting addon of their own.
**Why.** Owner ruling, repeated twice: the blockchain addons stay fully independent of the sales core; the standard `account_payment` already reconciles when a transaction is done, so a separate accounting addon has no user yet.
**Cost if wrong.** An accounting addon is added when FX or batch reconciliation is needed.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 685; [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 44.

### INT-ODOO-08 — Odoo verifies ECDSA signatures itself
- old: R13 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-08 · superseded-by: —

**Rule.** Odoo verifies ECDSA signatures itself
**Why.** It gives the user immediate feedback and is the third implementation of the digest, pinned by the shared test vectors; no external crypto library is a dependency of the ERP.
**Cost if wrong.** ERC-1271 contract-wallet signatures cannot be recovered and are left to the node's simulation, and a contract wallet that returns a 65-byte signature is refused.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 706.

### INT-ODOO-09 — Portal pay button calls model facade
- old: R14 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-09 · superseded-by: —

**Rule.** The portal pay button is plain JS calling the model facade
**Why.** All logic lives in model methods, and the standard payment form would need its own payment-form JavaScript.
**Cost if wrong.** Website checkout has no chain button yet.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 712.

### INT-ODOO-10 — Portal pays confirmed orders only
- old: R19 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-10 · superseded-by: —

**Rule.** The portal pays confirmed orders only
**Why.** When a transaction completes, the sale post-processing confirms a draft or sent quotation by itself, which would skip the sales approval and the credit check.
**Cost if wrong.** Buyers cannot prepay a quotation until a separate approval flow exists.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 723.

### INT-ODOO-11 — One receiving-company seam; platform company
- old: R57 · status: current · owner: no · date: 2026-10-03 · normative: integration-odoo-example.md#INT-ODOO-11 · superseded-by: —

**Rule.** One receiving-company seam and one "platform company".
**Why.** Provider, receiving-wallet and staff-note lookups each resolved the receiving company on their own; one method gives a future tier one place to change, and a test turns red if the resolved company stops matching the order's. "Host" already meant the record with no company in the territory model, so it was renamed.
**Source.** [history/specs/2026-10-03-blockchain-round3-design.md](history/specs/2026-10-03-blockchain-round3-design.md) line 530.

### INT-ODOO-12 — Late Matched after restore debits Odoo book
- old: RS5-20(odoo-book) · status: current · owner: no · date: 2026-10-07 · normative: integration-odoo-example.md#INT-ODOO-12 · superseded-by: —

**Rule.** A late `Matched` after a restore debits the Odoo-held book.
**Why.** Without it a trade restored as failed and later settled leaves phantom liquidity in the book.
**Source.** [history/specs/2026-10-03-dex-design.md](history/specs/2026-10-03-dex-design.md) line 449.

### INT-ODOO-13 — Odoo stores UAs as addresses
- old: R318 · status: current · owner: no · date: 2026-10-06 · normative: integration-odoo-example.md#INT-ODOO-13 · superseded-by: —

**Rule.** Odoo stores UAs as addresses of a new kind and never derives policy off chain.
**Why.** Same rule as every other address.
**Source.** [history/specs/2026-10-06-universal-account-design.md](history/specs/2026-10-06-universal-account-design.md) line 334.

### INT-ODOO-14 — Key registration is not the addon's job
- old: UD:§15:D14, canon:D14 · status: current · owner: yes · date: 2026-08-30 · normative: integration-odoo-example.md#INT-ODOO-14 · superseded-by: —

**Rule.** Key registration is not the addon's job.
**Why.** Owner ruling: the payment addon must not know what an outlet is, because that belongs to the sales system; the operator owns the policy of who gets a key, when, and who pays the registration gas.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 869.

### INT-ODOO-80 — Host company configuration parameter
- old: R23 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: INT-ODOO-11

It said: Host company configuration parameter; replaced by INT-ODOO-11.
**Source.** [history/specs/2026-10-03-blockchain-payments-addendum-wallets.md](history/specs/2026-10-03-blockchain-payments-addendum-wallets.md) line 194.

<!-- /example -->

## <a id="alias-index"></a>39. Alias index

<!-- BEGIN alias-index (generated by scripts/docs_check.py --write) -->
| Old id | New id(s) | Status |
|---|---|---|
| APP:Q1 | CLI-APP-07 | current |
| APP:Q2 | CLI-APP-21 | current |
| APP:Q3 | CLI-APP-16 | current |
| CR-ADW-1 | CTR-ACC-07 | current |
| CR-ADW-2 | NET-HED-03 | current |
| CR-ADW-3 | CLI-SGN-07 | current |
| CR-ADW-4 | CLI-SGN-08 | current |
| CR-PD-1 | NODE-JOB-01(c), INT-ERP-05(a/b) | current (split) |
| CR-PD-2 | NODE-IDX-01 | current |
| CR-PD-3 | NODE-GW-01 | current |
| CR-PD-4 | NODE-STO-01(node), CTR-MTX-04(issuer), NET-ALL-01(pruning) | current (split) |
| CR-PD-5 | NODE-LANE-02 | current |
| CR-PD-6 | NET-EVM-02 | current |
| CR-R3-1 | NET-ALL-04(grammar), NET-COS-03(cosmos-binding), NET-COS-81(cosmos-address) | current/superseded (split) |
| CR-R3-2 | NODE-IDX-01 | current |
| CR-R3-3 | NET-SOR-09(rule), NET-SOR-80(error-name) | current/superseded (split) |
| CR-R3-4 | NET-SOL-01 | current |
| CR-R3-5 | NET-SUI-02 | current |
| CR-R3-6 | NET-ALL-05 | current |
| CR-R3-7 | NET-TON-02 | current |
| CR-R3-8 | NODE-STO-01(node), NET-ALL-01(pruning) | current (split) |
| CR-R3-9 | NET-TON-03 | current |
| CR-R3-10 | NET-COS-04 | current |
| CR-R3-11 | CTR-GEN-02 | current |
| CR-WSF-1 | NET-ALL-23 | current |
| CR-WSF-2 | NET-HED-15 | current |
| MESH:I1 | NODE-MESH-04 | current |
| MESH:I2 | NODE-MESH-04 | current |
| MESH:I3 | NODE-MESH-04 | current |
| MESH:I4 | NODE-MESH-14 | current |
| NI:I1 | NODE-JOB-15 | open |
| NI:I2 | NODE-STO-08 | open |
| NI:I3 | NODE-JOB-16 | open |
| NI:I4 | INT-ERP-20 | open |
| NI:I5 | NODE-JOB-17 | open |
| NI:I6 | NODE-IDX-06 | current |
| NI:I7 | NODE-STO-09 | open |
| NI:I8 | NODE-JOB-18(tombstones), NODE-LANE-21(outer-tx), NODE-ADM-09(last-admin) | open (split) |
| R1 | ARCH-POS-80 | superseded |
| R2 | CTR-MTX-01(op), CTR-MTX-80(cost) | current/superseded (split) |
| R3 | CTR-DEX-80 | superseded |
| R4 | CTR-TOK-80 | superseded |
| R5 | CTR-MTX-02 | current |
| R6 | NODE-JOB-80 | superseded |
| R6-1 | NET-HED-08 | current |
| R6-2 | NET-HED-09 | current |
| R6-3 | INT-ERP-13 | current |
| R6-4 | NET-HED-10 | current |
| R6-5 | NET-HED-80 | superseded |
| R6-6 | NET-HED-11 | current |
| R6-7 | NET-HED-05 | current |
| R6-8 | NET-HED-06 | current |
| R6-9 | NET-HED-07 | current |
| R6-10 | NET-HED-12 | current |
| R6-11 | NET-HED-13 | current |
| R7 | INT-ODOO-06 | current |
| R8 | INT-ODOO-07 | current |
| R8-1 | NET-SOR-02 | current |
| R8-2 | NET-SOR-03 | current |
| R8-3 | NET-SOR-05 | current |
| R8-4 | NET-SOR-06 | current |
| R8-5 | NET-SOR-07 | current |
| R8-6 | INT-ERP-14 | current |
| R8-7 | NET-SOR-08 | current |
| R8-8 | NET-SOR-04 | current |
| R8-9 | NET-SOR-09 | current |
| R8-10 | NET-SOR-10 | current |
| R8-11 | NET-SOR-11 | current |
| R8-12 | NET-SOR-12 | current |
| R8-13 | NET-SOR-13 | current |
| R8-14 | NET-SOR-14 | current |
| R8-15 | NET-SOR-15 | current |
| R9 | CTR-MTX-03(lane), CTR-MTX-81(pay-once) | current/superseded (split) |
| R9-1 | NET-COS-80 | superseded |
| R9-2 | NET-COS-05 | current |
| R9-3 | NET-COS-06 | current |
| R9-4 | NET-COS-07 | current |
| R9-5 | NET-COS-08 | current |
| R9-6 | NET-COS-09 | current |
| R9-7 | NET-COS-10 | current |
| R9-8 | NET-COS-11 | current |
| R10 | INT-ERP-06 | current |
| R10-1 | NET-TON-04 | current |
| R10-2 | NET-TON-05 | current |
| R10-3 | NET-TON-81 | superseded |
| R10-4 | NET-TON-06 | current |
| R10-5 | NET-TON-07 | current |
| R10-6 | NET-TON-08 | current |
| R10-7 | NET-TON-09 | current |
| R10-8 | NET-TON-10 | current |
| R10-9 | NET-TON-11 | current |
| R10-10 | NET-TON-12 | current |
| R10-11 | NET-TON-13 | current |
| R10-12 | NET-TON-14 | current |
| R10-13 | NET-TON-15 | current |
| R10-14 | NET-TON-16(node), NET-TON-82(contract) | current/superseded (split) |
| R10-15 | NET-TON-17 | current |
| R10-16 | NET-TON-18 | current |
| R10-17 | NET-TON-19(cancel/fees), NET-TON-83(bounced) | current/superseded (split) |
| R11 | NODE-IDX-02(gate), NODE-IDX-80(quorum) | current/superseded (split) |
| R12 | NODE-IDX-03 | current |
| R13 | INT-ODOO-08 | current |
| R14 | INT-ODOO-09 | current |
| R15 | NODE-LANE-03 | current |
| R16 | NODE-STO-80 | superseded |
| R17 | INT-ERP-07 | current |
| R18 | NODE-LANE-04 | current |
| R19 | INT-ODOO-10 | current |
| R20 | NODE-STO-03 | current |
| R21 | CLI-SGN-06 | current |
| R22 | INT-ERP-01 | current |
| R23 | INT-ODOO-80 | superseded |
| R24 | INT-ERP-02 | current |
| R25 | CTR-ACC-06 | current |
| R26 | CTR-TOK-01 | current |
| R27 | INT-ERP-03 | current |
| R28 | INT-ODOO-05 | current |
| R29 | INT-ERP-04 | current |
| R30 | NET-ALL-02 | current |
| R31 | CTR-ACC-08(account), CLI-SGN-09(client) | current (split) |
| R32 | CLI-SGN-11(vault), CLI-SGN-85(path), CLI-SGN-86(scrypt) | current/superseded (split) |
| R33 | CLI-SGN-10(keys), CLI-SGN-83(deferred), CLI-SGN-84(pop) | current/superseded (split) |
| R34 | CTR-ZTH-01(scope), CTR-ZTH-80(params), CTR-ZTH-81(registry), INT-ERP-11(erp) | current/superseded (split) |
| R35 | NODE-DEX-01(book), CTR-DEX-01(contract), INT-ERP-12(erp) | current (split) |
| R36 | NET-ALL-80 | unused |
| R37 | NET-ALL-80 | unused |
| R38 | NET-ALL-80 | unused |
| R39 | NET-ALL-80 | unused |
| R40 | NET-ALL-80 | unused |
| R41 | NET-ALL-80 | unused |
| R42 | NET-ALL-80 | unused |
| R43 | NET-ALL-80 | unused |
| R44 | NET-ALL-80 | unused |
| R45 | NET-ALL-80 | unused |
| R46 | NET-ALL-80 | unused |
| R47 | NET-ALL-80 | unused |
| R48 | NET-ALL-80 | unused |
| R49 | NET-ALL-80 | unused |
| R50 | INT-ERP-08 | current |
| R51 | NODE-OPS-01 | current |
| R52 | CTR-GEN-01 | current |
| R53 | NODE-STO-02 | current |
| R54 | NODE-GW-02 | current |
| R55 | NODE-LANE-05 | current |
| R56 | INT-ERP-09 | current |
| R57 | INT-ODOO-11 | current |
| R58 | NODE-LANE-06(adapter), NODE-LANE-80(family-enum) | current/superseded (split) |
| R59 | NODE-LANE-07 | current |
| R60 | NODE-LANE-08 | current |
| R61 | INT-ERP-10 | current |
| R62 | NET-ALL-03 | current |
| R63 | NET-HED-04 | current |
| R64 | NET-SUI-01 | current |
| R65 | NET-SOR-01 | current |
| R66 | NET-COS-02 | current |
| R67 | NET-TON-01(core), NET-TON-80(bindkey) | current/superseded (split) |
| R68 | NODE-MESH-80 | unused |
| R69 | NODE-MESH-80 | unused |
| R70 | NODE-MESH-01 | current |
| R71 | NODE-MESH-02(seq), NODE-MESH-81(store) | current/superseded (split) |
| R72 | NODE-MESH-03 | current |
| R73 | INT-ERP-15 | current |
| R74 | NODE-MESH-04 | current |
| R75 | NODE-MESH-05 | current |
| R76 | NODE-MESH-06 | current |
| R77 | NODE-MESH-07 | current |
| R78 | NODE-MESH-08 | current |
| R79 | NODE-MESH-82 | superseded |
| R80 | NODE-LANE-09 | current |
| R81 | NODE-MESH-09 | current |
| R82 | NODE-MESH-10 | current |
| R83 | NODE-MESH-11 | current |
| R84 | NODE-LANE-10 | current |
| R85 | NODE-MESH-12 | current |
| R86 | NODE-MESH-13 | current |
| R87 | ARCH-POS-05 | current |
| R88 | NODE-STO-04 | current |
| R89 | NODE-JOB-02 | current |
| R90 | NODE-JOB-03 | current |
| R91 | NODE-JOB-04 | current |
| R92 | NODE-JOB-05 | current |
| R93 | NODE-IDX-04 | current |
| R94 | NODE-IDX-05 | current |
| R95 | NODE-STO-03 | current |
| R96 | NODE-STO-05 | current |
| R97 | NODE-JOB-06(claim), INT-ERP-16(routing) | current (split) |
| R98 | NODE-JOB-07(node), INT-ERP-17(client) | current (split) |
| R99 | NODE-MESH-15 | current |
| R100 | NODE-LANE-10 | current |
| R101 | INT-ERP-18 | current |
| R102 | NODE-JOB-08 | current |
| R103 | NODE-JOB-09 | current |
| R104 | NODE-JOB-10 | current |
| R105 | NODE-DEX-14 | current |
| R106 | NODE-ADM-02 | current |
| R106a | NODE-ADM-03(oidc), NODE-ADM-80(ring) | current/superseded (split) |
| R107 | NODE-ADM-04 | current |
| R108 | NODE-ADM-05 | current |
| R109 | NODE-ADM-06 | current |
| R110 | NODE-ADM-07(audit), INT-ERP-19(store-loss) | current (split) |
| R111 | NODE-STO-06 | current |
| R112 | NODE-GSP-01 | current |
| R113 | NODE-GSP-02 | current |
| R114 | NODE-GSP-03 | current |
| R115 | NODE-GSP-04 | current |
| R116 | NODE-GSP-05 | current |
| R117 | NODE-GSP-06 | current |
| R118 | NODE-GSP-07 | current |
| R119 | NODE-GSP-08 | current |
| R120 | NODE-GSP-09 | current |
| R121 | NODE-GSP-10 | current |
| R122 | NODE-GSP-11 | current |
| R123 | NODE-GSP-12 | current |
| R124 | NODE-DEX-12 | current |
| R125 | NODE-GSP-13 | current |
| R126 | NODE-GSP-14 | current |
| R127 | NODE-ADM-01(admin), NODE-OPS-02(metrics) | current (split) |
| R128 | NODE-DEX-13 | current |
| R129 | CTR-TOK-02 | superseded |
| R130 | CTR-TOK-03 | current |
| R131 | CTR-MTX-07 | current |
| R132 | CTR-MTX-08 | current |
| R133 | CTR-TOK-04 | current |
| R134 | CTR-TOK-05 | current |
| R135 | CTR-TOK-06 | current |
| R136 | CTR-TOK-07 | current |
| R137 | CTR-TOK-08 | current |
| R138 | CTR-MTX-09 | current |
| R139 | CTR-MTX-10 | current |
| R140 | CTR-MTX-11 | current |
| R141 | CTR-TOK-09 | current |
| R142 | CTR-TOK-10 | current |
| R143 | CTR-TOK-11 | current |
| R144 | NET-HED-14 | current |
| R145 | NET-ALL-19 | current |
| R146 | CTR-TOK-12 | superseded |
| R147 | CTR-TOK-13 | current |
| R148 | NODE-LANE-22(node), CTR-MTX-12(contract) | current (split) |
| R149 | CTR-TOK-14 | superseded |
| R150 | CLI-APP-01 | current |
| R151 | CLI-APP-02 | current |
| R152 | CLI-APP-03 | current |
| R153 | CLI-APP-04 | current |
| R154 | CLI-APP-05 | current |
| R155 | CLI-APP-06 | current |
| R156 | CLI-APP-07 | current |
| R157 | CLI-APP-08 | current |
| R158 | CLI-APP-09 | current |
| R159 | NODE-GW-05(gateway), NODE-ADM-10(serving) | current (split) |
| R160 | NODE-ADM-11 | current |
| R161 | CLI-APP-10 | current |
| R162 | CLI-APP-11 | current |
| R163 | CLI-APP-12 | current |
| R164 | CLI-APP-13 | current |
| R165 | CLI-APP-14 | current |
| R166 | CLI-APP-15 | current |
| R167 | CLI-APP-16 | current |
| R168 | CLI-APP-17 | current |
| R169 | CLI-APP-18 | current |
| R170 | CLI-APP-19 | current |
| R171 | CLI-APP-20 | current |
| R172 | CLI-APP-21 | current |
| R173 | CLI-APP-22 | current |
| R173a | CLI-APP-22 | current |
| R173b | CLI-APP-22 | current |
| R173c | CLI-APP-22 | current |
| R174 | CLI-APP-23 | current |
| R175 | CLI-APP-24 | current |
| R176 | CLI-APP-25 | current |
| R177 | CLI-APP-26 | current |
| R178 | NODE-GW-06 | current |
| R179 | CLI-APP-27 | current |
| R180 | CTR-TND-01 | current |
| R181 | CTR-TND-02 | current |
| R182 | CTR-TND-03 | current |
| R183 | CTR-TND-04 | current |
| R184 | CTR-TND-05 | current |
| R185 | CTR-TND-06 | current |
| R186 | CTR-TND-07 | current |
| R187 | CTR-TND-08 | current |
| R188 | NET-ALL-18 | current |
| R189 | NODE-SPN-01 | current |
| R190 | NODE-SPN-02 | current |
| R191 | NODE-SPN-03 | current |
| R192 | CTR-MTX-05 | current |
| R193 | NODE-MESH-17(node), CTR-MTX-06(shape) | current (split) |
| R194 | NODE-SPN-04 | current |
| R195 | INT-ERP-22 | current |
| R196 | INT-ERP-23 | current |
| R197 | INT-ERP-24 | current |
| R198 | INT-ERP-25 | current |
| R199 | INT-ERP-26 | current |
| R200 | CTR-AS-01 | superseded |
| R201 | CTR-AS-02 | current |
| R202 | CTR-AS-03 | current |
| R203 | CTR-AS-04 | current |
| R204 | CTR-AS-05 | current |
| R205 | CTR-AS-06 | current |
| R206 | CTR-AS-07 | current |
| R207 | CTR-AS-08 | current |
| R208 | CTR-AS-09 | current |
| R209 | CTR-AS-10 | current |
| R210 | CTR-AS-11 | current |
| R211 | CTR-AS-12 | current |
| R212 | CTR-AS-13 | current |
| R213 | CTR-AS-14 | current |
| R214 | NODE-DEX-11(node), CTR-DEX-12(contract) | current (split) |
| R215 | NET-ALL-17 | current |
| R216 | CTR-AS-15 | current |
| R217 | CTR-AS-16 | current |
| R230 | NODE-OPS-03 | current |
| R231 | NODE-OPS-04 | current |
| R232 | NODE-OPS-05 | current |
| R233 | NODE-OPS-06 | current |
| R234 | NODE-OPS-07 | current |
| R235 | NODE-OPS-08 | current |
| R236 | NODE-OPS-09 | current |
| R237 | NODE-OPS-10 | current |
| R238 | NODE-OPS-11 | current |
| R239 | NODE-RUN-01 | current |
| R240 | NODE-RUN-02 | current |
| R241 | NODE-RUN-03 | current |
| R242 | NODE-OPS-12 | current |
| R243 | NODE-RUN-04 | current |
| R244 | NODE-OPS-13 | current |
| R245 | NODE-RUN-05 | current |
| R246 | NODE-OPS-14 | current |
| R247 | NODE-OPS-15 | current |
| R250 | CLI-SGN-12 | current |
| R251 | CLI-SGN-13 | current |
| R252 | CLI-SGN-14 | current |
| R253 | CLI-SGN-15 | current |
| R254 | CLI-SGN-16 | current |
| R255 | CLI-SGN-17 | current |
| R256 | CLI-SGN-18 | current |
| R257 | CLI-SGN-19 | current |
| R258 | CLI-SGN-20 | current |
| R259 | CLI-SGN-21 | current |
| R260 | INT-ERP-21 | current |
| R261 | NET-SUI-16 | current |
| R262 | NET-SUI-17 | current |
| R263 | CLI-SGN-22 | current |
| R264 | CLI-SGN-23 | current |
| R265 | CLI-SGN-24 | current |
| R266 | CLI-SGN-26 | current |
| R267 | CLI-SGN-27 | current |
| R268 | CLI-SGN-28 | current |
| R269 | CLI-SGN-25 | current |
| R270 | CTR-PQZ-01 | current |
| R271 | CTR-PQZ-02 | current |
| R272 | CTR-PQZ-03 | current |
| R273 | CTR-PQZ-04 | current |
| R274 | CTR-PQZ-05 | current |
| R275 | CTR-PQZ-06 | current |
| R276 | CTR-PQZ-07 | current |
| R277 | CTR-PQZ-08 | current |
| R278 | CTR-PQZ-09 | current |
| R279 | CTR-PQZ-10 | current |
| R280 | CTR-PQZ-11 | current |
| R281 | CTR-PQZ-12 | current |
| R282 | CTR-PQZ-13 | current |
| R283 | CTR-PQZ-14 | current |
| R284 | CTR-PQZ-15 | current |
| R285 | CTR-PQZ-16 | current |
| R286 | CTR-PQZ-17 | current |
| R287 | CTR-PQZ-18 | current |
| R288 | CTR-PQZ-19 | current |
| R289 | CTR-PQZ-20 | current |
| R290 | CTR-UA-02 | current |
| R291 | CTR-UA-03 | current |
| R292 | CTR-UA-04 | current |
| R293 | CTR-UA-05 | current |
| R294 | CTR-UA-06 | current |
| R295 | CTR-UA-07 | current |
| R296 | CTR-UA-08 | current |
| R297 | CTR-UA-09 | current |
| R298 | CTR-UA-10(2-3-4), CLI-SGN-29(1) | current (split) |
| R299 | CTR-UA-11 | current |
| R300 | CLI-SGN-30 | current |
| R301 | CTR-UA-12 | current |
| R302 | CTR-UA-13 | current |
| R303 | CTR-UA-14 | current |
| R304 | CTR-UA-15 | current |
| R305 | CTR-UA-16 | current |
| R306 | CTR-UA-17 | current |
| R307 | CTR-ACC-09 | current |
| R308 | CTR-UA-18 | current |
| R309 | CTR-UA-19 | current |
| R310 | CTR-UA-20 | current |
| R311 | CTR-UA-21 | current |
| R312 | CTR-UA-22 | current |
| R313 | CTR-UA-23 | current |
| R314 | NET-ALL-20 | current |
| R315 | NET-ALL-21 | current |
| R316 | NODE-MESH-18 | current |
| R317 | NODE-GSP-15 | current |
| R318 | INT-ODOO-13 | current |
| R320 | NODE-GW-03 | current |
| R321 | NODE-LANE-11 | current |
| R322 | NODE-ADM-08 | current |
| R323 | NODE-JOB-11 | current |
| R324 | NODE-JOB-12 | current |
| R325 | NODE-JOB-13 | current |
| R326 | NODE-LANE-12 | current |
| R327 | NODE-JOB-14 | current |
| R328 | NODE-GW-04 | current |
| R330 | NET-ALL-22 | current |
| R331 | CTR-UA-24 | current |
| R340 | NODE-LANE-13 | current |
| R341 | NODE-LANE-14 | current |
| R342 | NODE-LANE-15 | current |
| R343 | NODE-MESH-16 | current |
| R344 | NODE-LANE-16 | current |
| R345 | NODE-LANE-17 | current |
| R346 | NODE-LANE-18 | current |
| R347 | NODE-LANE-19 | current |
| R348 | NODE-STO-07 | current |
| R349 | NODE-LANE-20 | current |
| RS2-1 | CTR-ZTH-02 | current |
| RS2-2 | CTR-ZTH-03 | current |
| RS2-3 | CTR-ZTH-04 | current |
| RS2-4 | CTR-ZTH-05 | current |
| RS2-5 | CTR-ZTH-06 | current |
| RS2-6 | CTR-ZTH-07 | current |
| RS2-7 | CTR-ZTH-08 | current |
| RS2-8 | CTR-ZTH-09 | current |
| RS2-9 | CTR-UA-13 | current |
| RS2-10 | CTR-ZTH-82 | superseded |
| RS2-11 | CTR-ZTH-10 | superseded |
| RS2-12 | CTR-ZTH-11 | superseded |
| RS2-13 | CTR-ZTH-12 | current |
| RS2-14 | CTR-ZTH-13 | current |
| RS2-15 | CTR-ZTH-14 | current |
| RS2-16 | CTR-ZTH-15 | current |
| RS2-17 | CTR-ZTH-16 | current |
| RS2-18 | CTR-UA-01 | current |
| RS2-19 | CTR-ZTH-17 | current |
| RS2-20 | CTR-ZTH-20 | current |
| RS2-21 | CTR-ZTH-21 | current |
| RS2-22 | CTR-ZTH-83 | superseded |
| RS2-23 | CTR-ZTH-22 | current |
| RS2-24 | CTR-ZTH-23 | current |
| RS2-25 | CTR-ZTH-24 | current |
| RS2-26 | CTR-ZTH-25 | current |
| RS4-1 | CTR-ACC-01 | current |
| RS4-2 | NET-ALL-04 | current |
| RS4-3 | CTR-ACC-02 | current |
| RS4-4 | CTR-ACC-03 | current |
| RS4-5 | CTR-ACC-04 | current |
| RS4-6 | INT-ODOO-01 | current |
| RS4-7 | INT-ODOO-02 | current |
| RS4-8 | CLI-SGN-02(vault), CLI-SGN-80(scrypt) | current/superseded (split) |
| RS4-9 | CLI-SGN-03(keys), CLI-SGN-81(pop) | current/superseded (split) |
| RS4-10 | CTR-ACC-05 | current |
| RS4-11 | CLI-SGN-04 | current |
| RS4-12 | INT-ODOO-03 | current |
| RS4-13 | CLI-SGN-05 | current |
| RS4-14 | CLI-SGN-21 | current |
| RS4-15 | CLI-SGN-82 | superseded |
| RS4-16 | INT-ODOO-04 | current |
| RS5-1 | CTR-DEX-03 | current |
| RS5-2 | NODE-DEX-80 | superseded |
| RS5-3 | CTR-DEX-04 | current |
| RS5-4 | CTR-DEX-05 | current |
| RS5-5 | NODE-DEX-03 | current |
| RS5-6 | CTR-DEX-06(relayer-fee), CTR-DEX-81(dex-fee) | superseded (split) |
| RS5-7 | CTR-DEX-07 | superseded |
| RS5-8 | NODE-DEX-04 | current |
| RS5-9 | NODE-DEX-81 | superseded |
| RS5-10 | CTR-DEX-02 | current |
| RS5-11 | NODE-DEX-82 | superseded |
| RS5-12 | NODE-DEX-05 | current |
| RS5-13 | NODE-DEX-02 | current |
| RS5-14 | NODE-DEX-06(node), CTR-DEX-08(contract) | current (split) |
| RS5-15 | CTR-DEX-09(non-evm), NET-SOR-10(soroban) | current (split) |
| RS5-16 | NODE-DEX-07 | current |
| RS5-17 | NODE-DEX-08 | current |
| RS5-18 | NODE-DEX-09 | current |
| RS5-19 | CTR-DEX-10 | current |
| RS5-20 | NODE-DEX-10(r105), INT-ODOO-12(odoo-book) | current (split) |
| RS5-21 | CTR-DEX-11 | current |
| RS7-1 | NET-SUI-03 | current |
| RS7-2 | NET-SUI-04 | current |
| RS7-3 | NET-SUI-05 | current |
| RS7-4 | NET-SUI-06 | current |
| RS7-5 | NET-SUI-07 | current |
| RS7-6 | NET-SUI-08 | current |
| RS7-7 | NET-SUI-10 | current |
| RS7-8 | NET-SUI-09 | current |
| RS7-9 | NET-SUI-10 | current |
| RS7-10 | NET-SUI-11 | current |
| RS7-11 | NET-SUI-12 | current |
| RS7-12 | NET-SUI-13 | current |
| RS7-13 | NET-SUI-14 | current |
| RS7-14 | NET-SUI-15 | current |
| RS11-1 | NET-APT-04 | current |
| RS11-2 | NET-APT-05 | current |
| RS11-3 | NET-APT-03 | current |
| RS11-4 | NET-APT-06 | current |
| RS11-5 | NET-APT-07 | current |
| RS11-6 | NET-APT-08 | current |
| RS11-7 | NET-APT-09 | current |
| RS11-8 | NET-APT-02(table), NET-APT-81(oog) | current/superseded (split) |
| RS11-9 | NET-APT-10 | current |
| RS11-10 | NET-APT-11 | current |
| RS11-11 | NET-APT-12 | current |
| RS11-12 | NET-APT-13 | current |
| RS11-13 | NET-APT-01(deploy), NET-APT-80(upgrade) | current/superseded (split) |
| RS11-14 | NET-APT-14 | current |
| RS11-15 | NET-APT-15 | current |
| RS11-16 | NET-APT-16 | current |
| RS11-17 | NET-APT-17 | current |
| RS11-18 | NET-APT-18 | current |
| RS11-19 | NET-APT-19 | current |
| RS11-20 | NET-APT-20 | current |
| RS11-21 | NET-APT-21 | current |
| RS11-22 | NET-APT-22 | current |
| RS11-23 | NET-APT-23 | current |
| RS11-24 | NET-APT-24 | current |
| RS11-25 | NET-APT-25 | current |
| RS11-26 | NET-APT-26 | current |
| RS12-1 | NET-SOL-03 | current |
| RS12-2 | NET-SOL-04 | current |
| RS12-3 | NET-SOL-05 | current |
| RS12-4 | NET-SOL-06 | current |
| RS12-4a | NET-SOL-27 | current |
| RS12-5 | NET-SOL-07 | current |
| RS12-6 | NET-SOL-08 | current |
| RS12-7 | NET-SOL-09 | current |
| RS12-8 | NET-SOL-10 | current |
| RS12-9 | NET-SOL-11(formats), NET-SOL-81(text) | current/superseded (split) |
| RS12-9a | NET-SOL-30 | current |
| RS12-10 | NET-SOL-12 | current |
| RS12-11 | NET-SOL-13 | current |
| RS12-11a | NET-SOL-28 | current |
| RS12-12 | NET-SOL-14 | current |
| RS12-12a | NET-SOL-29 | current |
| RS12-13 | NET-SOL-15 | current |
| RS12-14 | NET-SOL-16 | current |
| RS12-15 | NET-SOL-17 | current |
| RS12-16 | NET-SOL-02(table), NET-SOL-80(cu) | current/superseded (split) |
| RS12-16a | NET-SOL-31 | current |
| RS12-17 | NET-SOL-18 | current |
| RS12-18 | NET-SOL-19 | current |
| RS12-18a | NET-SOL-32 | current |
| RS12-19 | NET-SOL-20 | current |
| RS12-20 | NET-SOL-21 | current |
| RS12-21 | NET-SOL-22 | current |
| RS12-22 | NET-SOL-23 | current |
| RS12-23 | NET-SOL-24 | current |
| RS12-24 | NET-SOL-25 | current |
| RS12-25 | NET-SOL-26 | current |
| RS-NV64-1 | CTR-ZTH-18 | current |
| RS-NV64-2 | CTR-ZTH-19 | current |
| S4F:Q1 | CLI-SGN-30 | current |
| SCaaS:N1 | NODE-GEN-01 | current |
| SCaaS:N2 | NODE-GEN-02 | current |
| SCaaS:N3 | NODE-GEN-03 | current |
| SCaaS:N4 | NODE-GEN-04 | current |
| SCaaS:N5 | NODE-GEN-05 | current |
| SCaaS:N6 | NODE-GEN-06 | current |
| SCaaS:N7 | NODE-GEN-07 | current |
| SCaaS:N8 | NODE-GEN-08 | current |
| SCaaS:N9 | NODE-GEN-09 | current |
| SCaaS:N10 | NODE-GEN-10 | current |
| SCaaS:N11 | NODE-GEN-11 | current |
| SCaaS:N12 | NODE-GEN-12 | current |
| SCaaS:N13 | NODE-GEN-13 | current |
| SCaaS:N14 | NODE-GEN-14 | current |
| SCaaS:N15 | NODE-GEN-15 | current |
| SCaaS:N16 | NODE-GEN-16 | current |
| UA:Q1 | CTR-UA-13 | current |
| UA:Q2 | CTR-UA-16 | current |
| UA:Q3 | CTR-UA-08 | current |
| UA:Q4 | CTR-UA-14 | current |
| UA:Q5 | CTR-UA-14 | current |
| UA:Q6 | CLI-SGN-30 | current |
| UA:Q7 | CTR-UA-14 | current |
| UA:Q8 | CTR-UA-25 | current |
| UA:Q9 | CTR-UA-23 | current |
| UA:Q10 | CTR-UA-07 | current |
| UA:Q11 | CTR-UA-19 | current |
| UA:Q12 | NET-ALL-20 | current |
| UA:Q13 | NET-ALL-21 | current |
| UA:Q14 | CTR-UA-21 | current |
| UD:§1:custody | NODE-LANE-03 | current |
| UD:§1:eip1776 | NET-ALL-02 | current |
| UD:§1:first-chain | NET-EVM-80 | superseded |
| UD:§1:independent-addon | INT-ODOO-07 | current |
| UD:§1:legal | ARCH-POS-81 | superseded |
| UD:§1:payment-mode | INT-ERP-27 | current |
| UD:§1:private-chain | CTR-ZTH-27 | open |
| UD:§1:smartcontracts-tree | CTR-GEN-03 | current |
| UD:§1:use-cases | ARCH-POS-06 | current |
| UD:§2 | CTR-ZTH-04 | current |
| UD:§3 | CTR-ZTH-07 | current |
| UD:§3.1 | CTR-MTX-13 | current |
| UD:§3.2 | CTR-ZTH-07 | current |
| UD:§3.3 | CTR-ZTH-28 | open |
| UD:§3.4 | CTR-ZTH-07 | current |
| UD:§3.4b | NODE-MESH-19 | current |
| UD:§3.5 | CTR-MTX-82 | superseded |
| UD:§4 | CTR-MTX-14 | current |
| UD:§5 | CTR-MTX-83 | superseded |
| UD:§6 | NODE-GSP-01 | current |
| UD:§10 | CTR-ZTH-08 | current |
| UD:§10:fee-layers | CTR-ZTH-05 | current |
| UD:§11:fee-denominator | CTR-MTX-13 | current |
| UD:§11:struct-variants | CTR-MTX-84 | superseded |
| UD:§12 | CTR-ZTH-01 | current |
| UD:§12.2 | CTR-ZTH-01 | current |
| UD:§12.3 | CTR-ZTH-01 | current |
| UD:§12.4 | CTR-ZTH-01 | current |
| UD:§12.7.3 | CTR-ZTH-84 | superseded |
| UD:§12.7.4 | CTR-ZTH-85 | superseded |
| UD:§12.7.5 | CTR-ZTH-29 | current |
| UD:§12.7.6 | CTR-ZTH-01 | current |
| UD:§13.1 | NODE-OPS-15 | current |
| UD:§13.2 | CTR-ZTH-30 | current |
| UD:§13.3 | CTR-ZTH-86 | superseded |
| UD:§14 | CTR-ZTH-87 | superseded |
| UD:§14:consequences | CTR-ZTH-88 | superseded |
| UD:§15:D1 | CTR-ZTH-89 | superseded |
| UD:§15:D2 | CTR-ZTH-01 | current |
| UD:§15:D7 | CLI-SGN-87 | superseded |
| UD:§15:D12 | ARCH-POS-06 | current |
| UD:§15:D14 | INT-ODOO-14 | current |
| UD:§15:D17 | CTR-ZTH-90 | superseded |
| UD:§16 | NET-EVM-03 | current |
| UD:§16:gas-limit | NET-EVM-81 | superseded |
| UD:§16:roadmap | NET-EVM-03 | current |
| UD:§16:single-signer | NET-EVM-04 | current |
| UD:§18 | NET-EVM-82 | superseded |
| UD:§19 | CTR-ZTH-91 | superseded |
| UD:§19:curve-param | CTR-ZTH-01 | current |
| UD:§19:reopen-conditions | CTR-ZTH-93 | superseded |
| UD:§19:unlocked | CTR-ZTH-92 | superseded |
| UD:§20 | CTR-TOK-15 | current |
| UD:§20.1 | CTR-ZTH-01 | current |
| UD:§20.2 | CTR-GEN-02 | current |
| UD:§20.3 | CTR-TOK-16 | current |
| UD:§20.4 | CTR-TOK-17 | current |
| UD:§20.5 | CTR-GEN-04 | current |
| UD:§20.6 | CTR-TOK-18 | current |
| UD:§21 | NODE-MESH-83 | superseded |
| UD:§21.1 | NODE-MESH-84 | superseded |
| UD:§21.2 | NODE-GEN-80 | superseded |
| UD:§21.3 | NODE-MESH-11 | current |
| UD:§21.4 | NODE-MESH-20 | current |
| UD:§21.5 | NET-ALL-02 | current |
| UD:§22 | NODE-MESH-85 | superseded |
| UD:§22.1 | NODE-LANE-09 | current |
| UD:§22.2 | NODE-GW-80 | superseded |
| UD:§22.3 | NODE-GSP-07 | current |
| UD:§22.4 | NODE-MESH-21 | current |
| UD:§22.5 | NODE-MESH-04 | current |
| UD:§22.6 | NODE-MESH-13 | current |
| UD:§22.7 | NODE-MESH-86 | superseded |
| UD:§22.8 | NODE-LANE-09 | current |
| UD:§22.9 | NODE-JOB-81 | superseded |
| UD:§22.10 | NODE-MESH-22 | open |
| UD:§22.10.1 | NODE-MESH-23 | open |
| UD:§22.10.2 | NODE-MESH-87 | superseded |
| UD:§22.10.3 | NODE-GSP-16 | open |
| UD:§22.10.4 | NODE-MESH-88 | superseded |
| UD:§23 | NODE-GEN-17 | current |
| UD:§23.1 | NODE-STO-04 | current |
| UD:§23.2 | NODE-GEN-01 | current |
| UD:§23.3 | NODE-GEN-17 | current |
| UD:§23.4 | NODE-SEC-80 | superseded |
| UD:§23.5 | NODE-LANE-03 | current |
| UD:§23.6 | NODE-GEN-81 | superseded |
| UD:§23.7 | NODE-STO-04 | current |
| UD:§23.8 | NODE-GEN-82 | superseded |
| UD:§23.10 | CLI-SGN-31 | current |
| UD:§23.11 | CLI-SGN-32 | current |
| UD:§24 | CTR-MTX-15 | current |
| UD:§24.1 | CTR-MTX-15 | current |
| UD:§24.2 | CTR-MTX-16 | current |
| UD:§24.3 | CTR-MTX-16 | current |
| UD:§25 | CTR-ZTH-01 | current |
| UD:§25:fallback | CTR-ZTH-31 | open |
| UD:§25:flipped | CTR-ZTH-01 | current |
| UD:§25:ruling | CTR-ZTH-01 | current |
| ZL:D1 | CTR-ZTH-18 | current |
| ZL:D2 | CTR-ZTH-18 | current |
| ZL:D3 | CTR-ZTH-26 | current |
| ZL:D4 | CTR-ZTH-19 | current |
| ZL:D5 | CTR-ZTH-19 | current |
| ZL:D6 | CTR-ZTH-14 | current |
| canon:D1 | CTR-ZTH-01 | current |
| canon:D2 | CTR-ZTH-01 | current |
| canon:D7 | CLI-SGN-32 | current |
| canon:D12 | ARCH-POS-06 | current |
| canon:D14 | INT-ODOO-14 | current |
| canon:D17 | CTR-ZTH-01 | current |
| net-aptos:L1 | NET-ALL-06 | current |
| net-aptos:L2 | NET-ALL-07 | current |
| net-aptos:L3 | NET-ALL-08 | current |
| net-aptos:L4 | NET-ALL-09 | current |
| net-aptos:L5 | NET-ALL-10 | current |
| net-aptos:L6 | NET-ALL-11 | current |
| net-aptos:L7 | NET-ALL-12 | current |
| net-aptos:L8 | NET-ALL-13 | current |
| net-aptos:L9 | NET-ALL-14 | current |
| net-aptos:L10 | NET-ALL-15 | current |
| net-solana:L1 | NET-ALL-06 | current |
| net-solana:L2 | NET-ALL-07 | current |
| net-solana:L3 | NET-ALL-08 | current |
| net-solana:L4 | NET-ALL-09 | current |
| net-solana:L5 | NET-ALL-10 | current |
| net-solana:L6 | NET-ALL-11 | current |
| net-solana:L7 | NET-ALL-12 | current |
| net-solana:L8 | NET-ALL-13 | current |
| net-solana:L9 | NET-ALL-14 | current |
| net-solana:L10 | NET-ALL-15 | current |
| net-solana:L11 | NET-ALL-16 | current |
| net-solana:L12 | NET-SOL-04 | current |
| owner:2026-10-06:families | ARCH-POS-02 | current |
| owner:2026-10-06:market-neutral | ARCH-POS-04 | current |
| owner:2026-10-06:naming | ARCH-POS-03 | current |
| owner:2026-10-06:node-independent | ARCH-POS-05 | current |
| owner:2026-10-06:precedence | ARCH-POS-01 | current |
| owner:2026-10-07:chain-7622 | NET-EVM-02 | current |
| owner:2026-10-07:immutable | CTR-GEN-02 | current |
| owner:2026-10-07:pqz-metatx | CTR-PQZ-15 | current |
| reorg:Q1 | NODE-JOB-19 | current |
| reorg:Q2 | ARCH-POS-07 | current |
| reorg:Q3 | NET-TON-02 | current |
| reorg:Q4 | NET-TON-03 | current |
| reorg:Q5 | CTR-ZTH-32(curve), CTR-ZTH-33(dev-chain) | open (split) |
| reorg:Q6 | NODE-MESH-24 | open |
| reorg:Q7 | NODE-IDX-07 | open |
| reorg:Q8 | NODE-OPS-16 | current |
| reorg:Q9 | ARCH-POS-08 | current |
| reorg:Q10 | ARCH-POS-07 | current |
| reorg:Q11 | ARCH-POS-09 | current |
| reorg:Q12 | NODE-GEN-18 | current |
| reorg:Q13 | ARCH-POS-07 | current |
| reorg:Q14 | ARCH-POS-07 | current |
| req:blockchain.md:celo-fee-currency | NET-EVM-01 | open |
| req:blockchain.md:hcs-anchoring | NET-HED-01 | open |
| req:blockchain.md:hedera-schedule | NET-HED-02 | open |
| req:blockchain.md:ibc | NET-COS-01 | open |
| req:blockchain.md:session-keys | CLI-SGN-01 | open |
| req:blockchain.md:usd-velocity | NODE-LANE-01 | open |
<!-- END alias-index -->
