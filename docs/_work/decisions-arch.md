# Register fragment: architecture and register policy (ARCH-POS)

## Architecture and register policy

These entries define themselves (`normative: decisions.md`): they are system-wide positions, and
[architecture.md](architecture.md) and [README.md](README.md) only explain them.

<a id="ARCH-POS-01"></a>
### ARCH-POS-01 — Source precedence: owner rulings first
- old: owner:2026-10-06:precedence · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-01 · superseded-by: —

**Rule.** When two sources disagree, the higher one wins: (1) owner rulings, i.e. entries of this register with
`owner: yes`; (2) the component docs under `node/`, `contracts/`, `networks/`, `clients/` and `integration.md`, each
for its own subject; (3) code, but only for pinned byte formats (typehashes, KAT and conformance vectors); (4)
`history/`; (5) `research/`, which is background only. [architecture.md](architecture.md), [SCaaS-v2.md](SCaaS-v2.md)
and [README.md](README.md) are not normative. A difference between code and an owner ruling is a bug in the code, not
in the ruling.
**Why.** The earlier system specification ranked itself above the component specs while restating them, and the
copies drifted; the specs disagreed with each other in several places. One register of rulings plus one normative home
per rule removes the second copy. Owner rulings override code that has not caught up, so a ruling is never "undone" by
an implementation shortcut.
**Cost if wrong.** A reader who trusts the overview instead of the component doc applies a stale rule; the checker
keeps ids out of the overview so there is nothing to trust there.
**Source.** [history/SCaaS-2026-10-07.md](history/SCaaS-2026-10-07.md) line 33; [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) §4 K14.

<a id="ARCH-POS-02"></a>
### ARCH-POS-02 — Family taxonomy
- old: owner:2026-10-06:families · status: current · owner: yes · date: 2026-10-06 · normative: decisions.md#ARCH-POS-02 · superseded-by: —

**Rule.** SCaaS supports six families; a family is a group of chains that share one contract code base and one node
adapter: `evm` (EVM chains, including Hedera), `cosmos` (CosmWasm), `soroban` (Stellar and Pi Network), `move` (Aptos
and Sui), `ton` and `solana`. A chain is keyed `chain_key = family:network`. This replaces the earlier list of
"Six ecosystems" (EVM, Hedera, TON, Sui, Soroban, Cosmos).
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
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) §3.1, §8 (Q2, Q10, Q13, Q14).

<a id="ARCH-POS-08"></a>
### ARCH-POS-08 — Market-specific research stays private
- old: reorg:Q9 · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-08 · superseded-by: —

**Rule.** The research note on one market's law and the large raw tool-output file stay in `research/` while the
repository is private and are removed before any public release. Neither ever enters the current docs.
**Why.** The market-neutral rule ([ARCH-POS-04](#ARCH-POS-04)) keeps market law out of the product; the files remain
useful background for the owner meanwhile.
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) §8 Q9.

<a id="ARCH-POS-09"></a>
### ARCH-POS-09 — Work plans stay in history and the TODO list
- old: reorg:Q11 · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-09 · superseded-by: —

**Rule.** Implementation work items (their scope, gates and dependencies) stay in the frozen design specs under
`history/` and are tracked in the repository TODO list; there is no roadmap document under `docs/`, and the current
docs carry no work-item ids.
**Why.** Work plans change weekly; normative docs that cite them go stale with every plan change.
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) §4 K22, §8 Q11.

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
**Source.** [history/blockchain.md](history/blockchain.md) lines 38–48, 56–74; [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) §2.5.

<a id="ARCH-POS-11"></a>
### ARCH-POS-11 — Documentation language and structure
- old: — · status: current · owner: yes · date: 2026-10-07 · normative: decisions.md#ARCH-POS-11 · superseded-by: —

**Rule.** The docs are English throughout and self-contained. Rulings carry new component ids with the old ids as
aliases in this register. The old system specification is frozen as `history/SCaaS-2026-10-07.md` for reference;
[SCaaS-v2.md](SCaaS-v2.md) is a short, non-normative product introduction. Line-budget overruns of the Zether, PQ
Zether, network pages and the node overview are accepted.
**Why.** One language and one id scheme for a product used worldwide; the old ids stay resolvable for code comments
(`python3 scripts/docs_check.py resolve <id>`).
**Source.** [superpowers/plans/2026-10-07-docs-reorg.md](superpowers/plans/2026-10-07-docs-reorg.md) §8 (owner answers 2026-10-07).

### ARCH-POS-80 — EVM-only, META-only first scope
- old: R1 · status: superseded · owner: no · date: 2026-10-03 · normative: — · superseded-by: NET-ALL-02, CTR-ZTH-01, CTR-ZTH-18, CTR-ZTH-19, CTR-UA-02, CTR-UA-16, CTR-UA-22, INT-ERP-11, ARCH-POS-02

It said: the first build covers EVM chains and the plain meta-tx token only; confidential amounts, non-EVM families
and the mesh are out of scope.
**Source.** [history/specs/2026-10-03-blockchain-payments-design.md](history/specs/2026-10-03-blockchain-payments-design.md) line 660.

### ARCH-POS-81 — Legal deferred to a separate chapter
- old: UD:§1:legal · status: superseded · owner: yes · date: 2026-08-30 · normative: — · superseded-by: ARCH-POS-04

It said: legal questions are deferred to a separate chapter that does not block the buildable parts.
**Source.** [research/_USER-DECISIONS.md](research/_USER-DECISIONS.md) line 47.
