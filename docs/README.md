# SCaaS documentation

SCaaS (SmartContract as a Service): the smart contracts are the API services; `scaas-node` is the open relayer and
indexer anyone can run in front of them. Start with [SCaaS-v2.md](SCaaS-v2.md) (product introduction) and
[architecture.md](architecture.md) (system overview). Neither is normative: the rules live in the component docs
below, and every rule's id, aliases and rationale are in [decisions.md](decisions.md).

## Reading order

0. [../README.md](../README.md) — the idea from the ground up: a smart chain as infrastructure, contracts as API
   services, meta-transactions and fee models, open relayers, Zether and PQ Zether.
1. [SCaaS-v2.md](SCaaS-v2.md) — what SCaaS is, who it is for, how to start.
2. [architecture.md](architecture.md) — positioning, authority model, service model, components, trust model,
   families, economics, data protection, glossary.
3. The component docs for your role (map below). Integrators: [integration.md](integration.md). Node operators:
   [node/README.md](node/README.md) then [node/runbooks.md](node/runbooks.md). Contract reviewers:
   [contracts/README.md](contracts/README.md). Wallet and app developers: [clients/](clients/signers-clientkeys.md).
4. [decisions.md](decisions.md) — why each rule holds, and the old-id alias index.

## Map

| Area | Docs |
|---|---|
| Overview | [SCaaS-v2.md](SCaaS-v2.md) · [architecture.md](architecture.md) · [decisions.md](decisions.md) (register, `ARCH-POS` system-wide positions) |
| Node (`NODE-*`) | [README](node/README.md) (roles, listeners, invariants) · [store](node/store.md) · [job API](node/job-api.md) · [submit lanes](node/submit-lanes.md) · [indexer and feeds](node/indexer-feeds.md) · [gateway](node/gateway.md) · [admin and auth](node/admin-auth.md) · [sponsorship](node/sponsorship.md) · [DEX venue](node/dex-venue.md) · [mesh](node/mesh.md) · [gossip](node/gossip.md) · [operations](node/ops.md) · [runbooks](node/runbooks.md) · [threat model](node/threat-model.md) |
| Contracts (`CTR-*`) | [README](contracts/README.md) (immutability, admin powers, production gates, build pins) · [meta-transactions](contracts/metatx.md) · [token wrappers](contracts/token-wrappers.md) · [accounts](contracts/accounts.md) (native, Universal Account, smart account) · [mandates](contracts/mandates.md) · [DEX](contracts/dex.md) · [tender](contracts/tender.md) · [asset suite](contracts/asset-suite.md) · [Zether](contracts/zether.md) · [PQ Zether](contracts/pq-zether.md) |
| Networks (`NET-*`) | [README](networks/README.md) (common model, signing domains, passkeys, head-of-line, availability) · [EVM](networks/evm.md) · [Hedera](networks/hedera.md) · [Cosmos](networks/cosmos.md) · [Soroban](networks/soroban.md) · [Sui](networks/sui.md) · [Aptos](networks/aptos.md) · [Solana](networks/solana.md) · [TON](networks/ton.md) |
| Clients (`CLI-*`) | [signers and clientkeys](clients/signers-clientkeys.md) · [app (console + dApp)](clients/app.md) |
| Integration (`INT-*`) | [integration.md](integration.md) (any ERP or back office) · [integration-odoo-example.md](integration-odoo-example.md) (one worked ERP connector, example only) |
| History (read-only) | [history/README.md](history/README.md) — frozen designs, the original requirements note and its [trace](history/blockchain-trace.md), the old-id inventory |
| Research (background) | `research/` — background and rationale only, never normative |

## Precedence

When two sources disagree, the higher one wins ([ARCH-POS-01](decisions.md#ARCH-POS-01)):

1. **Owner rulings** — entries of [decisions.md](decisions.md) with `owner: yes`. They override everything below,
   including code that has not caught up.
2. **Component docs** — `node/`, `contracts/`, `networks/`, `clients/`, `integration.md`, each for its own subject.
3. **Code** — for pinned byte formats only (typehashes, KAT and conformance vectors). A difference between code and an
   owner ruling is a bug in the code.
4. **History** — `history/` (frozen designs and their review dispositions).
5. **Research** — `research/`, background only.

[SCaaS-v2.md](SCaaS-v2.md), [architecture.md](architecture.md) and this page define no rules.

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
