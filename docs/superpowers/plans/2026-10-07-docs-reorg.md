# Plan: SCaaS docs reorganization (and scaas-node module layout)

> **Owner 2026-10-07 — SCaaS.md:** the current `docs/SCaaS.md` is kept as history for the owner's later
> reference (`history/SCaaS-2026-10-07.md`, unchanged). A new **`docs/SCaaS-v2.md`** is a short product
> introduction page only (what SCaaS is, who it is for, what it offers, how to start; links to README /
> architecture.md); it is not normative and defines no ids. `architecture.md` stays as planned.


> **Phase 0 executed 2026-10-07** (tag `docs-pre-reorg`; commits `08250aa`…`3d0afb5`). Outputs: `docs/history/`,
> `docs/research/`, `docs/history/ruling-ids.txt` (746 ids), `docs/_work/{id-map.tsv,facts/,section-map.tsv}` —
> see `docs/_work/README.md`. Deviations from the text below: (1) "current docs" also exclude `research/` and
> `_work/` (C3–C9 would fire on frozen research; C10 covers research); (2) 539 numbered ids, not ≈ 513: the §0 table
> sums to 523, plus the 16 unused R36–R49/R68–R69 registered as `unused`; net-aptos lessons are L1–L10 (= net-solana
> L1–L10, merged); (3) new ids are numbered in **old definition order** (file, line), not new-file reading order —
> stable, never renumbered; (4) ARCH-POS and register-policy entries are self-defining (`normative: decisions.md`),
> since C8 bans ids in architecture.md; (5) owner answers of §8 are aliases `reorg:Q1…Q14`; the six §2.5/Q13
> requirements are `req:blockchain.md:*` (`open`); (6) fact ledger has a 7th column `hint`, a `history:H` class
> ("plan says H — confirm"), and `;`-joined multi-targets; (7) small commits, pushed (owner); (8) Solidity/Tact/
> Solana comment paths left for Phase 3 (a `.sol` comment edit changes the bytecode metadata hash).

> **Phases 1–3 executed 2026-10-07.** Phase 1 `a492fa9`…`4cc227c` (component docs + register fragments, every fact
> placed); Phase 2 `2e9bf4e`…`e13be84` (README, architecture, SCaaS-v2, merged `decisions.md` + alias index, history
> README and blockchain trace; `docs/_work/` → `docs/history/reorg/`); owner rulings `9513731` (lane keys hold no roles,
> NODE-LANE-24 `max_inflight`, decisions.md budget); Phase 3 (§5) in the following commit — the `.sol`/`.tact`/Solana
> comment paths were checked against pinned codehashes first. This plan stays here (decisions.md cites it) until
> Phase 4 closes, then moves to `history/plans/` with its links repointed.

**Date:** 2026-10-07 · **Status:** Phases 0–3 executed, Phase 4 (reviews) open · **Owner-approved target structure:** see §1.
**Scope:** `scaas/docs/**` (rewrite), `scaas/scripts/docs_check.py` (new), references outside docs (§5),
`scaas-node` module/crate layout (§7, plan only). Nothing below has been done yet. Read-only survey basis:
`scaas` HEAD `d4c296d` (chainId 7622 sweep), docs as of 2026-10-07.

**Owner requirements folded in (2026-10-07):**

- **R-A No information loss.** Every normative statement, number, constant, formula, table, test-vector reference,
  threat/attack note and owner ruling in the old docs lands in a new doc, or is marked superseded with its
  replacement. Verified mechanically (§6.3 fact ledger) and by per-component reviewer diffing (§6.4).
- **R-B Self-contained product docs.** SCaaS is a standalone product. New docs never rely on the SRS drafts,
  bamboo-dms, DMS/NPP, Vietnamese-market context, Odoo-internal names, research "canon §Cx"/"UD §x" citations,
  or our session names (round 3, S4F, spec B, A2, PD, NI, R3D, stream ids …). Odoo appears only as **one example
  ERP** in a fenced example section of `integration.md`. Old names survive only as aliases in `decisions.md` and in
  `history/`. Enforced by a lint (§3.4 check C9).
- **R-C scaas-node restructuring** planned alongside (§7): survey, target module/crate layout, migration order that
  keeps tests green, alignment with the pending code streams.

---

## 0. Inventory (what exists today)

| Set | Files | Lines | Language | Notes |
|---|---|---|---|---|
| Component specs `docs/superpowers/specs/2026-*.md` | 26 | 20 751 | 11 VI / 15 EN | each a stack of revs with review/disposition/superseded tables inline |
| `docs/SCaaS.md` | 1 | 2 695 | EN | system spec; duplicates component specs and drifts (§4 lists the drifts it records itself) |
| `docs/integration.md` | 1 | 833 | EN | ERP guide; duplicates NI job-API rules and the call table |
| `blockchain-research/round3-wallet-signing-formats.md` | 1 | 428 | EN | research note that carries rulings CR-WSF-1/2 |
| `blockchain-research/` (rest) | 25 | ≈ 33 000 (2.9 MB) | VI/EN | research, CANON, `_USER-DECISIONS`, `_GROK-CODE`, critiques, legal-VN note |
| `docs/superpowers/plans/` | 19 (+ this) | ≈ 6 500 | VI | implementation plans for BUILT work; `r3-passkey-seed.md` **defines rulings RS4-1…16** |
| `docs/superpowers/HANDOFF-blockchain.md` | 1 | 56 | VI | owner/ops gates O1–O11, Zether gates Z1–Z6 |
| `docs/reviews/specs/` | — | 2.7 MB | — | review files, **git-ignored** (local only) |
| `docs/blockchain.md` | 1 | 641 | VI | the owner's original requirements note (moved from `scaas/blockchain.md` 2026-10-07): TOKEN list, SRS group 6.21, chapter 10 (10.1–10.5.3), 14.2.8, appendix D; corrected in places by research (`_MANIFESTS.md`, 16 "Where blockchain.md is wrong / under-specified" blocks) |

**Ruling-id inventory** (extracted with the definition regex of §3.4; 513 numbered ids + extras):

| Scheme | Ids | Defined in |
|---|---|---|
| `R1–R20`, `CR-PD-1…6` | 26 | payments design (PD) |
| `R21–R29`, `CR-ADW-1…4` | 13 | wallets addendum (ADW) |
| `R30–R35`, `R50–R67`, `CR-R3-1…11` | 35 | round-3 design (R3D); R36–R49 reserved, never used |
| `RS2-1…26`, `RS-NV64-1…2`, Zether-limits `D1–D6` | 34 | Zether design / limits |
| `RS4-1…16` | 16 | **plan** `2026-10-03-r3-passkey-seed.md` (cited by code) |
| `RS5-1…21` | 21 | DEX design |
| `R6-1…11` | 11 | net-hedera |
| `RS7-1…14` | 14 | net-sui |
| `R8-1…15` | 15 | net-soroban (R8-1, -2, -6, -7, -8 defined in prose/headings, not in a table) |
| `R9-1…8` | 8 | net-cosmos |
| `R10-1…17` | 17 | net-ton |
| `RS11-1…26` | 26 | net-aptos |
| `RS12-1…25` + `-4a, -9a, -11a, -12a, -16a, -18a` | 31 | net-solana |
| `R70–R86` | 17 | relayer mesh (MESH); R68–R69 explicitly unused |
| `R87–R111`, `R106a`, `R320–R328`, `R340–R349` | 45 | node independence (NI) |
| `R112–R128` | 17 | mesh gossip amendment (A2) |
| `R129–R149` | 21 | token wrappers v2 (TW2) |
| `R150–R179`, `R173a–c` | 33 | app (APP) |
| `R180–R199` | 20 | tender/sponsorship/shredding (TSS) |
| `R200–R217` | 18 | asset suite (AS) |
| `R230–R247` | 18 | operations (OPS) |
| `R250–R269` | 20 | signers follow-ups (S4F) |
| `R270–R289` | 20 | PQ Zether (PQZ) |
| `R290–R318`, `R330–R331` | 31 | Universal Account (UA) |
| `CR-WSF-1…2` | 2 | wallet signing formats (WSF) |
| **Extras (qualified aliases)** | ≈ 60 | SCaaS node invariants `SCaaS:N1–N16`; design lessons `net-aptos:L1–L8`, `net-solana:L1–L12`; MESH owner-confirmed interpretations `MESH:I1–I4`; NI interpretations-to-confirm `NI:I1–I8`; UA owner confirmations `UA:Q1–Q14`; APP `APP:Q1–Q3`; S4F `S4F:Q1`; unnumbered owner decisions `owner:2026-10-06:{families,naming,market-neutral,precedence,node-independent}`, `owner:2026-10-07:{chain-7622,pqz-metatx,immutable}` |

Ambiguities that make renumbering worth it: `R6` (PD) vs `R6-1` (Hedera); `R10` vs `R10-1`; review finding ids
(`H1`, `M3`, `L4`) reused as lesson ids (`L8`) and as stream-like names (`N1` app stream vs `N1` node invariant);
RS*n* = session stream *n* for some networks, R*n*-*m* for others.

Code cites old ids ≈ 900 times (`smartcontracts/` 256 in 99 files, `scaas-node/` 260 in 48, `clientkeys/` 25,
`zether-prover/` 21, bamboo-dms `dms_blockchain*` 111) and spec sections (`§`) ≈ 400 times in 165 files. §5 keeps
all of them valid without code edits.

---

## 1. Final file tree

Target sizes are soft budgets (review flags > 1.3×). Prefixes are the ruling-id prefixes defined in that file (§3).
Total current-state text ≈ 15 500 lines + `decisions.md` ≈ 3 000, against 24 700 today.

```
docs/
  README.md                      map, reading order, precedence, how ids/aliases/history work            ~100
  SCaaS-v2.md                    short product introduction page (owner 2026-10-07); not normative, no ids  ~150
  architecture.md                what SCaaS is, trust model, positioning, profiles, glossary; links only  ~450   ARCH-POS
  decisions.md                   ruling register + generated alias index (old id → new id)              ~3000
  integration.md                 generic ERP/back-office guide; Odoo as one fenced example              ~950    INT-ERP, INT-ODOO
  node/
    README.md                    node overview: roles, listeners, invariants, module map                 ~250    NODE-GEN
    store.md                     store schema, backends, owner lock/fencing, config authority, node.toml  ~600    NODE-STO
    job-api.md                   job API: auth, routes, idempotency, cancel, call table, errors, legacy pull ~550  NODE-JOB
    submit-lanes.md              adapters, signer, lane keys, journal, nonce plan, breaker, simulation,
                                 cost/grief metering, batching, unwrap jobs                               ~550    NODE-LANE
    indexer-feeds.md             finality gates, event-set quorum, event normalization, /v1/jobs, /v1/events ~400  NODE-IDX
    gateway.md                   door A: /v1/metatx, /v1/ops, /v1/gateway, UA routes, intake, CORS, errors ~300   NODE-GW
    admin-auth.md                admin API, built-in users, OIDC, roles, CLI, audit, app serving          ~400    NODE-ADM
    sponsorship.md               gas sponsorship policies, budgets, SponsorshipPool (planned)             ~250    NODE-SPN
    dex-venue.md                 order book persistence, matching, intake, /v1/dex, book gossip, managed markets ~400 NODE-DEX
    mesh.md                      intent envelope, pull bus, acceptance policy, exclusivity, private profile ~650  NODE-MESH
    gossip.md                    libp2p gossip, PQ transport, validation, numbers, hints, announce        ~600    NODE-GSP
    ops.md                       SLOs, metrics, alerts, traces, logs, FinOps, capacity                    ~550    NODE-OPS
    runbooks.md                  incident runbooks, backup/restore/DR, RACI, production gates             ~500    NODE-RUN
    threat-model.md              node threats T*, mesh/gossip threats, controls                           ~250    NODE-SEC
  contracts/
    README.md                    common rules: immutable at deploy, deploy gate, admin-power list,
                                 UNAUDITED gates, build/CI pins, availability matrix                      ~250    CTR-GEN
    metatx.md                    meta-tx v1/v2/v3: struct, typehash, mode, nonces, pipeline, FeePolicy,
                                 named functions, entryRef/pay lane, pay-once horizon, receiver-pays     ~650    CTR-MTX
    token-wrappers.md            tiers, rates, multi-underlying, factory v1/v2, allowance lockdown        ~650    CTR-TOK
    accounts-mandates.md         SubjectAccount (+factory), passkeys on chain, guardians, MandateWallet   ~350    CTR-ACC
    dex.md                       OrderBookDex, legacy MetaTxDex, managed-market venue contract            ~400    CTR-DEX
    tender.md                    sealed-bid tender                                                        ~400    CTR-TND
    asset-suite.md               regulated module, vesting, distributions, corporate actions, templates   ~750    CTR-AS
    zether.md                    classical Zether, byte-exact; limits; decryption bound                   ~700    CTR-ZTH
    pq-zether.md                 post-quantum Zether on private/PoA chains                                ~950    CTR-PQZ
    universal-account.md         UA ids, kinds, registry, verifiers, credentials, migration               ~950    CTR-UA
  networks/
    README.md                    common model for every family: R30 path, WebAuthn grammar, chain identity,
                                 key lifecycle, head-of-line table, design lessons, per-family matrices   ~400    NET-ALL
    evm.md                       EVM chains (Gnosis, Celo, private 7622), EIP-7702, deploy profiles       ~200    NET-EVM
    hedera.md  cosmos.md  soroban.md  sui.md  aptos.md  solana.md  ton.md                ~250/220/230/300/500/550/280  NET-HED/COS/SOR/SUI/APT/SOL/TON
  clients/
    app.md                       console + dApp                                                           ~750    CLI-APP
    signers-clientkeys.md        wallets standards, seed vault, passkey/seed signers per family, backup
                                 switch, role keys, connectors, signing review                           ~650    CLI-SGN
  history/
    README.md                    read-only rule; abbreviation register (PD, NI, …→ file, rev, old ids);
                                 where review dispositions live; SRS-delta table (owner reference)          ~120
    specs/                       the 26 dated specs, unchanged (git mv)
    SCaaS-2026-10-07.md          old system spec, unchanged
    integration-2026-10-07.md    old integration guide, unchanged
    specs/round3-wallet-signing-formats.md   the WSF note (normative content mined into networks/*), unchanged
    plans/                       superpowers/plans/*.md unchanged (this plan moves here when done)
    HANDOFF-blockchain.md        unchanged
    blockchain.md                the original requirements note, unchanged (git mv from docs/blockchain.md)
    blockchain-trace.md          generated: every requirement item of blockchain.md → new doc anchor and
                                 status (BUILT / SPECIFIED / PLANNED / open / rejected / out of scope), §2.5
    ruling-ids.txt               frozen old-id inventory (generated once, §3.4)
  research/                      blockchain-research/ moved here unchanged (except the WSF note): background and
                                 rationale only; README.md (new, ~30 lines) carries the non-normative banner and the
                                 file list; every file gets a one-line banner header inserted at the top (the only edit)
  reviews/specs/                 unchanged, git-ignored
  superpowers/                   stays for future design drafts (process §3.5); empty after the move
```

Why the additions to the owner's list: `node/README`, `contracts/README`, `networks/README` hold the rules every
file of the folder shares (otherwise they would be duplicated or orphaned); `node/dex-venue`, `node/runbooks`,
`node/threat-model` and `contracts/accounts-mandates` split material that has no home in the listed files.
`integration.md` stays one file; if it passes 1 200 lines, the Odoo example moves to `integration-odoo-example.md`.

**Writing rules for every new doc** (enforced in review and partly by §3.4):

1. Current normative state only. No deltas, rev history, review tables, "superseded by" prose, stream plans.
2. Each ruling is defined once: `<a id="NODE-JOB-03"></a>**NODE-JOB-03** — <rule>`. Why/cost-if-wrong go to
   `decisions.md`. Other docs link `[NODE-JOB-03](../node/job-api.md#NODE-JOB-03)`; they never restate it.
3. Status per section: **BUILT** / **SPECIFIED** / **PLANNED** (SCaaS convention kept). Where BUILT code differs
   from the target (legacy pull path, Odoo-held DEX book, Zether-only registry, mesh policy from the ERP), a short
   "Transitional (BUILT)" subsection says what runs today and what removes it, without stream ids.
4. English, self-contained (R-B): no SRS, no session names, no Odoo names outside the integration example, no
   `canon §`/`UD §`, no stream ids, no market-specific law or currency. Terms an outsider needs are in the glossary.
5. Byte formats, tables, constants, DDL, vectors move verbatim (translated captions only).

---

## 2. Source map

Notation: target `node/x#§` = file and section heading in the new doc; **H** = history only (stays readable in
`history/`); **D** = rationale/owner flag/supersession goes to `decisions.md`; **T** = live work item goes to
`scaas/TODO.md`; **X** = executed by this rewrite (an "amendments needed"/"doc corrections" list: the rewrite
applies it, the list itself is H). Every `##` section is listed; `###` subsections are listed where they split.
"Review log", "Claude review disposition", "Revision history / Lịch sử bản", "Code streams / Luồng code / Streams /
Work breakdown" and "Superseded …" sections are **H + D** everywhere and are listed once per file as "admin".

### 2.1 `SCaaS.md` (→ history/SCaaS-2026-10-07.md)

| § | Section | Target |
|---|---|---|
| header, status tags | — | README (status-tag convention) |
| 0.1 | Precedence | README#precedence (rewritten: owner rulings in decisions.md > component docs > code byte formats > history) |
| 0.1 | Component spec register | history/README (abbreviation register) |
| 0.1 | "Superseded positions" table | D (one supersession per row) |
| 0.1 | Naming note | architecture#glossary (names) |
| 0.2 | Glossary | architecture#glossary |
| 1.1–1.4 | Positioning, authority model, what SCaaS is not, deployment profiles | architecture#positioning, #authority-model, #profiles |
| 2.1–2.3 | Service model (anchor/land, four-condition test, saga vs atomic) | architecture#service-model |
| 3.1–3.5 | Components, node roles, topology, data flows, trust boundaries | architecture#components, #trust-model; node/README#roles |
| 4.1–4.5 | Token hierarchy, tiers, factory, allowance lockdown, permissionless vs controlled | contracts/token-wrappers |
| 4.6, 4.8, 4.9 | Vesting, equity/bonds on managed DEX, asset suite | contracts/asset-suite; contracts/dex#managed-markets |
| 4.7 | Mandates | contracts/accounts-mandates#mandatewallet |
| 5.1–5.8 | Meta-tx layer | contracts/metatx |
| 5.9 | Payer flexibility | contracts/metatx#payers; node/sponsorship |
| 6.1 | Node invariants N1–N16 | node/README#invariants (NODE-GEN) |
| 6.2 | Job lifecycle | node/job-api#states |
| 6.3 | Nonce journal and restart | node/submit-lanes#journal |
| 6.4, 6.5 | Gas breakers, simulation gate | node/submit-lanes |
| 6.6 | Finality gates per family | node/indexer-feeds#finality; per-family values → networks/* |
| 6.7 | Mesh | node/mesh (summary only; H for text already in MESH) |
| 6.8 | Transports and PQ KEX | node/gossip#transport |
| 6.9 | Economics | architecture#economics (short) + node/mesh#rewards |
| 6.10 | Call table, Door A intake, idempotent report | node/job-api#call-table (single home); node/gateway#intake; node/submit-lanes#legacy-pull |
| 7 intro, 7.1–7.7 | Families | networks/README, networks/<family> |
| 7.8 | Event normalization | node/indexer-feeds#event-normalization |
| 8.1–8.11 | Zether | contracts/zether (8.6 → contracts/universal-account#legacy-registry) |
| 8.12 | PQ Zether summary | H (duplicate of PQZ) |
| 9.1 | Custody axes | architecture#trust-model |
| 9.2 | SigningPolicyService (PLANNED) | clients/signers-clientkeys#signing-policy |
| 9.3 | Passkeys | contracts/accounts-mandates#passkeys; clients/signers-clientkeys#passkeys |
| 9.4 | Subject accounts, guardians, recovery, backup | contracts/accounts-mandates; clients/signers-clientkeys#backup-switch |
| 9.5 | Seed vault | clients/signers-clientkeys#vault |
| 9.6 | Relayer lane keys | node/submit-lanes#lane-keys |
| 9.7 | Threshold/aggregate signatures | contracts/universal-account#kinds |
| 9.8 | UA summary | H (duplicate of UA) |
| 10.x | Tender summary | H (duplicate of TSS §A) except 10.3 invariants → contracts/tender#invariants if missing there |
| 11.1 | Data-protection principles | architecture#data-protection (principle) |
| 11.2–11.4 | Crypto-shredding, disclosure, land gate | integration#data-protection |
| 12.x | Node API surface | node/job-api, node/gateway, node/admin-auth (summary text H; the error table rows each land in their route's file) |
| 13.1–13.5 | SLOs/telemetry, FinOps, RACI, IR, DR | node/ops, node/runbooks (summary text H) |
| 13.6 | Circuit breakers and emergency procedures | node/runbooks#emergency |
| 14.1 | IOpenFactory | contracts/token-wrappers#factory-interface |
| 14.2 | IERC20MetaTx / IERC20Payment | contracts/metatx#interfaces |
| 14.3, 14.4 | IZetherToken, ITransferDisclosure | contracts/zether#interfaces |
| 14.5 | IUniversalAccountRegistry (built) | contracts/universal-account#legacy-registry |
| 14.6–14.8 | Pointers | H |
| 14.9 | Other built interfaces | the owning contracts/* file |
| 15.1 | Roadmap | T (TODO already holds the order) + H |
| 15.2 | Open owner questions | §4 of this plan → D (status `open`) |
| 15.3 | SRS contradictions | history/README#srs-deltas (owner reference; never in current docs, R-B) |
| 15.3 | In-repo contradictions | §4 of this plan → resolved in the rewrite; D |

### 2.2 `integration.md` (→ history/integration-2026-10-07.md; new `integration.md` rewritten)

| § | Section | Target |
|---|---|---|
| 1 | Integration model | integration#model |
| 2, 2.1 | Onboarding, HMAC signing | rules → node/job-api#auth; client how-to + example code → integration#onboarding |
| 3.1–3.4 | Push request, accept checks, push algorithm, cancel | rules → node/job-api; client algorithm → integration#push |
| 3.5 | Outbox rules | integration#outbox (generic: immutable rows, operator read-only) + Odoo example |
| 3.6 | `call` targets | node/job-api#call-table (single home); integration links |
| 4.1–4.3 | Feeds, client rules | rules → node/indexer-feeds; client rules → integration#reconciliation |
| 5.1, 5.2 | entryRef generation and verification | contracts/metatx#entryref; integration#payment-references |
| 6, 7, 8 | P2P seven steps, fast path/batching, inbound payments | integration#procure-to-pay, #batching, #inbound |
| 9 | Tender in procurement | integration#tender (ERP flow); contract rules stay in contracts/tender |
| 10.1–10.3 | Subject accounts, UA registration, identity sync | integration#accounts |
| 11, 12 | Regulated-token compliance flow, asset-suite configuration | integration#regulated-assets |
| 13, 14 | clientkeys, app | pointers to clients/* (text H) |
| 15.1–15.5 | Odoo worked example | integration#example-odoo (fenced example block, R-B) |
| 16.1–16.3 | Failure handling, daily reconciliation, after a node restore | integration#runbook |
| 17 | Checklist | integration#checklist |

### 2.3 Component specs

#### `2026-10-03-blockchain-payments-design.md` (PD, VI)

| § | Section | Target |
|---|---|---|
| 0, 1 | Goals, overview | H (covered by architecture) |
| 2.1 | MetaToken v1 | contracts/metatx#v1 |
| 2.2 | OpenFactory | contracts/token-wrappers#factory-v1 |
| 2.3 | MetaTxDex | contracts/dex#legacy-metatxdex |
| 2.4 | Deploy | contracts/README#deploy; networks/evm#deployments |
| 3.1 | node.toml | node/store#config-file |
| 3.2 | submit (outbox pull) | node/submit-lanes#evm-runner; node/job-api#legacy-pull (transitional) |
| 3.3 | indexer finality gate | node/indexer-feeds#finality |
| 3.4 | gateway | node/gateway |
| 3.5 | Odoo ↔ node RPC (`/json/2`) | node/job-api#legacy-pull (inside example block); integration#example-odoo |
| 4.1–4.6 | Odoo addons, models, `relay.job.chain_state` table, payment, portal, groups | integration#example-odoo (state table → integration#outbox generic states + example) |
| 5 | End-to-end portal payment | integration#procure-to-pay (generic) + example |
| 6 | Typed data and digest, "one rule four places" | contracts/metatx#digest |
| 7 | Trust and key management | architecture#trust-model; node/submit-lanes#lane-keys |
| 8 | Incident handling | node/runbooks |
| 9 | Security and threats | node/threat-model; contracts/metatx#security |
| 10 | Test strategy | conformance sections of contracts/metatx, node/* |
| 11, 12 | Out of scope, implementation plan | H |
| 13 | Rulings R1–R20 | D (texts into targets per §3.2) |
| 14 | Review log | H |
| 15.1–15.6 | Claude review fold: CR-PD-1…6, superseded, amendments, streams, revisions | CR-PD-* texts per §3.2; 15.3 → D; 15.4 → X; 15.5 → T; rest H |

#### `2026-10-03-blockchain-payments-addendum-wallets.md` (ADW, VI)

| § | Section | Target |
|---|---|---|
| A | Approve rule: contract spenders only | contracts/token-wrappers#allowance-lockdown |
| B | Open-standard wallets (EIP-1193/6963/712/1271, WalletConnect) | clients/signers-clientkeys#wallet-standards |
| C | Receiving wallets per company | integration#receiving-wallets |
| D | Paying wallets, auto-pay | contracts/accounts-mandates#mandatewallet; integration#auto-pay |
| Rulings, CR-ADW-1…4 | — | D; texts per §3.2 |
| Review log, Claude review 1 (disposition, superseded, amendments, streams, revisions) | admin | H, D, X, T |

#### `2026-10-03-blockchain-infrastructure-service.md` (INFRA, VI)

| § | Section | Target |
|---|---|---|
| intro, comparison IaaS/BaaS/blockchain service | — | architecture#authority-model (table, translated, with the "Land" row and admin-exception list) |
| Owner ruling (CR-R3-11 restated) | — | D (alias to CTR-GEN id) |
| Claude review 1, superseded, amendments, streams, revisions | admin | H, D, X |

#### `2026-10-03-blockchain-round3-design.md` (R3D, VI)

| § | Section | Target |
|---|---|---|
| 0 | Cross-cutting principles | networks/README#principles |
| A.1 | Custody `env:` dev-only (R50) | integration#custody (generic) + node/submit-lanes#lane-keys (dev flag) |
| A.2 | → B.3 | — |
| A.3 | Monitoring (R51) | node/ops#health |
| A.4 | CI (R52) | contracts/README#build-pins |
| A.5 | Pause only blocks sending (R53) | node/store#chain-states |
| A.6 | Gateway auth + parser fuzz (R54) | node/gateway#auth |
| A.7 | Gas breaker (R55) | node/submit-lanes#breaker |
| A.8 | One journal per (chain, token) + drift (R56) | integration#accounting |
| A.9 | Territory seam, "platform company" (R57) | integration#example-odoo |
| A.10 | HANDOFF items | T / H |
| B.1 | ChainAdapter (R58) | node/submit-lanes#adapters |
| B.2 | Signer (R59) | node/submit-lanes#signer |
| B.3 | Relayer key config (R60) | node/submit-lanes#lane-keys |
| B.4 | ERP family/address/payload (R61) | integration#addresses (generic) + example |
| B.5 | Head-of-line table (R62) | networks/README#head-of-line |
| C (C.1–C.4) | Passkey (R31), seed wallet (R32), multi-key accounts, Zether key (R33) | contracts/accounts-mandates#passkeys; clients/signers-clientkeys#vault, #zether-keys |
| D.0 | Common non-EVM model | networks/README#model |
| D.1–D.5 | Hedera, Sui, Soroban, Cosmos, TON | networks/<family>#overview |
| D.6 | ERP and portal per family | integration#families (generic) + clients/signers-clientkeys#connectors |
| E, F | Rulings, owner decisions (R34, R35) | D; R34 → contracts/zether#scope, R35 → contracts/dex + node/dex-venue |
| G | Review log | H |
| H.1 | Disposition | H |
| H.2 | CR-R3-1…10 | per §3.2 (networks/README, node/indexer-feeds, networks/*) |
| H.3 | CR-R3-11 immutable at deploy | contracts/README#immutable; networks/README#deploy-gate |
| H.4 | Superseded | D |
| H.5 | Amendments | X |
| H.6, H.7 | Streams, revisions | T, H |

#### `blockchain-research/round3-wallet-signing-formats.md` (WSF)

| § | Section | Target |
|---|---|---|
| 1 | Hedera HIP-632 | networks/hedera#signatures |
| 2 | TON Connect `signData` | networks/ton#signatures |
| 3 | Sui `signPersonalMessage` | networks/sui#signatures |
| 4 | Cosmos ADR-036 | networks/cosmos#signatures |
| 5 | Freighter `signAuthEntry` | networks/soroban#signatures |
| Rulings CR-WSF-1/2 | — | networks/sui, networks/solana (CR-WSF-1), networks/hedera (CR-WSF-2); clients/signers-clientkeys#rendering |
| Signing-domain inputs per family (M4) | — | networks/README#signing-domains |
| Passkey format (M2) | — | networks/README#webauthn |
| Aptos and Solana (L3) | — | networks/aptos, networks/solana |
| Superseded, amendments, streams, revisions | admin | H, D, X, T |

#### `2026-10-03-dex-design.md` (DEX, VI)

| § | Section | Target |
|---|---|---|
| 0 | Summary | contracts/dex#overview |
| 1.1–1.8 | OrderBookDex: signed orders, settle, cancel, markets/fees/admin, relayer fee, read functions, allowance/lanes, invariants | contracts/dex |
| 2 | Book persistence (RS5-2, Odoo) | node/dex-venue#persistence (target = store; Odoo book = transitional) |
| 3.1–3.6 | Node: markets, price-time, matching, spam, `/v1/dex/*`, watcher | node/dex-venue |
| 4 | ERP DEX addon | integration#example-odoo (DEX accounting) |
| 5 | Non-EVM model | networks/README#dex-per-family; networks/<family>#dex |
| 6 | Tests | contracts/dex#conformance; node/dex-venue#tests |
| 7 | Rulings (+ rev 1.1, 1.2) | D; texts per §3.2 |
| 8, 9 | Review log, disposition, revisions | H |

#### `2026-10-03-zether-design.md`, `2026-10-05-zether-limits.md`, `2026-10-05-zether-consensys-max.md` (ZD, VI)

| § | Section | Target |
|---|---|---|
| ZD 1–9 | Parameters, curves, NUMS generators, transcript, ElGamal state, statement layout, Σ-protocols, Bulletproofs, proof wire format | contracts/zether (verbatim byte layouts) |
| ZD 10 | Envelope binding, replay | contracts/zether#envelope |
| ZD 11 | Delegation and registry | contracts/zether#registry (built, transitional until UA) + contracts/universal-account#legacy-registry |
| ZD 12 | Disclosure | contracts/zether#disclosure |
| ZD 13 | Safety gate | contracts/zether#safety-gate; contracts/README#unaudited |
| ZD 14 | Vectors | contracts/zether#vectors |
| ZD 15 | Gas (measured) | contracts/zether#gas |
| ZD 16 | Rulings (S2, n_v = 64, rev 1.1) | D; texts per §3.2 |
| ZD 17, 18 | Review, revisions | H |
| Limits 1–5 | Decisions D1–D6, limit tables, `n_b − n_v`, BSGS, device cache | contracts/zether#limits; clients/signers-clientkeys#zether-balance |
| Limits 6, 7 | admin | H |
| ConsenSys-max 1–5 | What `MAX = 2^32 − 1` is; three quantities; raising the bound | contracts/zether#decryption-bound (short normative part); analysis → D (rationale of RS-NV64 ids) |
| ConsenSys-max 6, 7 | admin | H |

#### Network specs (all VI): hedera, cosmos, soroban, sui, ton, aptos, solana

Common pattern; family-specific sections listed.

| Spec § (pattern) | Target |
|---|---|
| Scope / summary of decisions / "lessons from other networks" (Aptos §0, Solana §0) | networks/<family>#overview; lessons L1–L12 → networks/README#design-lessons (NET-ALL) |
| Payload `MetaOp` v1, signature scheme, passkey | networks/<family>#payload, #signatures |
| Contracts / objects / accounts / instructions / lanes / mandate / DEX / admin | networks/<family>#contracts (+ #dex, #mandate) |
| Relayer adapter, fees, keys, simulation, submit/status/`Rejected`, crash-safety, finality/events/indexer, node config, head-of-line row | networks/<family>#relayer (node-common rules stay in node/*) |
| Odoo / portal sections | integration#families (generic, per-family address/verification rules) + example; clients/signers-clientkeys#connectors |
| Tests / devnet / cross vectors | networks/<family>#conformance |
| Confidential payments feasibility | contracts/zether#families (one table) |
| Risks / gaps / seams | networks/<family>#limitations |
| "Needed from other file owners" (Aptos §12, Solana §12) | H (executed) |
| Open questions + "Owner decisions 2026-10-04" (Aptos §14 + tail, Solana §15 + tail) | D (RS11-14/15, RS12-5 …) |
| Sources (Aptos §15, Solana §16) | networks/<family>#references |
| Execution results (Aptos §17, Solana §18) | H; facts already true of the code fold into the body |
| Rulings, rev 1.1 rulings, "Quy tắc node chung (NI rev 3.7)" | D; texts per §3.2; node-common rules are node/* ids, cited |
| Review log, disposition, code streams, revisions | H, T |

Family-specific placements: Hedera §5 head-of-line (R6-1) → networks/hedera#relayer + README row; Hedera §7 HTS →
networks/hedera#hts; Hedera §10 and TW2 §11 → networks/hedera#wrappers. Soroban §1.2 ledger expiry without RPC
(R8-1) → networks/soroban#payload. Sui §2.1 flags → networks/sui#signatures. Solana §2.4 write-lock (RS12-2) →
networks/solana#write-locks; §3.6 SPL/Token-2022 → networks/solana#tokens; §5.5 why Anchor → networks/solana#toolchain.
Aptos §3.2 balances, §3.3 keys/guardian, §4.2 `signMessage` envelope → networks/aptos. TON §3.4 escrow DEX,
§3.5 passkey, §4 anti-lock → networks/ton.

#### `2026-10-05-relayer-mesh-design.md` (MESH, EN)

| § | Section | Target |
|---|---|---|
| 1.1, 1.2 | Scope, non-goals | node/mesh#scope (as amended by A2 §18.1 and NI §13.1) |
| 2 | Rulings R70–R86 | D; texts per §3.2 |
| 3.1 | Shapes | H (superseded by NI: every node is Odoo-free) |
| 3.2 | node.toml changes | node/store#config-file (mesh keys) |
| 3.3 | Standalone mode | H (superseded entirely, NI §13.1) |
| 3.4 | Dependencies | node/gossip#crates (aws-lc-rs per A2 R114) |
| 4.1–4.6 | Envelope `scaas-intent/1.2`: family qualification, wire, fields, `intent_id`, `hub.sig`, conformance vectors | node/mesh#envelope (verbatim) |
| 5.1–5.4 | Bus HTTP API: auth/limits, routes, errors, forwarding/hops | node/mesh#bus |
| 6 | Node-local store | node/store#mesh-tables (NI §4 shape wins; SQLite-only text H) |
| 7.1–7.3 | Acceptance policy | node/mesh#acceptance (policy now in node store, NI R99) |
| 8.1–8.7 | Exclusivity, submit, cancel, dedup, classification, restart, guarantees | node/mesh#exclusivity; 8.4 → node/submit-lanes#shared-submit; 8.7 → node/README#invariants |
| 9 | Private profile | node/mesh#private-profile |
| 10.1, 10.2, 10.5, 10.6 | ERP-side chain field, policy/peer models, outbox publication, ACL | H (superseded by NI R95/R99) |
| 10.3 | Consumption / `landed_elsewhere` | integration#reconciliation (generic) + example |
| 10.4 | Company bus-scope setting | integration#mesh-scope (per-job `bus_scope`, NI R99) |
| 11 | Security | node/threat-model#mesh |
| 12 | Observability | node/ops#metrics |
| 13.1–13.4 | Test plan | node/mesh#tests; 13.4 → H (ERP tests) |
| 14 | Work breakdown | H, T |
| 15.1 | Doc corrections to research | H (research frozen; recorded in history/README) |
| 15.2 | Owner-confirmed interpretations | node/mesh (as rules, NODE-MESH ids; alias MESH:I1–I4) |
| 15.3 | Deferred work | node/mesh#limitations (PLANNED list) |
| 15.4 | Contradictions resolved | D (rationale) |
| 16 | Review disposition | H |

#### `2026-10-06-node-independence-design.md` (NI, EN)

| § | Section | Target |
|---|---|---|
| header (rev notes) | — | H |
| 1.1–1.3 | Today, scope, non-goals | node/README#scope (1.1 evidence H) |
| 2 | Rulings R87–R111, R320–R328, R340–R349 | D; texts per §3.2 |
| 3 | Architecture after inversion (diagram, listener table) | node/README#listeners; architecture#components (diagram) |
| 4 | Store schema additions (DDL) | node/store#schema (verbatim, merged with A1.3, TSS B1.2, OPS 8.2 additions) |
| 5.1–5.4 | Job API auth, routes, cursor semantics, errors/limits | node/job-api; 5.3 → node/indexer-feeds#cursors |
| 5.5 | Gateway (door A) routes | node/gateway#routes |
| 6 | Event feed format per family | node/indexer-feeds#event-items |
| 7.1–7.6 | Admin API: credentials/OIDC, built-in users/CLI, routes, CORS, audit, errors | node/admin-auth |
| 7.7 | App serving | node/admin-auth#app-serving; clients/app#deploy |
| 8 | Configuration authority, bootstrap | node/store#config-authority |
| 9.1 | Node code changes | node/submit-lanes, node/indexer-feeds (as current behaviour) |
| 9.2 | Safety properties, where each lives | node/README#invariants |
| 9.3, 9.4 | Durability vs SKIP LOCKED; same lane keys in two stores | node/store#durability; node/submit-lanes#lane-keys |
| 10.1–10.8 | ERP side: models, client library, push/sync crons, cancel/requeue/expiry, transitional gates, deletions, ACL | integration#push, #reconciliation (generic) + example-odoo; 10.6, 10.7 → H |
| 11.1–11.4 | Migration: version matrix, per-chain cutover, namespace bootstrap, proof criterion | integration#migration-from-pull (generic); node/runbooks#cutover |
| 12.1–12.4 | DEX on the node | node/dex-venue |
| 13.1, 13.2 | Interplay with mesh | X (applied to node/mesh) + H |
| 14 | Security T1–T19 | node/threat-model |
| 15 | Observability | node/ops#metrics |
| 16.1–16.5 | Test plan | test sections of node/*; 16.3 (ERP) → H |
| 17 | Work breakdown | T, H |
| 18.1 | Doc corrections | X |
| 18.2 | Interpretations to confirm | D (status `open`, NI:I1–I8) |
| 18.3 | Deferred | node/README#limitations (PLANNED) |
| 19.1–19.6 | Review dispositions | H |
| 20 | Additions consolidated in rev 3.4 | folded into the node/* file each row names |
| A1.1–A1.4 | Storage backends: owner/fencing, transactions, per-backend schema rules, driver/secrets/tests | node/store#backends |

#### `2026-10-06-mesh-gossip-amendment.md` (A2, EN)

| § | Section | Target |
|---|---|---|
| 1 | Scope | node/gossip#scope |
| 2 | Rulings R112–R128 | D; texts per §3.2 |
| 3, 3.1 | Architecture, node.toml | node/gossip#architecture; node/store#config-file |
| 4.1–4.4 | Identity, signing contexts, PQ KEX, private-profile consequences | node/gossip#identity, #transport |
| 5.1–5.4 | Topics, message-id/size, schemas, protocols | node/gossip#wire |
| 6, 6.1, 6.2 | Validation pipeline, acceptance codes | node/gossip#validation |
| 7.1–7.4 | Numbers | node/gossip#numbers |
| 8.1–8.4 | Intents over gossip | node/gossip#intents; 8.4 store changes → node/store#schema |
| 9 | Landed hints | node/gossip#hints |
| 10.1–10.4 | Announce | node/gossip#announce |
| 11.1–11.7 | DEX book gossip | node/dex-venue#gossip |
| 12 | Private-scope isolation proof sketch | node/gossip#private-isolation |
| 13.1 | Admin routes | node/admin-auth#routes |
| 13.2 | App screens | clients/app#node-screens |
| 13.3 | Metrics | node/ops#metrics |
| 14 | Threat model | node/threat-model#gossip |
| 15.1, 15.2 | Crates, budget | node/gossip#crates |
| 16.1, 16.2 | Tests | node/gossip#tests |
| 17 | Streams | T, H |
| 18.1–18.3 | Changes to existing specs | X (18.3 research/SRS edits → H + history/README) |
| 19 | Owner answers | D |
| 20 | Review disposition | H |

#### `2026-10-06-operations-design.md` (OPS, EN)

| § | Section | Target |
|---|---|---|
| 1.1–1.3 | Scope, non-goals, severities | node/ops#scope, #severities |
| 2 | Rulings R230–R247 | D; texts per §3.2 |
| 3.1–3.3 | SLIs/SLOs, latency per family/profile, error budget | node/ops#slos |
| 4.1–4.4 | Metric rules, existing, new, admin/store additions | node/ops#metrics |
| 4.5 | Subject denylist | node/ops#denylist (intake hook cited from node/job-api#intake) |
| 5.1–5.3 | Alert rules, routing, dashboards | node/ops#alerts |
| 6, 7 | Traces, logs | node/ops#traces, #logs |
| 8.1–8.4 | FinOps: measurement, `usage_day`, report, budget alarms | node/ops#finops; DDL → node/store#schema |
| 9.1, 9.2 | RACI | node/runbooks#raci |
| 10.0–10.x | Incident runbooks | node/runbooks#incidents |
| 11.1–11.4 | RPO/RTO, restore loss, commands, DR drills | node/runbooks#backup-dr |
| 12 | Capacity | node/ops#capacity |
| 13 | Streams | T, H |
| 14, 15 | Owner answers, review | D, H |

#### `2026-10-06-tender-sponsorship-shredding.md` (TSS, EN)

| § | Section | Target |
|---|---|---|
| header table of NI amendments | — | X |
| 1.1, 1.2 | Scope | split: contracts/tender#scope, node/sponsorship#scope, integration#data-protection |
| 2.1–2.5 | Rulings R180–R199 | D; texts per §3.2 |
| A.1–A.5, A.7–A.9 | Tender roles, rules, interface, storage, flows, security, gas, tests | contracts/tender (A.5 ERP flow → integration#tender) |
| A.6 | Node/ERP/app touchpoints | node/job-api#call-table rows; integration#tender; clients/app |
| A.10 | Families | networks/README#availability |
| B1.1–B1.8 | Sponsorship policy (node) | node/sponsorship (B1.2 DDL → node/store#schema; B1.5 routes → node/admin-auth#routes; B1.6 → node/ops#metrics) |
| B2.1–B2.4, B2.6 | Receiver-pays messages, function, invariants, abuse, gas/tests | contracts/metatx#receiver-pays |
| B2.5 | Touchpoints | node/sponsorship#receiver-pays; integration#inbound |
| B2.7 | Families | networks/README#availability |
| B3 | SponsorshipPool (PLANNED) | node/sponsorship#pool |
| C.1–C.7 | Crypto-shredding | integration#data-protection (C.2 commitment formats verbatim) |
| C.8 | Families | networks/README#availability |
| 8 | Streams | T, H |
| 9 | Open questions/follow-ups | D; follow-up (scoped key kind) → contracts/accounts-mandates#limitations (PLANNED) |
| 10, 11 | Review dispositions | H |

#### `2026-10-06-asset-suite-design.md` (AS, EN)

| § | Section | Target |
|---|---|---|
| 1.1, 1.2 | Scope | contracts/asset-suite#scope |
| 2 | Rulings R200–R217 | D; texts per §3.2 |
| 3.1–3.12 | Regulated module | contracts/asset-suite#regulated |
| 4.1–4.8 | Vesting | contracts/asset-suite#vesting |
| 5.1–5.3, 5.5–5.7 | Distributions | contracts/asset-suite#distributions |
| 5.4 | Snapshot (node, deterministic) | contracts/asset-suite#snapshot (format) + node/indexer-feeds#snapshots (service) |
| 6.1–6.4 | Corporate actions `ExchangeOffer` | contracts/asset-suite#corporate-actions |
| 7 | Templates | contracts/asset-suite#templates |
| 8.1 | Managed market venue | contracts/dex#managed-markets |
| 8.2–8.4 | Intake/matching, gossip, security | node/dex-venue#managed-markets |
| 9.1–9.3 | Node / ERP / app touchpoints | node/* (cited rows), integration#regulated-assets, clients/app |
| 10 | Per-family availability | networks/README#availability |
| 11 | Factory and catalogue changes | contracts/token-wrappers#factory-v2 |
| 12 | Storage layout pins | contracts/asset-suite#storage |
| 13 | Work breakdown | T, H |
| 14, 15 | Open questions (none), review | H |

#### `2026-10-06-token-wrappers-v2.md` (TW2, EN)

| § | Section | Target |
|---|---|---|
| 1 | Scope | contracts/token-wrappers#overview |
| 2 | Rulings R129–R149 | D; texts per §3.2 |
| 3.1–3.3 | MetaTxCore | contracts/metatx#v2 |
| 4, 5.1–5.4 | Tier 1, tier 2 | contracts/token-wrappers |
| 5.3 | Gasless unwrap op | contracts/metatx#ops (op) + token-wrappers (semantics) |
| 6.1–6.6 | Rates | contracts/token-wrappers#rates |
| 7.1–7.4 | Named functions, payLane, mtxBatch | contracts/metatx#named-functions |
| 7.5, 7.6 | Node usage, unwrap jobs | node/submit-lanes#batches, #unwrap-jobs |
| 7.7 | Gasless wrap (PLANNED) | contracts/token-wrappers#limitations |
| 8.1–8.5 | Tier 3 multi-underlying (incl. depeg disclosure text) | contracts/token-wrappers#multi |
| 9 | Factory v2 | contracts/token-wrappers#factory-v2 |
| 10.1–10.4 | Storage, events, errors, gas, tests | contracts/token-wrappers (+ metatx for shared events/errors) |
| 11 | Hedera | networks/hedera#wrappers |
| 12 | Non-EVM | networks/README#availability |
| 13 | Open questions (none) | H |
| 14 | Migration | contracts/token-wrappers#migration |
| 15, 16, 17 | Stream plan, requirement trace, review | T, H |
| 18 | Implementation notes T1–T6 | normative facts → contracts/token-wrappers (as built); rest H |

#### `2026-10-06-scaas-app-design.md` (APP, EN)

| § | Section | Target |
|---|---|---|
| 1–8 | Scope, architecture, config.json, family adapters, signers/accounts, availability matrix, screens | clients/app |
| 9.1–9.5 | Node clients, built-in login, OIDC, several nodes | clients/app#node-clients |
| 9.6 | Node addendum (normative for gateway/ops/UA routes) | node/gateway#routes, node/admin-auth (single home); clients/app links |
| 10.1–10.7 | Security | clients/app#security (10.5 signing review → clients/signers-clientkeys#signing-review if shared) |
| 11–14 | i18n, testing, build/deploy, performance | clients/app (13.2 node-served → node/admin-auth#app-serving) |
| 15 | Work breakdown | T, H |
| 16 | Owner answers | D |
| 17 | Doc corrections | X |
| 18 | Review | H |

#### `2026-10-06-signers-followups.md` (S4F, EN)

| § | Section | Target |
|---|---|---|
| 1 | Scope | clients/signers-clientkeys#scope |
| 2.1–2.6 | Rulings R250–R269 | D; texts per §3.2 |
| 3 | What the UA spec rules | H (duplicate) |
| 4.1–4.3, 4.6, 4.7 | Backup-key switch | clients/signers-clientkeys#backup-switch |
| 4.4 | ERP portal part | integration#example-odoo |
| 4.5 | Per-family applicability | networks/README#key-lifecycle |
| 5.1–5.6 | Device-bound vault v2, scrypt | clients/signers-clientkeys#vault |
| 6.1, 6.3, 6.4 | Sui key verification facts, JS, vectors | networks/sui#key-verification |
| 6.2 | Python ERP verifier | integration#families (generic rule) + example |
| 7.1–7.4 | Role keys and seed signers | clients/signers-clientkeys#role-keys |
| 8.1–8.3 | Passkey signers on non-EVM | clients/signers-clientkeys#passkeys |
| 9.1–9.4 | Portal connectors | clients/signers-clientkeys#connectors (9.1 "today" → H) |
| 10 | Streams | T, H |
| 11 | Open question Q1 (answered: kindNo 18) | D |
| 12 | Review | H |

#### `2026-10-06-pq-zether-design.md` (PQZ, EN)

| § | Section | Target |
|---|---|---|
| header source table | — | H |
| 1 | Summary | contracts/pq-zether#overview |
| 2.1–2.7 | Research summary | D (rationale of CTR-PQZ ids); 2.6 hardware fact and 2.7 chain limits → contracts/pq-zether#constraints |
| 3 | Rulings R270–R289 | D; texts per §3.2 |
| 4.1–4.5 | MLWE-BFV-add scheme | contracts/pq-zether#encryption |
| 5 | Encodings | contracts/pq-zether#encodings |
| 6.1–6.3 | Keys, UA kinds, derivation, seed custody | contracts/pq-zether#keys; clients/signers-clientkeys#zether-keys |
| 7.1–7.11 | Protocol | contracts/pq-zether#protocol |
| 8 | Proof engine | contracts/pq-zether#proof-engine |
| 9.1–9.5 | On-chain verifier, precompiles, gas, contracts | contracts/pq-zether#verifier |
| 10.1–10.4 | Nethermind precompile on chain 7622 | contracts/pq-zether#chain-integration; networks/evm#private-chain links |
| 11.1, 11.5 | Prover, retail WASM prover | contracts/pq-zether#provers |
| 11.2 | clientkeys | clients/signers-clientkeys#zether-keys |
| 11.3 | Node operator recommendations | node/ops#pqz |
| 11.4 | ERP | integration#confidential-payments |
| 12.1, 12.2 | Threat model | contracts/pq-zether#threats |
| 13 | Hybrid path, migration | contracts/pq-zether#migration |
| 14 | Per-family availability | networks/README#availability |
| 15 | Tests and vectors | contracts/pq-zether#vectors |
| 16 | Streams | T, H |
| 17.1–17.4 | Owner answers, dispositions | D, H |
| 18 | Sources | contracts/pq-zether#references |

#### `2026-10-06-universal-account-design.md` (UA, EN)

| § | Section | Target |
|---|---|---|
| 1 | Scope | contracts/universal-account#scope |
| 2.1–2.6 | Rulings R290–R318, R330–R331 | D; texts per §3.2 |
| 3 | Model in one page | contracts/universal-account#model |
| 4.1–4.4 | Kinds, derivation, kind table, MuSig2/FROST, guidance | contracts/universal-account#kinds |
| 5.1–5.5 | Function → accepted kinds | contracts/universal-account#functions |
| 6.1–6.6 | Registry | contracts/universal-account#registry |
| 7.1–7.3 | Verifier library | contracts/universal-account#verifiers |
| 8.1 | Layer 1: derivation and wallets | clients/signers-clientkeys#derivation |
| 8.2–8.4 | Layers 2–4 | contracts/universal-account#purposes |
| 9.1–9.7 | VC/eKYC layer | contracts/universal-account#credentials |
| 10 | SubjectAccount as option (b) | contracts/accounts-mandates#subjectaccount |
| 11.1 | Mesh | node/mesh#ua-intents |
| 11.2 | Node | node/indexer-feeds, node/gateway (cited rows) |
| 11.3 | App and clientkeys | clients/* |
| 11.4 | ERP | integration#accounts |
| 12.1, 12.2, 12.4 | Migration from the built registry | contracts/universal-account#migration |
| 12.3 | New registration flow | integration#accounts |
| 13 | Security analysis | contracts/universal-account#security |
| 14.1–14.3 | Gas and calldata | contracts/universal-account#gas |
| 15.1–15.3 | Vectors, tests | contracts/universal-account#vectors |
| 16 | Streams | T, H |
| 17 | Owner confirmations Q1–Q14 | D (UA:Q1–Q14, owner flag) |
| 18, 19 | Review dispositions | H |

### 2.4 Other docs

| Item | Decision |
|---|---|
| `blockchain-research/` (25 files, 2.9 MB) | `git mv` to **`docs/research/`** (out of `specs/`; not history, because it stays a live background library). New `research/README.md` + a one-line banner atop each file: *"Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md)."* Current docs never link it except decisions.md "Source" lines (check C10). Mining rules per file in §2.6. |
| `blockchain-research/round3-wallet-signing-formats.md` | **normative** (carries CR-WSF-1/2): content → networks/* per the WSF table above; the file → `history/specs/round3-wallet-signing-formats.md` |
| `superpowers/plans/*.md` (19) | `git mv` to `history/plans/`; RS4-* rulings get new ids like any other; this plan moves there after execution |
| `superpowers/HANDOFF-blockchain.md` | `git mv` to `history/`; still-open owner/operator gates O1–O11 and Z1–Z6 become items in `scaas/TODO.md` §2 and, where they are standing production rules, `node/runbooks#production-gates` / `contracts/README#unaudited` |
| `docs/reviews/specs/` | stays, git-ignored; `history/README` says each history spec carries its disposition tables and that raw review files are local-only (other clones do not have them) |
| `docs/superpowers/` | stays as the drafting area for future designs (§3.5) |
| `docs/blockchain.md` | `git mv` to `history/blockchain.md` (decision: it is a source, Vietnamese, organized by SRS numbering; R-B forbids that numbering in current docs). Every item is traced (§2.5); the trace is `history/blockchain-trace.md`. `scaas/README.md` row "blockchain.md — original requirements note" repoints to it. |

### 2.5 `blockchain.md` (owner requirements note) — requirement trace

blockchain.md is a **fact-ledger source** like the specs (§6.3), with three extra disposition classes:
`rejected:<new id>` (deliberately not done; the decisions.md entry gives the reason), `open:<new id>` (owner
decision pending), `out-of-scope:<new id>` (belongs to a client system, not to SCaaS). Every bullet, numbered item,
table row and interface block is one item. Phase 0 extracts it; Phase 1 agents fill dispositions for their area;
Phase 2 generates `history/blockchain-trace.md` (`item · excerpt · status · new doc anchor or decision id`) with
`docs_check.py facts trace history/blockchain.md`, and `facts check` fails on any item without a disposition. The new
docs carry the substance in self-contained English; "Nhóm 21", "CHƯƠNG 10", "§10.5.3", "6.21", "14.2.8", "D." never
appear outside history (C9 bans them: `\bNhóm \d`, `CHƯƠNG`, `\b(6\.21|10\.[1-5](\.\d)?|14\.2\.8)\b` next to §).

Where research already corrected the note, the correction is the current text and the note's claim gets a
`rejected:` disposition citing it (`research/_MANIFESTS.md`, 16 blocks "Where blockchain.md is wrong /
under-specified", one per research note 01–16).

| blockchain.md part | Items (summary) | Target / disposition |
|---|---|---|
| TOKEN (top list) | self-minted issuer token; wrap an existing ERC-20; mint/burn from one or a group of ERC-20 at a rate; shared code via delegation, "support many versions"; factory with create2; addable contract prototypes; singleton account registry extensible to multisig, Schnorr, BLS, FALCON | tiers 1–3, rates, multi-underlying → contracts/token-wrappers (BUILT); EIP-1167 clones + factory versions → contracts/token-wrappers#factory (BUILT); "delegate + versions" via **UUPS rejected** (immutable clones, new implementation per version: CTR-GEN immutability; research 01 storage-layout note); weighted basket **rejected** in favour of any-of multi-underlying (R136 → CTR-TOK); prototypes = factory kinds + asset templates → contracts/asset-suite#templates; registry kinds → contracts/universal-account#kinds (FALCON = `fndsa512`, SPECIFIED) |
| TOKEN interface sketches (`IEIP1776`, `IZetherAccountRegistry`, …) | `MetaTransaction`, `executeMetaTransaction`, `meta_nonce(from, batchId)`; registry with `SchnorrPublicKey {x, y}`, `register(x, y, sig)` | contracts/metatx#interfaces (BUILT, 2D nonces); registry shape **rejected/corrected** per research 02 (pkX/pkY, `abi.encode`, PoP challenge with domain tag + chain id + registry, on-curve checks, non-upgradeable) → contracts/zether#registry, contracts/universal-account#registry |
| BLOCKCHAIN item 11 | six ecosystems, EIP-1776 philosophy, open relayer network | family taxonomy (EVM incl. Hedera; Cosmos; Soroban; Move = Sui + Aptos; TON; Solana) → networks/README (owner decision ARCH-POS); meta-tx → contracts/metatx; open relayers → node/mesh, node/gossip |
| 6.21 data format and properties | blocks, txs, receipts, events; immutability; confidential balances; identities visible, no mixers | node/indexer-feeds#event-items (what the node delivers); "identity visible, amounts hidden" → contracts/zether#philosophy |
| 6.21 scope of six chains | EVM L1/L2 list, Gnosis xDAI, stablecoin-fee chains (Celo); Hedera HSCS/HCS/HTS/Schedule; TON FunC/Tact, W5 gasless; Sui PTB, sponsored tx; Soroban TTL, fee-bump; Cosmos feegrant, authz, IBC ICS-20/27 | networks/<family> (BUILT parts); W5 gasless extensions for subjects **rejected** (R67), Sui sponsored tx as gas mechanism **rejected** (R64), `x/authz` **rejected** and `x/feegrant` seam only (R66), payer-sponsored Hedera **rejected** (R63); HCS anchoring, Schedule Service, IBC ICS-20/27, Celo CIP-64 fee currency and `l1_batch` → **PLANNED/open** entries in networks/hedera, networks/cosmos, networks/evm; Solana and Aptos are additions (owner) |
| 6.21 collection and `raw` landing tables | dedicated nodes, RPC, indexers, WebSocket; relayer network listening to gossip/mempool; `raw.blockchain_*_landing` tables | node/indexer-feeds (finality-gated feeds; polling, no WebSocket: RS5-5 → NODE-DEX/NODE-IDX); mesh intake → node/mesh, node/gossip; the ERP-side landing tables are **out of scope** (a client's data platform consumes `/v1/events`) → integration#reconciliation note |
| 6.21 projector pipeline (`ods`, `vec`, `ekg`, `sem`, `proc`, `olap`/ClickHouse) | decoded business events, vectorized ABIs/audits, on-chain knowledge graph, settlement metrics, tool gateway, OLAP | **out-of-scope** (client data platform / AI layer), one ARCH-POS decision; the inputs SCaaS provides (event feed, job feed, metrics, usage reports) → node/indexer-feeds, node/ops#finops |
| 6.21 enterprise-AI value | tamper-evident proof of action (anchor hashes), frictionless payments via relayers, confidentiality with accountability | anchoring → architecture#service-model (anchor/land) + integration#data-protection (commitment formats); payments → integration; Zether disclosure → contracts/zether#disclosure |
| Ch.10 intro + 10.1 overview | Web3 gateway, open relayers, Zether processor | architecture#components |
| 10.1 (1) relayer economics | relayer as gas middleman; token-fee compensation; issuer sponsorship/rebate pool; open fee competition | contracts/metatx#fee-policy (BUILT); node/sponsorship (policies SPECIFIED; SponsorshipPool PLANNED, not a mesh reward: R75/R194); node/mesh#rewards |
| 10.1 (2) simulation engine | mandatory simulation, 0 % revert | node/submit-lanes#simulation (BUILT); "0 % revert" **rejected** as a guarantee (races; consumption handling R80) |
| 10.1 (3), 10.3 (2) Redis nonce manager | Redis cluster, monotonic lock, `INCRBY`, priority queue, +15 % replacement | **rejected**: store journal + owner lock + fencing (R88/R111), no Redis; replacement policy → node/submit-lanes#journal (×1.25 to cap, gap-fill R18) |
| 10.1 (4) RPC gateway and failover | dedicated + provider RPCs, latency probes, failover | node/indexer-feeds#quorum (independent endpoints, event-set quorum); provider names dropped (vendor-neutral) |
| 10.1 (5) Zether engine | ZKP generation/verification | contracts/zether; prover → contracts/zether#prover, clients |
| 10.1 (6) event ingestion + finality gate | WebSocket logs, signal ERP only after finality depth | node/indexer-feeds#finality (polling; WebSocket **rejected**) |
| 10.2.1 EVM | chains list; EIP-1776 contracts; **UUPS for all contracts**; gas-token specifics | networks/evm; UUPS **rejected** (immutable at deploy, CTR-GEN; registry must never be upgradeable — research 02) |
| 10.2.2–10.2.6 Hedera, TON, Sui, Soroban, Cosmos | per-chain meta-tx technique | networks/<family>#overview (as built; deviations listed above) |
| 10.3 (1) key custody | no plaintext keys for agents; HSM/MPC; ephemeral session keys 1–8 h; FIPS 140-2 L3 | node/submit-lanes#lane-keys (KMS/HSM seam, dev-only env custody R50); session keys → clients/signers-clientkeys#role-keys / UA purposes (SPECIFIED) or **open** if no equivalent; FIPS 140-2 → FIPS 140-3 language; "all keys in HSM" **corrected**: spending keys in HSM, Zether decryption key not HSM-capable (research 02/07) |
| 10.3 (3) anti-replay | domain separator with chain id + verifying contract; `valid_before`/deadline; 15-minute expiry | contracts/metatx#digest, networks/README#signing-domains (BUILT); the fixed 15 min **rejected** for per-chain `max_valid_for_secs` + pay-lane horizon (CR-PD-4) |
| 10.4 (1) simulation per family | `eth_estimateGas`, Tenderly forks, `devInspect`, `simulateTransaction`, `tx/simulate`, ton-emulator; failures to `ops.incident_log` | node/submit-lanes#simulation + networks/<family>#relayer (BUILT methods); Tenderly **rejected** (vendor; `eth_call`/`estimateGas` on own RPCs); incident log → node/ops#logs |
| 10.4 (2) gas circuit breakers | base-fee spike (×3), hourly USD velocity per agent and per enterprise | node/submit-lanes#breaker (BUILT: spike, hourly gas budget, lane floor; R340 metering); USD-denominated budgets → **open/PLANNED** (node budgets are native units, R190) |
| 10.4 (3) finality table | per-chain block time, consensus, finality threshold, wait | node/indexer-feeds#finality + networks/<family>#finality (values re-checked; Arbitrum/Base/Polygon/Ethereum L1 rows → networks/evm as **unsupported until configured**, not BUILT profiles) |
| 10.5.1 philosophy | identity visible, amounts hidden; anti-mixer; compliance | contracts/zether#philosophy |
| 10.5.2 cryptography | ElGamal homomorphic, range proofs, `MAX`, gas claims (180–250 k) | contracts/zether (byte-exact); `MAX = 2^128 − 1` and 180–250 k gas **rejected/corrected** (decryption bound vs range bits, measured 3.29 M / 3.92 M; RS-NV64, ZL:D1–D6); harvest-now-decrypt-later → contracts/pq-zether#scope and contracts/zether#threats |
| 10.5.3 identity, registry, token | Schnorr address by hash, shared registry, separate Zether token inheriting IERC20; principles 1–5; interfaces | contracts/zether#registry, #interfaces (BUILT), contracts/universal-account (SPECIFIED successor); corrections: hash identity costs more gas overall (calldata claim kept), `IZetherToken.MAX_AMOUNT` not `pure`, recipient/fee bound into transfer transcript (envelope binding RS2-5), Travel-Rule claim (needs amounts: `ITransferDisclosure` + auditor key, RS2-8/R283) |
| 14.2.8 settlement plane | decentralized settlement, open relayer, Zether contract | architecture#service-model (summary); detail as above; "8-plane" target architecture → **out-of-scope** (client platform architecture) |
| Appendix D standards | contract, blockchain, relayer, Zether standards list | each standard to the file that applies it (EIP-712, -1271, -1167, -1193, -6963, -7702, TEP-74, CW20, SEP/Soroban auth, WebAuthn); standards not used → **rejected** with reason, or **open** |

Phase 0 extends the inventory: owner requirements from blockchain.md that the specs never ruled on (e.g. ephemeral
agent session keys, USD velocity limits, HCS anchoring, IBC) get `open` entries in decisions.md (aliases
`req:blockchain.md:<item>`), so nothing silently disappears.

### 2.6 Research (`docs/research/`) — what is mined, what stays

| File | Treatment |
|---|---|
| `_USER-DECISIONS.md` (2 702 lines, §0–§25, the owner's decisions + findings from code) | **Mined fully into decisions.md.** Every decision unit (each `##`/`###` that states a choice: e.g. §3 fee modes, §3.2 Zether fee must be FIXED, §4 EIP-712 not `personal_sign`, §10 Zether is a child of MetaTransaction, §12 `transferWithProof` disclosure, §13.1–13.3 owner corrections, §14/§17/§19 curve decision D1 history, §15 D1/D2/D7/D12/D14/D17, §16 first chain is private, §20 open factory/no upgrade/one wrapper per creator, §21 two relayer modes, §22 intent lifecycle, §23 one Rust binary, §24 no forwarder/keep `mode`, §25 `rollOver` permissionless default) becomes an entry with `owner: yes`, its date and `Source: research/_USER-DECISIONS.md §n`; aliases `UD:§n` (and `canon:Dn` for the D-ids). Where a later ruling replaced it (§5 "wildcard, no mode bitmask" → §24 keep `mode`; §23 `[odoo]` control plane → NI R87; §18 genesis of chain 9000 → 7622), the entry is `superseded` with `superseded-by`; current ones are cited by the component doc that applies them. Pure findings ("§7 findings from code", "§8 Grok conversation", "§9 environment") get disposition `history:research-finding` unless a current rule depends on them. The file itself stays in `research/` unchanged. |
| `00-CANON.md`, notes `01`–`12`, `14`–`16` | stay in `research/`. Rationale is quoted (self-contained, R-B) into decisions.md "Why" where a ruling rests on it. **Measured** numbers (gas from forge/anvil runs, precompile I/O sizes and costs, latency/timing runs, preflight results such as `_USER-DECISIONS` §14 EIP-2537 and §17 MSM spike) go into the doc that owns the thing measured — contracts/zether#gas, contracts/pq-zether#gas, contracts/universal-account#gas, networks/evm#precompiles, networks/<family>#costs — with method, tool version and date; estimates stay in research (or are labelled "estimate" if a current doc needs them). |
| `13-legal-vn.md` | market-specific law: **never** enters the new docs (market-neutral rule; the generic GDPR-class controls are in integration#data-protection). Stays in `research/` only; owner question Q9. |
| `_CRITIQUES.md`, `_MANIFESTS.md`, `_REVIEW-01-UPGRADE.md`, `AUDIT_SPEC_REPORT_20260831_021000.md`, `_GROK-CODE.md`, `SYNTHESIS_ENTERPRISE_BLOCKCHAIN_V3.md`, `_EXPLAIN-07-CUSTODY.md` | stay in `research/` unchanged; cited only as decisions.md sources (`_MANIFESTS.md` also feeds the blockchain.md `rejected:` dispositions, §2.5). |
| `round3-wallet-signing-formats.md` | normative → networks/* (§2.3 WSF table); file → `history/specs/`. |

Fact ledger (§6.3) sources from research: `_USER-DECISIONS.md` (every fact, like a spec) and, in all other research
files, only facts of kind **measurement** (a number with a unit next to "measured", "đo", "đã đo", "gas report",
"forge", "anvil", "benchmark", or inside a results table). Each measurement needs `target:` or
`history:estimate` / `history:superseded-measurement` (a newer measurement is in a current doc).


---

## 3. Ruling ids and `decisions.md`

### 3.1 Scheme

`<AREA>-<TOPIC>-<NN>` — e.g. `NODE-JOB-03`. Regex `\b(ARCH|NODE|CTR|NET|CLI|INT)-[A-Z]{2,4}-\d{2}[a-z]?\b`.

| Area | Topics (file) |
|---|---|
| ARCH | POS (architecture.md) |
| NODE | GEN (node/README), STO (store), JOB (job-api), LANE (submit-lanes), IDX (indexer-feeds), GW (gateway), ADM (admin-auth), SPN (sponsorship), DEX (dex-venue), MESH (mesh), GSP (gossip), OPS (ops), RUN (runbooks), SEC (threat-model) |
| CTR | GEN (contracts/README), MTX, TOK, ACC, DEX, TND, AS, ZTH, PQZ, UA |
| NET | ALL (networks/README), EVM, HED, COS, SOR, SUI, APT, SOL, TON |
| CLI | APP, SGN |
| INT | ERP (generic integration), ODOO (inside the example block only) |

Numbering:

- `01–79` for rulings that are current at migration, in **order of definition in the target file** (reading
  order = id order). `80–99` for ids that are already superseded or withdrawn at migration (they exist only in
  decisions.md, so a reader can follow an old id to its replacement).
- Ids are never renumbered or reused. A clarification keeps its id. A reversal creates a new id; the old one turns
  `superseded` with `superseded-by`.
- One old ruling may **split** (clauses to different ids: `CR-PD-1(a,b)` → INT-ERP, `CR-PD-1(c)` → NODE-JOB) and
  several may **merge** (`CR-PD-2` + `CR-R3-2` → one NODE-IDX id; `CR-R3-8` → the CTR-MTX id of `CR-PD-4`).
- Statuses: `current`, `superseded`, `withdrawn`, `unused` (R36–R49, R68–R69), and **`open`** (owner question with
  a default applied in the text; proposed extension, Q10).

### 3.2 Allocation defaults (Phase 0 refines per id; exceptions are decided by reading the ruling)

| Old ids | Default new prefix | Known exceptions / splits |
|---|---|---|
| R1 | ARCH-POS (superseded) | — |
| R2, R5, R9 | CTR-MTX | R2 cost clause superseded (by R138–R140) |
| R3, R4 | CTR-DEX, CTR-TOK (superseded) | — |
| R6, R16 | NODE-JOB, NODE-STO (superseded by R87/R88) | — |
| R7, R8, R13, R14, R19 | INT-ODOO | — |
| R10, R17 | INT-ERP / CTR-MTX | decide on reading |
| R11, R12 | NODE-IDX | R11 superseded by CR-PD-2 |
| R15, R18 | NODE-LANE | — |
| R20 | NODE-STO | merged into R95 |
| CR-PD-1 | split | (a)(b) INT-ERP outbox rules; (c) NODE-JOB call table |
| CR-PD-2 + CR-R3-2 | NODE-IDX (merged) | — |
| CR-PD-3 | NODE-GW | floor/sponsor part cites NODE-SPN |
| CR-PD-4 + CR-R3-8 | CTR-MTX (merged) | pruning-family clause → NET-ALL |
| CR-PD-5 | NODE-LANE (legacy pull) | — |
| CR-PD-6 | NET-EVM | — |
| R21, CR-ADW-3, CR-ADW-4 | CLI-SGN | — |
| R22–R24, R29 | INT-ERP | R23 superseded by R57 |
| R25, CR-ADW-1 | CTR-ACC | — |
| R26 | CTR-TOK | narrowed by R63 (NET-HED) |
| R27, R28, R50, R57, R61 | INT-ODOO / INT-ERP | R50 dev-only custody also NODE-LANE |
| R30, R62, CR-R3-1, CR-R3-6 | NET-ALL | — |
| R31 | CTR-ACC | client half → CLI-SGN |
| R32, R33 | CLI-SGN | R32 scrypt clause superseded by R259 |
| R34, RS2-*, RS-NV64-*, ZL:D1–D6 | CTR-ZTH | RS2-20/25/26 client clauses cite CLI-SGN |
| R35 | CTR-DEX | book location → NODE-DEX |
| R51 | NODE-OPS | — |
| R52, CR-R3-11 | CTR-GEN | CR-R3-11 node half = R348 (NODE-STO) |
| R53 | NODE-STO | — |
| R54 | NODE-GW | — |
| R55, R58–R60 | NODE-LANE | R58 family enum superseded |
| R56 | INT-ERP | — |
| R63, R6-*, CR-ADW-2, CR-WSF-2 | NET-HED | R6-3 ERP clause → INT-ERP |
| R64, RS7-*, CR-R3-5 | NET-SUI | — |
| R65, R8-*, CR-R3-3 | NET-SOR | — |
| R66, R9-*, CR-R3-10 | NET-COS | — |
| R67, R10-*, CR-R3-7, CR-R3-9 | NET-TON | conflicts K2, K3 (§4) |
| CR-R3-4, RS12-* | NET-SOL | — |
| RS11-* | NET-APT | — |
| CR-WSF-1 | NET-ALL | per-family rendering cited from NET-SUI/NET-SOL |
| RS4-* | CTR-ACC (1–5, 10), CLI-SGN (8, 9, 11, 13–15), INT-ODOO (6, 7, 12, 16) | — |
| RS5-* | CTR-DEX (contract), NODE-DEX (book/matcher/watcher: 2, 5, 8, 9, 11, 12, 16–18), INT-ODOO (20) | RS5-6 fee clause superseded by RS5-21 |
| R70–R86 | NODE-MESH | R73 → INT-ERP (per-job bus scope); R79 superseded (R95/R99) |
| R87 | ARCH-POS (owner) | — |
| R88, R95, R96, R99, R111, R348 | NODE-STO | — |
| R89–R92, R97, R98, R100, R102–R104, R321, R323–R325, R327 | NODE-JOB | — |
| R93, R94 | NODE-IDX | — |
| R101 | INT-ERP | — |
| R105, R124, R128, R214 (node part) | NODE-DEX | — |
| R106, R106a, R107–R110, R322 | NODE-ADM | R106a crypto library: conflict K5 |
| R320, R328, R178, R159 | NODE-GW | R159/R160 serving → NODE-ADM |
| R326, R340–R342, R344–R347, R349 | NODE-LANE | — |
| R343, R316, R317 | NODE-MESH / NODE-GSP | — |
| R112–R123, R125, R126 | NODE-GSP | R127 → NODE-ADM + NODE-OPS |
| R129, R130, R133–R137, R141–R143, R146, R147, R149 | CTR-TOK | — |
| R131, R138–R140, R148 | CTR-MTX | R148 node half → NODE-LANE |
| R144 | NET-HED | — |
| R145, R188, R215, R314, R315, R330 | NET-ALL | — |
| R150–R158, R161–R177, R179 | CLI-APP | — |
| R180–R187 | CTR-TND | — |
| R189–R191, R194 | NODE-SPN | — |
| R192, R193 | CTR-MTX (receiver-pays) | — |
| R195–R199 | INT-ERP (data protection) | R196 formats verbatim |
| R200–R213, R216, R217 | CTR-AS | — |
| R230–R238, R242, R244, R246, R247 | NODE-OPS | — |
| R239–R241, R243, R245 | NODE-RUN | — |
| R250–R259, R263–R269 | CLI-SGN | — |
| R260–R262 | NET-SUI | — |
| R270–R289 | CTR-PQZ | — |
| R290–R297, R299–R306, R308–R313, R331 | CTR-UA | R298 layer 1 → CLI-SGN; R300 → CLI-SGN |
| R307 | CTR-ACC | — |
| R318 | INT-ODOO | — |
| SCaaS:N1–N16 | NODE-GEN | — |
| net-aptos:L*, net-solana:L* | NET-ALL (merged where equal) | — |
| MESH:I1–I4 | NODE-MESH | — |
| NI:I1–I8 | NODE-JOB/NODE-STO, status `open` | Q2 |
| UA:Q1–Q14, APP:Q1–Q3, S4F:Q1 | the area of the rule they confirm | most are aliases of an R-id already allocated |
| owner:* decisions | ARCH-POS | `chain-7622` → NET-EVM; `immutable` → CTR-GEN |
| UD:§n, canon:Dn (`_USER-DECISIONS` units) | the area of the rule (fees → CTR-MTX; Zether → CTR-ZTH; relayer/mesh → NODE-MESH/NODE-GSP; one binary → NODE-GEN; factory → CTR-TOK; first chain private → NET-EVM) | most are superseded or aliases of a later R-id |

### 3.3 `decisions.md` format

Two parts: hand-written entries (single source), and a generated alias index.

```markdown
### NODE-JOB-03 — Idempotency key and payload hash
- old: R91 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-03 · superseded-by: —

**Why.** Retries never duplicate; JCS makes the hash independent of key order and whitespace. A mismatch means
"the node holds a job under this key", never "dead".
**Cost if wrong.** A client upgrade that changes payload values flags `needs_attention` on re-push; nothing is lost.
**Source.** [history/specs/2026-10-06-node-independence-design.md](history/specs/2026-10-06-node-independence-design.md) §2.
```

- `old:` lists old ids, comma-separated; a clause split writes `CR-PD-1(c)`. Qualified extras use their alias
  form (`SCaaS:N4`, `net-solana:L8`, `owner:2026-10-06:families`).
- `owner: yes` when the ruling (or the clause kept) was an owner ruling; `date` = date of the ruling text that is
  current.
- Superseded entries are three lines (heading, meta line, one-sentence "what it said").
- Entries are grouped by area/topic in file order. Rationale is self-contained (R-B): it may say "an earlier design
  claimed jobs from the ERP database" but not "UD §23.1".
- Between `<!-- BEGIN alias-index (generated by scripts/docs_check.py --write) -->` and `<!-- END alias-index -->`:
  table `| Old id | New id(s) | Status |`, natural sort, regenerated by the script.

### 3.4 `scripts/docs_check.py` (new; python3 stdlib only, ~300 lines) + `scripts/test_docs_check.py`

Subcommands:

| Command | Does |
|---|---|
| `inventory` | one-time (Phase 0): scan `history/specs`, `history/plans/2026-10-03-r3-passkey-seed.md`, `history/specs/round3-wallet-signing-formats.md`, `research/_USER-DECISIONS.md` (decision units, §2.6), `history/SCaaS-2026-10-07.md` for definition lines; union with `history/ruling-ids.extra.txt` (prose-defined R8-1/2/6/7/8, R173a–c, RS-NV64-1/2, qualified extras); write `history/ruling-ids.txt` (one id per line + defining file:line). Definition regex: `^\s*(?:\|\s*\|?[-*]\s+)(?:~~)?\*{0,2}(ID)(?:\s*\((?:owner\|[Ss]uperseded)[^)]*\))?(?:\*\*\|\s*\|\|\s)` with `ID = CR-[A-Z0-9]+-\d+[a-z]? \| RS-NV64-\d+ \| RS\d+-\d+[a-z]? \| R\d+-\d+[a-z]? \| R\d+[a-z]?`. Expected ≈ 513 numbered + extras; the run prints counts per scheme and fails if they differ from §0. |
| `check` | all checks below; exit 1 on any error; warnings for budgets |
| `check --area node\|contracts\|netcli` | Phase 1 partial: C2–C4 restricted to that area's files and the id map |
| `--write` | regenerate the alias index in decisions.md |
| `resolve <id>` | old → new id(s), status, link; new → old ids. For code readers: `python3 scripts/docs_check.py resolve RS5-9` |
| `facts extract` / `facts check` / `facts trace <source>` | the fact ledger (§6.3); `trace` renders a source's items with their dispositions (used for `history/blockchain-trace.md`) |

Checks (current docs = `docs/**/*.md` minus `history/`, `reviews/`, `superpowers/`):

- **C1 coverage** — every id in `ruling-ids.txt` appears in exactly one entry's `old:` list, either unqualified, or
  only clause-qualified with distinct clauses (the entry set covering it is listed as a split in the index). Every
  `old:` token is in the inventory (typo guard).
- **C2 register integrity** — new ids unique and well-formed; heading id = meta id; status enum; `current` ⇒
  `normative` file exists and defines the id exactly once via `<a id="ID">`; `superseded` ⇒ `superseded-by`
  non-empty and every target exists; `superseded`/`withdrawn`/`unused` ⇒ defined in no current doc.
- **C3 doc ids** — every `<a id="AREA-…">` in current docs is a `current` or `open` register entry and is defined
  once across all docs; every new-id token cited in current docs exists; citing a superseded/withdrawn id outside
  decisions.md is an error.
- **C4 no old ids** — no old-id token (lookarounds `(?<![A-Za-z0-9-])…(?![A-Za-z0-9])`) in current docs outside
  decisions.md; fenced code blocks skipped.
- **C5 alias index** fresh (regenerate in memory, compare).
- **C6 links** — every relative `](path#frag)` in current docs resolves: file exists; fragment = explicit `<a id>`
  or GitHub heading slug (lowercase, strip punctuation except `-`/space, spaces → `-`, `-n` suffix for repeats).
  Links into `history/` allowed.
- **C7 artifacts** — every load-bearing token in history sources (§6.3 key extraction) is present in some current
  doc or listed in `history/dropped-artifacts.tsv` with the superseding new id.
- **C8 architecture is non-normative** — architecture.md and README.md define no ids.
- **C9 self-contained (R-B)** — banned in current docs outside `<!-- example:odoo -->…<!-- /example -->` and
  decisions.md alias index: `\bSRS\b`, `bamboo`, `\bDMS\b`, `\bNPP\b`, `canon`, `_USER-DECISIONS`, `\bUD §`,
  `\b(round|vòng) \d`, `\bspec [A-F]\b`, `\b(PD|ADW|R3D|WSF|INFRA|ZD|NI|MESH|A2|TW2|APP|TSS|AS|OPS|S4F|PQZ)\s*(§|rev\b|R\d)`,
  stream-id patterns (`\b(P\d+b?|NR\d|OP\d|S\d+′*|G\d|T\d|TB\d|RP\d|CS\d|PL\d|SP\d|AS\d|F\d+|N\d|A\d+(-\w+)?|E-S\d+|D\d)\b`
  next to "stream"), `\bdms_`, `res\.company`, `\bOdoo\b`, Vietnamese diacritics outside i18n examples
  (`[ăâđêôơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]`).
- **C10 research is background** — links into `research/` from current docs only in decisions.md `Source.` lines;
  every file under `research/` starts with the non-normative banner.
- Budgets (warning) — per-file line counts against §1 × 1.3.

Self-test `scripts/test_docs_check.py` builds a temp tree (one entry, one doc, one alias) and asserts: pass; fails
on a missing anchor; fails on an old id in a doc; fails on a banned term. CI: new job `docs` in
`.github/workflows/ci.yml` runs `python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check` when
`docs/**` or `scripts/docs_check.py` change.

### 3.5 Keeping it maintained

- New design work starts as a draft `docs/superpowers/specs/<date>-<topic>.md` (superpowers workflow) with
  provisional ids `NEW-1…`; reviews fold into the draft.
- On acceptance: text goes into the component docs, real ids are allocated in decisions.md (rationale from the
  draft), the draft moves to `history/specs/`, `docs_check.py check` passes, one commit.
- Owner rulings: `owner: yes` + date; precedence in README.

---

## 4. Known conflicts to resolve during the rewrite

**Owner?** = needs an owner decision (the default applies until answered, entry status `open`).

| # | Conflict | Evidence | Proposed resolution | Owner? |
|---|---|---|---|---|
| K1 | Call table lacks rows for tender, issuer/compliance, vesting, distribution, ExchangeOffer calls; factory excluded outright | PD CR-PD-1(c) table; TSS §A.5/§A.6/§B1 assume `call` jobs to tenders; AS §4.5, §5.5, §9.2 assume sponsored `call` jobs (claims, release, attest); integration §9 "Open"; SCaaS §15.3 | One table in node/job-api. Add rows only for **permissionless or self-authenticating** selectors on registered targets: tender `commitBid` (carries the signed deposit intent), `revealBid`, `withdrawDeposit`, `settleTender` (target `chain_contract.kind = tender`); vesting `release` / distribution `claim`, `claimMany` (target = EIP-1167 clone of the registered implementation, codehash check like `SubjectAccount`); `ExchangeOffer` legs (as `OrderBookDex.settle`). Every **role-restricted** call (`createTender`, `disqualifyWinner`, bonds, issuer/compliance interventions, `attest`, factory `create*`) goes through the role holder's own contract — existing rows `SubjectAccount.executeAsOwner`, plus a new row `Safe.execTransaction` on a registered role-holder contract — so a lane is never `msg.sender` of a privileged call. Factory stays excluded (a lane would become token creator/admin). | **Yes** (extends lane exposure; Safe row is new) |
| K2 | TON domain binding | R3D CR-R3-7: per-wallet `domains` set from master `defaultDomains`, changed by owner-wallet `SetDomains`; net-ton R10-14: `domainHash` in wallet init, domain change = new master | Node half identical in both (check domain at every door) → keep. Contract: recommend **CR-R3-7** (a set): SCaaS is multi-tenant, many ERP portals share one token; R10-14 would need one master (token) per portal domain. Residual risk (a phishing page asks for a `SetDomains` wallet tx) stated in threats. | **Yes** |
| K3 | TON DEX bounced payouts | R3D CR-R3-9: `payoutOf[queryId] → (owner, master, amount)`, `unclaimed`, permissionless `Claim`; net-ton R10-17: `bounced[master]` + admin `RefundBounced` because the bounce body is truncated to 256 bits | **CR-R3-9**: `query_id` sits in bits 32–95 of the bounced `JettonTransfer` body, so it survives truncation; the lookup needs no destination in the body. Removes an admin power (contracts/README admin-power list). Keep R10-17's other clauses (`cancel` of an unknown order ⇒ `returnExcess`; `WithdrawFees` never touches bounced/unclaimed). | Confirm (technical; changes the admin list) |
| K4 | NI lacks `CALL_TARGET_REFUSED`, `chain_contract.kind = account_factory`, event-set quorum, Door A rules, horizon config check | PD §15.4 amendment; SCaaS §6.10 "normative until NI folds" | Rewrite folds them: node/job-api (call table, error), node/store (`chain_contract.kind` values incl. `account_factory`, `dex`, `tender`), node/indexer-feeds (quorum, `scaas_finality_quorum`), node/gateway (CR-PD-3), node/store config validation (`max_valid_for_secs ≤ LANE_HORIZON` on pruning families). | No |
| K5 | JWS verification library | NI R106a / §7.1 / P2b: `ring`; A2 R114 + §18.2: "one crypto library", R106 ring ⇒ `aws-lc-rs`; SCaaS §15.3 "open (S8″)" | `aws-lc-rs` everywhere (A2 is later and explicit). | No |
| K6 | `max_gas_per_tx` default 3 M < classical Zether transfer (3.36 M; ZD says ≥ 4.2 M on Zether chains); PQZ needs 16 M on the private chain | SCaaS §15.3; ZD §15; PQZ §9.4 | Keep the 3 M default; contracts/zether and pq-zether state the per-chain minimum; node/store config validation warns when a Zether/PQZ token is registered on a chain whose cap is below it. | No |
| K7 | MESH text predates NI and A2 (standalone mode, `[odoo]`, R79, `rusqlite`, "pull instead of gossip", `ring`) | NI §13.1 lists; A2 §18.1/§18.2 "edits made in S8″" (never made) | Apply both lists exactly; node/mesh describes the post-NI/A2 state; MESH sections marked H in §2. | No |
| K8 | Research and SRS corrections listed in MESH §15.1, A2 §18.3, NI §18.1 (UD, §05, §06, canon, owner SRS) | — | Research is frozen (history); list kept in history/README for the owner's SRS. | No |
| K9 | Pull path (BUILT) vs push job API (SPECIFIED) | PD R6 vs NI R87/R97/R101 | Normative text = push API; "Transitional (BUILT)" subsections in node/job-api and node/submit-lanes describe the pull adapter until it is removed. Same pattern: DEX book in the ERP (BUILT) vs store (R105); Zether-only registry (BUILT) vs UA (R312); mesh policy from the ERP (BUILT) vs node store (R99). | No |
| K10 | Chain 9000 remnants in MESH, A2, TW2, S4F, AS, `AuthScheme.sol:7`, TRAPS.md | SCaaS §15.3 | New docs say 7622 only. History stays as it is after the running CHAINID sweep (Phase 0 waits for it). | No |
| K11 | Duplicated call table (PD, SCaaS §6.10, integration §3.6) with drift (PD lacks the epoch-bound `revokeWithSig` and `executeAsOwnerRaw` notes) | — | One table (node/job-api) from the SCaaS version, which has both notes. | No |
| K12 | Accept checks duplicated (NI §5.2, integration §3.2) | — | node/job-api only; integration links. | No |
| K13 | APP §17 corrections partly unapplied: UA §11.3 does not name `POST /v1/ua/register` | grep UA: 0 hits | Name the route in node/gateway and cite from contracts/universal-account#migration. | No |
| K14 | Precedence: SCaaS.md said "SCaaS.md > component specs" | SCaaS §0.1 | README: owner rulings (decisions.md `owner: yes`) > component docs > code (byte formats, vectors) > history > research (background only). architecture.md is not normative (C8). | No |
| K15 | TSS R189 `~gateway` default floor per profile (PD asked TSS rev 1.3 to add it) | PD §15.4 | Verify during rewrite; one statement in node/gateway#intake citing NODE-SPN. | No |
| K16 | Private chain 7622 as a classical Zether dev chain (`ZetherSafety` allowlist is {31337, 1337}) | HANDOFF-blockchain Z3; SCaaS §15.2 Q2 | Unchanged (not a dev chain) until owner decides. | **Yes** (open) |
| K17 | Curve policy for production Zether tokens (bn254 vs BLS12-381; BLS measured more expensive) | Z4; ZD §15 | Unchanged (open). | **Yes** (open) |
| K18 | Soroban on the mesh (host auth nonce as consumption signal) | MESH R77, §15.3; SCaaS §15.2 Q3 | Job-API only until decided. | **Yes** (open) |
| K19 | Second independent event source to bound a compromised node's `/v1/events` | NI §18.3, T7; SCaaS §15.2 Q4 | PLANNED item in node/indexer-feeds#limitations. | **Yes** (open) |
| K20 | OPS default numbers marked OA | OPS header | Stated as defaults; entries `open`. | **Yes** (approve) |
| K21 | NI interpretations I1–I8 (Odoo namespace `allow_call = true`; paused chain holds jobs; namespace sharing; status latency; cancel of a published job; repeated `entryRef`; names; rev 3.5 defaults) | NI §18.2; SCaaS §15.2 Q1 | Written as rules with the stated defaults, status `open`. | **Yes** (confirm) |
| K22 | Stream definitions (scope/gate/depends) live in spec "Streams" sections that become history | every spec | Default: `scaas/TODO.md` keeps stream ids and links the history section for scope; new docs carry no stream ids (R-B). Alternative: a `docs/roadmap.md`. | **Yes** (Q11) |
| K23 | HANDOFF-blockchain gates O1–O11/Z1–Z6 cite GA/SRS sections and VN-only context | — | Rewrite as self-contained items: production gates in node/runbooks and contracts/README#unaudited; tasks in TODO.md. | No |
| K24 | `scaas-node/README.md` describes only the pull model, Odoo service users, in Vietnamese | — | Rewritten in Phase 3 (English, points to docs/node/). | No |

---

## 5. References outside docs

| Where | What | Action |
|---|---|---|
| `scaas/TODO.md` | §0 "Sync SCaaS.md + integration.md" (obsolete after this), cross-spec nits (K-list), §1 stream table "Area \| Streams (spec)" | §0: close the sync item, add "docs reorg" item; §1: add column `Doc` (new file#anchor per stream group) and a column `Scope` linking the history stream section; stream ids unchanged |
| `scaas/HANDOFF.md` | reading order, links to `docs/superpowers/specs`, `SCaaS.md`, `integration.md` | new reading order (README → architecture → component docs); links updated |
| `scaas/README.md` | `docs/superpowers/` row; `blockchain.md` row | replace with `docs/` row (README, decisions, history); blockchain.md row → `docs/history/blockchain.md` + trace |
| `scaas-node/README.md` | VI, pull-model text, spec links | rewrite (K24) |
| `smartcontracts/evm/README.md`, `src/chains/private7622/README.md` | links to SCaaS.md, specs, plans, `_USER-DECISIONS` | repoint: SCaaS.md → `docs/architecture.md` or the owning contracts/* file; specs/plans/research → `docs/history/…` |
| Code comments with spec **paths** (≈ 12 files: `IZetherToken.sol`, `IZetherVerifier.sol`, `HederaSmoke.sol`, `common.tact`, `solana/…/lib.rs`, `scaas-node/src/mesh/mod.rs`, `adapters/{sui,soroban,ton,aptos,solana}.rs`, `tests/e2e_hedera.rs`) | `docs/superpowers/specs/…` | mechanical path rewrite to `docs/history/specs/…` (and `docs/superpowers/specs/blockchain-research/` → `docs/research/`, incl. `_USER-DECISIONS` path cites in `smartcontracts/evm/README.md`); comment-only diff, checked with `git diff --stat` and a grep that no non-comment line changed |
| Code comments citing **ruling ids** (≈ 900) and **sections** (≈ 400) | `R91`, `RS5-9`, `NI §5.2`, `spec §3.4`, `TW2 §7` | **No change.** Old ids stay valid through decisions.md aliases and `docs_check.py resolve`. Section references resolve against the frozen copies in `history/specs/` (same numbering); history/README maps abbreviations to files. Code comments are rewritten opportunistically when touched (and module headers in the node restructuring, §7). |
| bamboo-dms (separate repo): `dms_blockchain_dex/__manifest__.py`, `TODO.md`, `HANDOFF.md`, `TRAPS.md` | paths into `scaas/docs/superpowers/specs/…` and research | repoint to `scaas/docs/history/…` or the new doc; separate bamboo-dms commit. **Exclude** bamboo-dms's own `docs/superpowers/plans` references (e.g. in `COMPLETED.md`) — they are a different docs tree. |
| bamboo-dms addons citing ids (`dms_blockchain*`, ≈ 111) | old ids | no change (aliases) |
| `.github/workflows/ci.yml` | — | add `docs` job (§3.4) |

---

## 6. Execution

Constraints: ≤ 3 parallel agents (memory cap); no builds needed for docs; one commit per phase; no push unless the
owner asks. Agents never edit files outside their set.

### 6.1 Phases

**Phase 0 — freeze and allocate (1 agent, sequential).** Starts only after the running chainId-rename agent has
committed (it edits specs).

1. Tag `docs-pre-reorg`. `git mv` specs → `history/specs/`, research → `docs/research/` (WSF note → `history/specs/`; add banners + `research/README.md` in a separate commit so the move stays a pure rename), plans (except this
   one) → `history/plans/`, `HANDOFF-blockchain.md` → `history/`, `SCaaS.md` → `history/SCaaS-2026-10-07.md`,
   `integration.md` → `history/integration-2026-10-07.md`, `blockchain.md` → `history/blockchain.md`. Commit (pure moves: `git diff -M --stat` shows renames only).
2. Write `scripts/docs_check.py`, `scripts/test_docs_check.py`; run `inventory`; commit `history/ruling-ids.txt`
   + `.extra.txt`.
3. Run `facts extract` (§6.3) → `docs/_work/facts/*.tsv` with section-level default dispositions from §2.
4. Allocate ids: `docs/_work/id-map.tsv` (`old, clause, new, status, superseded_by, target, owner, date`) for every
   inventory id, using §3.2 and reading each ruling. Merges/splits decided here. Commit `docs/_work/` (deleted in
   Phase 2).

**Phase 1 — write component docs (3 agents in parallel, disjoint file sets).**

| Agent | Writes | Reads (history) | Order |
|---|---|---|---|
| A node | `docs/node/*.md`, `docs/_work/decisions-node.md`, `docs/_work/facts/` rows it owns | NI, MESH, A2, OPS, TSS §B1/B3, PD §3/§8/§9, R3D §A/§B, DEX §2–§3, AS §8.2–8.4, APP §9.6, SCaaS §6/§12/§13 | README → store → job-api → submit-lanes → indexer-feeds → gateway → admin-auth → sponsorship → dex-venue → mesh → gossip → ops → runbooks → threat-model |
| B contracts | `docs/contracts/*.md`, `docs/_work/decisions-contracts.md`, its fact rows | PD §2/§6, ADW §A/§D, R3D §C/§H.3, DEX §1, ZD + limits + max, TW2, AS, TSS §A/§B2, UA, PQZ, plan r3-passkey-seed, SCaaS §4/§5/§8/§14 | README → metatx → token-wrappers → accounts-mandates → dex → tender → asset-suite → zether → universal-account → pq-zether |
| C networks, clients, integration | `docs/networks/*.md`, `docs/clients/*.md`, `docs/integration.md`, `docs/_work/decisions-netcli.md`, its fact rows | net-*, WSF, R3D §D, APP, S4F, ADW §B/§C, INT, PD §4/§5, NI §10–§11, MESH §10, TSS §C, SCaaS §7/§9/§11 | networks/README → evm → hedera → cosmos → soroban → sui → aptos → solana → ton → clients/signers-clientkeys → clients/app → integration |

Rules for each Phase-1 agent: read every source section fully before writing its target; apply §1 writing rules;
cite other areas by their pre-allocated ids (id-map) without waiting for them; a needed new id is allocated in its
own prefixes (next free number) and recorded in its fragment; for every source section set the fact-ledger
disposition (section default, then per-fact where a key does not land in the default target); finish with
`docs_check.py check --area <x>` and `facts check --area <x>` clean. Each agent also disposes the
`history/blockchain.md` items routed to its area by §2.5 (A: relayer, nonce, simulation, breakers, finality,
RPC, data feeds; B: TOKEN list, interfaces, Zether, registry; C: chain scope per family, keys/custody, anti-replay,
standards list); Phase 2 disposes the rest (data-platform and 8-plane items as out-of-scope ARCH-POS entries). Each agent
also places the research **measurements** for its files (§2.6). The `_USER-DECISIONS.md` mining is a Phase 0 task
(it feeds the id map; entries are written in Phase 2).

**Phase 2 — assemble (1 agent).** Merge fragments into `decisions.md` (entries + why/cost from the history rulings,
rewritten self-contained), `--write` the alias index; write `architecture.md`, `README.md`, `history/README.md`
(abbreviation register, review-disposition note, SRS-delta table, research-correction list K8), and generate
`history/blockchain-trace.md` (§2.5); run full `check`
and `facts check`; fix; delete `docs/_work/`; commit.

**Phase 3 — outside references (1 agent; may run beside Phase 4 reviewers since files are disjoint).** §5 table.
Two commits: scaas, bamboo-dms.

**Phase 4 — verification (≤ 3 reviewer agents in parallel, read-only, then fixes by the owning area).** §6.4.

### 6.2 Mechanical checks (all must pass)

1. `python3 scripts/test_docs_check.py` and `python3 scripts/docs_check.py check` — C1–C9 zero errors.
2. `python3 scripts/docs_check.py facts check` — zero unplaced facts, zero key misses (§6.3).
3. Link check is C6 (covers README, decisions, every current doc).
4. Orphan normative text: (a) every `current` old id's new id is defined exactly once in a current doc (C1+C2);
   (b) every `superseded` id has an existing `superseded-by` (C2); (c) no superseded id is cited (C3);
   (d) no fact disposition `history-only` outside the admin section classes of §2 unless it names a superseding id.
5. `grep -rn 'docs/superpowers/specs\|blockchain-research' scaas --include=*.{rs,sol,move,tact,ts,js,py,md}`
   outside `docs/history` and `docs/research` returns nothing.

### 6.3 Fact ledger (owner requirement R-A)

`docs_check.py facts extract` splits every history source (the 26 specs, WSF, SCaaS, integration, the RS4 plan,
HANDOFF-blockchain, `blockchain.md`) by heading into sections and each section into **facts**:

| Kind | Unit | Keys extracted (language-independent, so Vietnamese sources work) |
|---|---|---|
| ruling | a definition line + its continuation | the old id; backticked identifiers; numbers |
| table-row | each row of each table (header kept for context) | every cell's backticked identifiers, numbers, quoted strings |
| list-item | each bullet / numbered item | same |
| code | each fenced block (DDL, toml, Rust/Solidity/Move, JSON, vectors) | normalized block hash + identifiers (table/column names, keys, function names) |
| formula / constant | any line with `=`, `≤`, `≥`, `<`, `>`, `2^`, `×`, `mod`, hex literals, units (`s`, `ms`, `gas`, `B`, `%`, `wei`, `days`) | the numeric tokens and the identifiers around them |
| reference | test-vector / KAT / fixture paths (`vectors/…`, `*_kat`, `*.json`, `tests/…`), threat ids (`T1–T19`, `E1–X1`), owner-ruling markers (`(owner)`, `owner:`) | the path / id |
| prose | a paragraph with a normative marker (`must`, `never`, `only`, `always`, `exactly`, `at most`, `refuse`, `reject`, `phải`, `không bao giờ`, `chỉ`, `luôn`, `từ chối`, `tối đa`) | identifiers and numbers |

Output per source: `docs/_work/facts/<source>.tsv` = `fact_id (file:line) · section · kind · excerpt · keys ·
disposition`. Disposition is one of `target:<file>#<anchor>` | `superseded:<new id>` | `history:<class>` with
class ∈ {review, revision, streams, execution-log, amendments-executed, duplicate-of:<fact_id>, research-correction, research-finding, estimate,
superseded-measurement};
for `blockchain.md` also `rejected:<new id>` | `open:<new id>` | `out-of-scope:<new id>` (§2.5).
Phase 0 fills section defaults from §2 (admin sections get `history:*`); writers override per fact.

`facts check` fails when: a fact has no disposition; a `target:` fact has a key that appears neither in the target
file nor (for identifiers) anywhere in current docs; a `superseded:` id is not superseded in decisions.md; a
`duplicate-of` points to a fact that is not itself placed. Numbers are matched as normalized tokens (`2^54`,
`2⁵⁴`, `18014398509481984` equivalents listed in a small normalization table; `3,000,000` = `3 000 000` =
`3000000`). The report lists misses per section — that list is the reviewers' work queue.

### 6.4 Reviewer pass (semantic, per component)

Three read-only reviewer agents (node / contracts / networks+clients+integration), each given its id-map rows and
fact-ledger rows. For every `current` ruling: old text vs new definition — same constraint, same numbers, same
exceptions, nothing weakened. For every section of §2 with a `target`: old section vs new section, tables row by
row, byte layouts byte by byte, threat notes and test-vector references one by one. For every `superseded`
disposition: the replacement really covers it. Output: a findings file (git-ignored, `docs/reviews/reorg/`) with
`missing | changed | wrong-target | fine` per item; the owning area fixes; checks re-run. A second reviewer (Codex
`-m gpt-5.5` if credit, else Claude) samples 10 % of `fine` rows per area.

Owner sign-off at the end: the list of `open` entries (K1, K2, K3, K16–K22) and the merged/split rulings.

---

## 7. scaas-node restructuring (plan only; read-only survey, no builds)

### 7.1 Survey (HEAD `d4c296d`)

One crate `scaas-node` (bin + lib), Rust 1.90, `alloy 1.6`, `axum 0.8`, `sqlx 0.8` (sqlite feature), no workspace.
`src/` ≈ 18 650 lines, `tests/` ≈ 4 350.

| Module | Lines | Role today | Depends on |
|---|---|---|---|
| `main.rs` | 320 | CLI (`addresses`, `store init/restored`), spawns submit/indexer/gateway/admin per config | everything |
| `config.rs` | 1 077 | toml schema + validate (`[api]`, `[store]`, `[odoo]` optional, chains, lanes, mesh) | keys, signer, store |
| `odoo.rs` | 282 | `/json/2` client **and the `Job`, `NodeConfig`, `TokenCfg`, `Report` types** | config, metatx |
| `submit.rs` | 842 | EVM runner: Odoo outbox pull, simulate, sign, broadcast, replace, gap-fill; `Work`, `InflightSet` | abi, breaker, chain, config, nonce, odoo |
| `adapter.rs` | 834 | `Family` enum, `ChainAdapter` trait (build/sign/status/index on `odoo::Job`), `lane_runner`, `recover_lane`, `lane_step(_metered)`, `index_runner/step` (all take `&Odoo`) | breaker, chain, finality, odoo, submit |
| `adapters/{evm,hedera,cosmos,soroban,sui,aptos,solana,ton}.rs` | 7 264 | one file per family | adapter, chain, config, keys, signer, **odoo**, submit (hedera, ton, evm) |
| `chain.rs`, `abi.rs`, `metatx.rs` | 503 | EVM RPC + wallet; ABI; wire ↔ struct + canonical digest | config |
| `signer.rs`, `keys.rs` | 568 | `Signer` trait, local signer; lane key derivation, keystores | — |
| `breaker.rs`, `nonce.rs`, `finality.rs` | 314 | pure: gas breaker, cold-start plan, finality window | config |
| `indexer.rs`, `drift.rs` | 314 | EVM indexer, drift C report — push to Odoo | abi, chain, finality, odoo |
| `gateway.rs`, `gwauth.rs` | 580 | door A `/v1/metatx`, DEX routes; bearer/hmac middleware | abi, breaker, chain, dex, metatx, submit |
| `admin.rs` | 290 | `/healthz` `/readyz` `/metrics` | adapter, breaker, odoo, submit |
| `dex.rs` | 1 088 | pure book/matcher | metatx |
| `dex/venue.rs` | 1 015 | venue I/O, book persisted **in Odoo** (`dex_book_commit`) | chain, finality, odoo, submit |
| `mesh/{envelope,digest,hubsig,accept,export}.rs` | 1 098 | pure library (S3): envelope 1.2, per-family digests, hub sig, L0–L3 acceptance, export filter | adapter (Family), adapters (digest), metatx, signer |
| `store/{mod,sqlite,tests}.rs` + `migrations/sqlite/0001_store_v2.sql` | 2 107 | store v2 (P1 BUILT): `Backend` trait, SQLite, owner lock + fencing, CAS, audit chain; **no `crate::` deps**; not yet the job source | — |

Findings: (1) the Odoo client and its `Job` type are threaded through every runner and all eight adapters — the
main obstacle to the push model (P3) and to P9's "delete `odoo.rs`"; (2) `adapter.rs` mixes the trait, the family
enum and the Odoo-bound runners; (3) `submit.rs` is the EVM runner, not a "submit module"; (4) store and mesh are
already clean (no I/O / no crate deps) — natural crate seams; (5) module docs are Vietnamese and cite SRS,
`_USER-DECISIONS`, GA (R-B applies to the product's code headers too); (6) no job API, admin API/auth, OIDC,
sponsorship, gossip, ops modules yet — P2–P7/G1–G3 will add them, so the layout should exist before they land.

### 7.2 Target layout

Docs ↔ code are named alike so `docs/node/<x>.md` maps to a module.

```
scaas-node/                       Cargo workspace root (crate `scaas-node` = the binary + services)
  crates/
    scaas-core/                   pure, no tokio, no network; alloy-primitives/sol-types only
      job.rs        Job, JobKind, states + transition table (from store/mod.rs pure parts + odoo::Job)
      family.rs     Family (from adapter.rs); address.rs (addresses.rs)
      metatx.rs     wire ↔ struct, canon, digest (+ abi constants it needs); jcs.rs (P2)
      finality.rs  breaker.rs  nonce.rs
      dex/book.rs   (dex.rs)
      mesh/         envelope, digest, hubsig, accept, export
    scaas-store/                  Backend trait, sqlite (+ postgres, mysql features), migrations/, contract tests
    scaas-chains/                 ChainAdapter trait, Signer, keys, evm rpc (chain.rs, abi.rs), families/<family>.rs
                                  (cargo feature per family: `fam-ton`, … default = all)
  src/                            bin crate
    main.rs  cli.rs  config/{mod.rs, validate.rs}
    lanes/      evm_runner.rs (submit.rs), lane_runner.rs + recover.rs (from adapter.rs), batches, unwrap  ↔ node/submit-lanes
    indexer/    run.rs (indexer.rs, index_runner), drift.rs, events feed builder                         ↔ node/indexer-feeds
    api/        jobs.rs, events.rs, auth_hmac.rs (job API, P2/P4)                                        ↔ node/job-api
    gateway/    mod.rs (gateway.rs), auth.rs (gwauth.rs), ops.rs (/v1/ops, N2), ua.rs                   ↔ node/gateway
    admin/      health.rs (admin.rs), auth.rs, users.rs, oidc.rs, routes.rs, audit.rs                   ↔ node/admin-auth
    dex/        venue.rs                                                                                 ↔ node/dex-venue
    mesh/       bus.rs, sched.rs; gossip/ (libp2p, feature `gossip`)                                     ↔ node/mesh, node/gossip
    sponsor.rs                                                                                           ↔ node/sponsorship
    ops/        metrics.rs, usage.rs                                                                     ↔ node/ops
    legacy/     odoo.rs — the pull adapter: implements JobSource + OutcomeSink; deleted whole at P9
```

Seams introduced: `trait JobSource` (lease next job for a lane) and `trait OutcomeSink` (report signed/mined/
reverted/consumed) in `scaas-core`; implemented by `scaas-store` and by `legacy::odoo`. Adapters take
`&core::Job`, never `&Odoo`. Crate split is justified only where it pays: `scaas-core` tests (book, mesh vectors,
digests, transitions) build without alloy-provider/axum/sqlx — smaller, faster test builds under the 4 GB cap;
`scaas-store` keeps PG/MySQL drivers out of other builds; `scaas-chains` per-family features let a family fix run
`cargo test -p scaas-chains --no-default-features --features fam-ton`. No other crates (no separate gateway/admin/
mesh crates: they share config and runtime and would only add re-export churn). `mesh/gossip` stays a module behind
a feature until libp2p build cost is measured; promote to a crate only if it hurts.

### 7.3 Migration order (tests green at every step; one heavy build at a time via `scripts/capped`)

| Step | Change | Behaviour | Gate |
|---|---|---|---|
| M0 | Baseline: record `cargo test` (lib + non-ignored integration) pass list; list `--ignored` e2e suites | — | `cargo test` |
| M1 | **Pure moves inside the one crate** to the §7.2 module tree (`git mv`; `mod` declarations; `pub use` shims in `lib.rs` keep old paths, e.g. `pub use crate::lanes::evm_runner as submit;`, so `tests/*.rs` compile unchanged) | none | `cargo test`; `git diff -M` = renames + `mod`/`use` lines |
| M2 | Drop the shims: update `use` paths in src and tests | none | `cargo test` |
| M3 | English `//!` module headers (current behaviour, new doc anchors, old ids only as "(was R58)" if useful — or none, aliases exist) | none (comments) | `cargo test` not needed; `cargo check` |
| M4 | **Job seam** (= first commit of P3): `core::job::Job` replaces `odoo::Job` (`pub use` in odoo.rs during the step), `JobSource`/`OutcomeSink` traits, `legacy::odoo` implements them, runners/adapters take the traits | none (same calls through a trait) | `cargo test` + `e2e` and one non-EVM e2e (`e2e_cosmos`, lightest) |
| M5 | Workspace + `scaas-core` crate (pure modules) | none | `cargo test --workspace`; `cargo test -p scaas-core` |
| M6 | `scaas-store` crate (already dependency-free) | none | `cargo test -p scaas-store` (contract suite) |
| M7 | `scaas-chains` crate (adapters, signer, keys, evm rpc) + per-family features | none | `cargo test --workspace`; each `e2e_<family>` alone, one at a time, when the owner schedules them |

Alignment with the pending streams (NI order S3 → P1 → NR5 → P2 → N1 → P3 (+NR2, NR4, OP1, OP8) → NR1 → P4 → P5 →
OP5 → P6 → cutover → P2b → … → P7 → … → P9):

- **M0–M3 right after the docs reorg and before P2.** P2 creates `jobs_api.rs`, `job.rs`, `admin_auth.rs`,
  `cli.rs`; they are born in `api/`, `admin/`, `cli.rs` instead of being moved later. NR5 (small: adapters'
  upgradeability read + config check) may run before or after M1; if before, M1 moves its code with the rest.
- **M4 is P3's first commit.** P3 adds the store as a second `JobSource` ("store ∪ legacy start"); the seam is what
  makes that a small change. NR2 (payload-sourced fields) and NR4 (adapter journals → store) land on the seam:
  adapters get journal access through a core trait, not through `odoo`.
- **M5–M6 after P3 is green and before P1b** (PG/MySQL backends live in `scaas-store` features from day one) and
  before NR1 touches every adapter.
- **M7 when no adapter stream is in flight**, earliest after NR1/NR4; family fix streams (`NET-*-FIX`, NR1 halves)
  then run per-family test builds.
- **P4** (events feed) lands in `indexer/` + `api/events.rs`; **P2b** in `admin/`; **SP1** in `sponsor.rs`;
  **P7** moves the book persistence in `dex/venue.rs` from `legacy::odoo` to the store; **S5/G1–G3** in `mesh/`;
  **P9** = delete `src/legacy/` + its config block + `fake_odoo` test helper (`grep -r json/2 src` empty).
- Every step is its own commit with its gate result in the message; no step mixes a move with a behaviour change.

Risks: shim period (M1–M2) briefly doubles paths — keep M1 and M2 in one session; workspace change (M5) alters
`Cargo.lock`/target dirs — run once, alone; per-family features must keep `default = all` so CI is unchanged.

---

## 8. Open owner questions (collected)

> **Answered 2026-10-07 after Phase 0:** (K25) Cosmos passkey address follows UA — 32-byte id (ADR-028-style module address) per UA R291/R315; CR-R3-1 keeps only the rpIdHash/origin/UV binding, its 20-byte address clause is superseded. (K26) Soroban non-positive `pay` amount error is `NonPositiveAmount` (i128: negative also refused); CR-R3-3's `ZeroAmount` is superseded.


> **Answered 2026-10-07 (owner: "Còn lại theo mặc định")** — every question below takes its default; record each as an owner ruling dated 2026-10-07 in decisions.md. Also confirmed: English throughout; new component ids with old ids as aliases; SCaaS.md → history + new SCaaS-v2.md product intro.


| # | Question | Default if unanswered |
|---|---|---|
| Q1 | K1: call-table rows for permissionless tender/vesting/distribution/offer selectors + a `Safe.execTransaction` row for role-holder contracts; factory stays excluded? | as proposed |
| Q2 | K21: confirm NI interpretations I1–I8 | stated defaults, status `open` |
| Q3 | K2: TON domain binding — per-wallet domain set (CR-R3-7) or one `domainHash` per master (R10-14)? | domain set (CR-R3-7) + node check at every door |
| Q4 | K3: TON bounced payouts — per-owner `unclaimed` + permissionless `Claim` (removes the admin refund)? | yes (CR-R3-9) |
| Q5 | K16/K17: chain 7622 as a classical Zether dev chain; production curve | unchanged (not dev; open) |
| Q6 | K18: Soroban on the mesh | job API only |
| Q7 | K19: second event source | PLANNED |
| Q8 | K20: approve OPS OA defaults | stated as defaults |
| Q9 | `research/13-legal-vn.md` is market-specific law (market-neutral rule: it never enters the new docs). Drop it from the repo if scaas goes public? Same question for `_GROK-CODE.md` (206 KB tool output) | keep in `research/` while private; drop both before a public release |
| Q10 | Add status `open` to the decisions register (beside current/superseded/withdrawn)? | yes |
| Q11 | K22: stream definitions — stay in history (linked from TODO.md) or a new `docs/roadmap.md`? | history + TODO.md |
| Q13 | blockchain.md requirements the specs never ruled on (ephemeral agent session keys 1–8 h, USD-denominated gas velocity limits, HCS anchoring, Hedera Schedule Service, IBC ICS-20/27, Celo fee currency): which are wanted? | recorded `open`, PLANNED where a seam exists |
| Q14 | `_USER-DECISIONS` decisions later replaced by specs (e.g. §5 mode wildcard, §23 ERP as control plane): record as superseded owner rulings, not re-open? And are the remaining unrulled UD items (e.g. §3.3 tiered-fee leakage, §22.10 open points) wanted as `open` entries? | superseded; open entries for unruled items |
| Q12 | scaas-node: approve the 3-crate workspace (core/store/chains + bin) or stop at M1–M4 (module moves + job seam, one crate)? | M1–M4 now; M5–M7 when their windows in §7.3 open |
