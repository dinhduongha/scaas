# History (read-only)

Everything under `history/` is frozen as of the 2026-10-07 documentation reorganization (git tag `docs-pre-reorg`
marks the state before it). Nothing here is normative: the current rules are in the component docs, their rationale and
the old-id aliases in [../decisions.md](../decisions.md), and the precedence of sources in
[../README.md](../README.md#precedence). History files are never edited, except that the reorganization tooling may add
files next to them (this README, the trace, the ledgers).

**Relative links inside the history files are broken by the move.** They were written for the old layout. Map them by
hand:

| Old path (as written inside history files) | Now |
|---|---|
| `docs/superpowers/specs/<file>.md`, `superpowers/specs/<file>.md`, `specs/<file>.md` | `docs/history/specs/<file>.md` |
| `docs/superpowers/specs/blockchain-research/<file>.md`, `blockchain-research/<file>.md` | `docs/research/<file>.md` (the wallet-signing-formats note: `docs/history/specs/round3-wallet-signing-formats.md`) |
| `docs/superpowers/plans/<file>.md` | `docs/history/plans/<file>.md` |
| `docs/SCaaS.md`, `SCaaS.md` | `docs/history/SCaaS-2026-10-07.md` (frozen); the product introduction is now [../SCaaS-v2.md](../SCaaS-v2.md) and the overview [../architecture.md](../architecture.md) |
| `docs/integration.md` (before 2026-10-07) | `docs/history/integration-2026-10-07.md`; the current guide is [../integration.md](../integration.md) |
| `docs/blockchain.md`, `scaas/blockchain.md` | `docs/history/blockchain.md` |
| `docs/superpowers/HANDOFF-blockchain.md` | `docs/history/HANDOFF-blockchain.md` |

## Contents

| Path | What |
|---|---|
| `specs/` | the 26 dated design specs (each a stack of revisions with its review, disposition, superseded and stream tables inline) and the wallet-signing-formats note |
| `plans/` | implementation plans of built work; `2026-10-03-r3-passkey-seed.md` defined the rulings `RS4-1…16` |
| `SCaaS-2026-10-07.md` | the former system specification, kept unchanged for the owner's reference |
| `integration-2026-10-07.md` | the former integration guide |
| `blockchain.md` | the owner's original requirements note (Vietnamese, organized by the numbering of the owner's SRS drafts); every item is traced in [blockchain-trace.md](blockchain-trace.md) |
| `HANDOFF-blockchain.md` | owner and operator gates of 2026-10-03…06 (now production gates in [../node/runbooks.md](../node/runbooks.md) and [../contracts/README.md](../contracts/README.md), tasks in `scaas/TODO.md`) |
| `ruling-ids.txt`, `ruling-ids.extra.txt` | the frozen inventory of every old ruling id and alias with its defining line |
| `reorg/` | the reorganization ledgers: `id-map.tsv` (every old id → new id), `facts/` (every fact of every frozen source and where it landed), `section-map.tsv`, `phase0/` (provenance scripts) — read by `scripts/docs_check.py` |
| `dropped-artifacts.tsv` | tokens of the frozen sources deliberately absent from the current docs (Vietnamese quotes, revision labels, internal paths, …), each with a reason and where the meaning lives now |

## Abbreviation register

Short names used in history files, design sessions and code comments, and where their content lives now. Old ruling
ids resolve to new ids through the [alias index](../decisions.md#alias-index) or
`python3 scripts/docs_check.py resolve <id>`; section references (`NI §5.2`) resolve against the frozen file below,
whose numbering is unchanged.

| Short name / session label | File under `history/` | Last rev | Old ids | Content now in |
|---|---|---|---|---|
| PD (payments design) | `specs/2026-10-03-blockchain-payments-design.md` | 1.2 | R1–R20, CR-PD-1…6 | contracts/metatx, contracts/token-wrappers, contracts/dex, node/*, integration |
| ADW (wallets addendum) | `specs/2026-10-03-blockchain-payments-addendum-wallets.md` | 1.1 | R21–R29, CR-ADW-1…4 | contracts/token-wrappers, contracts/accounts, contracts/mandates, clients/signers-clientkeys, integration |
| R3D, "round 3" | `specs/2026-10-03-blockchain-round3-design.md` | 1.3 | R30–R67 (R36–R49 unused), CR-R3-1…11 | networks/*, node/submit-lanes, contracts/README, clients/signers-clientkeys |
| WSF (wallet signing formats) | `specs/round3-wallet-signing-formats.md` | 1.1 | CR-WSF-1…2 | networks/{hedera,ton,sui,cosmos,soroban}, networks/README |
| INFRA (infrastructure-service positioning) | `specs/2026-10-03-blockchain-infrastructure-service.md` | 1.2 | — | architecture.md (authority model) |
| ZD (Zether design, limits, ConsenSys `MAX` note) | `specs/2026-10-03-zether-design.md`, `specs/2026-10-05-zether-limits.md` (limits D1–D6, alias `ZL:D1…`), `specs/2026-10-05-zether-consensys-max.md` | 1.1 | RS2-1…26, RS-NV64-1…2 | contracts/zether, clients/signers-clientkeys |
| DEX | `specs/2026-10-03-dex-design.md` | 1.2 | RS5-1…21 | contracts/dex, node/dex-venue |
| net-hedera | `specs/2026-10-03-net-hedera.md` | 1.2 | R6-1…11 | networks/hedera |
| net-sui | `specs/2026-10-03-net-sui.md` | 1.1 | RS7-1…14 | networks/sui |
| net-soroban | `specs/2026-10-03-net-soroban.md` | 1.1 | R8-1…15 | networks/soroban |
| net-cosmos | `specs/2026-10-03-net-cosmos.md` | 1.1 | R9-1…8 | networks/cosmos |
| net-ton | `specs/2026-10-03-net-ton.md` | 1.1 | R10-1…17 | networks/ton |
| net-aptos | `specs/2026-10-04-net-aptos.md` | 1.1 | RS11-1…26, lessons `net-aptos:L1…L10` | networks/aptos, networks/README (design lessons) |
| net-solana | `specs/2026-10-04-net-solana.md` | 1.1 | RS12-1…25 (+4a, 9a, 11a, 12a, 16a, 18a), lessons `net-solana:L1…L12` | networks/solana, networks/README |
| MESH (relayer mesh), "round 4" | `specs/2026-10-05-relayer-mesh-design.md` | 3 | R70–R86 (R68–R69 unused), `MESH:I1…I4` | node/mesh, node/store, node/threat-model |
| NI (node independence) | `specs/2026-10-06-node-independence-design.md` | 3.7 | R87–R111, R106a, R320–R328, R340–R349, `NI:I1…I8` | node/* (store, job-api, submit-lanes, indexer-feeds, gateway, admin-auth, dex-venue), integration |
| A2 (mesh gossip amendment) | `specs/2026-10-06-mesh-gossip-amendment.md` | 2.1 | R112–R128 | node/gossip, node/dex-venue |
| TW2 (token wrappers v2) | `specs/2026-10-06-token-wrappers-v2.md` | 1.2 | R129–R149 | contracts/token-wrappers, contracts/metatx |
| APP (console + dApp) | `specs/2026-10-06-scaas-app-design.md` | 1.3 | R150–R179, R173a–c, `APP:Q1…Q3` | clients/app, node/gateway, node/admin-auth |
| TSS, "spec B" (tender, sponsorship, shredding) | `specs/2026-10-06-tender-sponsorship-shredding.md` | 1.4 | R180–R199 | contracts/tender, node/sponsorship, contracts/metatx (receiver-pays), integration (data protection) |
| AS, "spec A" (asset suite) | `specs/2026-10-06-asset-suite-design.md` | 1.1 | R200–R217 | contracts/asset-suite, contracts/dex, node/dex-venue |
| OPS, "spec C" (operations) | `specs/2026-10-06-operations-design.md` | 1.3 | R230–R247 | node/ops, node/runbooks |
| S4F, "spec D" (signers follow-ups) | `specs/2026-10-06-signers-followups.md` | 1.1 | R250–R269, `S4F:Q1` | clients/signers-clientkeys, networks/sui |
| PQZ, "spec E" (post-quantum Zether) | `specs/2026-10-06-pq-zether-design.md` | 1.4 | R270–R289 | contracts/pq-zether |
| UA, "spec F" (Universal Account) | `specs/2026-10-06-universal-account-design.md` | 1.4 | R290–R318, R330–R331, `UA:Q1…Q14` | contracts/accounts, clients/signers-clientkeys |
| RS4 plan (passkey and seed) | `plans/2026-10-03-r3-passkey-seed.md` | — | RS4-1…16 | contracts/accounts, clients/signers-clientkeys, integration example |
| SCaaS.md (system spec) | `SCaaS-2026-10-07.md` | 2026-10-07 | node invariants `SCaaS:N1…N16` | architecture.md, node/README (invariants), the component docs |
| HANDOFF | `HANDOFF-blockchain.md` | 2026-10-06 | gates O1–O11, Z1–Z6 | node/runbooks (production gates), contracts/README (unaudited gates), `scaas/TODO.md` |
| UD (owner decision log) | `../research/_USER-DECISIONS.md` (research, not history) | — | `UD:§n…`, `canon:Dn` | decisions.md entries (owner rulings) |
| CANON | `../research/00-CANON.md` | — | canon §Cn | background only |
| Owner decision lists | SCaaS-2026-10-07.md §0.1 and the reorg plan §8 | — | `owner:2026-10-06:*`, `owner:2026-10-07:*`, `reorg:Q1…Q14` | decisions.md (`ARCH-POS`, and the area entries they confirm) |
| Requirements note | `blockchain.md` | — | `req:blockchain.md:*` (open requirements) | decisions.md `open` entries; [blockchain-trace.md](blockchain-trace.md) |

Stream ids (`P1`…`P9`, `NR1`…, `OP1`…, `S3`, `G1`…, `N1`…, `*-FIX*`, …) are work items: their scope, gates and
dependencies stay in the "Streams" / "Code streams" sections of the specs above and are tracked in `scaas/TODO.md`
([ARCH-POS-09](../decisions.md#ARCH-POS-09)).

## Review dispositions

Each spec carries its own review log and disposition tables inline (sections named "Review log", "Claude review",
"Codex review", "Review disposition"). The raw review files are in `docs/reviews/specs/`, which is git-ignored:
they exist only in the clone where the reviews ran; other clones have the dispositions only. Reviews of the
reorganization itself go to `docs/reviews/reorg/` (also git-ignored).

## SRS deltas (owner reference)

The owner's SRS drafts (`ai-enterprise-blockchain-architecture.md` v3.3 and `ai-enterprise-blockchain-integration.md`
v2.5, outside this repository) are reference material and never edited from here. The round-3 design announced a
`2026-10-03-srs-deltas.md` file; it was never written — the deltas were collected in SCaaS.md §15.3, reproduced here
with the new homes. Current docs never mention the SRS (they are self-contained).

| Topic | SRS says | Current position | Old ruling | Now in |
|---|---|---|---|---|
| Job source | ERP outbox claimed with `FOR UPDATE SKIP LOCKED`, updates over `/json/2` | ERP pushes to the node job API and polls feeds | R87, R97, R101 | ARCH-POS-05, node/job-api, integration |
| Nonce store | Redis Lua lease + fencing generation | Node store journal + owner lock + fencing epoch | R88, R111, UD §23.7 | node/store |
| Config authority | `blockchain.chain`/`blockchain.token` in the ERP | Node store; toml bootstraps | R95 | node/store |
| Mesh transport | libp2p gossipsub only, topic `/metatx/v1`, validate with `metaTxDigest` + simulation before gossip | Gossip (open mesh) + pull bus (admitted); per-chain topics `/scaas/intent/1.2/<chain_key>`; bounded freshness read, simulation on submit only | R112, R117, R118 | node/gossip, node/mesh |
| Private profile | Mesh off, single internal hub, round robin | Admitted private peers over a PQ bus, origin-only serving | R76, R85, R113 | node/mesh |
| Ecosystems | Six ecosystems | Family taxonomy; Soroban = Stellar + Pi; Move = Aptos + Sui; Solana added; Soroban not on the mesh v1 | owner, R77 | ARCH-POS-02, networks/README |
| EOA approve lockdown | Block EOA **callers** of `approve` | Block EOA **spenders** and EOA callers of `transferFrom`; EIP-7702 designators are EOAs | R26 | contracts/token-wrappers |
| Fast path | `mtxPay(sender, …, payId, …)` and `batchMtxPay` with their own typehash | v1 `pay(bytes32 entryRef)` op and `payWithFee`; v2 named `mtxPay`/`mtxBatch` over the one pinned typehash | R2, R138–R140 | contracts/metatx |
| Tier 3 | Weighted basket (`depositBasket`/`redeemBasket`) | Any-of multi-underlying, pooled reserve, guardian disables wrap only | R136 | contracts/token-wrappers |
| Fee recipient | Relayer or any address | Never the payee (`FeeRecipientIsPayee`, v2) | R132 | contracts/metatx |
| `payId` derivation | `keccak256(companyId ‖ moveId ‖ amount ‖ ephemeralSalt)` | `entryRef` = 32 random bytes; lane = `keccak256("scaas.pay.lane" ‖ entryRef)`; v2 `payId` is `entryRef` | R9, R139 | contracts/metatx |
| Event name | `Payment(sender, recipient, amount, fee, feeRecipient, payId)` | `PaymentSettled(from, to, amount, feeAmount, feeRecipient, entryRef)` | code | contracts/metatx |
| `cancelMetaNonce` event | `MetaNonceCancelled` emitted | no event in the built code | code | contracts/metatx |
| Pipeline | 8 steps | 9 steps (nonce++ and emit separate) | code | contracts/metatx |
| Zether `n_v` | 32 | 64 | RS-NV64-1 | contracts/zether |
| `DECRYPT_BOUND` | constant 2^40 | client-configured BSGS (`bound_bits ≤ 54`) + device balance cache | RS-NV64-2 | contracts/zether, clients/signers-clientkeys |
| Large transfers | auto-split above 2^32 − 1 units | one transaction up to the balance (≤ 2^54) | Zether limits D1 | contracts/zether |
| `shieldScale` | number of decimals kept | raw units per shielded unit (e.g. `10^4`) | RS2-3 | contracts/zether |
| Zether gas | ~1.905 M per transfer; BLS cheaper | 3.29 M (bn254) / 3.92 M (BLS) measured; BLS more expensive | ZD §15 | contracts/zether |
| `IZetherToken` | 6-parameter `transferConfidential` with outer fee | 4 parameters, registration in the registry | RS2-14 | contracts/zether |
| Registry PoP challenge | `keccak256(registry ‖ encodedY ‖ msg.sender)` | built: same + `authPop`; UA: kind-tagged PoP over chain, registry, UA and `authRef`, never the caller | ZD §11.2, R295 | contracts/zether, contracts/universal-account |
| Account schemes | `AuthScheme` enum incl. `PQ_COMMITMENT` | UA kind table; PQ kinds verified on chain; `PQ_COMMITMENT` retired | R293, R313 | contracts/universal-account |
| Hedera sponsorship | payer-account sponsoring | not used; HIP-632 for ED25519 | R63 | networks/hedera |
| Cosmos | `x/feegrant` + `x/authz` | feegrant only as a seam, authz never | R66 | networks/cosmos |
| TON | W5 gasless extensions for the subject | relayer W5 lanes; custom jetton wallet verifies `SignedOp` | R67 | networks/ton |
| Sui | sponsored transactions as the gas mechanism | relayer lane PTB | R64 | networks/sui |
| Inbound API | `POST /api/v1/blockchain/{ecosystem}/{network}/inbound-{tx_type}` with raw native transactions | gateway `POST /v1/metatx` + job API `POST /v1/jobs` (signed payloads) | R30, R87 | node/gateway, node/job-api |
| Celo finality | `l1_batch` | PLANNED; `tag` until built | config | networks/evm |
| Data protection | names one country's regulation | market-neutral GDPR-class controls | owner | ARCH-POS-04, integration |
| Example amounts | local-currency examples and caps | neutral units | owner | — |
| FIPS | "FIPS 140-2 moved to historical on 2026-09-21" | FIPS 140-3 Level 3 language | canon §C15.1 | node/submit-lanes, clients/signers-clientkeys |
| Precedence | compiled code > canon > SRS | owner rulings > component docs > code (byte formats) > history > research | owner | ARCH-POS-01 |
| Redis / KeyPool | multi-wallet KeyPool canonical; Redis lease optional | lanes per chain from one mnemonic; lane scheduler; no Redis | R60, R62, UD §23.7 | node/submit-lanes |

## Research corrections (not applied; research is frozen)

Three specs listed text corrections to the research notes and the owner's SRS that were never made. Research stays
frozen; the corrections are kept here for the owner (`UD` = `research/_USER-DECISIONS.md`, `§05`/`§06` =
`research/05-open-relayer-network.md` / `06-relay-pool-enterprise.md`).

| Listed in | File and place | Correction |
|---|---|---|
| MESH §15.1 | UD §22.2 row "C. Mesh" | transport: HTTP pull bus between admitted peers (R70), later also gossipsub with per-chain topics `/scaas/intent/1.2/<chain_key>` (A2); auth mTLS with SPKI pinned per peer row (R72), libp2p Ed25519 + peer score on gossip; rate limit: per-peer token bucket, peer score per source/origin/from |
| MESH §15.1 | UD §22.2 rule 3 | keep `MAX_HOPS = 4`, incremented by the receiver on store; a row at `MAX_HOPS` is not served; private intents are never forwarded (R85) |
| MESH §15.1, A2 §18.3 | UD §23.6 diagram, §23.3 module `mesh`, §21.4 shapes | mesh = gossip + pull bus; store = the node store (intent + bus_seq); pool = the mesh store |
| MESH §15.1 | UD §22.6 `profitable()` | use the effective fee (R86) after normalizing an unbound `feeRecipient` (R84) |
| MESH §15.1, A2 §18.3 | §05 §5.0, §5.1, §5.1.2, §5.2 | public bus federated between admitted peers, libp2p built (R112); private: origin-approved private peers over the PQ bus (R76, R85, R114); exclusivity is an origin-signed round robin (R74); routes as in node/mesh; envelope `scaas-intent/1.2`, 1.0/1.1 void (R81) |
| MESH §15.1 | §06 §06.0.2 | profile default `private`, not `public` (R76) |
| MESH §15.1, NI §18.1 | PD §3.4 / R16, R6, R11, R20 | `/v1/metatx` normalizes unbound fields (R84); intents durable in the node store (R88); ERP calls the job API, the node never calls the ERP (R87); finality config in the node store (R96); RPC/database URLs and OIDC issuers toml-only (R95) |
| NI §18.1 | R3D R51, R53, R54, R56 | metrics from store counts; two pause gates (R96); job-API key ids (R92); drift via `balances` feed items and `PUT /v1/watch` (R94) |
| NI §18.1 | canon §C14.1 "two service keys" | replaced by per-namespace key scopes (R92) |
| NI §18.1 | everywhere | `scaas` names (ARCH-POS-03) |
| A2 §18.3 | owner SRS architecture draft §5.1 | topics per chain; simulation on the submit path, gossip does a bounded nonce/balance freshness read (R118); private chains never on gossip, admitted peers over the PQ bus (not a single hub) |

## The reorganization itself

Plan: `../history/plans/2026-10-07-docs-reorg.md`. New ids were allocated in old definition order (file, line)
and are never renumbered. `scripts/docs_check.py` keeps the current docs consistent with `ruling-ids.txt`, the
ledgers in `reorg/` and `dropped-artifacts.tsv`.
