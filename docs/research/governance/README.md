> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Governance: research index

**State, 2026-11-04.** The owner's decisions are in the register: CTR-GOV-01 to -19, in
[decisions.md](../../decisions.md#ctr-gov-01--governancebase-on-every-token-kind-and-the-dex). The model is BUILT on branch `governance`, EVM, UNAUDITED: `GovernanceBase` on the six token kinds and `SCaaSDex`, the whole `Grant` record, the two-call delay, hybrid underlying, rescue, identity by UA and one `GovernanceRouter` per chain; summary in [contracts/README.md §8](../../contracts/README.md#governance), design in the spec [2026-11-02-governance.md](../../superpowers/specs/2026-11-02-governance.md) and its [UA identity Change](../../superpowers/specs/2026-11-04-governance-ua-identity.md). SPECIFIED: the regulated implementations, `MODERATE`, `_delayedRelaxBits()`; PLANNED: every non-EVM family. The notes below are research and records of the rounds that led there. Everything cryptographic is `UNAUDITED`.

Read in this order.

| File | What it is | Status |
|---|---|---|
| [the spec](../../superpowers/specs/2026-11-02-governance.md) | The buildable design: rulings, ABI, holder, enum, regulated confidential rules, receiver check, hybrid, families, matrix, disposition of every finding, size gate, tests, build order, proposed doc text | BUILT on branch `governance` (EVM) as far as its sections say |
| [bit-table.md](bit-table.md) | The bit table after the decisions of 2026-11-02 | Record; the spec's §1.2 fixes it |
| [permission-model.md](permission-model.md) | The model, version 2: `GovernanceBase`, bit bands, `Grant`, the global bit table, the families, prior art, D1-D9 with their recommendations | Accepted as the design; its status against the build (2026-11-04) heads the note, and superseded statements are marked |
| [permission-model-gaps.md](permission-model-gaps.md) | The gaps closed after v2: a holder contract for a UA or `msig` (with the gas it runs under), the rule for relayed admin, the governance matrix from code with `file:line`, v2 re-verified, the proposed Change to CTR-AS-17, what the owner's statement on regulated confidential kinds contradicts | Record; superseded by the built model (identity by UA, the router in place of a holder contract) |
| [prototype/RESULTS.md](prototype/RESULTS.md) | The measurement: bytes per contract, room to the stop line, gas before and after, what contradicts v2, the commands | Measured |
| [permission-model-v2-attack.md](permission-model-v2-attack.md) | The attack round on v2, the gaps note and the prototype: findings B-01 to B-34, R-01 to R-19, with a test file | Record; the spec's §8 disposes of every finding |
| [model-comparison.md](model-comparison.md) | The model against OpenZeppelin, Safe, USDC, ERC-3643, Token-2022, Hedera, Stellar, Algorand, Sui, Aptos, Uniswap, Aave, Compound, Morpho, Maker, ERC-7710, Zodiac: where SCaaS is weaker or has no equivalent | Comparison |
| [permission-model-attack.md](permission-model-attack.md) | The attack round on version 1: findings A1-A21 | Record; v2 answers it |
| [permission-model-v1.md](permission-model-v1.md) | Version 1, superseded by v2 | Record |
| [gov-inventory.md](gov-inventory.md) | Every property and power in the EVM contracts at an older branch (2026-10-20), about 110 rows | Record; the matrix in the gaps note replaces its line numbers |
| [gov-survey.md](gov-survey.md) | Survey: issuers, native token frameworks, ERC-3643, DeFi, OpenZeppelin, published taxonomies. Tags [F], [M], [I] | Input |
| [gov-survey-2.md](gov-survey-2.md) | Survey: Curve, Balancer, Lido, Chainlink, Safe, Seaport, ENS, Yearn, bridges, Ethena, EigenLayer, GMX, Pendle, security councils; §15 lists 21 patterns | Input |

**Open and the owner's:** how to reduce size (CTR-GOV-19: `WrappedPqzToken` is 72,160 B, above 65,536 B), the Change to CTR-AS-17 (spec §12.1), and the questions the spec's §4.3 leaves undetermined on regulated confidential kinds.
