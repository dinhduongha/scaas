> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Governance matrix — research inputs (2026-10-20)

Owner request 2026-10-20: a governance matrix for every factory-made contract (tokens, DEX, later lending, …):
fixed by the implementation × set at creation × changeable after deployment (who, delay, bounds, lockable). Owner,
same day: **deferred** — the synthesis and the SCaaS matrix draft come later (TODO §0 "Governance matrix").

- `gov-inventory.md` — every configurable property / privileged power in today's SCaaS EVM contracts (Z2 branch
  `fd672de9`, main differences noted), ≈ 110 rows with file:line.
- `gov-survey.md` — token issuers, native token frameworks (Hedera, Token-2022, Stellar, Algorand, Sui, Aptos,
  tokenfactory), ERC-3643, Uniswap, Aave, Compound, Morpho, Euler, Maker, OpenZeppelin, L2BEAT-style taxonomies.
  Tags: [F] fetched this session, [M] from memory (re-check), [I] inference.
- `gov-survey-2.md` — Curve, Balancer, Lido, Chainlink, Safe, Seaport, ENS, Yearn v3, LayerZero / Wormhole, Ethena,
  EigenLayer, GMX, Pendle, rollup security councils (added when its run finishes).

Findings to carry into the synthesis (from the inventory): most post-deployment powers act with no delay (role grants,
DEX setters, registrar); `lockedFeatures` locks a power on, not off; CTR-TOK-22 names a delayed admin transfer that
`AdminLib` lacks; the DEX admin can neither be transferred nor renounced; a pending rate change pauses wrapping on every
adjustable leg and can be renewed without limit; no upgrade path and no emergency / rescue power anywhere.
