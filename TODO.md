# TODO — scaas

Ordered by what blocks what (updated 2026-10-06 late). The Odoo side lives in bamboo-dms (`dms_blockchain*`).

### Specs (all committed on main)

| Spec | Rulings | State |
|---|---|---|
| `docs/SCaaS.md` + `docs/integration.md` | precedence, system | written; owner review of PLANNED material pending |
| `specs/2026-10-05-relayer-mesh-design.md` | R70–R86 | rev 3, reviewed ×2 |
| `specs/2026-10-06-node-independence-design.md` | R87–R111 | rev 3.2, reviewed (36 findings fixed) |
| `specs/2026-10-06-mesh-gossip-amendment.md` (A2) | R112–R128 | rev 2.1, reviewed (32 fixed) |
| `specs/2026-10-06-token-wrappers-v2.md` (TW2) | R129–R149 | rev 1.1, review in progress |

### 0. First
- [ ] Owner: confirm node-independence §18.2 interpretations.
- [ ] Redeploy every dev/test contract (domain tags renamed to `scaas.*`); fix DB rows `blockchain.token.domain_name` ("Bamboo MetaToken") and Cosmos `network_key` (`bamboo-1`) after redeploy; operators rename env `BAMBOO_*` → `SCAAS_*`.

### 1. Streams (one heavy build at a time)

Node: S3 ✅ → **P1** store v2 SQLite (in progress) → P2 job API + client API keys + built-in admin auth/CLI → P3 submit/lanes from the store → P4 indexer + `/v1/events` → P5 Odoo client → P6 push e2e + cutover runbook → [owner cutover] → P2b OIDC + full admin routes + CORS → P1b PostgreSQL/MySQL → P7 DEX in store → S1b′ → S5 → S6′ → G1 libp2p core + QUIC/PQ → G2 announce/exclusivity/hints → G3 DEX book gossip (home-bound + relayer-unbound) → S7″ e2e → P9 remove pull path → S8″ doc corrections.

Contracts: TW2 T1–T8 after its review (three tiers, rates, multi-underlying, named mtx functions, gasless unwrap, factory v2, Hedera child).

App: `app/` (React + Vite) after the node APIs — spec → plan → impl.

Fixes: TON `mined` report carries the payer jetton-wallet tx hash ✅ (merged). Residual: a `final` from the indexer before the node's `mined` still flags `landed_elsewhere` (informational) — Odoo could accept a late `mined` on `final` and clear it.

Queued: S4 follow-ups (backup-key toggle, device-bound vault, Sui `fam_sui.verify`, Soroban/Aptos/Solana signers, `chain_pay.js`), Zether portal balance cache, post-quantum Zether (BFV/BGV).

### Doc/code inconsistencies found while writing docs/SCaaS.md (2026-10-06)
- [ ] `smartcontracts/evm/README.md`: says the mode bitmask was removed (code keeps it) and Zether is "interface only" (it is built).
- [ ] `private9000` profile: READMEs say berlin, `foundry.toml` says prague.
- [ ] Seed-vault scrypt cost: round-3 R32 says N=2^15, clientkeys uses 2^17 — owner to pick; align spec or code.
- [ ] MESH §3.4 still says `ring`; R114 (A2) moved to aws-lc-rs — S8′ doc corrections.
- [ ] NI default job API bind `127.0.0.1:8547` collides with the gateway default bind — pick another port in the spec.
- [ ] Owner review of PLANNED material filled from the SRS in docs/SCaaS.md (W3B SLOs, RACI, tender interface, backup-key toggle, P2P 7-step flow).
