# TODO — scaas

Ordered by what blocks what (2026-10-06 shutdown). Owner rule: **finish all specs before app code**.
Max 3 agents, one heavy build at a time (`scripts/capped`). The Odoo side lives in bamboo-dms (`dms_blockchain*`).

## 0. Finish the spec phase (≈ 6 items)

- [x] S4F (signers) rev 1.1 — review fixes (9695051). Open for the UA fold: kindNo for keys of a Soroban `scaas-account` `C…` — default 18 (`soroban-contract` 0x0012) vs 17 (`stellar-account`).
- [ ] PQZ review → fold fixes: review in `docs/reviews/specs/2026-10-06-pq-zether-review-1.md` (FIX-THEN-GO; 4 High: params ~109/99-bit core-SVP, `fund`-dust K_MAX lock-out, LaZer GMP/MPFR/HEXL ⇒ rewrite + LGPL, `abort()` in precompile halts chain).
- [ ] UA review → fold fixes: review in `docs/reviews/specs/2026-10-06-universal-account-review-1.md` (FIX-THEN-GO; 4 High: PoP must bind `authRef` (front-run freezes Zether), closed kind sets per role (v3 `to` → Zether UA locks funds), PQ/hybrid msig unregistrable under the 12M budget, native signers sign raw digests → EIP-712 `UAAuth` wrapper). **Owner decision needed on M1**: the review proposes collapsing the MuSig2/FROST kinds into `bip340`/`schnorr-bn254` (MPC still works via one aggregate key) — MPC kinds were an owner request. Also the S4F kindNo question above.
- [ ] **NI consolidation**: fold every addition other specs listed for node-independence — `GET /v1/gateway`, gateway
      CORS + error contract, `POST /v1/ops` (app §9.6 N2), `POST /v1/ua-metatx`, `POST /v1/ua/register` (N4), Hedera
      64-byte sigs on `/v1/metatx`, denylist (`deny_subject`, OPS R246), `sponsor_policy`/`sponsor_usage` + job cost
      columns (spec B), `chain_contract`, `receiver_fee` payload + `token.features`, `usage_day`, `job.trace_id`,
      `lane_adopted`, `breaker_latch`, `[modules] metrics_bind`, store-restore pause (OPS H1), non-EVM DEX books (N3).
- [ ] **SCaaS.md / integration.md clean-up**: remove the ~9 admin-API-key mentions (`scaas_ak1.`), rewrite
      integration §10.2 (UA registration, spec F §12.3), roadmap §15 rows (S4F row 22, scrypt row in §15.3), app
      chain list gains 9000 for PQZ (PQZ §11.5), D/F amendments listed in app §17.
- [ ] Doc inconsistencies: `smartcontracts/evm/README.md` (mode bitmask kept, Zether built), `private9000` README says
      pre-London (chain runs through Fusaka), `wasm-smoke.sh` needs `--target web`, node default `max_gas_per_tx` 3M
      rejects classical Zether transfers (3.36M).

## 1. Code streams (after §0)

Suggested first wave: **NI P2 → P3** (money-safety core), **UA F0 → F1** (many specs depend on it), **app A1 + A0-evm**.

| Area | Streams (spec) |
|---|---|
| Node | P2 job API + client API keys + built-in admin/CLI → P3 submit/lanes from store → P4 indexer + `/v1/events` → P5 Odoo client (bamboo-dms) → P6 push e2e + cutover runbook → [owner cutover] → P2b OIDC + admin routes + CORS → P1b PostgreSQL/MySQL → P7 DEX in store → S1b′ → S5 mTLS bus → S6′ → G1 libp2p/QUIC-PQ → G2 announce/exclusivity/hints → G3 DEX book gossip (home-bound + unbound) → S7″ → P9 remove pull path → S8″ docs. Plus N1/N2/N4 (app §9.6), N3 non-EVM DEX books, OPS OP1–OP8, SP1 sponsorship |
| Contracts | TW2 T7 (node/Odoo/SDK follow-ups) · AS1–AS9 asset suite · TB1–TB3 tender, RP1–RP2 receiver-pays (RP1 before production registration O3), CS1–CS2 shredding, PL1 pool (later) · UA F0–F10 · PQZ E-S0…E-S9 (spikes first; licence gate G-LIC before production) |
| Clients | S4F D1–D7 · app A0–A18 (order in app spec §15) |
| Odoo (bamboo-dms) | P5, UA F6, AS/TB/SP Odoo parts, connectors wiring (S4F finding: non-EVM portal connectors not wired) |

## 2. Ops / housekeeping

- [ ] Redeploy all dev/test contracts (tags renamed); update `blockchain.token.domain_name` / Cosmos `network_key`.
- [ ] Remove merged worktrees under `.claude/worktrees/`.
- [ ] Residual TON: a `final` from the indexer before the node's `mined` still flags `landed_elsewhere` (informational).
- [ ] Queued research: none open beyond the specs above.
