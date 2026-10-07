# TODO — scaas

Ordered by what blocks what (shutdown 2026-10-07). Owner rule: **finish all specs before app code**.
Max 3 agents, one heavy build at a time (`scripts/capped`). The Odoo side lives in bamboo-dms (`dms_blockchain*`).

## 0. Finish the spec phase (5 items left)

Done 2026-10-07: every spec reviewed — Codex on PQZ/UA/NI/B, Claude on the 16 older specs — and every review
folded (dispositions inside each spec; review files in `docs/reviews/specs/`, git-ignored). Owner rulings today:
chainId 9000 → **7622**; `PqzToken` implements `IERC20MetaTx` (PQZ rev 1.4 R284); Move/Solana (and Cosmos
`--no-admin`) programs **immutable at deploy** (round3 CR-R3-11, NI R348).

- [ ] **Docs reorg** (plan `docs/superpowers/plans/2026-10-07-docs-reorg.md`): Phase 0 done 2026-10-07 (history frozen in
      `docs/history/`, research in `docs/research/`, id map in `docs/_work/`); Phases 1–4 replace the sync item below.
- [ ] ~~**Sync `docs/SCaaS.md` + `docs/integration.md`**~~ (superseded by the docs reorg; files now `docs/history/SCaaS-2026-10-07.md`,
      `docs/history/integration-2026-10-07.md`) with the latest folds — collect every "Amends"/"amendments"
      table in: NI rev 3.7 (R340–R349), PQZ rev 1.4 (R284 meta-tx, register row still says 1.2), round3 rev 1.2,
      payments rev 1.1, wallets addendum, signing-formats, infra rev 1.2, DEX rev 1.1, Zether rev 1.1, net-* rev 1.1/1.2.
      Known SCaaS.md errors: §7.7 Solana `MetaOp` is 336 B not 337; §7.6 TON TODO #8 done, `BindKey` doesn't exist
      (stateInit in `SignedOp`, R10-5); §7.4 Soroban nonce is `sha256("scaas.soroban.nonce"‖entryRef‖validUntil)`, `pay_ref`
      lock per `(from, pay_ref)` (R8-9), DEX needs relayer binding (R8-10); §7.2 `associateUnderlying()` superseded
      (R6-8, TW2 R144); §7.5 add lane-horizon client obligation (RS7-11, RS11-24, RS12-24) + Aptos multisig-wrap risk;
      §1.2/§1.3 immutability now true by ruling; admin-exception list; outbox rules into integration.md.
- [ ] Cross-spec nits: DEX RS5-15 "relayer 0 = open" needs a note — no open form on Soroban (net-soroban R8-10);
      merge PAY-FIX6 into DX-FIX3 (same 1271 cap); PAY-FIX7 (DEX fee-per-fill round-up) needs a DEX ruling;
      spec B's NI-amends row should list `job.sponsor_fallback`.
- [ ] **Codex reviews still owed** (credit ran out after 4): AS, TW2, app, OPS, S4F, mesh, A2, SCaaS.md, integration.md.
      All already have a Claude review. Run with `codex exec -m gpt-5.5 -s read-only -C <scaas> -o <out.md> "<prompt>"`
      (default `gpt-6.1-sol` is rejected for a ChatGPT account); outputs `docs/reviews/specs/*-codex-review-1.md`; fold.
- [x] **ChainId 9000 → 7622** stream CHAINID done 2026-10-07: genesis reset (`0x24e43dcb…c464`), `private7622` dir +
      foundry profile, KAT/mesh vectors regenerated, node examples, Odoo chain record + tests. Left: `private9000`
      mentions in `docs/history/SCaaS-2026-10-07.md` + `docs/history/integration-2026-10-07.md` (history: the reorg writes 7622 only); `chain_uid` = genesis hash binding (UA R330, not built);
      redeploy the dev contracts on the empty chain.
- [ ] Doc nits: `wasm-smoke.sh` needs `--target web`; node default `max_gas_per_tx` 3M < classical Zether transfer 3.36M
      (Zether rev 1.1 says ≥ 4.2M on Zether chains).

## 1. Code streams (after §0)

**Fix first (bugs found in BUILT code by the 2026-10-07 reviews):**
1. **NET-TON-FIX1** (BLOCK: unbounded forward TON drains a lane — no job API/mesh/gateway path may reach a TON lane until the node half lands), NET-TON-FIX2…4.
2. Node money safety: **NR1** breaker meters fees/value/deposits + attempt cap + grief score (R340–R342), **NR2** payload-sourced fields, value-out cap, deposit rule (R344–R346), NR3 mesh sig verify (R343, before S5), NR4 journals → `outer_tx` (R347), NR5 immutable-program check + one custody key per family (R348–R349).
3. **PAY-FIX1** Odoo outbox ACL + immutable job fields, **PAY-FIX2** node `call` target/selector table, PAY-FIX3 event-set quorum, PAY-FIX4 gateway intake, PAY-FIX5 idempotent signed report; ADW-FIX1–4.
4. DEX: DX-FIX1–5 (dust maker freeze, poison fee token, 1271 gas cap, non-EVM relayer binding).
5. Per family: R3-FIX1–15 (Cosmos passkey v2, WebAuthn vectors, event quorum, Soroban `pay_ref`, Solana build-time network, Sui `Keys`, guardians, TON domain, **R3-FIX15 immutable deploy + gate + redeploy**), WSF-FIX1–2, NET-{COSMOS,SUI,HEDERA,SOROBAN,APTOS,SOLANA}-FIXn (specs' "Luồng code" tables), ZF-FIX1–3.

Then the first feature wave: **NI P2 → P3** (money-safety core), **UA F0 → F1** (many specs depend on it), **app A1 + A0-evm**.

| Area | Streams (spec) |
|---|---|
| Node | P2 job API + client API keys + built-in admin/CLI → P3 submit/lanes from store → P4 indexer + `/v1/events` → P5 Odoo client (bamboo-dms) → P6 push e2e + cutover runbook → [owner cutover] → P2b OIDC + admin routes + CORS → P1b PostgreSQL/MySQL → P7 DEX in store → S1b′ → S5 mTLS bus → S6′ → G1 libp2p/QUIC-PQ → G2 announce/exclusivity/hints → G3 DEX book gossip (home-bound + unbound) → S7″ → P9 remove pull path → S8″ docs. Plus N1/N2/N4 (app §9.6), N3 non-EVM DEX books, OPS OP1–OP8, SP1 sponsorship · DX-FIX1 dust maker skip, DX-FIX2 fee-token allowlist + pair-failure attribution, DX-FIX5 pending commitment + market re-check + IOC single-maker + late-Matched debit (DEX spec rev 1.1; fold into P7 if P7 starts first) · ZF-FIX3 Zether verifier/registry pin (gateway + clientkeys), cache key chain id, `schnorrSign` k test-only (Zether rev 1.1) |
| Contracts | TW2 T7 (node/Odoo/SDK follow-ups) · AS1–AS9 asset suite · TB1–TB3 tender, RP1–RP2 receiver-pays (RP1 before production registration O3), CS1–CS2 shredding, PL1 pool (later) · UA F0–F10 · PQZ E-S0…E-S9 (spikes first; licence gate G-LIC before production) · DX-FIX3 `OrderBookDex` 1271 gas cap + bounded returndata (redeploy), DX-FIX4 non-EVM DEX relayer binding (Cosmos/Soroban/TON) + `min_nonce` caps (Sui/Aptos/Solana) · ZF-FIX1 `ZetherMetaTx` 1271 400k/50k + FeeWouldStick + disclosure NatSpec, ZF-FIX2 Zether invariant/subgroup/`D_out = O` tests |
| Clients | S4F D1–D7 · app A0–A18 (order in app spec §15) |
| Odoo (bamboo-dms) | P5, UA F6, AS/TB/SP Odoo parts, connectors wiring (S4F finding: non-EVM portal connectors not wired) |

## 2. Ops / housekeeping

- [ ] Redeploy all dev/test contracts (tags renamed); update `blockchain.token.domain_name` / Cosmos `network_key`.
- [ ] Remove merged worktrees under `.claude/worktrees/`.
- [ ] Residual TON: a `final` from the indexer before the node's `mined` still flags `landed_elsewhere` (informational).
- [ ] Queued research: none open beyond the specs above.
