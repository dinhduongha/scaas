# HANDOFF — scaas

## Shutdown 2026-10-07 — read this first

Spec phase is almost closed: **every spec has had at least one independent review and every review is folded**.
Remaining spec work = TODO §0 (SCaaS.md/integration.md sync, a few cross-spec nits, 9 Codex reviews owed, the
9000 → 7622 sweep). No code was written today (owner rule); all bugs the reviews found in BUILT code are now spec
rulings + named fix streams (TODO §1 "Fix first").

### Today (2026-10-07), all pushed on `main` (head `df45e59` + this handoff)

| Commit | What |
|---|---|
| d9c227a, 4fd706c, df45e59 | NI rev 3.5 (Codex: C1 admin-user escalation, tombstones, empty token subset, live-call per namespace, `outer_tx`, atomic intake, CORS) → 3.6 (spec B + UA 1.4 sync, `chain_uid` check) → 3.7 (R340–R349: breaker meters fees/value/deposits, attempt cap, grief score, mesh sig verify, payload-sourced fields, value-out cap, deposit rule, journals in store, immutable programs, one custody key) |
| bb75ad7 | UA rev 1.4 (Codex: R330 `chain_uid` = genesis hash in PoP/domain salt; R331 EIP-7702; hedera-native member; BBS not legal evidence) |
| f3c521f, 39e42ce, 991d835 | PQZ rev 1.3 (Codex: MSG_TAG, authRef binding, hint leakage on `e1`, inline lengths, self-test price, chain 7622) → 1.4 (**owner: `PqzToken` implements `IERC20MetaTx`** like ZetherToken; v3 `UAMetaTransaction` for a PQ-only payer; `wrap`/`unwrap` parity; gasless exit = envelope `burn`) |
| 9fe2534 | spec B rev 1.3 (Codex: sponsorship accounting at accept, `min_valid_secs`, per-namespace dedupe, EIP-1153 prerequisite, itemized erasure log) |
| 9e27d35 | SCaaS.md/integration.md aligned (admin API keys removed, spec register, §8.12 PQZ, §9.8 UA, chain 7622) — needs one more sync (TODO §0) |
| 5ea19e6 | DEX + Zether + zether-limits + consensys-max (Claude review; DX-FIX1–5, ZF-FIX1–3) |
| a23f14a, 7e986f8 | payments, wallets addendum, round3, signing formats, infra-service (Claude review; PAY/ADW/R3/WSF-FIX streams) + **owner: programs immutable at deploy** (CR-R3-11) |
| df45e59 | net-{ton,cosmos,sui,hedera,soroban,aptos,solana} (Claude review; **TON C1 BLOCK**: unbounded forward TON) |
| 191c2ed | `blockchain.md` Mermaid fix (quoted edge label with parentheses) |

### Owner rulings today
- Private chain id **9000 → 7622** (9000 is Evmos Testnet); dev chain gets a new genesis; `chain_uid` = genesis hash bound everywhere (UA R330).
- `PqzToken` follows `IERC20MetaTx` (PQZ R284).
- Aptos/Sui/Solana programs **immutable at deploy** (fix = new deploy + migrate); agent extended it to Cosmos `--no-admin` per SCaaS §1.3 — owner may drop that line.
- MuSig2/FROST kinds kept; Soroban `C…` keys kindNo 18.

### Reviewer state
- Codex works **only with `-m gpt-5.5`** (default `gpt-6.1-sol` rejected for a ChatGPT account; the `codex:codex-rescue` agent fails on it). Credit ran out after 4 reviews; 9 owed (TODO §0).
- Claude reviews of the 16 older specs: `docs/reviews/specs/*-claude-review-1.md`.

### Next session
1. TODO §0 (≈ 1 hour of docs).
2. Code: TODO §1 "Fix first" (NET-TON-FIX1 first), then NI P2 → P3, UA F0 → F1, app A1.

## Earlier: shutdown 2026-10-06

SCaaS = **SmartContract as a Service: the smart contracts themselves are the API services**. `scaas-node`
(doubles as relayer) is infrastructure anyone can run, with its own policies; it is not the product.
Repo `git@github.com:dinhduongha/scaas.git`, checked out as an independent nested repo at
`bamboo-dms/scaas/` (ignored by bamboo-dms). The Odoo addons (`dms_blockchain*`) stay in bamboo-dms and read
vectors from `scaas/…`.

### State

| | |
|---|---|
| `main` | pushed (see `git log`). Merge commits were linearised by `pull --rebase` — content is complete |
| Layout | `smartcontracts/{evm,move/{aptos,sui},soroban,cosmos,ton,solana,scripts}`, `scaas-node/`, `zether-prover/`, `clientkeys/`, `app/` (planned), `docs/` |
| Code landed this session | mesh S0 (gateway fee binding), S1a (consumed state, in bamboo-dms), S2 (R80), S3 (envelope + 32 vectors), P1 store v2 SQLite + review fixes, TW2 token wrappers v2 (EVM + Hedera), TON tx-hash fix, `bamboo → scaas` rename |
| Last gates | scaas-node `cargo test` 239/0 + clippy + e2e 4/4 (after P1 fix); forge 550/0 (TW2); every family e2e 1/1 (after rename); Odoo blockchain suite 432/0 (after rename) |
| Not deployed anywhere | domain tags renamed `bamboo.* → scaas.*` ⇒ every dev/test contract must be redeployed; DB rows `blockchain.token.domain_name` ("Bamboo MetaToken") and Cosmos `network_key` (`bamboo-1`) need updating after redeploy; operators rename env `BAMBOO_* → SCAAS_*`; every node needs `scaas-node store init` once (migration 0001 was edited in place — recreate dev `node.db`) |
| Worktrees | `.claude/worktrees/{p1,p1fix,rename,s3,tonhash,tw2}` — all merged; remove when convenient |

### Specs (all on `main`, frozen in `docs/history/specs/` since the 2026-10-07 docs reorg), rulings and review state

| Spec | Rulings | Rev | Review |
|---|---|---|---|
| `docs/history/SCaaS-2026-10-07.md` (system) + `docs/history/integration-2026-10-07.md` | precedence | — | PLANNED material owner-review pending |
| `2026-10-05-relayer-mesh-design.md` | R70–R86 | 3 | ×2 |
| `2026-10-06-node-independence-design.md` (NI) | R87–R111 | 3.3 | ×1 + P1 code review |
| `2026-10-06-mesh-gossip-amendment.md` (A2) | R112–R128 | 2.1 | ×1 |
| `2026-10-06-token-wrappers-v2.md` (TW2) | R129–R149 | 1.2 | ×1 + impl review — **BUILT** |
| `2026-10-06-scaas-app-design.md` | R150–R179 | 1.2 | ×1 |
| `2026-10-06-tender-sponsorship-shredding.md` | R180–R199 | 1.2 | ×1 |
| `2026-10-06-asset-suite-design.md` (AS) | R200–R217 | 1.1 | ×1 |
| `2026-10-06-operations-design.md` (OPS) | R230–R247 | 1.2 | ×1 |
| `2026-10-06-signers-followups.md` (S4F) | R250–R268 | 1.0 → 1.1 in flight at shutdown | ×1 |
| `2026-10-06-pq-zether-design.md` (PQZ) | R270–R289 | 1.1 | review in flight at shutdown |
| `2026-10-06-universal-account-design.md` (UA) | R290–R318 | 1.2 (all owner items closed) | review in flight at shutdown |

Reviews (local, git-ignored): `docs/reviews/specs/`. Owner decisions are recorded inside each spec (owner-answers tables).

### Key owner rulings this session (details in the specs)

- Node independent of Odoo; Odoo is a client (push jobs, poll feeds). Store SQLite/PostgreSQL/MySQL (storage only).
- Admin auth: built-in users (CLI bootstrap) + optional OIDC; roles viewer ⊂ operator ⊂ admin + key_custodian.
  **API keys = external server-side clients only** (never in browser/mobile apps); automation = OIDC
  client-credentials or host CLI.
- Mesh: HTTP pull bus + libp2p gossip (QUIC default, hybrid X25519MLKEM768; TCP+Noise; HTTPS); private peers PQ-only.
- Universal Account: key-derived 32-byte kind-tagged ids, no wallet contract; native single-key accounts and 1271
  need no registration; one key = one purpose; purpose `m/7622'`; MetaToken v3 UA ledger; PQ + ed25519 everywhere;
  SubjectAccount kept as option (b); VC/eKYC optional.
- Token wrappers v2: three tiers, rates fixed/adjustable (issuer option), multi-underlying any-of, named `mtx*`
  functions, gasless unwrap with `minOut`.
- Owner wants **all specs finished before app code**.

### Constraints that bit this session

- Max 3 sub-agents; one heavy build at a time: wrap with `scaas/scripts/capped` (also `CARGO_BUILD_JOBS=4`).
- Worktrees need gitignored deps: copy `smartcontracts/evm/lib` (OpenZeppelin is a symlink to
  `/home/ha/work/blockchain/openzeppelin-contracts`), `mkdir smartcontracts/evm/deployments`, `npm ci` where needed;
  soroban e2e needs `STELLAR_BIN=~/.local/bin/stellar28`.
- `rtk` mangles `git diff`/`grep`/`ls` output in scripts — use `rtk proxy …` or `/usr/bin/grep`.
- Never `git commit -a` in scaas while an agent edits a spec in the main checkout (happened once: 9ad8711).
- Ruling-number ranges collided twice — reserve a range per spec before dispatching.
