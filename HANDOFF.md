## Session 2026-10-31 (UA-Soroban merged, SCaaS testnet rolled out, PQZ / Zether unlocked) — resume here

**State:** `main` = this note on top of `27d77467`; origin = `63e49509` (pushed 2026-10-31 on the owner's "push"); the
`scaas-testnet` rename merge and this note are local. Running at the time of writing: branch `zether-testnet`
(classical Zether deployed + e2e + verified on the SCaaS testnet; brief `.superpowers/sdd/2026-10-31-zether-testnet/brief.md`).
Owner 2026-10-31: **continue automatically up to the contracts audit with Codex / agy / Claude, then stop** for the owner
(Codex credits ran out on 2026-10-27, owner: no refill — ask before any Codex run).

**Merged today (all on `main`):**
- `ua-soroban` (`d9af46c3`): UA on Soroban (registry, token UA ledger, mandate epoch, DEX, relay-fee router + executor,
  node `ua_metatx`, clientkeys); owner ruling A-I1 option (b): `soroban-contract` 0x0012 is not an msig MEMBER (invoker
  auth); router/executor refused as a mandate delegate. Next on Soroban: T14 Stellar testnet run (from 2026-11-03), then
  `ua8-soroban` (with the msig pop minimal form on every family), then `zether-soroban` (Z0 measures first).
- `zether-ungate` (`ea2c5c94`), owner rulings 2026-10-31:
  - classical Zether has no chain-id lock: open on every chain with EIP-2537 (BLS12-381 only; Hedera refused) — CTR-ZTH-52
    supersedes CTR-ZTH-02 / -33;
  - PQZ has no chain-id allowlist: gated by the precompile self-test only — CTR-PQZ-01 Change;
  - UA kinds enabled by capability, no `dev` flag: `bls-bn254-minsig` by the bn254 G2 probe; PQ signing kinds
    (mldsa44/65, fndsa512, slhdsa128s) where cap ≤ 66 % of the chain's verify budget (was 50 %; Hedera now gets all four)
    — CTR-UA-23 Changes;
  - an audit is not a deploy gate for the PQ kinds or ed25519 (audit still required before real funds / the SCaaS
    mainnet launch, TODO.md:14);
  - the label is just "UNAUDITED" (was "UNAUDITED — NOT FOR PRODUCTION FUNDS"; DEX KAT regenerated).
- `docs-drift-1031` (`6582329f`): stale chain-lock / audit / bn254 / one-recipient text; PQZ corpus regenerated
  (`PQZ_SET=n2304-kmax4096 corpus.py`, 877 inputs / 51 valid); `e2e.py` `first_honest()`.
- `fs3-t13-rollout` (`63e49509`), the SCaaS testnet roll-out (owner rulings 2026-10-31 throughout):
  - reset onto `2.2.0-pqz6` with option (b) calibrated rows (one ecMul baseline 0.016 ms; option (c) built, re-measure on
    a quiet host later), CREATE2 deployer `0x4e59…` in the genesis alloc (proposed for 22776, owner decides at launch);
  - node: sealer (key, pruned, internal `chain-p2p` only, `AcceptTxWhenNotSynced` — sole Clique signer goes
    `Disconnected` after ~10 min and would drop gossiped txs, 1 GiB) + rpc (archive, no key, public 8545/8546/30303,
    Docker-only 8547 for Blockscout, admin 8550 on the container loopback via sidecar), calls filter, `MaxTxSize` 2 MiB,
    `restart: unless-stopped` everywhere (option (b); watch `RestartCount`);
  - Blockscout 9.0.2 (UI port 8558, API 4000), coin-balance fetcher on, `API_RATE_LIMIT_DISABLED`, patched
    `sc-verifier` for Amsterdam (built in `/home/dockers/mba-chain-nethermind/sc-verifier/`, temporary until upstream;
    `check-image.sh` tests upstream readiness), `verify-blockscout.sh` 136 / 136 verified (Deploy.s.sol + PQZ e2e);
  - PQZ native leak test: no leak (< ≈ 50 B per verify), `pqz-core/nethermind/runs/2026-10-31-leak-harness.txt`;
  - gas facts recorded: Amsterdam caps REGULAR gas at 2^24 (calldata ≤ 261,909 B); gasLimit may exceed it for state gas;
  - reference configs `pqz-core/nethermind/chain/scaas-testnet/` (secret-free) for 22776.
- `scaas-testnet-rename` (`27d77467`): `private7622` → `scaas-testnet` (profile, chain dir, chain-uids key, CI, docs).

**Live stack** `/home/dockers/mba-chain-nethermind` is now its own git repo (owner): secrets in `.env` / `password.txt` /
`keystore` (ignored); backups `*.bak-*` ignored.

**Private notes (scratchpad/, git-ignored):** `audit-scope.md` (full external-audit scope by risk tier),
`zether-vs-pqz.md` (Classical Zether vs PQZL vs PQZH), `zether-families.md` (Soroban plan; NEAR and Algorand
feasibility, separate), `dero-he-vs-zether.md` (owner: DERO anonymity not needed), `mina-protocol.md` (no HE),
`deleted-branches-2026-10-31.txt` (SHAs of the 7 branches the owner had deleted; only `metatx-lib` kept).

**TODO added today:** Zether verifier one merged MSM (batch verification); switch to the upstream sc-verifier when it
supports Amsterdam; mandate epoch on every family; Soroban per-job fee cap + lane_hint; msig pop minimal form with UA-8
Part B; BSC venues (PancakeV3Executor) after the DEX round.

**Later the same day:** `zether-testnet` merged (`bcb0e1b5`): classical Zether live on the SCaaS testnet — the gen-1
registry of phase C lacked 0x0141 (kinds fixed at construction; gen 2 refuses 0x0141 because 0x0105 shares the
bls12381-g1 group), so the controller redeployed a full stack v2 beside phase C (salt `scaas.deploy.v2`, no reset,
716 M gas; registry `0x6814…7b79`, factory `0xFa48…9626`); on-chain e2e (register, shield, single, Compact M = 4,
BUNDLE M = 2, rollover, unshield, disclosure, wrapped) all ok; 144 verified. `deployments/7622.json` (git-ignored)
restored in the main checkout from the deploy log. TODO: owner decision on the gen-1 kind set before the SCaaS mainnet.

**Next:** (1) done; (2) prepare the contracts audit (scope since the 2026-10-27
review: UA-8, kem-scheme, msig-pophash, webauthn, DEX round, ua-soroban, zether-ungate; layout as part 2: frozen
detached worktree, units, agy in parallel, Claude workflow, one triage) and **stop for the owner before Codex**.

## Session 2026-10-30 (part 3: paused for shutdown) — resume here

**State (owner paused 2026-10-30 to shut down):** nothing running — every agent stopped, no Docker container of ours,
no `capped` job. All WIP is committed on its branch (nothing pushed from the branches). `main` = this note, ahead of
origin by the commits after `04472c24` (UA-Soroban rename `e5d913a7`, DEX spec / plan merge `c2cfc223` and the
restorePulled amendment `6e166897`, the no-Falcon-DET-1024 TODO line `3fe8d60e`, this note); push on the owner's word.
CI is green on origin `04472c24`.

**Branches in flight** (worktrees under `.claude/worktrees/`; ledgers under `.superpowers/sdd/`, git-ignored):
1. **`dex-round`** (worktree `dex-round`; plan `docs/superpowers/plans/2026-10-30-dex-round.md`; ledger
   `2026-10-30-dex-round/progress.md`): T1 (minFill floor removed), T2 (`InteractionFailed`), T3 (`mtxHybrid` /
   `mtxHybridVia`) done and reviewed; **T4 WIP `b45c4322`** (DX7 refund + `restorePulled`; not compiled). T4 must also
   forbid both `restorePulled` selectors in `_interact` (T3 review: a submitter interaction runs as the DEX = `o.dex` and
   could over-sell an order) and add the T3 review tests m1–m4; attack tests saved in `scratchpad/dex-round-DexHybridAttack.t.sol`.
   `test_dexKat` stays red until T9. Then T5–T19.
2. **`ua-soroban`** (worktree `soroban-4b`; plan `docs/superpowers/plans/2026-10-30-ua-soroban.md`; ledger
   `2026-10-30-soroban-4b/progress.md`): **T0 WIP `53e8501d`** (Protocol 30 spike: crate + quickstart / run / measure
   scripts; nothing measured yet). The first T0 agent stalled on a lost background notice; brief agents to run forge /
   cargo / docker in the FOREGROUND. stellar-cli must be pinned newer than the installed 22.2.0 (own dir). T0 is a HARD
   GATE (stop for the owner if a figure is over a limit). Then T1–T13; T14 (testnet) after 2026-11-03; then
   `zether-soroban` Z0–Z10 (Z0 = the real measure-first STOP check); then `ua8-soroban`.
3. **`kem-scheme`** (worktree `kem-scheme`; ledger `2026-10-30-kem-scheme/progress.md`): owner 2026-10-30 — the first
   byte of `kemPk` is the scheme id (1 = ML-KEM-1024 + X25519, 1,601 B; 2 reserved for ML-KEM-1024 + HQC + X25519 after
   FIPS 207). Done `90c79186` (clientkeys, `portable.json` regenerated, old copy in `vectors/ua/legacy/`). Not done:
   EVM `UARegistry` / `UAKinds` (`KEM_PK_LENGTH`, `_kemAt`), forge tests, the 9 other clients, docs (CTR-UA-32,
   decisions, client docs, UA-Soroban spec / plan), gates. Merge it before UA-Soroban T3 (the Soroban registry stores
   KEM records).

**Owner answers this part:** DEX spec accepted (DX7 refund of the taker's unsold remainder only when the sold part meets
its `minFill` and limit; capacity restored via `restorePulled`; DX10 / DX11 confirmed); `minFill` is an amount, not a
percentage (rationale in CTR-DEX-14); classical Zether on Soroban in this round (S13a; S13b PQZ none); "4b" renamed
UA-Soroban, naming `ua-<family>` / `ua8-<family>` / `zether-<family>` (NET-ALL-84); KEM scheme id; no Falcon-DET-1024
kind (Algorand waits for AVM v14 Falcon-DET-512); HQC only after FIPS 207, as scheme 2. Research answers (chat only):
C# node scope (`scratchpad/csharp-node-scope-2026-10-30.md`), Cosmos PQ (no CosmWasm verifier; SDK 0.55 `ml_dsa_65`
native accounts), NTRU (used only through Falcon), SSTORE2 (no refund; records are write-once anyway).

**Next, in order:** re-dispatch DEX T4 → T5…; re-dispatch UA-Soroban T0 (foreground) → T1…; finish `kem-scheme` and
merge before UA-Soroban T3; fs3 Task 13 + Task 9 (owner's go for timing; reset 7622 with 7702 off from
`/home/dockers/mba-chain-nethermind/genesis.json`). Max 3 agents, 2 `capped` slots.

## Session 2026-10-30 (part 2: UA-8 + no7702 merged and pushed, token rename, UA-Soroban spec + plan) — resume here

**Pushed** (origin/main `cc07fced`): fs3 Task 6 (merge `2b162239`), UA-8 step 1 (merge `0390d3cf` + fixes), EIP-7702 work
`no7702` (fast-forward to `b82f7c7f`), CI fixes (`920f13d0` Algorand artifacts in the node job, libudev for cargo-near;
`74ae18f9` node anvil e2e on the UA-8 ABI — CI green from there), the token-family rename (merge `1a68427a`), the UA-Soroban
Soroban spec (merge `b7c34170`, S13 split `70bc6cf7`), NET-ALL-84 UA checklist (`cc07fced`). **Local, not pushed:**
`04355b57` (classical Zether on Soroban in this round, spec S13a), `17342f75` (gate step `node-e2e-anvil`; parity gas
refreshed), `ee6bfd22` (parity kind labels NONE / UNDERLYING → NORMAL / WRAPPED), `f18ed81a` (merge of the UA-Soroban plan).

**Owner rulings 2026-10-30** (all in `docs/decisions.md`; ledgers `.superpowers/sdd/2026-10-30-ua8-portable-registrations/progress.md`,
`.superpowers/sdd/2026-10-30-soroban-UA-Soroban/progress.md`):
- UA-8 final review: R-node (the node relays register / setKemKey / storePqzPop / setPqzKey; split when estimate >
  min(block limit, relayer cap)); R-cross-set (setPqzKey may replace an unproven key of another set); R-7702 superseded by D1.
- EIP-7702 (after the 2026-10-29 Binance hot-wallet drain): an EOA signs with its own key only, never ERC-1271 through a
  delegate (D1); a designator direct caller is refused `CallerDelegated` wherever a caller is authority (D2); relayer
  binding guarded (D3); relay-fee targets must be contracts, designator unwrap recipients refused (D4); deploy-time code
  checks use isContract (D5); D6 (Algorand rekey refusal) built then dropped → NET-ALL-83 residual risk. **7702 off on
  the SCaaS testnet 7622** (`/home/dockers/mba-chain-nethermind/genesis.json`, takes effect at the fs3 Task 13 reset —
  never reset from a scratchpad genesis copy) **and on 22776 at launch** (NET-EVM-07). Audit:
  `docs/research/eip7702-audit-2026-10-30.md`. Disclosure rule held: ua8 pushed only together with no7702.
- Token-family rename option (a) incl. deploy keys and (follow-up) the parity labels.
- UA-Soroban Soroban spec accepted (S6 UA ledger in each token, S10 msig members confirmed); classical Zether (S13a) and PQZ
  (S13b) are separate items; **classical Zether on Soroban is in this round** (own track, measure first); NET-ALL-84: every
  family's UA spec answers the 19-row checklist; plan runs without owner review.
- C# node: scope assessment only (`scratchpad/csharp-node-scope-2026-10-30.md`), owner questions open.

**Running at this note:** UA-Soroban **T0** (Protocol 30 spike, branch `soroban-UA-Soroban`, worktree `.claude/worktrees/soroban-UA-Soroban`;
HARD GATE — stop for the owner if a UA-Soroban figure is over a limit); the combined **DEX spec** (worktree `.claude/worktrees/spec-dex`);
CI on `cc07fced`.

**Next:** UA-Soroban T1–T13 subagent-driven (T14 testnet after 2026-11-03), then `zether-soroban` Z0–Z10 (Z0 = the real
measure-first STOP check), then UA-8 Part B (`ua8-soroban`); the DEX round after its spec (owner review of the spec);
fs3 Task 13 + Task 9 calibration (owner's go for timing; reset 7622 with 7702 off; redeploy incl. the new MtxRelayFee
address; `e2e.py` full + `--split` + setPqzKey path; check `probe.sh`, which gave 28 ok / 30 FAIL against the default
engine-pqz.json on a throwaway node). Node follow-ups: gateway route `POST /v1/ua/register` + `~gateway` sponsor policy
(not in code). Docker images to prune on the owner's word (`pqz-core-artifact:t6`, `:t12`, 3 untagged).

## Session 2026-10-30 (UA-8 A1–A10; node-ua-jobs + fs3 Task 12 merged) — resume here

**State (owner paused 2026-10-30 to shut down):** nothing running — agents stopped, Docker container `pqz-t6` stopped,
no `capped` jobs.

- **`main`** = `769b3b42` (local). `origin/main` = `30dd93b0`, which holds:
  - the merges of `node-ua-jobs` (`c14b105c`: EVM node `ua_metatx` jobs) and `fs3-t12` (`a3ec5f72`: fs3 Task 12,
    `gate.sh` fin PASS);
  - the TODO update (`30dd93b0`).
  Not pushed yet: `769b3b42` — every bamboo-dms / Odoo-side item dropped from TODO (owner 2026-10-30: scaas is separate
  from bamboo-dms). The removed text is verbatim in `scratchpad/bamboo-dms-followups.md` (git-ignored).
- **UA-8 step 1** — branch `ua8`, worktree `.claude/worktrees/ua8`, tag `ref/pre-ua8`; not merged.
  - A1–A10 complete, each reviewed clean (commits `6f72d0ba..317ef775`).
  - Gas log `smartcontracts/evm/runs/2026-10-30-ua8-gas.txt`. A full registration with the PQZ proof exceeds a 60 M
    block at every set, so registrations use `register` + `storePqzPop`.
  - All nine client reproducers (clientkeys, ua-rs, ua-cs, ua-qt, ua-py, ua-go, ua-c, ua-cxx, ua-dart, ua-dart-frb)
    are on the portable digests and the PQZ key record, with the personal_sign KAT pinned.
  - **A11 paused**: WIP commit `6dd00de7` (node test in `scaas-node/src/submit.rs`, never run). The scripts
    (`script/pqz/e2e.py`, `scripts/e2e-zether.sh`) are not started.
  - Ledger with every ruling: `.superpowers/sdd/2026-10-30-ua8-portable-registrations/progress.md` (git-ignored).
    Briefs `task-*-brief.md` there; the A10 / A12 briefs carry controller additions.
- **fs3 Task 6** — branch `fs3-t12`, worktree `.claude/worktrees/fs3-t12`.
  - WIP commit `ea044220`: reproduction package edits (`pqz-core/artifact/*`) plus the completed Docker quick run
    `runs/fs3-t6-docker-quick` (2026-10-30 04:48, about 54 min).
  - A second quick run was stopped mid-way; restart it, the image is `pqz-core-artifact:t6`.
  - No report written yet. Check the run against `expected-results.json`, then commit and review.
- **Owner decisions 2026-10-30:**
  - merge `node-ua-jobs` and `fs3-t12` + push: done.
  - token-family rename: option (a), regenerate `dex_order_kat.json` and `metatx-parity.json` (CREATE2-derived fields
    only), and rename the deploy JSON keys `implementation_none…` as well. Start after the `ua8` merge, rebased onto
    main. Inventory: `scratchpad/token-rename-report.md`; worktree `.claude/worktrees/token-rename`: BUILT on branch
    `token-rename` (on main `b7c34170`; code `d4550552`, vectors `ea7a671f`, docs and gate logs after; report
    `scratchpad/token-rename-report-2.md`); waits for the owner's go to merge.
  - no bamboo-dms / Odoo items in scaas (memory `bamboo-dms-separate`).

**Next (in order, subagent-driven):**
1. UA-8 A11: re-dispatch from `6dd00de7` with `task-A11-brief.md`. Rules:
   - the node test asserts the new writes (`register` with UAAttrs, `setKemKey`, `storePqzPop`, `setPqzKey`) as
     `call` jobs, per the ledger l.115 ruling;
   - the scripts choose `storePqzPop` from the chain's real block gas limit;
   - syntax checks only.
   Then the review.
2. UA-8 A12 (docs, decisions, TODO; plus `docs/clients/ua-libraries.md`, `app.md`, `signers-clientkeys.md`; the
   deferred minors in the ledger: A7 m1 / m3, A8 N1, A6 n3, gen-1/gen-2 "one PQZ key per UA" note), then A13 (gate
   runner + CI; it must catch a client that stops building, as ua-qt did from A2 to A9), then the whole-branch review,
   then the owner's go to merge / push.
3. fs3 Task 6: restart the quick run in `fs3-t12`, write the report, then the review.
4. After the `ua8` merge: the token-family rename (a).
5. Then TODO "Now (order)" steps 3 onward: DEX round, 4b Soroban + UA-8 step 2, fs3 Task 13 + Task 9 calibration
   (ask the owner to stop other sessions before measuring).

## Session 2026-10-29 (near-algorand merged + pushed) — resume here

- `main` = the merge of `near-algorand` (owner 2026-10-29: "sửa N1 + N2 rồi merge và push"): NEAR + Algorand families,
  Tasks 1–22, whole-branch review (3 parts) → one fix wave (`3ab2c3e3`, `bc10398d`) → re-review → owner-approved residual
  fix N1 / N2 (`1736a60b`: the node never relays router → `token.mtx_trade`; NET-NEAR-31 signer-binding note). Gate runner
  31 steps rc=0 (`e3e778c7`), affected steps rc=0 after each fix. Merge conflicts only in HANDOFF.md, TODO.md and
  docs/contracts/dex.md (§11 table: NEAR / Algorand rows kept, the "no 50 % minimum fill" phrase dropped per CTR-DEX-14).
- CI note: the `algorand` CI job runs no contract behaviour tests (localnet pytest and `e2e_algorand` only in the local
  gate); the local gate stays mandatory for Algorand contract changes. The `near` job builds cargo-near from source.
- Next: the work order in TODO.md "Now (order)" from step 2 (token-family rename first; node stream; fs3 Task 12 → 6;
  specs incl. the UA-8 plan and the 4b Soroban spec). Ledger of the finished plan:
  `.claude/worktrees/near-algorand/.superpowers/sdd/2026-10-28-near-algorand/progress.md` (git-ignored; every ruling is
  in decisions.md NET-NEAR-* / NET-ALG-*).

## Session 2026-10-29 (near-algorand T16–T21) — resume here

- **`near-algorand`** (worktree `.claude/worktrees/near-algorand`): Tasks 1–21 complete and reviewed; not merged, not
  pushed (owner's go only). NEAR: contracts, adapter, clients, near-sandbox e2e 10/10
  (`smartcontracts/near/runs/2026-10-28-near-e2e.txt`). Algorand: apps, adapter, clients, localnet e2e 8/8
  (`smartcontracts/algorand/runs/2026-10-28-algorand-e2e.txt`), quote = lane decrease for every job kind. Node 426 lib
  tests + clippy. T21 wrote the docs: `docs/networks/near.md` (NET-NEAR-*), `docs/networks/algorand.md` (NET-ALG-*),
  decisions.md §35 / §36 (every spec §0 row and every controller call, superseded quote rulings NET-NEAR-80 / -81),
  README / metatx / accounts / dex / node tables with separate NEAR and Algorand rows.
- **Next:** Task 22 (gate steps in metatx-split's resumable runner, CI jobs `near` / `algorand`); then the owner's
  go for merge / push. Follow-ups: TODO.md item "NEAR and Algorand family bring-up". The SCaaS testnet `UARegistry`
  needs its redeploy at the next reset (kinds `0x0017` / `0x0018`).
- Ledger: `.claude/worktrees/near-algorand/.superpowers/sdd/2026-10-28-near-algorand/progress.md`.

## Session 2026-10-28 / 29 (metatx-split merged + pushed; near-algorand T7–T16) — resume here

**State (owner paused 2026-10-29 to shut down):** nothing running (agents stopped, no capped jobs, no algorand containers).
- `main` = `f6d5d7d7` = origin (pushed): merge of `metatx-split` (`34423173`, owner "merge và push metatx-split đi") + the
  CI clippy fix (`SignedOpFields` alias in `scaas-node/src/adapters/ton.rs`). CI green on `f6d5d7d7`. Before the merge:
  T20 closing gates (21 steps rc=0), final whole-branch review → fix wave (TON relayed-call pre-check I1, docs M1–M13) →
  3 re-review rounds (TON payment leg: LANE_TTL, balance, validity floor) → owner rulings 2026-10-28 (all controller
  proposals accepted; item 1 EIP-7702: delegate-only signatures accepted on BOTH paths, `SigCheck.isValid` follows
  CTR-UA-24 — superseded 2026-10-30 by the EIP-7702 owner rulings D1–D5, branch `no7702`; Q1 risk acceptance reversed → payment validity floor kept; Solana recovery adds a key; no fee for a no-op;
  immutable Sui / Aptos deploys) → review minors. Records in `docs/decisions.md`, TODO items for the follow-ups (EVM node
  UA path, TON passkey relays need P-256 in the node, relay-fee minimum before mainnet, e2e still owed incl. Sui
  make_immutable / Aptos immutable publish).
- **`near-algorand`** (worktree `.claude/worktrees/near-algorand`) at **`8cc5efbc`**, clean, rebased onto `main`
  (post-rebase gates all rc=0, DEX KAT regenerated). Tasks 1–15 complete, each reviewed (Critical findings fixed:
  T13 C1 mandate funding front-run → the open executes the funding itself; T15 I1 executor address off-curve via a
  creation-time salt). Key figures: NEAR msig 12 passkeys, Algorand MSIG_MAX_MEMBERS 3 (2,048 B args with Chrome-shaped
  assertions; inner budget calls relayer-paid); Algorand executor salt chosen off-curve at deploy.
  - **Task 16 (scaas-node NEAR adapter)**: `3a53404e` + fix 1 `a36dafa1` + fix 2 `32121167` (NEAR DEX `leg_settle`
    view) / `8bde594c` + fix 3 `8cc5efbc`; crate 385 lib tests + clippy rc=0. Review rounds closed I1–I3, R1–R4, f1–f4,
    N1 / N2, g1 / g2 (relayer-loss paths: router target allowlist + `_check`, same-token balance, DEX pair replica,
    120 s expiry margin, unopened-subject origins, node-set target gas / deposit). **The round-3 re-review was stopped
    before reporting** (round 3 of 5).

**Next (in order, subagent-driven):**
1. Re-dispatch the T16 fix-3 re-review (diff `.superpowers/sdd/2026-10-28-near-algorand/review-8bde594c..8cc5efbc-code.diff`;
   question: any job left that passes every node check, fails on chain at the relayer's cost and is free for the payer,
   excluding operator-listed third-party targets).
2. T17 Algorand adapter: collect the Algorand-specific "→ T16" notes of the ledger into `task-17-notes.md`, plus T15 f1
   (startup rebuilds the executor from the router's `salt` global, asserts == `executor()` and off-curve).
3. T18–T22 (clients, devnets / e2e, docs + decisions T21 with every recorded choice, closing gates T22), then the
   whole-branch review → owner rulings → merge / push on the owner's go.

## Session 2026-10-28 evening (metatx-split T20 + final review, near-algorand T7 + T8 WIP) — resume here

**State (owner paused 2026-10-28 evening to shut down):** nothing running (agents stopped, no capped jobs).
- `main` = this note, **ahead of origin** (spec `387583e9`, plan `1e28f850`, HANDOFF/TODO notes); owner 2026-10-28:
  **do not push yet**.
- **`metatx-split`** (worktree `.claude/worktrees/metatx-split`) at **`cecde76b`**, clean. Tasks 1–20 complete.
  - T20: `67fa7a45` (TON `jest.config.js` `verbose: true`, so `named-tests` sees per-test lines) + `cecde76b`. The
    resumable runner `smartcontracts/evm/runs/2026-10-27-metatx-split-gates.sh` (`--only <step>`, `GATES_FRESH=1`)
    ran all 21 steps with rc=0. Results: forge 1482 / 1482 / 1480 / 1473 pass, 0 fail; sizes 0 errors (45 contracts);
    docs 0 errors, facts 0; zether 59 + cross 6/0/0 + wasm; scaas-node 344; clientkeys 119; ua-rs 21; ua-qt 14;
    soroban 41, solana 68, cosmos 27, sui 94, aptos 140, ton 54; named-tests 260 names. The guard was self-checked:
    3 tampered log copies each exit 1.
  - Figures: `ROLL_MAX` unchanged 96 / 80 / 64 / 32 (n2560: 6,032 gas under on `uaExecute`). `debit_min_gas`
    6,826,921 / 6,998,368 / 7,168,690 / 7,358,343. The part of the split overhead that grows with data size is
    ≤ 2,405 gas (bound 8,000). `WrappedPqzToken` is 61,137 B (4,399 B headroom).
    `clients/ua-qt/build` (2 GB, git-ignored) is kept for incremental re-runs.
  - **Final whole-branch review: Ready with fixes**
    (`.superpowers/sdd/2026-10-27-metatx-split/final-review.md`, git-ignored).
    - ABIs and storage layouts vs main: only additions (`mtxPayMeta`, `uaPayMeta`, `metaPayId`, `PaymentMeta`).
      The pay-meta and relay-ref vectors, recomputed independently, show 0 mismatches. The cross-family rules hold
      on all 7 families. A trial merge into `main` conflicts only in `HANDOFF.md`.
    - **I1 (fix):** the TON node's `build_relay_fee` (`scaas-node/src/adapters/ton.rs` ~:1334-1366) never checks the
      relayed inner call. The relayer pays about 0.025 TON in bounce fees for every failing relay, and a submitter
      can repeat this at no cost. Fix: a getter-check of the inner call, refuse on failure, plus a test.
    - **I2 (owner ruling, pre-existing `6c02d686`):** Solana account recovery replaces every key. CTR-ACC-03, which
      EVM / Sui / Aptos follow, says recovery adds a key and removes none. Choose: align Solana, or record a Solana
      exception.
    - **M1–M13:** docs and records. M1–M3 `+16` cells / SET.md (n2048 `uaExecute` = 13,030,688, measured). M4
      sizes cite `size-baseline.json`. M5 relay-fee cost from `t9-fix1-relaygas.txt` + `evm.md` size rows. M6 TODO
      hashes. M7 standalone "§9 node checks per adapter" decision. M8 TON settlement-ring residual. M9 "once until
      prune / rotation" for Aptos + TON. M10 / M11 spec wording. M12 job-api errors. M13 TON meta journal: fsync the
      directory after the rename.
    - **Owner rulings list (final-review.md):**
      1. EIP-7702 delegate-only signatures: refused on the address path, accepted on the UA path.
      2. Solana recovery (I2).
      3. ua-rs / ua-qt narrowed to hash libraries.
      4. TON relay-fee only for SCaaS wallet / Mandate targets, open mode only.
      5. Keep or drop Solana's generic relay-fee entry.
      6. One rule for paying for a no-op cancel / revoke (Solana charges, Sui / Aptos abort, TON refunds).
      7. `min_amount` is one flat floor per chain, while TON / Solana have per-token maps.
      8. Once-per-payment holds only until prune / rotation (Solana, Aptos, TON).
      9. Sui / Aptos packages are upgradeable as built, while the specs say immutable.
      10. The EVM node does not serve UA payers.
      11. TON relay outcomes older than the last 128 router transactions stay `Pending`.
      12. Info: the split shrank each token kind only 269–456 B.
      13. Per-set test fixtures instead of skips.
      The earlier controller calls (previous session note) also go on this list.
- **`near-algorand`** (worktree `.claude/worktrees/near-algorand`) at **`3918209c`**.
  - **Task 7 (NEAR mandate)** is done: `a73620bb` + fix `e6986995`. The review found no Critical or Important issue
    and fund safety holds; the fix round added tests for the minors.
    - Mandate tests 9/9. Gas: open 3.9, pay 3.9–4.1, revoke 3.4, refund 2.7 Tgas. Wasm 392,814 B.
    - Choices taken (they go to decisions.md in T21):
      - `delegate: Holder` in `MandateTerms`;
      - funds held under `Ua(mandate id)`;
      - pays use `payLane(pay_ref)` at nonce 0, so `payment_settled.from` = the mandate id;
      - a pay applies the delegate's own policy;
      - revoke by the owner or the delegate, no nonce;
      - permissionless `mandate_refund`;
      - one-shot mandates.
    - Carry-forward: T13 (Algorand) needs the `delegate` field; T16 keys mandates by (token, id).
  - **Task 8 (NEAR escrow DEX): WIP commit `3918209c`.** The agent was stopped while adding extra guard tests; the
    commit is unreviewed and its test state is unknown. Controller rulings for T8 (in the ledger):
    `settle_id = sha256(digest(op_a) ‖ digest(op_b))`; a `settle_gas_pin` test; the Order / cancel / invalidate
    `extra` vectors go in the generator.

**Next (in order, subagent-driven):**
1. `metatx-split` **final fix wave** (not started; brief = final-review.md I1 + M1–M13, not I2). Then the affected
   gate steps only: `--only cargo-scaas-node`, `--only docs`, `--only gen-set`. Then a scoped re-review.
2. **Owner rulings** on I2 + list 1–13 (+ earlier controller calls). Then merge `metatx-split` into `main`
   (HANDOFF.md conflict only) and push, both only on the owner's go.
3. `near-algorand` **Task 8**: re-dispatch on top of `3918209c` (finish the tests; NEAR family to rc=0 with log
   `runs/2026-10-28-near-dex.txt`), then review. Then Tasks 9–22 automatically. Rebase onto `metatx-split` after its
   fix wave.

Ledgers: `.claude/worktrees/metatx-split/.superpowers/sdd/2026-10-27-metatx-split/progress.md` and
`.claude/worktrees/near-algorand/.superpowers/sdd/2026-10-28-near-algorand/progress.md` (each ends with a PAUSED line).

## Session 2026-10-27 / 28 (metatx split T1–T19, CI fixed, NEAR + Algorand spec + plan + T1–T6) 

**State (owner paused 2026-10-28 to shut down):** nothing running; both worktrees clean.
- `main` = `1e28f850`, **ahead of origin by 2** (NEAR + Algorand spec `387583e9`, plan `1e28f850`; not pushed). CI on
  `main` green since `a01357a9` (forge pin v1.8.5 `e5e3a46d`, e2e anvil amsterdam `123e947f`, fixed remappings
  `a01357a9` — OZ's nested lib/ had leaked into solc metadata and moved every CREATE2 address / KAT).
- Branch **`metatx-split`** (worktree `.claude/worktrees/metatx-split`) at `a3a02a1c`: **Tasks 1–19 complete**, each
  task-reviewed clean. Not merged, not pushed (merge blocker cleared: `ERC1271_FLOOR` raised in T17). Ledger:
  `.superpowers/sdd/2026-10-27-metatx-split/progress.md` (every ruling, deferred item, "Final-review item").
- Branch **`near-algorand`** (worktree `.claude/worktrees/near-algorand`) at `25f98847`, rebased onto `metatx-split`
  `a3a02a1c` (backup `backup/near-algorand-pre-rebase`): **Tasks 1–6 complete** (P-256 gate PASS 42.27 / 300 Tgas, UA
  kinds 0x0017 / 0x0018, vector generators, NEAR token, accounts / UA, metatx). Ledger:
  `.superpowers/sdd/2026-10-28-near-algorand/progress.md` (pre-flight rulings R1–R12).

**Next (in order, subagent-driven as before):**
1. `metatx-split` **Task 20** (resumable gate runner + full branch gate; affected steps only, no full pqz-core gate) —
   was stopped before writing anything; re-dispatch from `task-20-brief.md`.
2. `metatx-split` **final whole-branch review** (opus) → ONE fix wave (folds the ledger's "Final-review item" lines and
   the T19 minors) → scoped re-review → **owner rulings list** → finishing (merge + push only on the owner's go).
3. `near-algorand` **Task 7** (NEAR mandate) — stopped before writing anything; re-dispatch from `task-7-brief.md`;
   then Tasks 8–22 (owner 2026-10-28: run automatically, no plan review; merge / push need the owner's go). Rebase onto
   `metatx-split` again after its final fix wave.

**Owner rulings already given (2026-10-27 / 28):** Solana CTR-MTX-27 = static `relay_fee_<entry>` wrappers; NEAR +
Algorand right after T16 in parallel, same feature set, storage / MBR paid by the relayer, standard-compatible where
possible, "choose the best option yourself" for the rest, plan without review.

**Controller calls to put on the owner rulings list (owner may override):** relay-fee router refuses code-less targets
(EVM) / non-executable / unknown targets everywhere; `RelayFeePaid.payee` is bytes32; Soroban pay-ref set keyed
`(from, pay_ref)` + payer-signed salt; Solana router never forwards signer privileges, wrapper `ref` lane-agnostic;
Cosmos router refuses `Relay` while it has an admin; TON releases the fee only on a `RelayAck` from known SCaaS code
(no arbitrary TON targets), fees from config params; ua-rs / ua-qt stay hash + vector libraries (clientkeys builds);
EVM node UA path (uaPayMeta / uaRelay) deferred to TODO; NEAR `mtx_pay` takes any lane (NET-NEAR-07); NEAR recovery per
CTR-ACC-03 (adds a key, guardian finishes) — Solana's replace-all recovery flagged for the final review.

**Outside this repo:** the `dms_blockchain_bridge` portal bundle needs a rebuild (new clientkeys exports); the 7622
testnet `UARegistry` needs a redeploy at the next reset (near-algorand T2 kinds).

## Session 2026-10-26 / 27 (8d part 2b merged, pqz-core docs, contracts review part 2 + its fix round merged) — resume here

**State:** `main` pushed up to `3fd2e384` (owner 2026-10-27, "push đi"). Merged today: `pqz-8d2b` (`6fd75c83`) and
`review2-fix` (`e2e7a01e`). The SCaaS testnet node (7622, `2.2.0-pqz5`) was started by hand for the contracts e2e and is
**running** (no restart policy). Worktrees: `pqz-8d2b`, `review2-fix` (merged; removable), `review-2026-10-26` (detached
review target `64549aa4`, read-only; removable).

**Done:**
- **8d part 2b** (`ROLL_MAX` per set, gas per relation, PQZH calldata research, part b items (a)–(d)), its review + fix
  round: `ROLL_MAX` **96 / 80 / 64 / 32** bounded on both relay paths (`mtxExecute`, `uaExecute`; owner ruling
  2026-10-27). PQZH per-transaction cap: **owner ruling option (A)**. Testnet contracts e2e **217 ok / 0 FAIL** (three
  `e2e.py` fixes: `CAP_PQZ`, non-zero `out` probe for T, PQZ key via `recordOf`).
- **pqz-core READMEs** brought to the current state (owner: "not accurate"; 23 files, `f5abd77f`).
- **Contracts review, part 2 of three** (part 1 = core, 2026-10-25; part 3 = pqz-prover + node relay, after P6h / P6i):
  Codex C0–C2 (credits ran out at C3; **owner: no refill**), agy C0–C6, Claude UltraCode workflow C0–C6 (465 agents),
  Fable C0 + consolidation → `pqz-core/research/code-review-2026-10-26/README.md`: **1 P0, 2 P1, 5 P2, 57 P3**.
  P0 C0-1: classical Zether audited multi-recipient transfers shared one auditor mask (amounts and decoys public; PQZ not
  affected).
- **Owner rulings 2026-10-27:** C0-1 → **(ii) independent auditor randomness per leg** (the controller's first proposal
  (i), per-leg coefficients under one `s`, was found broken: `h_k·C_aud_j − h_j·C_aud_k = [h_k v_j − h_j v_k]G`); C0-2 →
  PQZH value tokens only at `n2048-kmax1024` with single-key `mldsa44` / `mldsa65` / `fndsa512` holders; C0-3 → Zether
  records in state (SSTORE2), NONE retired; C0-6 → accept (spec corrected, wallets re-prove on `PendingRange`). Triage
  items 5–10 (C0-7, C0-9, C0-10, C0-18, C5-1, C2-5) are **controller proposals, owner may override**.
- **Fix round** (`docs/superpowers/plans/2026-10-27-contracts-review-fixes.md`, subagent-driven, 9 tasks, each reviewed,
  final whole-branch review "Yes with fixes" → fix wave → re-review clean): classical Zether label `…/v3` (per-leg `t_j`,
  E6′_j, `validUntilBlock`, `AuditorKeyAsParty`), disclosure strong Fiat–Shamir (tag `SCAAS-ZETHER-DISCLOSE-V2`), PQZ
  guards, PQZ holder authorization bound, metatx / DEX hardening (500 k cap on outside-token calls, nonce cap, release
  deploy gate on `block.gaslimit`), node / client items (`uaSigner` required on relayed Zether builds), docs. Gates
  (resumable runner `smartcontracts/evm/runs/2026-10-27-review2-gates.sh`, owner 2026-10-27: per-step logs, skip done):
  forge at four sets 1,396–1,402 pass / 0 fail, sizes 0, gen-set, docs, zether-prover cargo + wasm + cross-check 6/6,
  scaas-node, clientkeys — all rc=0. Every controller ruling of the round: README "Fix round" and the ledger copy
  `scratchpad/review2-fix-ledger-2026-10-27.md` (`Ruling:` lines).

**Open / owner:**
1. ~~Push `main`~~ done 2026-10-27 (`6ac02dc5..3fd2e384`).
2. ~~Gas run for the Zether prover~~ done 2026-10-27 (merge `gas-zether`); Task 9 calibration (timing) still needs the
   owner's go.
3. ~40 deferred minors (README "Fix round"). ~~facts check misses~~ fixed (merge `docs-facts`). Dependabot: #42–#45
   `fast-uri` fixed (`885c91f4`), #36 closed, #19 / 20 / 21 left open (owner 2026-10-22).
4. The node keeps running (owner 2026-10-27: leave it).

**Next (TODO §00):** Task 9 calibration (owner's go) → metatx split + `mtxPayMeta` → `MtxRelayFee` (re-check PQZH n2048
`uaExecute` headroom 1.3–2.8 KB and n2560's `ROLL_MAX` margin 15,281 gas with it; done on branch `metatx-split`: the margin is now 6,032 gas, see TODO P6 item 5) → UA-8 → fs3 Task 12 → 6 → 13 → 14,
UA-7, governance; publications (fill gas / timing / package placeholders, LaZer preview mail).

## Session 2026-10-26 (part b merged, testnet on pqz5, pqz-16k merged into main, 8d part 2b paused, publication drafts) — resume here

**State:** `main` has plan 5h part B, R0 fix part a + b and the pqz5 roll-out (merge `d07d0057`; forge 1361 / 0 / 9,
size gate 0 errors); pushed up to `d14fe16f`. Local `main` commits not pushed: `fc0749db`, `ca57f2ae` (TODO), this note.
`pqz-16k` `31af331e` pushed and now merged into `main`: later work branches from `main`. SDD ledger (git-ignored):
`.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/` (`progress.md`, `task-8d-report.md`,
`task-r01-report.md`, briefs and reviews).

**Done today:**
- **R0 fix part b** (contracts, node, spec / docs) + fix round + re-review **Approved** → fast-forwarded into `pqz-16k`
  and pushed (`349b96b8`). Owner ruling I-1 option (a): the start-up id check reads the schedule at the block-tree head
  + 1 (genesis on an empty DB), not the wall clock; an id switch on a running chain swaps after T (spec §9.1, RUNBOOK
  path A, CTR-PQZ-10).
- **SCaaS testnet (7622) on `scaas/nethermind-pqz:2.2.0-pqz5`** (`n2304-kmax4096`, PQZL v5 / PQZH v3, provisional
  prices × 1.3 until Task 9): reset on path B, image `4d906b55…`, library `dd0e7668…`, probe 420 ok / 0 FAIL, e2e 84 ok
  / 0 FAIL (`31af331e`; stack backups `*.bak-pqz4-20261026`). No PQZ / UA contracts deployed yet. The node container
  has **no restart policy**: after the shutdown start it by hand (`docker compose up -d blockchain-node` in
  `/home/dockers/mba-chain-nethermind`) or leave it stopped (owner's choice; the 2026-10-25 shutdown stopped it too).
- **`pqz-16k` merged into `main`** (owner order 2026-10-26: right after the roll-out).
- **Publication drafts** (P6-PUB; owner 2026-10-26 scope: only PQ + PQZ results) in `scratchpad/pub/` (git-ignored,
  never commit / post): `ethresearch-post.md`, `eprint/main.tex` + `refs.bib`, `NOTES.md` (sources per number,
  placeholders, owner rulings §5), `lazer-preview-mail.md`. Author Đinh Dương Hà ("Dinh Duong Ha"), SCaaS project,
  `ai@dad.vn`; links to `main`; the 2026-10-25 review stated as AI-assisted; LaZer maintainers thanked; the licence
  sentence of the mail kept. Placeholders: TBD-GAS (8d part 2b), TBD-TIME (Task 9), TBD-PKG (fs3 Task 6), the posting
  date, attachments. LaZer gets the drafts 1–2 weeks before posting, no waiting for a reply; the G-LIC letter was sent
  earlier and has no reply.

**8d part 2b — paused** (branch `pqz-8d2b`, worktree `.claude/worktrees/pqz-8d2b`, from `main` `d14fe16f`; brief
`task-8d2b-brief.md`): head `6027eff5` (5 commits), stopped by the owner at
  shutdown right after the last forge run restored `PqzSet.sol` to HEAD.
  - **Done, committed:** item 2: `ROLL_MAX` measured and pinned per set (96 / 80 / 64 / 48; `set.toml` → gen_set →
    `PqzSet.ROLL_MAX`; `AMS_ROLL_MAX` / `ROLL_CEILING` deleted), the gas table per relation and set, the hint-test fix,
    docs. Items 3 (a)–(d): the C wasm32 arena peak at M = 2 is 303.5 / 356.7 / 413.3 MiB at n2048 / n2304 / n2560, margins
    1.69 / 1.44 / 1.24×; `PQZ-START` logs the id check's head; the R4-C6 panic child-process test; the Dockerfile
    self-test label. Item 1: research note `docs/research/pqzh-calldata-cap.md` with a proposal. It gives both regimes:
    the EIP-7976 floor allows 261,909 B, EIP-7623 alone 418,905 B. **The owner decides the option**; nothing is
    implemented.
  - **Uncommitted, on disk:** `smartcontracts/evm/script/pqz/e2e.py` (`CAP_PQZ` 3,000,000 → 4,500,000: `R_REG`
    verify costs 3.62 M at n2304's provisional row, so 3 M would revert every testnet registration); the logs
    `smartcontracts/evm/runs/2026-10-26-t8d2b-forge-<set>.txt` (4) and `…-t8d2b-sizes.txt`. Forge: 1,363 pass / 2 fail
    at n2048 / n2304 / n2560 and 1,361 / 2 at n2816. The same 2 tests fail everywhere (`test_storageL…`,
    `test_libraryErrorsAre…`), because they read `out/` artifacts that a fresh worktree lacks (`at-set.sh` builds into
    `out/at-set-<set>`). Size gate: 0 errors.
  - **Resume:** in the worktree run `forge build` once, then `script/pqz/at-set.sh <set> test` at all four sets (expect
    0 fail). Commit e2e.py and the logs. Item 4: the e2e on the testnet with `script/pqz/e2e.py` (`pqz_prove` is built;
    fresh factory; documented test key). Then write `task-8d-report.md` "Part 2b — Result" and a `progress.md` line →
    review → fix round.
  - **Findings for the owner** (in the committed docs): op 7 M = 8 uses 54–70 M state gas (EIP-8037), more than a 60 M
    block at every set but n2560. PQZH debits fit one transaction only at n2048, and there not op 7 M = 4 with the
    auditor and not with the hint. n2816's `ROLL_MAX` 48 is only 7,296 gas under `0.75 · 2^24`.

**Next (order, TODO §00 "Now"):** (1) resume 8d part 2b (steps above) → review → fix
round → owner ruling on the PQZH calldata option (`docs/research/pqzh-calldata-cap.md`) → merge into `main`;
(2) one Codex pass on the contracts (`codex sandbox` check first); (3) Task 9 calibration (timing: owner stops the other
heavy sessions first); (4) metatx split with `mtxPayMeta` → `MtxRelayFee`; then UA-8, fs3 Task 12 → 6 → 13 → 14, UA-7,
governance. Publications: fill gas after (1), timing after (3), the package after fs3 Task 6, then the LaZer preview
mail, 1–2 weeks, post.

**Branches / worktrees:** `pqz-r01` (merged; removable), `pqz-8d1` (merged; removable), `pqz-8d2a` (keep local,
**never push**: ≈ 10 MB of fixtures in its history; squash-merged), `review-2026-10-25` (detached, read-only review
target; removable), `metatx-lib` (older, not part of this session).

## Session 2026-10-26 (R0 fix part a built, reviewed, fix round paused) — resume here

**State:** main + this note (main local commits not pushed: `4d6482ff` UA-7 / UA-8 / research note, and this note).
SDD ledger (git-ignored): `.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/` —
`progress.md` (last lines = this session), `task-r01a-brief.md`, `task-r01-report.md` ("Part a — Result",
"Part a — Fix round (paused 2026-10-26)"), `task-r01a-review.md`, `task-r01a-fix-brief.md`.

**Branches (none pushed):**
- `pqz-16k` `bb324c56`: 8d part 2a squash-merged (`19f3135e`, `ab47f974`) and the whole-core review plan.
- `pqz-r01` (worktree `.claude/worktrees/pqz-r01`): the review outputs (Codex / agy / Claude UltraCode / Fable, the
  consolidated triage in `pqz-core/research/code-review-2026-10-25/README.md`) and **R0 fix part a** (`411dea7e` …
  `37d2971f`, plus the fix-round commits after it).
- `pqz-8d2a`: keep local, **never push** (about 10 MB of fixtures in its history).

**Done:**
- **Whole-core review 2026-10-25:** R0-1 (audited R_TXM auditor copies share randomness: P1), R0-C2 (`Bprime = 8`),
  R0-C3 (η filter on the challenge), F-4 and the P3 / P4 items.
  - Owner rulings: R0-1 direction 2; `s_aud` 2 / 3 / 4 / 4 with the auditor on (groups of 4 without it); the n2048
    exception widened to dual_hybrid ≈ 444; one id bump per set ("gom").
  - `MAX_PROOF_PQZH` = 327,680 and `MAX_INPUT` = 524,288 at the PQZH sets (CTR-PQZ-10).
- **R0 fix part a (core):** PQZL `…/v5` and PQZH `…/v3` at all four sets.
  - Every spec has β ≥ 450 (n2048 has its first `e-s1.txt`).
  - Largest PQZL proofs are 85,167 / 80,330 / 72,761 / 79,208 B (n2048 / n2304 / n2560 / n2816).
  - Full gates ran at all four sets. Five parts failed; all five were fixed and re-run individually.
  - **Review: Approved with fixes** (I1: the cargo step stopped at the first failing binary; m1–m12).
- **Fix round, paused at shutdown** (`pqz-r01` head **`406c7512`**, tree clean, no jobs running).
  - Done: I1 (`--no-fail-fast`; the cargo/ligero re-runs at n2048 / n2304 and the forge Ligero 27/27 logs), m1, m2,
    m3, m4, m6 / m7, m10 / m11 / m12. The vectors at n2048 and n2304 are regenerated and checked.
  - Left:
    - regenerate the vectors at n2560 and n2816; until then `pqz-vectors --check` fails there, because the
      description text changed;
    - the n2816 ffi step (m7);
    - m8: the `PQZL=c` ffi runs at all four sets, and the wasm32 leg limits labelled as estimates;
    - m9: verify `run.sh` at n2560;
    - m3: confirm the test fails with the filter removed;
    - m5: the report wording (no multi-group PQZH shape at n2560 under `MAX_PROOF_PQZH`);
    - the vectors README numbers and the report section.
  - Resume commands: `task-r01-report.md`, section "Part a — Fix round (paused 2026-10-26)". Resume the implementer
    with a fresh agent and that section.

**Next, in order:**
1. **Finish the fix round** (resume commands in the report): the remaining findings and the vectors per set. Run only
   the affected steps listed in `task-r01a-fix-brief.md` (Verify table). Then a short re-review, and part a is done.
2. **Write the part b brief.**
   - **Contracts:** the PqzCore group map / `_legOf` with `S_AUD`; `disclosureStatement` with `kind + 256·w`; the F-4
     rule (the auditor as sender or recipient); the new ids; every `PqzSet.sol` consumer and its tests;
     `PqzCt.t.sol` still lists the old ids.
   - **Node:** a start-up check that the schedule ids match the library ids (R4-C3); an ML-DSA KAT (R4-C4);
     `add-schedule.py` / the provisional rows with the new ids; `ExpectedLibrarySha256`.
   - **Spec / docs:** KeyGen V2 (§4.2), the windows (§8.1 / §8.2), CTR-PQZ-03 / -04 / -26 row 5, anonymity §8.2,
     the n2048 not-recommended note (dual_hybrid ≈ 444), the n2304 3-β heuristic margin, F-6, and the label-scheme
     note (below).
   - **Open:** a C wasm32 run to confirm the estimated leg limits at n2048 / n2304 / n2560.
   - **Owner note:** a PQZH proof above about 261,909 B does not fit one transaction's calldata under the EIP-7825
     2^24 cap. The largest PQZH proofs are 277,036 / 293,112 / 301,194 B, so 2b must handle this.
   - Then review part b and merge `pqz-r01` into `pqz-16k` (owner approval).
3. **8d part 2b (gas):** `ROLL_MAX` per set into `set.toml`; gas per relation; R_TXM M = 8 under EIP-8037; calldata
   vs spec §12; the README gas columns; e2e on the testnet. Timing runs only with the owner's go.
4. One Codex pass on the contracts after 2a / 2b (owner request, sandbox check first).
5. Task 9 calibration (owner's timing go); a new node image (review the library hash).
6. Then UA-8 (before fs3 Task 13), then UA-7.

**Label-scheme ruling (owner 2026-10-25):** keep the current label scheme during development. At the production
freeze, switch to `scaas/pqz/<set>/pqzl/v1` / `…/pqzh/v1`; every old id stays refused. Write this into the sets
README in part b.

## Session 2026-10-25 (8d part 1b merged, testnet on pqz4, 8d part 2a built; UA-7 / UA-8 specs) — resume here

**State:** main + this note. Shutdown ≈ 11:15 (owner). SDD ledger (git-ignored):
`.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/` — `progress.md` (last lines = this
session), `task-8d-report.md` ("Part 1", "Part 1b", "Part 2a — Result"), `task-8d2a-brief.md`, reviews `task-8d1-review.md`,
`task-8d1b-review.md`.

**Done today:**
- **8d part 1b** (`n2816-kmax65536` a full PQZL set; no PQZH — reason in its SET.md / decisions, owner: no spike):
  review → fix round → re-review approved; **merged into `pqz-16k`** (fast-forward `46069582`), pushed.
- **SCaaS testnet (7622) runs `scaas/nethermind-pqz:2.2.0-pqz4`** (8d part 1 node, set `n2304-kmax4096`, provisional
  rows × 1.3 until Task 9; reset on path B, no backup, owner-authorised); probe 398 ok / 0 FAIL. No PQZ contracts yet.
- **8d part 2 split:** 2a (contracts correct at all four sets) / 2b (gas: `ROLL_MAX` per set, gas per relation per set,
  R_TXM M = 8 under EIP-8037, calldata vs spec §12, README gas columns, e2e on the testnet).
- **8d part 2a built** on branch **`pqz-8d2a`** (worktree `.claude/worktrees/pqz-8d2a`, from `46069582`): contracts read
  `PqzSet` (committed `PqzSet.sol` = `n2304-kmax4096`), P46 packing generic in `PACK_BITS`, M7 `HAS_PQZH`, `PqzSafety`
  ids / self-test / 32-bit addresses, `UAPqzVerifier` / Env / release roll-out, contract vectors per set, EVM Ligero
  fixtures + `evm_fixtures` un-ignored, `e2e.py` per set, M2 foreign-id negative rows. Forge suite PASS at all four
  sets; gates n2048 / n2304 PASS; n2560 / n2816 full gates stopped (owner: full gates only for core changes — memory
  `full-gate-only-for-core`). **Next: review 2a → fix round → merge into `pqz-16k` → write the 2b brief → 2b.**
- LaZer: comment posted on lazer#28 (B-1 / A-2 described, links only to commits on main); issue **lazer#31** filed
  (D-2 / D-3).
- Specs on main (owner decisions inside): **UA-7** `PqChat` (ML-KEM-1024 + X25519 only; sessions with KEM-wrapped AES
  keys on chain; messages off chain via Matrix or stored on chain; ua-qt on libQuotient), **UA-8** portable
  registrations (chain-independent PoP; one `register(kind, keyData, UAAttrs, pop, pqzPop)`; optional `R_REG` with a
  `proven` flag; KEM key in `UARegistry` with signed versions in any order; everything stored in state; `mtx*` forms
  with an optional fee). Order: 5h → **UA-8 before fs3 Task 13** → UA-7.

**Branches:** `pqz-16k` head `008e196c` (one local docs commit not pushed: n2816 no-PQZH reason); `pqz-8d2a` (not
merged, not pushed); `pqz-8d1` (merged, worktree removable).

**Owner rules added today (memory):** push in batches (not after every edit); full gate only for core changes.

## Session 2026-10-23 (evening; 8b DONE, 8c part 2 half done) — resume here

**State:** main `be0e102b` + this note. No agent, gate, capped job or background shell running (paused for the
shutdown ≈ 16:45); only the testnet node and the owner's Odoo containers. SDD ledger (git-ignored):
`.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/` — `progress.md` (last lines = this
session), `task-8b-report.md` (top: "Status: DONE"), `task-8c-report.md` (top: "Part 2 — Paused", exact next commands),
`task-8c2-brief.md` (the 8c part 2 brief).

**Branches (not pushed):**
- **`pqz-16k`** (worktree `.claude/worktrees/pqz-16k`), head **`fe5abb63`**. **Task 8b DONE:** the four gates PASS at
  the fix-round head `a542f6cf` (`n2048-kmax1024` all 11 steps `fdf2ae7a`; `n2304-kmax4096`, `n2560-kmax16384`,
  `n2816-kmax65536` `020127bc`, resumed per part after the afternoon shutdown; xcheck skipped for the three non-frozen
  sets until 8c part 2); re-review minors N1–N4 merged; `z21diff` re-run alone per set after N4 = the gate outputs byte
  for byte at all four sets. Also merged: **`pqz-8c`** (`eec5d510`: 8b's pqz-stmt taken over the stand-in; semantic fix
  — pqz-stmt allows at most one `set-<set>`, none = `n2048-kmax1024`, default `[]`, because pqzh-ligero forwards its
  set with pqz-stmt's default features; `gen_set.py --check` accepted 8c's hand-written `pqzh_set*.rs`).
- **`pqz-8c2`** (worktree `.claude/worktrees/pqz-8c2`, from `fe5abb63`), **8c part 2 paused**, WIP `4a2acab9`,
  `ea7beeae`: `gen_set.py` writes `pqzh_set.rs` from a `[pqzh_preset]` table in `set.toml`; per-set `MAX_PROOF_PQZH` /
  `MAX_INPUT` constants in `rust/set.rs` used by pqz-stmt; `n2560-kmax16384` PQZH in pqzh-ligero (all bounds ≤ 303,590 B
  under its 327,680 limit); pqz-ffi / pqz-vectors / `pqz_kat.py` take PQZH per set; `gate.sh` cargo/ligero with the set
  feature, xcheck = STARK check (n2048 only) + `pqzh/xcheck/ligero.sh` at every PQZH set. Checked: n2048 PQZH 24/24
  proofs byte-identical, replay 16/16, native = wasm32, 144/144 mutations; n2304 tests + native = wasm32; n2560 suites
  green (oom test fixed, re-run alone); Ligero xcheck ok at n2304 / n2560; pqz-stmt tests at three sets; `gen_set
  --check` ok. **Not done:** vectors for n2304 / n2560 (stopped mid-generation, nothing written), the full n2560 round
  (wasm, ct, honest sizes), fallback tests, clippy, `ligero_params.py` per set, docs, the three gates.
- `pqz-8b-fix` merged (worktree removable); `pqz-8c` merged (worktree removable; branch kept with `pqz-8c-spike`).

**Owner questions (8c part 2) — ANSWERED 2026-10-23: (1) OK, (2) t = 122, (3) header accepted:**
1. **`MAX_INPUT` per set** — the code still had 393,216 (512 KiB is the ruling, not yet in code). Implementer set
   `n2048-kmax1024` 393,216 (keeps its vectors byte-identical), `n2304-kmax4096` and `n2560-kmax16384` 524,288 (else
   pqz-ffi rejects every n2560 PQZH debit and n2304 op 7 M = 4 with the auditor). `pqz_ffi.h` and the node limit
   (393,216) untouched → 8d. Confirm or overrule.
2. **`n2560-kmax16384` PQZH preset**: kept the n2048 preset at t = 121 (soundness 127.23 bits = n2048's, below
   n2304's 127.40); t = 122 ≈ 127.55 bits [estimate] for ≈ +1.3 KB per proof, still < 327,680 (one `set.toml` line).
3. **Generated `pqzh_set.rs`** for n2048 / n2304 equal the hand-written files in every code line, but the comment header
   is now "Generated … do not edit" + the set.toml description; exact byte identity would need the old prose copied
   into set.toml. Accept the header change?

**Measured today (memory, four gates at once):** peaks per capped scope 2,415 / 2,590 / 3,072 (= cap) / 2,500 (= cap)
MB for n2048 / n2304 / n2560 / n2816 (page cache included; nothing killed) → `CAPPED_MEM=3G` for every set; min
available 5.5 GB. Watcher: `scratchpad/gate-memwatch.sh`.

**Next (order):** (1) apply the answers on `pqz-8c2`: `n2560-kmax16384/set.toml` `[pqzh_preset]` t = 122 → `gen_set.py
--all` (sizes / soundness re-measured in its round; MAX_INPUT and header as built); (2) resume 8c part 2 (fresh implementer or the controller)
from `task-8c-report.md` "Part 2 — Paused": vectors n2304 / n2560, full n2560 round, fallback tests, clippy,
`ligero_params.py`, docs, then the three PQZH gates concurrently (`PQZ_SET=<set> CAPPED_SLOTS=4 CAPPED_MEM=3G
scripts/capped pqz-core/gate.sh`, xcheck must run) → review → merge `pqz-8c2` into `pqz-16k`; (3) 8d → Task 9 (timing
only on the owner's go) → merge part B → metatx split (variant A).

## Session 2026-10-23 (afternoon; 8b review + fix round, four gates at once)

**State:** main `7d649675` + this note. No agent, gate, capped job or background shell running (stopped for the
shutdown 13:36); only the testnet node and the owner's Odoo containers. SDD ledger (git-ignored):
`.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/` — `progress.md` (last lines = this
session), `task-8b-report.md` (top: gates + re-review, then "Fix round 1", then the final "Result"),
`task-8b-review.md` (review + re-review).

**Branches (not pushed):**
- **`pqz-16k`** (worktree `.claude/worktrees/pqz-16k`), head **`fdf2ae7a`**. Since `eb823b44`: 8b review (agent):
  Approved with fixes, 0 Critical / 4 Important (I1 z21diff used `n2048-kmax1024`'s `Bsq` at every set and its sweep never
  reached the bound at most relations — dead check; I2 PASS gates predated the head; I3 resume key blind to binary
  files; I4 C wasm32 limb path never run at `n2816-kmax65536`) / 10 Minor → fix round 1 (agent, `a8ed109f..75339b5f`,
  fast-forwarded): z21diff takes each set's `Bsq` and sweeps to the first reject (n2560: all 14 relations now cross
  the bound, closest 1.004 × Bsq, 0 mismatches), gate checks its summary; resume key = binary contents + scripts +
  GATE_ENV; new part `fnv/cwasm` (C wasm32 = native C on 14 relations at n2816); **per-set build / output paths**
  (`PQZ_BUILD_TAG=<set>`: `pqzl/build/<set>/`, `ffi/target/<set>`, `build/fuzz-<set>`, …) so the four gates run at
  once from one worktree; 9 of 10 minors (m3 `__multi3` wasm32 cost → Task 14; m8 moot). `a542f6cf`: `e-s0.txt` for
  `n2048-kmax1024` (GATE MET, 14 relations). Re-review: approved pending I2.
- **`pqz-8b-fix`** (worktree `.claude/worktrees/pqz-8b-fix`), head **`bd27243e`** = `a542f6cf` + re-review minors N1–N4
  (resume key recomputed before a part is recorded, `fuzz/corpus` + `RUSTFLAGS` in the key, `unset B`; `make.sh kat`
  per-set build dir; one gate per label (flock); z21diff reads `Bsq` through its `int_t`). **Not merged on purpose:** it
  changes `gate.sh`, i.e. the resume key of the paused gates.
- **`pqz-8c`** unchanged (`bf38bbbd`, 8c part 1b done). Dry-run merge into `pqz-16k`: conflicts only in
  `pqz-core/stmt/Cargo.toml` and `stmt/src/lib.rs` (take 8b's pqz-stmt).

**Gates at `a542f6cf` (four at once, owner: `CAPPED_SLOTS=4`):** `n2048-kmax1024` **PASS** (all 11 steps, logs
`fdf2ae7a`); stopped, resumable per part: `n2304-kmax4096` (kat..ffi ok, in rust), `n2560-kmax16384` (kat..vectors ok,
in ffi), `n2816-kmax65536` (kat..diff ok, in fnv/wasm). Memory peaks per scope: 2,415 / 2,590 / 1,327 / 1,291 MB (the
last two before rust); min available 6.1 GB; a 2.5G cap would be tight for the full sets (rust / cargo ≈ 2.6 GB, fuzz
`rss_limit_mb` 3072). Watcher kept in `scratchpad/gate-memwatch.sh`.

**Owner rulings today (afternoon):** 8b review by an agent at the normal model; never call the frozen set "v3" in new
text — `n2048-kmax1024` (memory updated); the four gates run concurrently, `capped` up to 4 slots for them
(`CAPPED_MEM=3G`; 2500M for `n2816-kmax65536`, no fuzz); verification jobs may use 4 slots.

**Next (order):** (1) in `pqz-16k`, resume the three gates at once (same tree — do NOT merge `pqz-8b-fix` first):
`for s in n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do CAPPED_SLOTS=4 CAPPED_MEM=3G scripts/capped pqz-core/gate.sh --last $s & done`
(≈ 1 h; n2816 may use `CAPPED_MEM=2500M`); (2) all PASS → I2 closed; merge `pqz-8b-fix` (`bd27243e`) into `pqz-16k`,
then run z21diff alone per set with the gate seeds and compare with
`pqzl/sv/runs/gate-<set>-z21diff.jsonl` (byte-identical expected); progress line "Task 8b: DONE"; (3) merge `pqz-8c`
into `pqz-16k` (take 8b's pqz-stmt) → 8c part 2 (pqz-ffi / vectors / gate / gen_set.py take PQZH per set;
`n2560-kmax16384` PQZH with `MAX_PROOF_PQZH` 327,680) → review; (4) 8d → Task 9 (timing only on the owner's go) →
merge part B → metatx split (variant A).

## Session 2026-10-23 (morning; 5h part B: 8b item 6 near done, 8c part 1b done, gate resume)

**State:** main `c5d2001d` + this note. No agent, capped job, gate or background shell running (stopped for the
shutdown); only the testnet node and the owner's Odoo containers. SDD ledger (git-ignored):
`.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md` (every ruling, last lines = this
session). Parameter sets are named by directory only (owner 2026-10-23): `n2048-kmax1024` (frozen v3),
`n2304-kmax4096` (default; older notes: "set (a)"), `n2560-kmax16384` ("16k"), `n2816-kmax65536` ("A′", core only).

**Branches (not pushed):**
- **`pqz-16k`** (worktree `.claude/worktrees/pqz-16k`), head **`eb823b44`**. Task 8b: v3 gate PASS on the final code
  (`b81e6e8c`); `n2560-kmax16384` built via set.toml + make.sh (`59860bae`), gate fixes (`07ae4c77`: C oracle arena
  2 GiB, pqz-stmt PQZH limit test per set; Rust suite and pqz-stmt re-run ok) — **its full gate not yet re-run on the
  fixed code**; `n2816-kmax65536` built (`76afd23e`: kmlwe 42, not 41 — at 41 dual_hybrid is 447 / 448 < 450; no 64-bit
  blocker; no PQZH: q − 1 lacks 19 / 43 / 431) and its gate fixes (`0b339ff8`: z21_big proof under `MAX_PROOF`,
  fixtures re-exported — the old ones were 16k files, core-only row count in the Rust vector tests). The 8b implementer
  stopped on the Opus weekly usage limit (resets 2026-10-24 23:00); the controller finished its fixes.
  Docs: `pqz-core/params/sets/README.md` — what a set fixes (cryptography first, cost follows), PQZL / PQZH shared vs
  own, PQZH per set, the three options when a PQZH proof exceeds `MAX_PROOF_PQZH` (`dc1d127d`, `75593342`, `031dfdfb`).
- **`pqz-8c`** (worktree `.claude/worktrees/pqz-8c`), head **`bf38bbbd`**. 8c part 1b DONE_WITH_CONCERNS: `n2304-kmax4096`
  PQZH = radix-7/17 preset (t 120; debits 251,608–253,048 B, soundness 127.40 bits; tests, native = wasm32, ct ok),
  fallback re-prove bug fixed (`2e071981`), `ligero_params.py` fix, docs; carries the stand-in pqz-stmt `cded0eb4`
  (take 8b's at the merge). Not measured: wasm32 verify time, `G_op`.

**Gate tooling (owner 2026-10-23, on `pqz-16k`):** `pqz-core/gate.sh` resumes per step and per part (diff / fnv /
vectors / ffi / rust per test binary / cargo / fuzz; `a0161798`, `pqz-core/resume.sh`), logs milestones to
`runs/gate/<label>-progress.txt` (`f76188ed`), label defaults to the set name (`eaa4b14f`), `runs/gate/last` + `gate.sh
--last` (`4b7afcee`), resume key = file contents, not the commit (`eb823b44`). `GATE_FRESH=1` restarts.

**Owner rulings today:** sets named by directory, never "set (a)" / "16k" / "A′" in new text; README section on what a
set fixes and PQZL / PQZH shared vs own; **`MAX_PROOF_PQZH` = 327,680 B (320 KiB) for `n2560-kmax16384` only** (per-set
limit raise; every other set 262,144; decisions CTR-PQZ-10; built in 8c part 2 + 8d); gates resume near the stop
point, label = set, milestones logged; do not start the `n2560-kmax16384` full gate without resume (now built).

**Next (order):** (1) in `pqz-16k`: `scripts/capped pqz-core/gate.sh --last` — resumes the `n2816-kmax65536` gate
(kat / tbox / sv / diff-portable done; stopped in diff/x86v3; ≈ 1.5 h left); (2) the `n2560-kmax16384` full gate:
`PQZ_SET=n2560-kmax16384 scripts/capped pqz-core/gate.sh` (owner go; several hours, resumable); (3) 8b final report
(rewrite the top of `task-8b-report.md`, progress line "Task 8b: DONE") → review (Opus limit until 2026-10-24 23:00:
ask the owner — controller review or sonnet) → merge `pqz-8c` into `pqz-16k` (take 8b's pqz-stmt) → 8c part 2
(pqz-ffi / vectors / gate / gen_set.py take PQZH per set; `n2560-kmax16384` PQZH with `MAX_PROOF_PQZH` 327,680) →
review; (4) 8d → Task 9 (timing only on the owner's go) → merge part B → metatx split (variant A).

## Session 2026-10-22 (5h part B: 8b items 1–5 + per-set generator, 8c part 1/1b, Amsterdam node gas merged, testnet 200 M) — resume here

**State:** main `9d2b90f8` + this note, pushed. Merged today: `amsterdam-node` (`b62a54f1`: node / relayer on the Amsterdam
2-D gas model, review APPROVE-WITH-FIXES + fix round 1). **SCaaS testnet reset 2026-10-22** with genesis `gasLimit` 200 M
(genesis `0xa17faef4…2ac2`, image 2.2.0-pqz3, probe / e2e / 64 KiB codesize ok; `chain-uids.json` private7622 updated,
client test vectors keep `0x24e43dcb…c464` as a fixed constant). No agent, capped job, gate or background shell running
(stopped at the owner's request); only the testnet node and the owner's Odoo containers run. SDD ledger with every
ruling (git-ignored): `.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md`.

**Branches (not pushed):**
- **`pqz-16k`** (worktree `.claude/worktrees/pqz-16k`), head **`61b0c003` WIP** on `c4df6064`. Task 8b done: (1) v3 gate
  byte-identical `fc61e6ca`; (2) set (a) cheat fixtures + Rust suite `0c1886e1`; (3) e_s0 all 14 relations MET `d24b4f41`;
  (4)(5) + generator `c4df6064`: pqz-stmt / pqz-ffi / pqz-vectors set-generic (PQZH only for v3 until 8c part 2), set (a)
  vectors `smartcontracts/vectors/pqz/n2304-kmax4096/`, **gate t8b set (a) PASS** (xcheck skipped: PQZH), SET.md, docs;
  **per-set generator** (owner): `params/sets/<set>/set.toml` (only input) → `gen_set.py <set>|--all [--check]` (specs,
  `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, feature blocks) → `make.sh <set> all|steps` (stops at the first
  failing step; e_s1 prints the values for set.toml); old gen_pa.py / regen.sh in `params/sets/legacy/`; `PqzSet.sol` not
  wired into contracts (8d). **Stopped mid gate t8b-v3b** (v3 re-run after (4)(5): kat..ffi ok; rust / cargo / xcheck /
  fuzz to re-run); the implementer's Paused section was NOT written — the ledger's last line + `c4df6064` message are the
  resume notes.
- **`pqz-8c`** (worktree `.claude/worktrees/pqz-8c`), head `6e69bfa0` WIP. 8c part 1: pqzh-ligero set-generic (Barrett
  field, wasm32 limbs, per-set `pqzh_set.rs`, v3 byte-identical, set (a) tests / native = wasm32 / ct ok, `PQZH.md`
  "Conditions for a chain to run PQZH" per set). Part 1b (owner): **set (a) production preset = B** (radices 2/7/17/19/43/431,
  n 45,752, k 952, **t 120**: debit bounds 251,608–253,048 B, 9–10 KB under `MAX_PROOF_PQZH` 262,144, soundness 127.40
  bits); fallbacks kept: **A** re-prove under the limit (Cargo feature `fallback-retry`, never default / production; ZK
  argument in `docs/research/pqzh-set-a-proof-limit.md`; tag `pqzh-set-a-fallback-A` on `4f3477b8`, local), **C** raise
  `MAX_PROOF_PQZH` per set (documented only); old preset `pqzh_set_fallback.rs`; branch `pqz-8c-spike` merged and kept.
  Carries a stand-in pqz-stmt commit `cded0eb4` — take 8b's pqz-stmt at the merge.
- `amsterdam-node` merged (worktree removable); `pqz-8c-spike` kept.

**Owner rulings today:** per-set generation (one `set.toml` + `gen_set.py` + `make.sh <set> all`); restore the K_MAX ≈ 65k
set as `n2816-kmax65536` (A′, core-only) via the generator; 8c in parallel to 8b; testnet reset now to 200 M, no load
run; chainUid handling (live hash in chain-uids.json / node example / evm.md, vectors keep the old constant); testnet
`max_gas_per_tx` 64 M; PQZH set (a) = B (t 120), A (own Cargo feature) and C fallbacks; Dependabot 19/20/21/36 left open
(dev / test-only); `/home/dockers/mba-chain-nethermind` = SCaaS testnet stack, not production (allow rules in the
git-ignored `.claude/settings.local.json`, + memory).

**Next (order):** (1) 8b: re-run `PQZ_SET=n2048-kmax1024 scripts/capped pqz-core/gate.sh t8b-v3` (alone), then item 6:
`n2560-kmax16384` (16k, from `pqzl/params/p16k/`; full vectors + gate + SET.md "Conditions for this set to work on a
chain") and `n2816-kmax65536` (A′ from `pqzl/params/aprime/`, `core_only`; report a 64-bit / limb blocker instead of
changing algorithms) each via `set.toml` + `make.sh <set> all`; item 7 final report → review (opus) → merge into
`pqz-16k`. (2) 8c part 1b: `scripts/capped pqz-core/pqzh/ligero/runs/c8b.sh` (≈ 45 min: v3 byte identity, set (a) tests,
sizes, native = wasm32, fallback tests, ct), `ligero_params.py` t ≥ minimum + FFT cost fix, PQZH.md / research note
"Fallbacks (owner 2026-10-22)"; 16k debit (~302 KB) > 262,144 is an open B / A / C question for that set. (3) merge
`pqz-8c` into `pqz-16k` (take 8b's pqz-stmt) → 8c part 2 (pqz-ffi / pqz-vectors / gate / gen_set.py take PQZH per set)
→ review. (4) 8d → Task 9 (timing only on the owner's go) → merge part B → metatx split (variant A).

## Session 2026-10-21 (evening; 5h part B: 8a done, 8b paused, Amsterdam re-plan) — resume here

**State:** main `28af51d3` + this note, pushed up to `28af51d3` (Nethermind 2.2.0 merge + SCaaS testnet rename). Part B
on branch **`pqz-16k`** (worktree `.claude/worktrees/pqz-16k`, not pushed), **8b paused at WIP `15c929b3`**; `foundry-185` (F185) merged
(`98cd0830`) and `pqz-pack` (spike PACK + P46 note) merged (`756713a2`): `pqz-16k` HEAD `756713a2`. SDD ledger with every ruling (git-ignored):
`.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md`; per-task briefs / reports /
reviews in the same dir. No agent, capped job, docker container (except the testnet node) or background shell running.

**Owner rulings today (in the spec addendum "Amsterdam re-plan (owner 2026-10-21)", `76fd9916` / `ab04e0bd`):**
- **Glamsterdam mandatory** on every chain that runs these contracts; never raise the 24 K code-size limit again
  (ceiling 64 KiB). The SCaaS testnet runs **Nethermind 2.2.0 with Amsterdam from block 1** (merged on main).
- **Ethereum's Amsterdam rules kept** (option (b): EIP-7976 calldata floor ≈ 261,909 B / tx, EIP-8037 state gas,
  EIP-8038 storage writes). **No zero-gas / own-block-limit assumptions** (the precompile may be deployed for
  customers); budgets per tx 2^24 regular, total against an Ethereum-like block (60 M today, 200 M expected with
  Glamsterdam: Sepolia / Hoodi).
- **Parameter set (a): n = 2304 (k 36), `K_MAX` 4,096, q = 61,275,424,977,257 (≈ 2^45.80), Δ = 233,747,196, proof
  MLWE rank 36**; β at 80 hints 468.5 (DDGR20) / 458.5 (dual), no exception; sizes −10 % vs 16k (Task 7c,
  `pqz-core/pqzl/params/n-study/`). Supersedes the 16k set approved this morning (Task 7, `params/p16k/`).
- **Parameter sets are source directories** `pqz-core/params/sets/n<N>-kmax<K_MAX>/` (shared by PQZL and, in 8c, PQZH),
  chosen at compile time (C `PQZ_SET=…`, Rust feature `set-…`; one set per library build); `SET.md` per set.
  Sets: `n2048-kmax1024` (today, byte-identical), `n2304-kmax4096` (default), `n2560-kmax16384` (16k: shippable — full
  vectors under `smartcontracts/vectors/pqz/n2560-kmax16384/`, gate, "Conditions for this set to work on a chain"),
  `n2816-kmax65536` (A': core-only, build + KATs; report a 64-bit-arithmetic blocker instead of changing algorithms).
- **op 7 M = 8**: the "M ≤ 4" rule was withdrawn (it rested on the precompile input sent as calldata; through the token
  the input is built in memory, M = 8 calldata ≈ 124 KB). Core keeps M = 8 at G = 2; 8d decides by measurement.
- **Blobs stay in contract state — absolute** ("Không được mất ciphertext"; calldata / events are pruned by EIP-4444).
- **Stored layout P46** (spike PACK, `pa-pack/results-pack.md`, `docs/research/pqz-pack.md`): 46-bit coefficients, 4 per
  23 B, stored data only (token unpacks to 64-bit lanes for the precompile; proofs / pqz-stmt unchanged); state −8.10 M
  per op 1, −16.80 M per op 7 M = 8; regular +0.22–0.29 M; `ROLL_MAX` ≈ 80 at (a); op 7 M = 8 total 56.42 M. The packing
  width is per set (⌈log2 q⌉: 46 for (a), 50 for 16k).
- **PQZH = backup only** (its debit inputs exceed one tx under EIP-7976); `MAX_PROOF_PQZH` stays 262,144;
  `MAX_INPUT` stays 512 KiB. 8c writes "Conditions for a chain to run PQZH" per set.
- **Precompile addresses → 32-bit** `0x…5caa0f01` (PQZ), `0x…5caa0012` / `0x…5caa0013` (ML-DSA-44 / -65) in 8d; then
  `PqzReleaseSpec`'s override goes.
- **Foundry 1.8.5** machine-wide; **every foundry.toml profile `amsterdam`** (F185; size gate +14 B per entry for the
  `"experimental": true` metadata, owner option (1)).
- **Metatx split: variant A** (library; only the data hash to the library), after part B, before governance.

**Measured today:** Task 7b (Amsterdam, forge 1.8.5 + testnet cross-check): 16k `ROLL_MAX` 80, op 1 / op 7 M ≤ 4 fit
2^24, state ≈ 33 M per debit. Spike PACK at (a), today's lanes: op 1 8.09 / 29.63 / 37.72 M (regular / state / total),
op 7 M = 4 6.98 / 31.64 / 38.62 M, op 7 M = 8 G = 2 10.54 / 62.39 / 72.93 M, `ROLL_MAX` 96. 8a: cheating prover 28
forgeries → 0 in all four verifiers; gate t8a PASS; review clean.

**8b so far:** sets tree + set-generic C / Rust cores; set (a) KAT 19/19 (new LaZer golden), v3 KAT 19/19 and v3 Rust
suite byte-identical; set (a) cheating bench + `check_tbox_fixes` (with an A-2 control) ok; all 14 specs at rank 36;
measured proofs R_TX 46,681 B, R_REG 30,270, op 7 M = 4 50,749, M = 8 G = 2 67,604 (aud); heap ≤ 937 MB (M = 8 needs
`PQZ_ARENA_MB=2048`). Rulings for resume (ledger): pqz-stmt set-generic now (ids / limits in 8d), PQZH compiled out
for non-v3 sets until 8c; vectors: v3 stays at `smartcontracts/vectors/pqz/`, set (a) / 16k in sub-dirs; Δ even at (a)
(note for review).

**Next:** (1) resume 8b from `task-8b-report.md` § "Paused" (v3 gate, set (a) Rust suite + cheat fixtures, e_s0 per
relation, pqz-stmt set-generic, vectors + gate t8b, SET.md, then the 16k set with vectors + gate, then A') → review; (2) 8c PQZH at the new
q (backup) + conditions doc; (3) 8d: pqz-stmt, P46 contracts, per-set Solidity constants, precompile addresses,
`ROLL_MAX`, M = 8 measurement, one proofSystemId bump, vectors; (4) Task 9 (timing only on the owner's go). TODO.md "Now".

## Session 2026-10-21 (5h part B: Task 7 done, Task 8a paused) — resume here

**State:** main has this note only (local commit, not pushed). Part B work on branch **`pqz-16k`** (worktree
`.claude/worktrees/pqz-16k`, from main `56943a36`, not pushed): Task 7 `a87795da`, fix `161121d2` (review + re-review
clean). SDD ledger with every ruling (git-ignored, on disk):
`.claude/worktrees/pqz-16k/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md`. No agent, capped job, docker or
background shell left running.
- **Task 7 (16k parameters, owner summary `pqz-core/pqzl/params/p16k/results-16k.md`):** q = 2^50 − 42,310,535, Δ =
  2^30 − 41, n = 2560, `K_MAX` 16,384; min β 455 with proof MLWE rank 39 (rank 38 → dual_hybrid 446 / 447); encryption
  uSVP 508 / dual 499; max PQZL proof 60,882 B (txm8 G = 1) < `MAX_PROOF` 98,304; max input 309,591 B < 512 KiB;
  n = 2304 out (β 415 at 80 hints).
- **Owner checkpoint 2026-10-21 (approved):** (1) the 16k set above incl. rank 39; (2) **`ROLL_MAX` = 192** (full
  relayed tx 11,934,843 gas, 208 is over 0.75·2^24); (3) **op 7 M = 8 uses one randomness group G = 1** (dual_hybrid at
  144 hints 453.68 / 455.68 ≥ 450, thin; relayed gas ≈ 15.69 M fits 2^24, G = 2 ≈ 20.96 M does not); (4) **PQZH
  `MAX_PROOF_PQZH` raised to 320 KiB = 327,680** (every debit proof ≈ 302.7 KB).
- **Risk carried to Task 9:** G = 1 fits 2^24 relayed only while the 16k op 7 M = 8 precompile price ≤ 8.81 M (1.43×
  today); today's M = 8 relayed is already ≈ 17.0 M > 2^24 (pre-existing, fixed by 16k + G = 1).
- **Task 8 split (ruling):** 8a transcript on today's parameters (B-1 V3 / V4 from the post-`tg` hash in C generic,
  C SV, Rust generic, Rust `verify_fast` + both provers, `tg`-mutation test, review A's cheating prover
  `scratchpad/reviewA/poc/` as a committed fixture; A-2 distinct Schwartz–Zippel challenges; `R_REG`) → 8b PQZL C +
  Rust at 16k (+ txm8 G = 1 relation) → 8c PQZH Ligero over the new q → 8d `pqz-stmt`, Nethermind, Solidity (`PqzCt`,
  `ROLL_MAX` 192 re-pin, `PqzSafety`, new `UAPqzVerifier` / Env / releases), vectors, one `proofSystemId` bump,
  `gate.sh fin`. Briefs `task-8a-brief.md`, `task-8-brief.md` in the ledger dir.
- **Task 8a paused before code:** the implementer mapped every B-1 / A-2 line and designed the fixture
  (`pqzl/rust/tests/cheat_b1.rs` + test-only hooks); resume steps in `task-8a-report.md` § "Paused". Ruling: `R_REG` —
  UA-6 §9 keeps relation / statement / verifier, only the message pre-image changed (UA-6 built it) → 8a documents the
  message in `pqz-stmt`, re-pins `UAPqzVerifier.PROBE_PQZL`; PQZ vectors keep an opaque 32-byte message.
- **Metatx split:** spike on branch `metatx-lib` (`bbca6985`, worktree `.claude/worktrees/metatx-lib`, report
  `scratchpad/metatx-lib-report.md`): NormalToken 38,351 B; A (library) token 34,588 + lib 11,577, +7–8.7k gas
  cold; B (module behind `fallback`) token 7,083, +2.7k cold; B′ 3,347. Owner 2026-10-21: size vs 24,576 is not an
  argument (wait for Glamsterdam); the real ceiling is 64 KiB — `WrappedPqzToken` ≈ 61 KB + governance. **Timing
  (controller ruling on the owner's ask):** after part B merges, before fs3 Tasks 12 / 6 / 13 and before governance code.

- **Spike A on `WrappedPqzToken` (owner ask, done `a12cd06b` on `metatx-lib`; report section in
  `scratchpad/metatx-lib-report.md`, log `smartcontracts/evm/runs/2026-10-21-metatx-lib-spike-pqz.txt`; 49 / 49 tests,
  parity prod / A / A2):** runtime 61,045 (headroom 4,491 under 65,536) → **A 56,898 (8,638)** with `SpikeMtxLib`
  11,577 → A2 (+ `SpikePqzMtxLib` 4,212) 54,321 (11,215). PQZ layer stays ≈ 12.7 KB (its auth / digest / nonce / fee are
  already in the PQZ libraries; ceiling ≈ 13.5 KB headroom). Gas cold: relayed +7.1–9.4k (A) / +13–15k (A2); relayed
  op 1 ≈ +20k / +25k (+0.5–0.66 %); warm +5.9k / +8.2k; direct calls unchanged. **Concern:** A passes the envelope data
  to the library a second time → a ≈ 340 KB op 7 would pay ≈ +1.0 M gas (computed); fix if A is chosen: keep the
  self-call in the token, pass the library only the data hash. Governance code in the shared base lands in every kind.
- **Owner question 2026-10-21 (answered in chat, recorded in TODO §0 governance item):** mint allowance per minter
  (total, per window, expiry); moderator transfer without the user's signature (bounded, public balances only, never
  confidential kinds); hybrid underlying + mint under one cap (reserve accounting: unbacked units not redeemable).

**Next:** (1) resume Task 8a (resume the ledger; dispatch a fresh implementer with `task-8a-brief.md` + the report's
"Paused" section); then 8b → 8c → 8d → Task 9 (timing only on the owner's go).

## Session 2026-10-20 (night; 5h part A merged) — resume here

**State:** main pushed (this note). **5h part A merged** (branch `pqz-state-b`, `0b499439..`; merge commit "Merge branch
'pqz-state-b'"). Gates on the branch head: forge 1325 / 0 / 9, size gate 0 (`WrappedPqzToken` ≈ 61 KB, all tokens
< 65,536 B), PQZ statement vectors byte-identical, docs_check 0 errors, clientkeys 107 / 0 / 2, zether-prover cargo +
wasm smoke green. **Not exercised:** `script/pqz/e2e.py` on a chain (fs3 Task 13). No agent, capped job or Codex run
left running. SDD ledger with every ruling (git-ignored, kept for part B):
`.claude/worktrees/pqz-state-b/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md`.
- **Built:** T1 library split; T2 state in contract + B + TRIVIAL shield + CHAIN-01 (`ROLL_AGE` 5, `ROLL_MAX` 256);
  T3z / T3 `SHIELD_POOL` on both layers, txFee + decoyFee (op 7, sender word `d ≥ minDecoyFee`, both layers), PQZ NONE
  retired, libraries return what the debit moved (`PqzCore.Paid` / Zether `fee`); T3b `IConfidentialToken`, `mtx*`
  names, shared signature `(payload, proof, auth, beneficiary, accHint[, …])` (Zether `auth` / `accHint` empty), UA-5c
  (a) Zether UA envelope `SCAAS-ZETHER-UA-ENVELOPE-V1`, (b) one `mtxUnshield(…, uint256 amount, bytes32 recipient)`,
  `WrappedLib.payOutTo`; T4 e2e.py / zether-prover (32-byte recipient) / clientkeys; T5 docs + decisions.
- **Final review fixes:** `ACC_MARK` on every stored `acc` word (a shield-only rollover zeroed them → next `ROLL_MAX`
  20.9 M gas; now 12.09 M); Zether decoyFee built (owner ruling 4).
- **Owner rulings today (night):** keep the shared arg order as built (`mtxUnshield(…, amount, recipient)` vs
  `Unwrap{underlying, recipient, amount, minOut}`); **every `mtx*` write is relayable, the outer fee may be 0** —
  rollovers relayed on both layers (PQZ `mtxRollOver`, `mtxPrepareAcc`; Zether `mtxRollOver`, `mtxRollOverBatch`,
  `mtxRollOverSigned`, `mtxSetRollOverMode`; relayed `ROLL_MAX` 12.19 M gas), fee class `ABSOLUTE` kept; **`MtxRule`
  (feeClass 0 = not relayable) — owner reviews it, do not change** (TODO item).
- **Behaviour to know:** a multi transfer with no beneficiary still pays decoyFee to every leg (fee word = M·d, both
  layers); `Shielded.from` = `UA_POOL` for a UA signer; `mtxWrapShield` stays off the UA allow-list (two-step, CTR-ZTH-51).

**Next:** 5h part B (plan `docs/superpowers/plans/2026-10-20-pqz-state-redesign.md` Tasks 7–9: 16k parameters,
B-1 + A-2 + `R_REG` under one `proofSystemId`; ask the owner before any timing run), then the Codex review order in TODO.

## Session 2026-10-20 (evening; UA-6 merged, 5h part A in progress) — resume here

**State:** main pushed (this note). **UA-6 merged** `f007da31` (see the UA-6 note below). **5h part A in progress** on
branch `pqz-state-b` (worktree `.claude/worktrees/pqz-state-b`, NOT pushed), subagent-driven; ledger with every ruling:
`.claude/worktrees/pqz-state-b/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md` (git-ignored; task briefs and
reports beside it). No agent, capped job or Codex run left running.
- **Done on the branch (reviewed):** Task 1 library split `b978cf89` (`PqzStateLib` / `PqzTransferLib` / `PqzBurnLib` /
  `PqzViewLib` + internal `PqzCore`); Task 2 state + B + TRIVIAL shield + CHAIN-01 `85680d55..f4d367c4` (ROLL_MAX 256 =
  12.13 M gas, prepare-acc halves 5.76 M, **ROLL_AGE = 5** owner); Task 3z Zether `SHIELD_POOL` + kinds 6/7 dropped
  `7733910e..171d4884`, merged `f8715b65` (the pool guard lives in `ERC20MetaTx._uaMove`; layers move the pool only via
  `_poolMove`).
- **Done, NOT reviewed:** Task 3 `ff4e6948` — PQZ `SHIELD_POOL`, **txFee** (= today's `confidentialFee`) + **decoyFee**
  (op 7 only, sender-chosen payload word ≥ token `minDecoyFee`, same to every leg, check `fee == txFee + M·decoyFee`),
  fees to public UA balances, NONE mode retired, disclosure from the blob, events/views, relayed mode binding. forge
  1290 / 0 / 9, statement vectors unchanged, `WrappedPqzToken` 60,754 B.
- **Owner rulings today (5h):** ROLL_AGE 5 blocks; decoyFee explicit sender field (no derivation); txFee unchanged;
  **no view `fallback`** — views stay direct token functions calling the library; the 4 KiB size margin dropped (only
  the hard 65,536 B limit); UA-5c (a) confidential ops through the UA envelope + (b) unshield to a `bytes32` UA → Task
  3b; UA-5c (c)(d) → step 5c′; Zether owner ops accept a Zether UA only (in UA-6).

**Next (order):** (1) review Task 3 (opus) → fix loop; (2) **Task 3b**: shared `IConfidentialToken`, `mtx*` rename
(`mtxShield`, `mtxConfidentialTransfer…`, `mtxUnshield`, …), one selector per shared function with an `auth` argument
(PQZ signer signature; Zether must be empty), UA-5c (a)(b) on both layers; (3) Task 4 clients / tools / vectors (incl.
`script/pqz/e2e.py`, broken since Task 2/3); (4) Task 5 spec + decisions (incl. D18–D24, the T2 deviations: pending slot
byte offsets, floor raised with cleared, prepare-acc refusals; §5.6 race wording; `_poolMove` trust boundary); (5) Task 6
final review → owner approval → merge. Then 5h part B (16k regen) and the agreed review order in TODO ("Review order with
Codex": Codex + agy run 1 on pqz-core after the 16k regen).

## Session 2026-10-20 (reviews done, Z1 merged; UA / shield redesign decided) — resume here

**State:** main pushed (this note). Two WIP branches stopped for the shutdown (not merged, not pushed). No agent, capped job
or Codex run is left running.
- **Reviews of round 2 done:** review A (Task 10, PQZL Rust, `W-review-a-pqzl-rust.md`), review B (Task 11, `X-review-b-transcript.md`),
  Codex T2 on-chain re-run (`T2-codex-chain.md`, no new P0/P1). **P0 B-1 = A-1 CONFIRMED by a cheating prover** (V3/V4
  drawn from `hash0` before `tg`: z3/z4 errors cancelled through g are accepted by Rust `verify` and `verify_fast` on all
  14 codes). **Owner: keep the fold-in** — the fix (V3/V4 from the post-`tg` hash) ships with the K_MAX 16k parameter
  regeneration, one `proofSystemId` bump (CTR-PQZ-09); A-2 (β4 / υ share a challenge) renumbered in the same bump. The
  cheating-prover harness stays in `scratchpad/reviewA/poc/` (git-ignored) until the fix lands, then becomes the
  regression fixture. lazer#28 comment draft updated with B-1 (`scratchpad/lazer28-comment-draft.md`; post only after
  owner approval, also the D-2/D-3 issue draft).
- **5g-Z Z1 merged** `77f7478` (canonical Zether / PQZ verifiers pinned by `OpenFactory`, split transfer / burn /
  inner-product verifiers, deprecated versions refused, `isRegisteredToken`; review APPROVE + fixes m1–m8, o1, o4);
  full forge 1323 pass / 0 fail / 14 skip. The SCaaS testnet needs a redeploy with the new factory (Task 13).
- **Owner rulings today (all in decisions.md):** CTR-PQZ-06 `plainPending` removed (fees straight to the recipients'
  public UA balances; `pqzShield` = a proven debit funded by the signer's public balance moved to the pool, one
  call into `acc`; no shielding into another account); CTR-PQZ-15 / CTR-ZTH-51 **`SHIELD_POOL` sentinel
  instead of burn** for PQZ and Zether (shield / unshield / fees are transfers from / to the pool; `totalSupply()` stays
  the true total); **CTR-UA-30** (research `docs/research/ua-identity.md`): a UA is one signature-verifying entity, ids
  unchanged; classical Zether option (A) — the Zether key is itself the UA, "self" mode kept; a PQZ key is an attribute
  of a PQ-signing UA only (ML-DSA or PQ-dominant msig), supplied in `register`, immutable, one UA per key; `pqz-mlwe` kind
  and `authRef` go. Also answered (no change): EIP-7976 calldata floor (64 gas/byte) — keep it off on 22776 unless the
  tx gas cap rises; PQZ state is per (UA, token), blobs per token, pk per UA.

**WIP branches (resume each in its worktree):**
- `rev2-zether-z2` head `fd672de9`, worktree `.claude/worktrees/rev2-zether-z2`: Z2 (generic `Env`, `deployImplementation`,
  `initialize(creator, version, initArgs)`, release hashes, `usableFrom`); `forge build src` OK, **test tree does not
  compile yet**; resume notes `smartcontracts/evm/runs/2026-10-20-5gz2-wip.txt`. Owner questions, answered 2026-10-20 (chat):
  notice period defaults (10 min on the SCaaS testnet, 3 days on 22776) — **OK**; `initialize` without Env — **answered**: keep the split explicit — the implementation carries what never changes for it
  (Env: verifier addresses, registry, chain, libraries; fixed in its constructor), the contract instance carries its own
  configuration from `initArgs` (e.g. a wrapped USDC → VND token at 1 : 25,000 and a USDC → RUB token at another rate;
  mint / burn / blacklist / … allowed or not), and both feed the governance matrix below; `deployImplementation` binds the kind's latest Env — **No**, to be discussed
  together with smart-contract governance and token governance; library pins = registrar list checked by code hash, not
  compared with the init code's link references — **OK**.
- `rev2-small-fixes` head `8c7c00f2`, worktree `.claude/worktrees/rev2-small-fixes`: CHAIN-02 (first-activation future
  guard, `--check` ok) and CHAIN-03 (`Math.mulDiv`, 3 tests at 2^250; full forge 1326 / 0 / 14; size baseline raised,
  `WrappedPqzToken` 60,352 B) done; **A-3 (Rust secret wiping) WIP `aee749df`**: finish with
  `scripts/capped sh pqz-core/pqzl/rust/run.sh a3` (proof bytes must be unchanged), then mark A-3 fixed and drop the
  WIP prefix. Expect a `size-baseline.json` conflict with Z2.

**Next (order):** (1) `rev2-small-fixes` **merged 2026-10-20** `1003b871` (A-3 + review fixes, proof bytes unchanged; CHAIN-02 / -03; merge fixes: Dex test API, size baseline, DEX KAT regenerated); (2) Z2 **merged
2026-10-20** (review APPROVE-WITH-FIXES, fixes applied; forge 1330 / 0 / 14; notice period 3 days minimum on every mainnet, owner); (3) **UA-6** spec + plan from CTR-UA-30 (registry: PQZ key
in `register` for PQ signers, `keyOwner` uniqueness, `pqz-mlwe` kind / `authRef` removed, `R_REG` message bound to the
UA id; Zether stays a key-UA) — before 5h; (4) **5h** (PQZ state in contract, ordered rollovers, ROLL_AGE 24, per-credit
fee to public balances, `plainPending` removed, `SHIELD_POOL` for PQZ and Zether, CHAIN-01 all-zero `u` refused) then the
**16k parameter regeneration** with B-1 + A-2 + the R_REG change under one new `proofSystemId`, plus the 16k
measurements; (5) Task 12 gate fin → Task 6 package → Task 13 SCaaS testnet reset (image `pqz4`; ask the owner before timing)
→ Task 14 wasm32 limb path. Leftover worktrees: `rev2-zether-canon` (merged; removable), `rev4` (Codex T2, read-only;
removable).

**Later the same day (owner chat, 2026-10-20):** done — HANDOFF / TODO compacted, finished work moved verbatim to
`COMPLETED.md`; README §6 rewritten with the owner's UA definition (a UA is the actor that signs and answers for a write
to a contract, tokens included; recorded under CTR-UA-30). Owner later: Otterscan **dropped** (not needed); Zether `authRef` **removed entirely** (decisions CTR-UA-30). Were open: (a) **Otterscan on the SCaaS testnet** — not
possible on Nethermind 1.39 (no `ots_` / `erigon_` RPC, NethermindEth/nethermind#11990; node container stopped, nothing
changed): Blockscout from the commented stack in `/home/dockers/mba-chain-nethermind/docker-compose.yml` (recommended,
≈ 1.5–3 GB, pin tags, `mem_limit`, ports 22776+) or an own `ots_` shim; (b) Z2 `initialize` without Env (answered: implementation / instance split); (c) Zether
`authRef` (decided: removed); still open (d) the four transfer flows and shielding into another account (decided: all four on both layers, shield proof-free; names `mtxShield` / `mtxUnshield`, built in 5h; decisions CTR-PQZ-06, CTR-ZTH-45), proof-free
`pqzShield` (trivial pending entry folded by the permissionless rollover) into 5h — analysis
`docs/research/shield-and-key-reuse.md`.

Older session notes (2026-10-06 … 2026-10-19) are archived verbatim in [COMPLETED.md](COMPLETED.md#from-handoffmd).

**Plans merged (2026-10-20, late):** UA-6 spec + plan and the updated 5h spec + plan are on main with the owner's
plan-review rulings at the top of each plan (q = 2^50 − 42,310,535; third-party shield free; `mtx*` names incl.
`mtxConfidentialTransfer…`; fees `txFee` + `decoyFee` with token `minDecoyFee` ≥ 0 and sender-chosen `d`, op 7 only;
Zether signs every write; bn254 Zether to `legacy/` inside UA-6). **Next: UA-6 code (plan Task 1 onward), then 5h.**

**Review order agreed (owner 2026-10-20):** UA-6 → 5h part A (contracts) → 5h part B (16k regen in pqz-core) → **Codex
run 1 on pqz-core Rust + C** → fixes, fuzz, gate, freeze → **Codex run 2 on contracts** → fs3 Task 13 (TODO "Review
order with Codex"). UA-6 in progress on branch `ua6` (worktree `.claude/worktrees/ua6`; SDD ledger
`.superpowers/sdd/2026-10-20-ua6-encryption-key-attributes/progress.md` there): Tasks 1, 2, 5 done and merged into
`ua6`; Task 4 (Zether, bn254 to legacy) running in `.claude/worktrees/ua6-t4`.

**UA-6 merged (2026-10-20, late):** branch `ua6` (Tasks 1–9 + final review fix wave + the owner's Zether owner-op
kind check `4ce03f50`), subagent-driven with a reviewer per task and a whole-branch review (no on-chain authorization
hole found). Gates on the merged tree: forge 1243 / 0 / 9, size gate 0, docs_check 0; clientkeys 107 / 0 / 2,
zether-prover, ua-rs, ua-c, ua-cxx, ua-qt (Qt 6.12 at `~/usr/Qt/6.12.0/gcc_64`), ua-dart-frb, ua-py, ua-go, ua-cs,
ua-dart green. Not yet exercised: `script/pqz/e2e.py` on a PQZ chain and a real `R_REG` proof in evm tests (fs3 Task 13
/ 16k regen). Every controller ruling is in decisions.md under CTR-UA-30 with commits. **Next: 5h part A** (plan
`docs/superpowers/plans/2026-10-20-pqz-state-redesign.md`, owner rulings at its top).
