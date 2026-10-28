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
    ≤ 2,405 gas (bound 8,000). `UnderlyingPqzToken` is 61,137 B (4,399 B headroom).
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
  `scratchpad/metatx-lib-report.md`): NoUnderlyingToken 38,351 B; A (library) token 34,588 + lib 11,577, +7–8.7k gas
  cold; B (module behind `fallback`) token 7,083, +2.7k cold; B′ 3,347. Owner 2026-10-21: size vs 24,576 is not an
  argument (wait for Glamsterdam); the real ceiling is 64 KiB — `UnderlyingPqzToken` ≈ 61 KB + governance. **Timing
  (controller ruling on the owner's ask):** after part B merges, before fs3 Tasks 12 / 6 / 13 and before governance code.

- **Spike A on `UnderlyingPqzToken` (owner ask, done `a12cd06b` on `metatx-lib`; report section in
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
'pqz-state-b'"). Gates on the branch head: forge 1325 / 0 / 9, size gate 0 (`UnderlyingPqzToken` ≈ 61 KB, all tokens
< 65,536 B), PQZ statement vectors byte-identical, docs_check 0 errors, clientkeys 107 / 0 / 2, zether-prover cargo +
wasm smoke green. **Not exercised:** `script/pqz/e2e.py` on a chain (fs3 Task 13). No agent, capped job or Codex run
left running. SDD ledger with every ruling (git-ignored, kept for part B):
`.claude/worktrees/pqz-state-b/.superpowers/sdd/2026-10-20-pqz-state-redesign/progress.md`.
- **Built:** T1 library split; T2 state in contract + B + TRIVIAL shield + CHAIN-01 (`ROLL_AGE` 5, `ROLL_MAX` 256);
  T3z / T3 `SHIELD_POOL` on both layers, txFee + decoyFee (op 7, sender word `d ≥ minDecoyFee`, both layers), PQZ NONE
  retired, libraries return what the debit moved (`PqzCore.Paid` / Zether `fee`); T3b `IConfidentialToken`, `mtx*`
  names, shared signature `(payload, proof, auth, beneficiary, accHint[, …])` (Zether `auth` / `accHint` empty), UA-5c
  (a) Zether UA envelope `SCAAS-ZETHER-UA-ENVELOPE-V1`, (b) one `mtxUnshield(…, uint256 amount, bytes32 recipient)`,
  `UnderlyingLib.payOutTo`; T4 e2e.py / zether-prover (32-byte recipient) / clientkeys; T5 docs + decisions.
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
  1290 / 0 / 9, statement vectors unchanged, `UnderlyingPqzToken` 60,754 B.
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
  `UnderlyingPqzToken` 60,352 B) done; **A-3 (Rust secret wiping) WIP `aee749df`**: finish with
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
