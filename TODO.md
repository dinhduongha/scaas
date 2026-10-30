# TODO — scaas

Open work only, ordered by what blocks what. Finished items, superseded "Next" lines and the full history of the
items compacted below were moved verbatim to [COMPLETED.md](COMPLETED.md) (2026-10-20). Resume notes: [HANDOFF.md](HANDOFF.md).

## Standing rules

Owner rulings that still constrain open work (full text in COMPLETED.md; decisions in `docs/decisions.md`).
- **Specs before app code** (owner 2026-10-08).
- **Concurrency** (owner 2026-10-08 / 2026-10-15): max 3 agents; `scripts/capped` has 2 heavy slots (`heavy`,
  `heavy.2`; `CAPPED_SLOTS` overrides), 4 GB each; docker containers need their own `--memory`.
- **Chains** (owner 2026-10-15): SCaaS testnet = testnet, resettable — the controller backs up the chain data, then resets /
  redeploys itself; 22776 = future mainnet — every change is the owner's (work on a throwaway copy), precompiles only
  after the production gates (cryptographic audit, G-LIC), and from its launch "test-only, no migration" ends there.
- **P6 mandate** (owner 2026-10-14, session 4): carry P6 to its end; merge AND push each sub-phase once tests, size gate,
  docs checkers and review pass; decisions that come up are picked from the measurements and recorded in
  `docs/decisions.md` as "controller proposal, owner may override"; UA F5 unpaused only as far as P6i needs it
  (`ua_metatx` for `kind = pqz`). Owner steps (controller drafts only): ethresear.ch / ePrint posts, LaZer mails,
  Zenodo, G-LIC, the lawyer. G-LIC: the letter (`scratchpad/sz-private/g-lic-letter-lazer.md`) was sent, **no reply** as
  of 2026-10-26 (owner); it stays a production gate, not a publication gate.
- **Priority** (owner 2026-10-13): P6 / PQZ first; UA-5c and UA F5 paused until then. Owner 2026-10-19: the P0 PQZL
  Fiat–Shamir fix first; the token-family rename before P6h / P6i / P6j / P6-PUB.
- **Gas calibration** (owner 2026-10-15): one run; re-calibrate before 22776; timing on a quiet host (ask the owner to
  stop other heavy sessions first).
- **One `PQZ` precompile for PQZL and PQZH** (owner 2026-10-14): dispatch on `proofSystemId` via `pqz-ffi`, each id
  priced separately, node limits sized for the PQZH input 393,216 B (CTR-PQZ-10).
- **`R_TXM` e2 bound per vector ≤ 64** in ℓ2, not one block bound 64·√M (owner 2026-10-15, CTR-PQZ-03).
- **fee = 0 is valid** for classical Zether and PQZ (owner 2026-10-14); vectors and tests carry fee = 0 cases for every
  transfer form.
- **PQZ = Post-Quantum Zero-knowledge** (owner 2026-10-15); code / opTags / ids keep `pqz`; wording "a post-quantum
  zero-knowledge proof engine — first application: Zether-style confidential tokens".
- **PQZL Rust crate** (owner 2026-10-17): `pqz-core/pqzl/rust/` (crate `pqzl`), for any third party, Vegan Community
  License 1.0 (LaZer's MIT notice travels: NOTICE + lazer/LICENSE); production core since 2026-10-19; the C core is kept.
- **Code size** is not a concern until the Glamsterdam fork; the ratchet baseline records sizes (owner, P2a F4).
- **Backup, not delete**; **no built binaries on GitHub**. **Licence**: Vegan Community License 1.0 (owner 2026-10-17;
  terms in COMPLETED.md, §00 "License").

## 00. Meta-transaction redesign — code streams (accepted 2026-10-08; rules in the component docs)

### Now (order)

- **Work order (owner 2026-10-29, optimised the same day; supersedes the earlier 2026-10-29 order and the older "next"
  lines below where they conflict).** Streams run in parallel within the limits (3 agents, 2 `capped` slots); each
  stream keeps its order:
  1. [x] `near-algorand` — **DONE 2026-10-29**: Tasks 1–22, whole-branch review, fix wave, residual N1 / N2, merged into
     `main` and pushed (owner go 2026-10-29).
  2. Right after the merge, in parallel:
     - **UA-8 plan first** (steps 1–2: EVM + Soroban; the design is detailed, P1–P11), written at the start of this
       step so its EVM code can start at once.
     - **EVM contracts, two parallel tracks** (own worktrees; shared forge / size-gate slots; merge with care, the
       rename sweeps wide):
       - token-family rename (moved up from step 7, owner 2026-10-29: names only — enum numbers and ABI unchanged — so
         the new EVM code is written with the final names). Owner 2026-10-30: option (a) — regenerate
         `dex_order_kat.json` and `metatx-parity.json` (only CREATE2-derived fields move: addresses, domains, digests,
         the calldata embedding them); also rename the deploy JSON keys `implementation_none` /
         `implementation_{none,underlying}_zether_bls12381` (`deployments/<chainid>.json`, read by e2e and the node);
         start after the `ua8` merge (rebase onto main then). Inventory: `scratchpad/token-rename-report.md`;
         **BUILT 2026-10-30 on branch `token-rename`** (worktree `.claude/worktrees/token-rename`, on main `b7c34170`;
         code `d4550552`, vectors `ea7a671f`, then docs and gate logs; report `scratchpad/token-rename-report-2.md`);
         merge after the owner's go. `metatx-parity.json` needed no change (CREATE clones; its `gas` column is stale
         on main in eight PQZ rows, compared only under `PARITY_GAS=1`).
       - **UA-8 step 1 (EVM `UARegistry`)** — IN PROGRESS on branch `ua8` (worktree `.claude/worktrees/ua8`; plan
         `docs/superpowers/plans/2026-10-30-ua8-portable-registrations.md`): A1–A10 complete and reviewed, A11 paused
         at WIP `6dd00de7` (2026-10-30), then A12, A13, final review, owner go to merge. As soon as the plan is written (owner 2026-10-29, moved up from step 3):
         portable PoP, optional `pqzPop`, KEM keys, relayable writes, `checked = chain`, clients and vectors
         (`UARegistry` / `UAKinds` / `IUARegistry`; overlap with the rename only where tokens read the PQZ key's
         `proven`). Must land before fs3 Task 13 (the SCaaS testnet redeploys the registry once).
         **Status 2026-10-30:** built on branch `ua8` (worktree `.claude/worktrees/ua8`), tasks A1–A11 done (digests and
         `portable.json`, `ua-rs`, zether-prover, `UAKinds` / `UARegistry` with `storePqzPop`, `setPqzKey`, `setKemKey`, the gas
         log, ten client libraries, node call-job test, e2e scripts), A12 (docs, decisions, this TODO) and A13 (whole-branch gates:
         forge per set, size gate, client suites) done; the final whole-branch review (2026-10-30, two parts) is done and the
         **final fix wave is done** (owner rulings 2026-10-30: R-node, R-cross-set, R-7702 superseded the same day by the EIP-7702
         ruling D1 (registry only), `docs/decisions.md` CTR-UA-31, CTR-UA-16, CTR-UA-07, CTR-UA-24; contracts / node / clientkeys /
         e2e.py `e6cdc13e` … `128becef`, runner / client pins / docs `2d819009` … `95b00fde`, integration and gate logs after them);
         re-review: Ready with fixes (doc-level, fixed by the controller); owner go to merge 2026-10-30 (push only together with
         `no7702`). UA-8 follow-ups (final review / re-review nits, not blocking): the node binds one registry per chain, so
         generation-1 writes (e.g. `setKemKey` for a gen-1 record) are not relayable once a chain runs a gen 2; no test sends a bad
         signature against a replaceable other-set PQZ key; ua-c layout check is circular (assert the Rust struct size); zether-prover
         `pop` ignores leftover chain fields (clientkeys throws); ua-qt KEM version exact only to 2^53 (document it); py / C# / Go /
         Dart small inconsistencies (part-2 n-C10); the metatx-split runner's commands changed under its committed logs (n-G4);
         the `zetherPop` `popDigest` field name now means the portable digest (A3); doc nits n-D7 / n-J2 / n-V1
         (`.superpowers/sdd/2026-10-30-ua8-portable-registrations/final-review-part2.md`). Soroban (step 2, Part B) waits for the UA-Soroban spec and the Soroban UA base.
     - **EIP-7702 on branch `no7702` — BUILT, next: review + merge into `main` + push** (one push with `ua8`, never `ua8`
       alone: disclosure rule). Owner rulings D1–D5 of 2026-10-30 (after the 2026-10-29 EIP-7702 hot-wallet drain: "an EOA
       must really sign — no delegation at all; an EOA must not run code"; audit `docs/research/eip7702-audit-2026-10-30.md`;
       `docs/decisions.md` CTR-UA-24, CTR-MTX-25, CTR-MTX-18, CTR-MTX-27, CTR-TOK-03, NET-EVM-07, CLI-SGN-40). Rebased onto
       `main` `06cedadc`: D1 `SigCheck` own-key ECDSA only for a designator `5ddc577d`; D2 refuse a designator caller where the
       caller is authority + D3 bound relayer `6bb05818`; D4 relay target / native unwrap recipient + D5 deploy-time
       `isContract` `955f5337`; DEX KAT + size baseline `684f5643`; clientkeys `signDigest` opt-in + `signTyped` /
       `signKeyProof` `b76b168c`; node venue key-only + `is_contract_at` `dad611dc`; runner `20129a8b`; docs and gate logs
       after them. D6 (Algorand rekeyed sender) dropped: record only (NET-ALL-83, `644cb40a`). Left as ruled: the DEX order
       `relayer` binding, the `OpenFactory` creator, `TokenCall`'s code check, wallet `execute` / DEX interaction targets.
       Whole-branch review 2026-10-30: Ready with fixes, fixed in the `no7702 fix:` commits (m1 PQZ submitter read only
       on a pull `5f2724fa`, m2 registry `predecessor_` `isContract` + n3 `2738caee`, n1 / n2 `eaa1ba11`, n5 DEX test `d1a9ebe9`,
       m3 CLI-SGN-40 scope, n4, n7 docs).
       - [ ] **Watch: EIP-7851** (`0xef0101 ‖ delegate`, ECDSA key disabled; [research](docs/research/pq-eips-vs-scaas.md)):
         today such code is not a designator (`SigCheck.isDesignator` and the node's `is_contract` match only `0xef0100`),
         so it counts as a contract: ERC-1271 through its delegate, and allowed as a direct caller. If 7851 ships, classify
         it like a designator (owner rule "an EOA must not run code"; with its key off it then cannot sign at all) — owner
         decision at that time.
       - Gate logs: the `no7702` runner logs reuse the `ua8` file names (`smartcontracts/evm/runs/2026-10-30-ua8-*`), so the
         `ua8` merge evidence is overwritten in the tree; git history keeps it (`06cedadc` and before).
     - **Node:** follow-ups of the two merged branches — EVM node UA job path (`ua_metatx`; merged 2026-10-30), TON passkey relays (P-256
       in the node), relay-fee minimum before mainnet. **UA-8 (owner ruling R-node, 2026-10-30):** the gateway route
       `POST /v1/ua/register` and the `~gateway` sponsor policy for the four registry selectors (`register`, `setKemKey`,
       `storePqzPop`, `setPqzKey`; NODE-GW-03, `sponsorship.md#admin`) **do not exist in code** — the ruling asked to extend them, but
       there is no gateway route and no sponsor-policy code to extend; the node relays the four writes through job-API `call` jobs only
       (`Rule::UaRegistry`, `[[chains]] ua_registry`, `UA_REGISTER_SPLIT`, `64c233d4` on `ua8`). Build the route (calldata from the
       checked body, split rule) and the sponsor policy; optional: registry revert names (`UAPoP`, …) in `abi::decode_revert`.
     - **pqz-core:** fs3 Task 12 (final gate; merged 2026-10-30) → Task 6 (reproduction package; **DONE**, merged 2026-10-30
       `2b162239`: Docker quick run 252 ok / 0 FAIL, review clean); its heavy gate interleaves with
       the forge runs for the `capped` slots.
       **fs3 Task 13 (7622 reset): EIP-7702 off** (owner ruling 2026-10-30, NET-EVM-07): the reset must start from
       `/home/dockers/mba-chain-nethermind/genesis.json` (`eip7702TransitionTimestamp` removed 2026-10-30; backup
       `genesis.json.bak-pre-no7702-20261030`) — **never from a scratchpad genesis copy** (17 stale copies still enable 7702);
       after the reset a type-4 transaction must be refused (`InvalidTxType`). **Mainnet 22776: 7702 off at launch** (no
       config in the repo yet).
     - **Specs (docs only):** the combined DEX spec (minFill code + `mtxHybrid` / `Via` + `mtxExchangeBatch`), the
       **UA-Soroban spec for Soroban**, the governance matrix (§0).
  3. EVM contracts: **DEX, one round** — the 50 % minFill floor removed + `mtxHybrid` / `mtxHybridVia` +
     `mtxExchangeBatch` + mode 3 / 4 tests + reference executor + Uniswap fork test (item "DEX: drop the 50 % minimum-fill
     floor + four matching modes" under "Recorded, not scheduled"); `TradeLib`, `SCaaSDex`, node `dex.rs`, clientkeys.
     DEX spec accepted by the owner 2026-10-30: `docs/superpowers/specs/2026-10-30-dex-round-design.md` (branch `spec-dex`; DX7
     changed: a hybrid's unsold taker remainder is refunded when the sold part meets its `minFill` and limit, else revert;
     DX10 / DX11 confirmed). Plan written (no owner review): `docs/superpowers/plans/2026-10-30-dex-round.md` (T1–T19, build
     branch `dex-round` from `main`).
     **Status (paused 2026-10-30):** branch `dex-round` — T1 (floor removed), T2 (`InteractionFailed`), T3 (`mtxHybrid` /
     `Via`) done and reviewed; T4 WIP `b45c4322` (DX7 refund + `restorePulled`, capacity restored per the owner; must also
     forbid the `restorePulled` selectors in `_interact` — T3 review); then T5–T19.
     **Status (2026-10-30, later):** T4–T9, T11, T12, T14 done and reviewed; T10 (Uniswap mainnet fork test, owner:
     public dRPC `https://eth.drpc.org`, no key) in progress; then T13, T15–T19.
     **After the DEX round (owner 2026-10-30): BNB Smart Chain venues.** Uniswap v3 / v4 on BNB Chain through the
     existing `UniswapExecutor` (BSC factory, init-code hash, PoolManager in the constructor) and PancakeSwap v2 through
     path (a) interactions; **`PancakeV3Executor`** for PancakeSwap v3 (callback `pancakeV3SwapCallback`, pool address
     by CREATE2 from the separate PoolDeployer with Pancake's init-code hash; T7 review minor m3); a BSC fork test
     (public archive RPCs without a key: Blast `https://bsc-mainnet.public.blastapi.io`, Tatum
     `https://bsc-mainnet.gateway.tatum.io`; list in `scratchpad/public-rpc-providers.md`). PancakeSwap Infinity
     (v4-like) not in scope.
  4. **UA-Soroban (UA base) + UA-8 step 2 (Soroban registry)**, plus **classical Zether on Soroban** (owner 2026-10-30;
     spec S13a: its own track and branch `zether-soroban` after `ua-soroban`, BLS12-381 host functions, measure the verifier
     first — a verify over the per-transaction budget is a STOP for the owner), in one round — shared ML-DSA verifier (CAP-0087 host
     functions) and vectors. **No waiting** (owner 2026-10-29): code and tests on a local network / quickstart at
     Protocol 30 as soon as the stream is free (Stellar Core v30.0.0 stable, the SDK's ML-DSA wrapper merged 2026-10-19
     — check which soroban-sdk release carries it); only the testnet e2e runs after 2026-11-03 (Stellar testnet votes
     Protocol 30), as the last step of the round.
     UA-Soroban spec accepted by the owner 2026-10-30: `docs/superpowers/specs/2026-10-30-ua-soroban-design.md`; plan next (no owner review)
     **Status (2026-10-31): UA-Soroban built on branch `ua-soroban`** (tasks T0 to T10 incl. T2b WebAuthn canonical blob and
     T6b mandate epoch, each reviewed; local Protocol 30 end-to-end run passed; docs T11). Decisions: NET-SOR-17 to NET-SOR-26 in
     `docs/decisions.md` (spec rows S1-S18, plan SOR-D1 to SOR-D21). **Next:** the final review, the owner's go to merge, then UA-8
     Part B (`ua8-soroban`), Part Z (classical Zether, `zether-soroban`, Z0 measures first) and the Stellar testnet run (after
     2026-11-03, SDK 30.0.0). Branches `kem-scheme` and `msig-pophash` are merged (CTR-UA-32, CTR-UA-33). NODE-JOB-08 `lane_hint` and
     a per-job resource-fee cap for Soroban jobs are TODO items recorded on `main` (not repeated here); the CTR-ACC-07 epoch for NEAR,
     Algorand, Cosmos and Solana goes in each family's own round.
     UA-Soroban plan: `docs/superpowers/plans/2026-10-30-ua-soroban.md`; runs without owner review (Part UA-Soroban on `ua-soroban`,
     then UA-8 Part B and Part Z — classical Zether on Soroban, branch `zether-soroban`, S13a — after its merge).
  5. fs3 Task 13 (SCaaS testnet roll-out, Rust core image, gas re-calibration) **together with Task 9 calibration**
     (owner 2026-10-29: one measurement run; it still needs the owner's go at run time, other heavy sessions stopped)
     and, where possible, the metatx-split e2e owed on a real node → Task 14 (wasm32 limb path).
     **Owner 2026-10-30: timing and the 7622 reset are approved; run them after the three running streams are merged
     (`dex-round`, `ua-soroban`, `kem-scheme`)**, with no agent running during the two calibration runs (about 45–60 min
     quiet; the whole Task 13 + Task 9 about 2–3 h).
  6. P6h (clients + WASM) → P6i (node) → P6j (review) → P6-PUB drafts. In parallel: TradeEngine EVM ∥ non-EVM 1 × N
     (DEX).
  7. UA-7 PQ chat sessions (needs UA-8's KEM keys); then the next UA-Soroban / UA-8 plans in the family order (each spec answers the checklist [NET-ALL-84](docs/networks/README.md#NET-ALL-84))
     NEAR → Cosmos / Sui / Aptos / Solana → Algorand (`fndsa512` once AVM v14 ships `falcon_verify` Falcon-DET-512, the same key signing deterministically there; no Falcon-DET-1024 kind, owner 2026-10-30) → TON (registry design first).
  Details of the registration items:
     - **UA on non-EVM families — every kind, not only PQ** (owner 2026-10-29; rules NET-ALL-20 / NET-ALL-21,
       accounts.md "Where the records live"; today only EVM is built, NEAR / Algorand have a lazy-opened `Ua` on the
       `near-algorand` branch with classical / native / `msig` kinds): per family the UA id space (`webauthn-p256` owner
       ids per NET-ALL-21, URN display), the registry or lazy open, the UA ledger in the tokens, the mtx entries and
       account / mandate / DEX paths accepting UA holders, and the kinds the family verifies — classical first
       (`webauthn-p256`, `ed25519`, `secp256k1`, `msig`, native), then PQ where an on-chain verifier exists (Soroban
       `mldsa44` / `mldsa65` via CAP-0087, NEAR `mldsa65` via `ml_dsa_verify`, Algorand `fndsa512` after AVM v14). Same
       family order as UA-8: 1. EVM (done), 2. Soroban, 3. NEAR, 4. Cosmos / Sui / Aptos / Solana, 5. Algorand, 6. TON.
       Soroban's UA base and UA-8 step 2 go in one round (shared verifier + vectors). Supersedes the 2026-10-19 "Family
       priority for UA" order (EVM, Cosmos, Sui, Aptos, Solana first; Soroban / NEAR / Algorand assessed later).
     - UA-8 portable UA registrations, **steps 1–2 only** (owner 2026-10-29): 1. EVM (P1–P9), 2. Soroban (`mldsa44` /
       `mldsa65` via the CAP-0087 host functions, Protocol 30: testnet vote 2026-11-03, mainnet 2026-11-23; local network
       until then). Later plans, in this order: 3. NEAR (new `ua-registry`, `mldsa65` via `ml_dsa_verify`), 4. Cosmos /
       Sui / Aptos / Solana, 5. Algorand (`account` app; `fndsa512` once AVM v14 ships), 6. TON (registry design first);
       relayer-checked mode wherever a kind has no on-chain verifier (design P10 / P11).

- **Now (2026-10-26, owner order):** R0 fix part a **DONE**, merged into `pqz-16k` and pushed (`40366c76`). Part b
  (contracts, node, spec / docs) + its fix round **DONE** on `pqz-r01` `0d22e165` (review Approved with fixes; I-1 owner
  option (a): the start-up id check reads the schedule at the block-tree head + 1, not the wall clock; Nethermind 49 / 49
  at n2304 / n2816) → re-review → on approval merge `pqz-r01` into `pqz-16k` (fast-forward) and push `pqz-16k` (owner
  2026-10-26) → then, in this order (owner 2026-10-26):
  1. [x] **DONE 2026-10-26** (`31af331e`: image `4d906b55…`, library `dd0e7668…`, probe 420 ok / 0 FAIL, e2e 84 ok / 0
     FAIL; stack backups `*.bak-pqz4-20261026`). **New image + SCaaS testnet roll-out of part b**: image `2.2.0-pqz5` at `n2304-kmax4096`, reset via RUNBOOK
     path B (the new plugin refuses the live v4 / v2 schedule by design), redeploy, probe + e2e; provisional prices
     (retired calibration × 1.3) until Task 9. The testnet node is stopped until then (host shutdown 2026-10-25; owner:
     leave it stopped).
  1b. [x] **DONE 2026-10-26** (merge commit on `main`, no conflicts; forge 1361 / 0 / 9, size gate 0 errors).
     **Merge `pqz-16k` into `main`** (owner 2026-10-26), right after the roll-out passes: a merge commit (the
     branches diverged at `61476cd0`), doc conflicts resolved (`pq-zero-knowledge.md`, `decisions.md`, `TODO.md`),
     `docs_check`, forge at n2304 and the size gate (no full gate: no core / set change). Pushing `main` needs the
     owner's go. From then on 8d part 2b and every later step branch from `main`.
  2. [x] **8d part 2b — DONE 2026-10-27** (merged into `main` `6fd75c83`): `ROLL_MAX` 96 / 80 / 64 / 32 on both relay
     paths (owner ruling 2026-10-27), gas per relation and set, PQZH calldata research + owner ruling option (A), part b
     items (a)–(d), testnet contracts e2e 217 ok / 0 FAIL, review + fix round, pqz-core READMEs updated.
  3. [x] **Contracts review (part 2 of the three-part review) — DONE 2026-10-27**: Codex C0–C2 (credits ran out; owner:
     no refill), agy C0–C6, Claude UltraCode workflow C0–C6, Fable C0 + consolidation
     (`pqz-core/research/code-review-2026-10-26/README.md`: 1 P0, 2 P1, 5 P2, 57 P3); owner rulings 2026-10-27 (C0-1 (ii),
     C0-2 (2), C0-3 (1), C0-6 (3)); fix round plan `docs/superpowers/plans/2026-10-27-contracts-review-fixes.md`, merged
     `e2e7a01e` (9 tasks, each reviewed; final review Yes with fixes; gates green at four sets + clients). Done after it
     (owner 2026-10-27): the Zether prover's per-M gas table re-measured (merge `gas-zether`; BLS12-381 max M compact 8 / 8,
     BUNDLE 7 with the auditor, 8 without; state gas in zether.md §19), `docs_check facts check` 0 misses (merge
     `docs-facts`), Dependabot #42–#45 fixed. Open: ~40 deferred minors (README "Fix round",
     `scratchpad/review2-fix-ledger-2026-10-27.md`). Part 3 (pqz-prover + node relay) after P6h / P6i.
  4. [ ] **Task 9 calibration** (timing: needs the owner's go) → final prices replace the provisional rows.
  5. [x] **The metatx split, `mtxPayMeta` / `uaPayMeta` (CTR-MTX-26) and `MtxRelayFee` (CTR-MTX-27) — built on branch
     `metatx-split` 2026-10-27/28 (Tasks 1-20, the final fix wave, the owner rulings 2026-10-28 incl. I2 Solana recovery;
     merged into `main` and pushed 2026-10-28 on the owner's go)**: T1 parity fixture `c9ec6fb0`/`2ceda92d`, T2 library `76dc5be2`,
     T3 token paths `04a2ede6`, T4 trade `b36c9dac`, T5 PQZ/Zether `840f0642`, T6 link closure `c213e24a`, T7 pay-meta
     `a221b015`/`2623719a`, T8 re-measure `69fce983`/`004890a2`, T9 router `333c96b6`/`3f30ff87`, T10 Soroban `cd5e508c`,
     T11 Solana `b2986c5b`, T12 Cosmos `9dfcc559`, T13 Sui `8a033b0e`, T14 Aptos `78c67cff`, T15-T16 TON `1bba36e0`/`16bac7d0`,
     T17 node `9777679f`..`d784f264`, T18 clients `a0ab2e47`/`e7c9e3c4`, T19 docs `f80f2e73`/`a3a02a1c`, T20 closing gates
     `67fa7a45`/`cecde76b`, final fix wave `deead173` (TON relayed-call pre-check, review minors M1–M13), records `4f12980c`, logs `6b2cdd89`,
     re-review fixes `6c31fbac` (re-review F1/F2/m1–m5, TON Mandate `get_lane_nonce`), records `2ffa9c73`/`0beebc7c`,
     logs `c043e5b7`, second re-review `f0d4025e` (TON payment leg: LANE_TTL, balance), records/logs
     `afb8dd1d`..`31b02ed1`, third re-review `07d2f411`/`3dd94fb0`/`eff492c3`
     (payment validity floor; removed in `2cac867a`, restored by its revert `0c90f031`: owner ruling 2026-10-28, risk
     acceptance reversed, fix kept); owner rulings 2026-10-28 on the final review list: Solana recovery and no-op
     wrappers `e04a5733`, records and immutable Sui / Aptos deploy `99e44cce`, EIP-7702 address path `84b0a469` + records/gate logs (head). Figures: `docs/contracts/metatx.md` §8
     (relayed overhead +7.4 k to +7.6 k per call; `n2560-kmax16384` `ROLL_MAX` 64 keeps 6,032 gas, was 15,281: any further
     token-path growth above ~6 k forces 48). Next: NEAR and Algorand on their own branch from `metatx-split` (owner
     2026-10-27; spec approved 2026-10-28; its plan is written in the main checkout, executes in parallel,
     merge/push need the owner's go). Then UA-8 (before fs3 Task 13), fs3 Task 12 → 6 → 13 → 14, UA-7, governance code.

  `pqz-core` is a dev-freeze at the current ids; 8d part 2b may reopen it (PQZH calldata).
- [ ] **Label scheme at the production freeze** (owner 2026-10-25): keep the current labels during development; at
  the freeze switch to `scaas/pqz/<set>/pqzl/v1` / `…/pqzh/v1`, every old id refused. Note it in the sets README
  (part b).
- **Earlier (2026-10-23, evening shutdown):** `pqz-16k` `fe5abb63`: **Task 8b DONE** (four gates PASS, z21diff byte-identical
  after N4), `pqz-8c` merged; **8c part 2 paused** on `pqz-8c2` (WIP `ea7beeae`: generator owns `pqzh_set.rs`, per-set
  PQZH limits, n2560 PQZH, ffi / vectors / gate per set; vectors, docs, gates left) — owner answers
  2026-10-23: `MAX_INPUT` per set OK, n2560 preset t = 122, generated header accepted. Order in HANDOFF.md top note.
- **Earlier (2026-10-23, afternoon shutdown):** `pqz-16k` `fdf2ae7a`: 8b review (4 Important / 10 Minor) → fix round 1 + re-review
  (approved pending I2; per-set build paths so the four gates run at once, owner `CAPPED_SLOTS=4`); gate
  `n2048-kmax1024` PASS; resume the other three gates (`gate.sh --last <set>`, before merging `pqz-8b-fix` `bd27243e`,
  re-review minors N1–N4) → 8b DONE → merge `pqz-8c` → 8c part 2. Order in HANDOFF.md top note.
- **Earlier (2026-10-23, morning shutdown):** `pqz-16k` `eb823b44`: 8b item 6 built (`n2560-kmax16384`, `n2816-kmax65536`), gate
  resume tooling; next `scripts/capped pqz-core/gate.sh --last` (resumes the `n2816-kmax65536` gate), then the
  `n2560-kmax16384` full gate, 8b report → review → merge `pqz-8c` (`bf38bbbd`, 8c part 1b done) → 8c part 2
  (`MAX_PROOF_PQZH` 327,680 B for `n2560-kmax16384` only, owner). Order in HANDOFF.md top note.
- **Earlier (2026-10-22, shutdown):** 8b items 1–5 + per-set generator done on `pqz-16k` (`61b0c003` WIP; set (a) gate PASS;
  v3 gate re-run + item 6 16k / A′ via `set.toml` + `make.sh all` left); 8c part 1 + 1b on `pqz-8c` (`6e69bfa0` WIP; set (a)
  PQZH = preset B t 120, fallbacks A `fallback-retry` / C; `c8b.sh` checks left). Order in HANDOFF.md top note.
- **Earlier (2026-10-21 evening):** **5h part B** on branch `pqz-16k` (not pushed). Done: Task 7 (16k, now superseded),
  7b (Amsterdam re-measure), 7c (smaller n), 8a (B-1, A-2, `R_REG`; reviewed), spike PACK (P46) and F185 (Foundry 1.8.5,
  every profile amsterdam) — both merged into `pqz-16k`. **Task 8b paused** (parameter sets `pqz-core/params/sets/`, PQZL at set (a)). Then 8c PQZH
  (backup) → 8d stmt / contracts (P46, per-set Solidity, 32-bit precompile addresses, `ROLL_MAX`, M = 8 by measurement,
  one id bump) → Task 9. HANDOFF.md top note has every owner ruling of the day.
- [x] **Node / relayer on the Amsterdam gas model — done 2026-10-22, merged `b62a54f1`** (per-chain fork detection, regular ≤ 2^24 + EIP-7976 floor on Amsterdam chains, 2^24 clamp elsewhere, gas = estimate + 20 % capped by `max_gas_per_tx` / live block limit / 2^32 − 1, out-of-gas simulations refused, rebuilt jobs keep their gas; `DECOY_LEG_GAS` 120,000; testnet `max_gas_per_tx` 64 M, owner). Was (F185 finding): regular gas ≤ 2^24 per tx, total (regular + state)
  up to 2^32 − 1; `scaas-node` zether.rs `DECOY_LEG_GAS` 32,000 vs 116,698 measured per leg; the prover's `gas_limits` M
  table assumes total ≤ 2^24 (edge cells need 21–31 M); `docs/node/ops.md` `max_gas_per_tx` 16 M. Never assume gas
  price 0 or our block limit (owner 2026-10-21: the precompile may be deployed for customers).
- [ ] **UA-8 items owed to fs3 Task 13 and the next core change (2026-10-30, A12):** (1) **the SCaaS testnet's `UARegistry`
  is redeployed once in Task 13** with the UA-8 registry (`register(kind, keyData, attrs, pop, pqzPop)`, `storePqzPop`,
  `setPqzKey`, `setKemKey`, the views; the old chain-bound registry is not compatible — all chains are test-only, no
  migration); the e2e scripts (`script/pqz/e2e.py`, `scripts/e2e-zether.sh`) were rewritten on it and have **not run against
  a chain yet**. (2) **Watch item — `n2816-kmax65536` `storePqzPop` ≈ 59.9 M gas with the real `R_REG` verify** (57.5 M in the
  gas log with the `rreg` stand-in, plus ≈ 2.4 M regular gas for the ≈ 3.65 M verify), right at a 60 M block; **the gen-2 variant**
  (`storePqzPop` on a gen 2 that enables `0x0142` for a gen-1 record, 57,729,122 in the gas log with the stand-in) is **≈ 60.1 M, above a
  60 M block** (a gen-1 PQ holder's key could then never be proven on such a chain); `n2304-kmax4096`
  has ≈ 7 M headroom. **No split option for `storePqzPop` itself:** through a relayer its cap is min(block gas limit,
  `max_gas_per_tx`), and a `storePqzPop` over it (n2816 ≈ 57.7–60.1 M) gets the node's ordinary gas refusal — `UA_REGISTER_SPLIT`
  applies only to `register` with its proof, and the proof cannot be split further (final fix A concern 1, part 1 m1). Measure the real call (Task 13) before choosing `n2816-kmax65536` for a chain whose block limit (or relayer cap) is
  60 M; this concerns 60 M-block chains, **not the SCaaS testnet (200 M, genesis `gasLimit` `0xbebc200`)**. `e2e.py` takes the full path only when
  `eth_estimateGas` of the full register is at most `gasLimit·1023/1024`, otherwise (or on an estimate error) `register` + `storePqzPop` (a full
  registration with the proof is 84.8–109.1 M). Coverage note: on the SCaaS testnet (200 M) `e2e.py` takes the **full** path, so the inline `register` + proof runs
  in Task 13; the paths that have never run on a chain with the real `R_REG` verifier are the **split** one — `register` without `pqzPop`
  then `storePqzPop`, which `e2e.py --split` forces — and the **later PQZ key**: `setPqzKey` + `storePqzPop` with the `R_REG` proof over
  `uaMessage(0x0142, PURPOSE_PQZ_KEY, pqzKeyDigest(ua, h))`, which `e2e.py` now has as its own step (`a651600f`: `dave`, an ML-DSA-65 UA
  registered without a PQZ key, then `setPqzKey`, a third party's `storePqzPop`, `pqzKeyOf(ua).proven`, `checkedOf` = (1, 1, 0)); run both once on the SCaaS testnet in Task 13 (an
  anvil has no PQZ precompile). (2b) **A replaced `setPqzKey` key survives only in its log** (owner ruling R-cross-set, `cc965914`):
  when `setPqzKey` replaces an other-set key that `setPqzKey` itself stored, the old key, hash and signature are overwritten in
  state; the record survives only in its `UAPqzKeyAdded` log (and on the chains of its own set) — a replaced `register` key is kept
  for `registrationOf`. Watch: decide whether to keep it in state if logs get pruned (EIP-4444) before anyone copies it. (3) **`pqz-core/stmt/src/lib.rs` doc comment**: it still names `popDigest`; UA-8 changed only the 32-byte
  message's pre-image (`uaMessage(0x0142, PURPOSE_POP_V2, portablePopDigest(ua, pqzKeyHash, kemRecordHash))`), not the `R_REG`
  relation, statement or precompile. Edit the comment with the next pqz-core change (a doc-only edit in a core file would
  force the full pqz-core gate; owner rule: full gate only for core changes). Decision: `docs/decisions.md` CTR-UA-31 (the plan decision
  "pqz-core untouched").
- [ ] **SCaaS testnet at the next reset (plan fs3 Task 13):** ~~genesis `gasLimit` 200 M~~ **done 2026-10-22** (owner: reset now;
  genesis `0xa17faef4…2ac2`, `b62a54f1`; fail-closed drill, README v2-id note, `eth_estimateGas` probe row also done); the PQZ library v4 of the chosen set; the 32-bit precompile addresses; the
  `nethermind-2.2` review minors: fail-closed drill with a tampered library, e2e burst / fill drills under Amsterdam,
  a 200 M block load rehearsal, `.dockerignore` for the default (no `FFI_REV`) image build, README note that the
  testnet's PQZL v2 id is the forgeable one, an `eth_estimateGas` row in the probe; main's FFI library `ee2f7096…` is
  not the reviewed `16dd99ce…` (review the v4 library before building the image); the `UARegistry` redeploy for the native UA kinds `0x0017 near-account` /
  `0x0018 algorand-address` (near-algorand T2: `UAKinds` bytecode changed, spec 2026-10-28-near-algorand-design §8).
- [ ] **Dependabot alerts 19 / 20 / 21 — owner 2026-10-22: leave open (option 2), no dismiss.** (2026-10-27: #36 `sprintf-js` closed on its own; #42–#45 `fast-uri` < 3.1.9 in `smartcontracts/ton`, dev-only via `ajv`, fixed by the lockfile bump `885c91f4`, TON tests 28/28.) All dev / test-only:
  Solana `ed25519-dalek` 1.0.1, `curve25519-dalek` 3.2.0, `rand` 0.7.3 via `litesvm` 0.17 (dev-dependency) →
  `agave-precompiles` 4.3.0 — `cargo update` once litesvm / Agave move to `ed25519-dalek` 2; TON `sprintf-js` 1.0.3 via
  jest → babel-plugin-istanbul → `js-yaml` 3 → `argparse` 1 (no patched version) — goes when jest drops `js-yaml` 3.
- [ ] **Research (owner 2026-10-21, not blocking):** PQZH proof below ≈ 170 KB at the proven soundness (the debit
  inputs must fit one tx under EIP-7976, ≈ 261,909 B with the statement); Kyber-style compression of `u` (noise vs
  `K_MAX`); both only if PQZH on chain or smaller blobs are wanted.
- [ ] **UA-8: portable UA registrations** (owner 2026-10-25, queued **after 5h, before fs3 Task 13**, then UA-7): a UA
  registered on one chain can be registered on any other by anyone (chain-independent PoP digest); the KEM (chat)
  key registered in `UARegistry` as a signed versioned record, copyable the same way; short design
  [`2026-10-25-ua8-portable-registrations.md`](docs/superpowers/specs/2026-10-25-ua8-portable-registrations.md), plan
  [`2026-10-30-ua8-portable-registrations.md`](docs/superpowers/plans/2026-10-30-ua8-portable-registrations.md). **Step 1 (EVM) is
  built on branch `ua8` (A1–A13 done, final review done, final fix wave done, its re-review next; not merged, not pushed)**; step 2 (Soroban, Part B) is open.
- [ ] **UA-7: PQ chat sessions** (owner 2026-10-25, queued **after 5h**; **UA-7 can now read a UA's chat key with
  `UARegistry.kemKeyOf(ua)` (the highest stored version) and `kemKeyAt(ua, version)`**, UA-8 step 1 on branch `ua8`; wrap a session
  key to any stored version — every stored version is usable, no revocation): application contract `PqChat` — one
  ML-KEM-1024 + X25519 key per UA first, sessions whose AES-256 key is KEM-wrapped per member key and stored on chain (epochs
  for rekey / members), messages off chain (e.g. Matrix custom events); short design
  [`2026-10-25-ua7-pq-e2e-sessions.md`](docs/superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md) (owner 2026-10-25: ML-KEM-1024 + X25519 only,
  anyone may create a session, every write through mtx), then a plan.
- [ ] **Metatx split** (owner 2026-10-20 "kiểu gì cũng phải tách"; governance goes to a lib or module): spec → plan →
  build **after 5h part B merges, before fs3 Tasks 12 / 6 / 13 and before governance code** (timing ruled 2026-10-21).
  **Owner 2026-10-21: variant A** (DELEGATECALL library, the token keeps the entry points); pass the library only the
  envelope data hash (else a ≈ 340 KB op 7 pays ≈ +1 M gas).
- [x] **`MtxRule`: allow-list vs fee class — owner 2026-10-20: keep as is.** `feeClass = 0` = not relayable,
  `ABSOLUTE` / `AMOUNT` = the fee basis (CTR-MTX-20); on contracts with `supportedModes() = 0x03` (`SmartKeyAccount`,
  `MandateWallet`, their `cancelNonce`) an `ABSOLUTE` selector can only run with fee mode `NONE` (CTR-MTX-22; node
  `guard.rs` checks both). Rollovers on the tokens are `ABSOLUTE` (fee `NONE`, `FIXED 0` or `FIXED x`). No change.
- [ ] **Review order with Codex (owner 2026-10-20; Codex credits limited — two runs only, one type at a time, each on
  the owner's go):** (1) UA-6 (contracts, clients; Claude reviews) → (2) 5h part A (PQZ state, proof-free shield,
  `SHIELD_POOL`, `mtx*` names, fees; plus UA-5c (a) the confidential ops through the UA envelope binding and (b)
  unshield to a `bytes32` UA recipient, owner 2026-10-20 — the ABI is rewritten once; contracts, today's parameters;
  Claude reviews) → (3) 5h part B: the 16k
  regeneration in pqz-core (C, Rust, PQZH Ligero, codegen, vectors; q = 2^50 − 42,310,535, B-1, A-2, `R_REG`) →
  (4) **Codex run 1: pqz-core Rust + C** — one job over the v3 → v4 pqz-core diff, focus: Fiat–Shamir transcript (B-1,
  A-2), parameters / q / Ligero subgroup, `R_REG` message, constant-time paths, secret wiping (A-3), C = Rust parity;
  hand it the gate logs, fuzz results and review A's cheating prover; free sandbox check `codex sandbox` first →
  (5) fixes → fuzz → gate fin → **freeze pqz-core** → (5a) **token-family rename** (`NormalToken` / `WrappedToken`;
  before P6h and before Codex run 2, so the review sees the final names) → (5b) **`clients/pqz-prover` (P6h)**: the
  wallet PQZ prover — a Rust crate over `pqzl` + `stmt` with wasm bindings, API shaped like `clients/zether-prover`
  (read state, decrypt the balance, build statements, prove, envelope; the wallet view list `pqzAccount`, `pqzAcc`,
  `pqzPending`, `pqzPendingCt`, `pqzEntryBlob`, `minDecoyFee`; rollover by count; both `mtxRollOver` and `mtxPrepareAcc` are relayable (CTR-MTX-19), and the prover may also call `mtxPrepareAcc` directly) → (5c′) **UA-5c (c) + (d)**: the generic UA
  envelope pipeline in `MetaTxBase` and `MandateWallet` (+ Hedera) with `bytes32` owner / delegate / payees (needed by
  the node's `ua_metatx`) → (5c) **node relay (P6i + the needed part of
  UA F5)**: `ua_metatx` jobs (UA envelopes, `from: bytes32` — after UA-6 every Zether UA and PQ signer writes only
  through them; today the node relays address envelopes only), `pqz_call` (direct PQZ calls on the private chain),
  canonical re-encoding of Zether calldata (one intent, one id; NODE-JOB-20) → (6) **Codex run 2: contracts +
  pqz-prover + node relay** (OpenFactory 5g-Z2, UA-6 registry, PQZ / Zether after 5h; the prover's secret handling;
  the relay paths) before the SCaaS testnet redeploy → (7) plan fs3 Task 13 (SCaaS testnet reset, real e2e: wallet with pqz-prover,
  node relay, fees; ask the owner before timing).
  If credits allow only one run: pqz-core first (proof soundness); contracts keep Claude reviews.
  **Every Codex run is paired with an agy (Antigravity / Gemini) review of the same scope at the same time** (owner
  2026-10-20), then one triage of both reports (as G / H on 2026-10-19).
- **Next (2026-10-20 shutdown):** (`rev2-small-fixes` and Z2 merged 2026-10-20) → UA-6 (CTR-UA-30: PQZ key as an attribute of a PQ-signing UA, supplied in `register`; Zether key stays a UA) → 5h (+ `plainPending` removed, `SHIELD_POOL` for PQZ and Zether) → 16k parameter regen with B-1 / A-2 / R_REG under one `proofSystemId` → Task 12 → 6 → 13 → 14 (resume notes in HANDOFF.md).
- [ ] **P0 PQZL Fiat–Shamir fix — rest of plan `docs/superpowers/plans/2026-10-19-pqzl-fs3.md`** (owner 2026-10-19:
  first; code merged `361a86b`, PQZL `proofSystemId` v3; full item in COMPLETED.md): Task 5h, the 16k regeneration,
  Tasks 12 → 6 → 13 → 14 in the order of the Next line. Owner approval pending: the lazer#28 comment and the D-2/D-3
  issue (drafts in `scratchpad/`).
- [x] **Zether BLS12-381 only (owner 2026-10-20, decisions CTR-ZTH-32; done inside UA-6, design U10)** — bn254 Zether (verifier, `proofSystemId`, UA kind `zether-bn254` 0x0140 + its Schnorr verifier, deploy steps, vectors, client paths) to `legacy/`; specs zether.md / accounts.md / README follow; with UA-6 and 5h. Also with 5h: drop `*_ZETHER_PQZ` kinds (CTR-TOK-21), `mtxShield` / `mtxUnshield` (CTR-ZTH-45), four flows with proof-free shield (CTR-PQZ-06). **Done on branch `ua6` (merge pending).**
- [x] **UA-6: encryption keys as UA attributes (owner 2026-10-20, decisions CTR-UA-30; research `docs/research/ua-identity.md`; spec + plan merged 2026-10-20: `docs/superpowers/{specs,plans}/2026-10-20-ua6-encryption-key-attributes.md`, owner rulings at the plan's top; next: code)** — spec + plan, then code: registry `register` takes the PQZ key (PQ signers only), `keyOwner` uniqueness incl. msig, `pqz-mlwe` kind and `authRef` removed, `R_REG` message bound to the UA id (rides the 16k id bump), PQZ account keyed by the signing UA; classical Zether unchanged (key = UA, "self" mode). Before plan Task 5h. All UA clients follow. **Done on branch `ua6` (merge pending).**
- [x] **Z2 owner questions (answers 2026-10-20; Z2 merged 2026-10-20, all applied; notice period: 3 days minimum on every mainnet, owner):** notice period defaults (10 min on the SCaaS testnet, 3 days on 22776) — **OK**;
  library pins = registrar list checked by code hash, not compared with the init code's link references — **OK**;
  `initialize` without Env — **answered**: keep the split explicit — the implementation carries what never changes for it (Env: verifier addresses, registry, chain, libraries; fixed in its constructor), the contract instance carries its own configuration from `initArgs` (e.g. a wrapped USDC → VND token at 1 : 25,000 and a USDC → RUB token at another rate; mint / burn / blacklist / … allowed or not), and both feed the governance matrix item; `deployImplementation` binds the kind's latest Env
  — **No**: to be discussed together with smart-contract governance and token governance.
- [ ] **PQZL Rust port follow-ups** (port merged `5952951`; placed in the fs3 plan 2026-10-19; full text in
  COMPLETED.md): (1) roll-out on the SCaaS testnet — Rust-backed `Nethermind.Pqz` image (pqz-ffi default `pqzl-rust`), RUNBOOK steps
  as P6f, PQZ gas rows re-calibrated on the chain host before or with the image switch (CTR-PQZ-09 controller proposal)
  — Task 13; (2) at the roll-out pq-zero-knowledge.md (~1293 / 1320 / 1504) names the Rust crate as the production core
  — Task 13; (3) wasm32 limb path in `pqzl/rust/src/arith/ntt.rs` (wasm32 `verify_fast` 1.7–2.0× slower than C, R_TXM8
  p99 51.0 ms vs 60 ms; D6 `pqz-core/pqzl/rust/runs/d6/results-d6.md`) — Task 14, own branch; (4) M = 16 Rust rows
  (`--multi-bench`) — Task 13; (5) deferred minors (heap check in `verify_only` C-M5, pqz-ffi OOM and fallible `Ctx`
  tests, panic-path test, `PQZL_MEM_*` echo, gate PASS line file, two-limb S3 oracle) — Task 5e.
- [ ] **Rename token family** (BUILT on branch `token-rename` 2026-10-30, merge pending; owner 2026-10-13 / -18 / -19: right after the PQZL Rust port follow-ups, before P6h /
  P6i / P6j / P6-PUB): `UnderlyingToken` → `WrappedToken`, `NoUnderlyingToken` → `NormalToken`, the whole family
  (`UnderlyingZetherToken` / `NoUnderlyingZetherToken`, `UnderlyingLib`, `IUnderlyingToken`, `TokenKind` `NONE` →
  `NORMAL`, `UNDERLYING` → `WRAPPED` and the `_ZETHER` / `_PQZ` / `_ZETHER_PQZ` variants); names only (enum numbers, ABI,
  vectors, storage unchanged); keep `underlying()`; not "NativeToken"; `legacy/` and `docs/history/` unchanged, old
  names to `docs/history/dropped-artifacts.tsv`. Scope (2026-10-13): ≈ 67 files in `smartcontracts/evm`, ≈ 40 docs,
  `scripts/size_gate.py`, one node test.

### P6 — what is left

Roadmap `docs/superpowers/plans/2026-10-12-p6-roadmap.md`. Done: P6a–P6g, P6-SZ, P6-Z21, P6-REL, P6-PQZH-SOL, the
`R_TXM` multi-recipient transfer (P6-ANON S1–S9, op 7 live on the SCaaS testnet and in the PQZ tokens), gates A / B and the freeze
(2026-10-17) — details in COMPLETED.md.
- [ ] **P6h** clients and WASM (browser wallet bundle builds with `SV=0`, owner 2026-10-13), **P6i** node, **P6j**
  review — after the token-family rename (owner 2026-10-19).
- [ ] **P6c owner step:** audit the PQ verifiers and the expanded-key cache before any public chain enables a PQ kind.
- [ ] **P6f follow-ups (owner):** follower + public RPC, restart policy (the SCaaS testnet node has none), deleting backups; the
  hourly `watch.sh` check is manual. (P6f done and live on the SCaaS testnet since 2026-10-16.)
- [ ] **P6-PUB drafts** (owner 2026-10-14, session 4): after P6, the live precompiles and P6-ANON, the controller drafts
  the ePrint paper (LaTeX, citing the frozen package) and the ethresear.ch post (Markdown, results-first), kept private
  in `scratchpad/pub/` until the owner posts; the results mail to the LaZer maintainers
  (`scratchpad/sz-private/results-letter-lazer.md`) goes first (ruled 2026-10-13; **changed owner 2026-10-26: send them the
  drafts 1–2 weeks before posting, do not wait for a reply**; the mail also gently follows up the G-LIC question). Full scope in COMPLETED.md.
- [ ] **P6-PUB publish PQZL** (owner 2026-10-13; **scope owner 2026-10-26: only the PQ and PQZ results** — the PQ
  signature verification (ML-DSA-44 / -65 precompiles, EIP-8355 layout) and PQZ (PQZL + PQZH: relations, parameter sets,
  proofs, precompile, contract state); not the rest of SCaaS): ethresear.ch post + ePrint paper; source-only package
  `pqz-core/artifact/` (PQZL + PQZH, Docker + `reproduce.sh`), source tag + Zenodo DOI; re-measured headline numbers in
  README §11, a five-relation table in `pqz-core/README.md`, the posts' opening line (not the spec); the owner mails the
  LaZer maintainers the drafts 1–2 weeks before posting, without waiting for a reply (owner 2026-10-26). Status: freeze `--full` 2026-10-17; fs3 Task 6 updates the package to the current id.
- [ ] **P6-ANON leftovers:** `PQZ_DEBUG_MALLOC` sanitizer variant (ASan inside the arena; not scheduled); op 7
  disclosure-bundle / per-leg opening vectors (pqz-stmt codec; from S4); identity hiding beyond the receiver ring =
  research only (`docs/research/pqz-anonymity.md`), owner decides.
- [ ] **PQZH leftovers** (backend Ligero over F_q, proven, owner 2026-10-14): external review of the Ligero ZK argument
  with the cryptographic audit; 128-bit post-quantum target deferred (owner 2026-10-18: calldata ≈ 7 M gas; new
  parameter set and id); pin Plonky3 0.9.0 final for the backup crate (`docs/research/pqzh-ligero.md`).
- [ ] **P6-SV leftovers:** independent review of `pqz_sv.c` against `lnp-tbox.c` (started 2026-10-13; result not
  recorded in TODO); hand-written AVX2 and a run on the chain host (not needed for the limit).
- [ ] **Revisit the credit cap `K_MAX`** (owner 2026-10-13: keep 1024 for now): now part of Task 5h and the 16k
  parameter regeneration (`K_MAX` raised by A', q ≈ 2^54). Context in COMPLETED.md.

### Recorded, not scheduled

- [ ] **DEX: drop the 50 % minimum-fill floor + four matching modes** (owner 2026-10-29; research
  [docs/research/dex-matching-modes.md](docs/research/dex-matching-modes.md)): (a) owner decision: `MIN_FILL_PPM` goes,
  the per-fill minimum is the signer's `minFill` only (§6.3: new CTR-DEX-14 text, then `TradeLib`, `SCaaSDex` Path B,
  node `min_fill`, clientkeys, tests; non-EVM unchanged; spec DONE 2026-10-29: CTR-DEX-14 / NODE-DEX-15 / CLI-SGN-35 SPECIFIED; code after the near-algorand merge, owner 2026-10-29); (b) four modes book / outside / hybrid / CoW-ring on the two
  existing entry points, NODE-DEX-17 rewritten to one atomic plan per order (§1–§6); owner answers 2026-10-29 (§8): hybrid / CoW both via `mtxExchange` plans and a new `mtxHybrid` / `mtxHybridVia` entry (maker price on chain, surplus to the taker); CoW price = AMM marginal, else midpoint; `mtxExchangeBatch` now; TradeEngine EVM and non-EVM 1 × N in parallel. Order: after the near-algorand merge → minFill code → EVM contract spec + code (mtxHybrid, batch, mode 3 / 4 tests, executor, Uniswap fork test) → TradeEngine ∥ non-EVM 1 × N.
  Spec first, then code.
- [x] **EVM node: the UA job path** (controller call 2026-10-28, metatx-split T17 fix 1; owner ruling 2026-10-28: after the
  metatx-split merge; a new feature, not T17): BUILT on branch `node-ua-jobs` (2026-10-30, `f0f8fd50`; merged into main 2026-10-30): the
  `ua_metatx` kind (`uaExecute`, `uaExecuteTransfer`, `uaPayMeta`), the call-table row `MtxRelayFee.uaRelay` priced at
  `params.relay_fee.min_wei_value` against the quote, `UAPaymentSettled` / `UAMetaTransactionExecuted` rows joined by
  `join_pay_events`; choices in decisions.md (CTR-MTX-27, Change 2026-10-30). Left for UA F5 below: gateway route, record
  cache, mesh, the other `ua*` jobs.
  - [ ] Restart fee basis (node-ua-jobs fix 1 re-review minor 2): a tracked job's `Sent.fees` is the current `chain.fees()`,
    not the tracked tx's, so a priced job's replacements after a restart are refused by the mempool every stuck period
    (churn, no loss); seed `fees` from `tx_fees` (+ `maxPriorityFeePerGas`) for a priced job.
  - [ ] Forgotten tx after a restart (re-review minor 3): a priced job whose tracked tx the RPC no longer knows is only
    gap-filled (the payer re-signs; liveness only) and takes no subject hold while the old tx may still land (a small I2
    window); re-price and re-send it, and hold its payer.
  - [ ] Relay-fee starvation (re-review minor 4): a subject that keeps other jobs in flight keeps its own relay-fee job
    `SUBJECT_HELD` until it expires (hurts that subject only); if it shows up, refuse new non-relay holds while a relay-fee
    job of the subject waits.
- [ ] **Relay-fee minimum before mainnet** (owner ruling 2026-10-28, final review owner rulings item 7): the flat
  `params.relay_fee.min_amount` (one floor per chain, default 1 base unit, every token and call) stays until before mainnet;
  re-decide then between a per-token minimum and gas-proportional pricing (TON `min_ton_value` and Solana
  `min_lamports_value` already price per token).
- [ ] **TON passkey relays need P-256 in the node** (owner ruling 2026-10-28 on the final review residuals): the node refuses a
  passkey-signed relayed call until it verifies P-256 (`get_passkey` + the WebAuthn check; a `p256` dependency); passkey
  users send revoke / set_key directly meanwhile.
- [ ] **metatx split — e2e still owed on a real node** (no network operations were run in Tasks 1-19): (a) Soroban `relay_fee`
  simulate + submit on a testnet or the quickstart localnet, proving the explicit `SourceAccount` auth entry (the Rust test
  environment has no transaction source); (b) Cosmos gas of `Relay` and the executor on a wasmd localnet (cw-multi-test has no
  gas), then set the node's gas limits from it; (c) Aptos two-passkey `relay_*` against the 9,200 exec-gas ceiling
  (unmeasured), and the relay-fee job with the payer Account closed; (d) Solana `gen_vectors.py --check` in the checkout that
  holds the vector generator (`vectors.rs` relay lines were added by hand), and a passkey x passkey wrapper transaction against
  the 4,096-byte v1 limit; (e) a TON relay-fee run on a testnet (the sandbox config is the only pricing seen so far), which also exercises the node's
  new getter call shapes against TON Center v3 `runGetMethod`: `get_executor`'s address argument as `{"type": "slice"}` and
  its slice result read through `stack_cell`, `get_codes`, the Mandate's `get_lane_nonce`, `get_wallet_data` (only the
  fake API checks them today); (f) the immutable deploys (owner ruling 2026-10-28): Sui `deploy.sh sui` publish +
  `0x2::package::make_immutable` on the created `UpgradeCap` in the same run (the `--gas-budget` flag for older CLIs,
  `SUI_GAS_BUDGET`; the cap object must be gone afterwards), and the Aptos `deploy-object` publish with
  `upgrade_policy = "immutable"` (the package registry reads back policy 2); neither has run against a network.
- [ ] **metatx split — final review follow-ups** (review done, branch merged into `main` 2026-10-28; leftover minors the reviews deferred):
  - [x] 7702 intent: ruled (owner 2026-10-28): delegate-only signatures accepted on both paths. **Superseded** by owner
    ruling D1 (2026-10-30): a designator signs with its own key only, never through its delegate's ERC-1271 (CTR-UA-24,
    `SigCheck.isValid`); the parity case is now `err_e7702_viaDelegate_addr`.
  - Node items that T17 pulled forward (verify, they are believed done): bound-payee relay-fee jobs (Cosmos, Solana) refused
    unless `params.relay_fee.relay_bound_payee = true`; a plain pay to the router / marker / executor refused in every adapter;
    unknown or non-string `op.kind` refused in every adapter (T17c `3a98e74a`).
  - HederaLib errors (`HtsQueryFailed`, `AssociateFailed`) are not in the `Normal*` ABIs (pre-existing, unreachable from the
    library).
  - Test nits: the parity probe's write-time guard asserts some, not every, unlisted row refused (`MetaTxParity.t.sol:2212`);
    `bothFail_feeExceedsCapFixed_callReverts` is not a fee fault and no both-fail row has a FIXED fee over the cap; tests of T3
    were written after the code; `Factory.t.sol:489` / `HederaV2.t.sol:57` "+13 B" comment is the slack delta (actual +327 B);
    a size-dependent regression below ~5.6 k passes the absolute 8,000 bound (inherent); `LinkClosure._walk` comment on the
    metadata cut; the skips in `MetaTxParity` / `MtxSplitOverhead` stay (owner ruling 2026-10-28, no per-set fixtures); Soroban
    `relay-fee/src/test.rs:376,393` bare `is_err()`; Sui same-entry-other-instance Move test; Aptos `vectors.move` P-256 lines
    churn on regeneration (use RFC 6979 in `gen_vectors`).
  - TON relay fee after the I1 fix and its re-review fixes (decisions "TON only, node" and its re-review Change): passkey-signed
    relayed calls are refused until the node verifies P-256 (TODO item above); the payment leg is checked for `LANE_TTL` and the payer's balance (plain pays have the same two
    gaps at one hop's cost: owner rulings item 7, no code); a race in which the owner spends the lane or moves its tokens
    between the check and the message still bounces at the relayer's cost (costs the submitter a direct op or a paid relay
    each time); two relay-fee jobs of one payer wallet within one payment round trip: the router refuses the second (742)
    after the relayer paid its forward fee; every burst rides on one paid relay (accepted risk, owner ruling 2026-10-28: no
    per-payer-wallet hold in the node); the
    payment must stay valid more than 600 s, the lane tx expires at min(valid_until − 300 s, deadline) (plain pays: same
    window, owner rulings item 7, no code); no per-payer failure budget (owner's call).
  - `MtxRelayExecutor` copies return data on success (a hostile target can inflate the relayer's memory cost; the node simulates
    first).
  - Observation: the Zether prover's relayed gas rows are 8.2-8.7 k below the measured figures (inside `GAS_MARGIN`); re-pin
    them if exact rows are wanted.
- [ ] **Zether BLS12-381 verifier precompile in Rust** (owner 2026-10-17; after the PQZL Rust port, not scheduled):
  full verifier (Σ-protocol + the two Bulletproofs, `…/bls12-381/n64-n64/v2`) in `Nethermind.Pqz` (Rust cdylib +
  P/Invoke) for the SCaaS testnet / 22776; chains with it use it, others keep the Solidity `ZetherVerifier` (same statement, proof
  bytes and verdict; chain allowlist + self-test as `PqzSafety`); built only with an explicit option (Cargo feature +
  MSBuild property, image build argument; default off); a node built without it refuses a chainspec that activates it.
  bn254 stays Solidity-only. Controller notes in COMPLETED.md.
- [ ] **NEAR and Algorand family bring-up — owner 2026-10-27: build right after the metatx split** (own item: family spec → plan → build; contracts, `scaas-node` adapters, clients, devnets, tests), with `mtxPayMeta` / `uaPayMeta` (CTR-MTX-26) and `MtxRelayFee` (CTR-MTX-27) from the start; the long-lived-balance assessment below (NEAR storage staking, Algorand minimum balance / boxes) is part of its family spec.
  Status 2026-10-29: branch `near-algorand` (rebased onto main `f6d5d7d7`) Tasks 1–22 done and reviewed (T21 = docs: `docs/networks/near.md`, `docs/networks/algorand.md`, decisions.md §35 NEAR NET-NEAR-08…32 / 80–83 and §36 Algorand NET-ALG-01…23; T22 = gate steps + CI), the whole-branch review's final fix wave done (NET-NEAR-30…32); next the owner's go for merge / push. Ledger `.claude/worktrees/near-algorand/.superpowers/sdd/2026-10-28-near-algorand/progress.md`. Follow-ups from the build (none blocks the merge):
  - NEAR node: compare the contracts' code hashes at start with `deployments/<genesis>.json` (or configured hashes), and `implicit_transfer_gas()` on the token and relayexec too (today: keylessness, `executor()`, network, the pin on router + DEX; final review part 3 m6).
  - NEAR contracts: a backstop that forwards a panicked trade leg's deposit share at prune; NEP-616 `refund_to` once customer chains support it; an EVM-exact `mtx_pay` (derived lane, nonce 0) only if the owner wants it.
  - NEAR `deploy.py`: refuse adopting another deployment's same-code accounts under the same funder and symbols (today only metadata and admin are compared).
  - **NEAR indexer fix (owner 2026-10-29: deferred, "để sau, chưa làm vội"; ≈ 1.5 days incl. tests and review)**, one item for final review part 3 I2 (one non-final tx to a watched contract stalls the chain's feed; a NEP-519 yield makes it cheap) and I4 (payments through a third-party proxy contract or a NEP-366 delegate action are never booked): scan each chunk's receipts by `receiver_id` (watched token / router / DEX); map each to its originating tx with `EXPERIMENTAL_receipt_to_tx` (needs an RPC with `save_receipt_to_tx`: probe it at start and refuse to start without it); read the outcome with `EXPERIMENTAL_tx_status` and keep only that receipt's events (reuse `tx_events`); dedupe with the direct-tx path by receipt id; a non-final tx goes to a persisted pending set instead of `bail!` for the whole range. Tests: mocked RPC + near-sandbox e2e with a proxy fixture contract and a NEP-366 delegate action. Until then both are accepted risks (near.md §9 / §14). Busy chains may still want NEAR Lake; Algorand: an indexer feed (two algod calls per round today). (`.claude/worktrees/near-algorand/.superpowers/sdd/2026-10-28-near-algorand/final-review-node-clients.md` I2, I4)
  - Algorand node: derive `SPENT_KEEP` from `MaxTxnLife` × round time; cache the round-time block fetch per round; map "valid_until before last block time" / "expires before round" to a refusal instead of a retry on very slow chains; persist signed bytes so a restart reports `mined` (and charge a recovered job to the breaker); subtract the overlap instead of refusing when mandate `terms.payee` = the lane on the payment token.
  - Algorand contracts (owner ruling): `ensure_budget` at `token.mtx_pay_meta`'s start and after the router's inner pay (today the node's budget calls cover both, NET-ALG-08); optional: a router id in every app so lane-bound token / account / mandate ops can go through the router; a DEX view that tells an open order from a cancelled one; 4-member passkey msig if the argument limit rises.
  - Algorand deploy: the router salt race on a busy chain (orphans 128,500 µALGO each); T20 deferred minors N1 (`landed()` cannot tell two same-code apps without globals apart), N3 (`account_info` limits on a funder with many apps), N4 (read `status()` before `landed()`).
  - Algorand: protocol constants not in algod's REST (700 opcodes / app call, 2,048 B / page, 100-round deploy window): revisit if consensus changes.
  - Clients: an Algorand-side P-256 verify test of `passkeyAssertion`; the readable-text renderer (NET-ALL-23) must read the params of op 10 (set_guardian / set_policy) and op 11 (start / finish recovery).
  - CI (Task 22): `--check` runs of both vector generators (+ `pip install cryptography`), `algorand-tx.json` check mode in `test.sh algorand`; `metatx-split` gets the `a01357a9` remap fix at its next quiet point.
  - Final review: Solana recovery replaces all keys while CTR-ACC-03 (and NEAR / Algorand) add one: check the one-rule principle.
  - Public testnet / mainnet deployments of NEAR and of Algorand: none exist (owner only).
  - Final review "can wait" items (each with its review file under `.claude/worktrees/near-algorand/.superpowers/sdd/2026-10-28-near-algorand/`):
    - NEAR router `Stage::Settle` has no exit if `on_settle` itself fails (a 14 Tgas pin breach): let `relay_timeout` refund a Settle entry after `deadline + RELAY_TIMEOUT_S` (`final-review-near.md` m3).
    - NEAR DEX payout / refund that fails is not retried (`on_legs` sets `done` first; GAS_PAYOUT 4 vs 2.41 Tgas): record in near.md §14 or add a retry (`final-review-near.md` m4).
    - NEAR `(from, pay_ref)` payable twice by plain `mtx_pay` on different lanes (recorded deviation NET-NEAR-07; the EVM-exact derived lane is an owner option) (`final-review-near.md` m6).
    - CI: pin `dtolnay/rust-toolchain@master` (`.github/workflows/ci.yml`) to a tag or SHA (`final-review-near.md` m7).
    - Algorand: a rekey does not revoke SCaaS record keys the address added: one sentence in NET-ALG-20 / NET-ALG-07 + client rotation guidance ("after a rotation, remove them") (`final-review-algorand.md` m2).
    - Algorand: a relayed settle / mandate open signs its MBR split, so a box created meanwhile forces a re-sign (liveness only): state it in NET-ALG-12 / NET-ALG-17 (`final-review-algorand.md` m3).
    - Algorand: CI runs no contract behaviour test (localnet pytest and `e2e_algorand` only in the local gate): say so in the merge description, the gate stays mandatory for Algorand contract changes (`final-review-algorand.md` m5).
    - NEAR node: the quote uses the build-time gas price (≤ ≈ 1 % rise per block under load vs ≈ 7 % headroom on the largest wrapper): note in NET-NEAR-23 (`final-review-node-clients.md` m1).
    - Node: one breaker-accounting rule for every family (NEAR counts gas only, Algorand fee + MBR, Solana fee only) (`final-review-node-clients.md` m2).
    - Algorand node `recover_lane`: `sequence()` is the last round, so after a restart a landed group is requeued and reported `consumed` with its spend unbooked (T17 concern) (`final-review-node-clients.md` m3).
    - NEAR node: `relay_timeout` sent outside the runner's sequence (documented; at most one `Rejected` requeue) (`final-review-node-clients.md` m4).
    - clientkeys `algorand.js` `buildRelayFee`: derive the router address with `appAddress(routerApp)` instead of taking the address key (`final-review-node-clients.md` m5).
    - NEAR e2e: read the quote from the node's `Built` (as Algorand's) instead of recomputing `quote_gas` from the call sent (`final-review-node-clients.md` m7).
- [ ] **Family priority for UA and long-lived balances (owner 2026-10-19, late; order superseded 2026-10-29 by work order item UA-Soroban, the long-term-balance assessment stays):** first EVM, Cosmos, Sui, Aptos and Solana (balances and records stay in state for good: no TTL, a one-time deposit or fee); then assess each of Soroban, NEAR and Algorand separately — whether balances can be kept long-term there and at what cost (Soroban: TTL / archival and restore fees; NEAR: storage staking by attached deposit, records per token contract; Algorand: minimum balance and box MBR, records in the shared `account` app). The UA F phases on non-EVM follow this order.
- [ ] **`secp256k1` UA kind: EIP-191 `personal_sign` variant (owner 2026-10-19, on-chain review W-J; after P6)**: today the kind 0x0108 verifier checks ECDSA over the raw digest, so an EOA-held key signs it only through `eth_sign` (residual risk recorded in accounts.md S23). Add a verifier for the `personal_sign` form, new vectors, the six clients.
- [ ] **ERC-7674 temporary approvals on SCaaS tokens (owner 2026-10-18; after P6)**: `temporaryApprove(spender, value)`
  (EIP-1153 transient allowance, contract callers only) in the token base, read first by `transferFrom`; SCaaS contracts
  use it on SCaaS tokens instead of approve + `approve(spender, 0)`; outside tokens keep approve + revoke. Spec in
  token-wrappers.md / metatx.md, forge tests, size impact. Full note in COMPLETED.md.

### Leftovers of P1–P5 (phases done; history in COMPLETED.md)

- [ ] **MT-4:** `salt = chain_uid` still open for the UA registry (UA F1).
- [ ] **MT-5 / DEX:** `checkOrder` for the new DEX (not specified; with the node's P7 intake), the DEX invariant suite
  (dex.md §14), the fork test with real Uniswap bytecode, `IS_HEDERA` in `SCaaSDex` (a Hedera ED25519 account cannot
  sign a `DexOrder`); the node's P7 gas rules for `mtxSettle` are in COMPLETED.md (P2b-2).
- [ ] **P3 Zether:** a real-passkey envelope test (CTR-ZTH-21), gas of `mtxWrapShield` / `mtxUnshieldUnwrap`
  (zether.md gas tables re-measured on the new kinds), client Zether encoders, the disclosure questions (P3 plan header).
- [ ] **MT-8 node:** breaker per `(from, selector)` and batching (NODE-LANE-11/25), TradeEngine (NODE-DEX-17/18, P7),
  NODE-IDX-06 `repeat_of`, `ua_metatx` (UA F1), per-poll venue check (NODE-DEX-08); review leftovers (gateway guard
  order, config docs, `settle` refusal reason, padded gas above the maximum, entry 1271 floor, no client report for a
  guard-refused job rebuilt after a restart).
- [ ] **MT-9 clientkeys:** the app bundle rebuild.
- [ ] **Controller rulings pending the owner:** pay inline behind `PAYABLE`, no `PayLib` (P1); `increaseAllowance` and
  Permit2 `approve` refused with `ForbiddenSelector` (P2c); P4 mandate rulings (a revoke or any `setMandate` voids queued
  delegate pays; `setMandate` keeps the running period when delegate and period are unchanged; CTR-ACC-07).
- [ ] **Asset-suite stream notes** (P1c reviews): reword `asset-suite.md` ~791/793/794/854/906 ("minter renounced" →
  "`MINTABLE` disabled (`disableFeature`)"); issuer and compliance contract-only when flags 5–8 are built; roles keyed
  by role id (or mapped bits); every `_update` refusal mirrored in `_checkTransfer` and before the receiver-fee transfer.
- [ ] **P1c–P1e parked:** P1c test gaps (list in COMPLETED.md "P1c notes" (e)); P1d test gaps (`mtxExecute(single-asset
  selector)` on a two-leg token, native `UnderlyingTransferMismatch`, `addReserve` with native `msg.value > amount`,
  guardian revoke); a native 4th leg in the `WrapperInvariant` handler + §12 row for CTR-TOK-26; deploy scripts deploy
  `WrappedToken` once it fits EIP-170; the size ratchet is lowered by hand; `deploy.sh` needs `PRIVATE_KEY` (KMS /
  hardware wallet needs a change); libraries placed from the sender's nonce (E7). Full notes in COMPLETED.md.
- [ ] Mandate epoch-bound pay and period-keeping `setMandate` (M1/M2) are EVM-only in P4; the other families keep their rules. One follow-up per family, owner decision first: Solana (generation binding), Sui, Aptos, Soroban, Cosmos, TON (one-shot or own pay binding).
- [ ] Agent mandates (research `docs/research/node-ai-agents.md` row c, not accepted): several delegates per token, per-payee caps, a co-sign threshold, a gateway route for mandate payments — owner decision.

**Non-EVM families (NM-*)** (full stream text in COMPLETED.md)
- [ ] Per-family meta-call streams, new immutable deployments each: **NM-APT** (`MetaCall`/`MetaTransfer` in BCS,
  `scaas::metacall::verify`; NET-APT-27, NET-ALL-26…29), **NM-SUI** (as Aptos + `mtx_forward`; NET-SUI-18, NET-SUI-16),
  **NM-SOR** (`mtx_` functions, SEP-41 `transfer` kept, `__check_auth` allowlist per key; NET-SOR-16, NET-SOR-04),
  **NM-COS** (`scaas-metacall` crate, `Mtx*` messages; NET-COS-12), **NM-TON** (`Mtx` messages, opcodes fixed with
  vectors; NET-TON-20), **NM-SOL** (fixed layouts, `mtx_` instructions; NET-SOL-33); key / mandate entries move to
  `mtx_` and the old op types go. Node adapters and clients (`fam/*.js`, CLI-SGN-27) follow each family; vectors per
  family.

## 0. Finish the spec phase (6 items left)

- [ ] **Governance matrix for factory-made contracts (owner 2026-10-20)** — tokens, DEX, later lending and the other
  contract families: for every property and power (verifiers and Env, rates and legs, mint, burn, blacklist, pause, fees,
  roles, upgrades of the release) state where it comes from and who may change it: **fixed by the implementation**
  (Env, constructor) × **set at creation** (`initArgs`, per instance) × **changeable after deployment** (by whom, with
  which delay, lockable or not). Covers smart-contract governance (releases, Env versions, `deployImplementation` — owner:
  it must not simply bind the kind's latest Env) and token governance (today's `features` / `lockedFeatures`, `AdminLib`
  roles, `owner = 0`, `RATE_ADJUSTABLE` with `rateDelay` / `maxRateStepBps`). Spec first (owner rule), then Z2 follows it.
  - Inputs (owner 2026-10-21, chat): (1) **mint allowance per minter** — `{total, perWindow, window, expiry}`, two-tier
    (USDC masterMinter pattern), a reduce-only role; (2) **moderator transfer** of a user's balance without the user's
    signature (loyalty points), bounded by a per-moderator total and per window (same primitive as (1)), own event,
    relayable, public balances only — never on confidential kinds (FORCE rule); proposal: enabled at INIT only;
    (3) **hybrid underlying** — wrap (citizen brings a stablecoin) plus issuer mint under one `maxSupply`; reserve
    accounting needed (proposal: unbacked units not redeemable for the underlying; alternatives pro-rata or queue P15);
    PQZ / Zether minters never mint shielded value.
- [ ] **SCaaS Chain 22776** (owner 2026-10-12): a new chain "SCaaS Chain", chain id 22776, beside the existing ones; SCaaS testnet and the UA key tree `m/7622'/…` stay unchanged. Ports in the 22776+ range (proposed RPC HTTP 22776, WS 22777, P2P 22778). Onboard like any chain: docs/networks/evm.md row, profile, finality gate, genesis/identity pin, deploy, node config. The chain itself (docker/chainspec) is run by the owner outside this repo.
- [ ] **Template library** (owner 2026-10-12): every README use case (escrow with an arbiter, milestone service
  contracts, sale with delivery, leases, installment loans, subscriptions, revenue sharing, deposit with periodic
  withdrawal, provenance and family-tree registries) as an implementation deployed once per chain, instances by clone /
  CREATE2 through a factory, called by meta-transaction. Spec first: `docs/contracts/templates.md`. Full note in
  COMPLETED.md.
- [ ] **P0 follow-ups (minor doc nits, deferred by the final review):** `zether.md` (single-recipient-only gas-cap
  figures, ~1327 `recipient` vs `to`, informal `zetherShield(Y…)` prose), architecture sequence 5 (`WrappedLib`),
  `asset-suite.md` 893–897 and the old `IRegulatedToken` names, `clients/app.md` CLI-APP-26, `node/store.md`:157,
  `node/job-api.md`:328, CTR-TOK-26 wording, `dropped-artifacts.tsv` duplicates / bare `273`, CTR-ACC-80, budget
  warnings in `token-wrappers.md` / `dex.md` (owner). Full list in COMPLETED.md.

- [ ] **Rewrite `docs/integration.md`** (owner 2026-10-09: later). Goal to settle when started: shorten/restructure, align with the token tree and meta-tx v3, ERP-neutral; then `integration-odoo-example.md`. Keep the 27 `INT-ERP-*` ids (supersede, never renumber). No code dependency; PQZ parts stay open.

- [ ] **Codex reviews still owed** (credit ran out after 4; Codex runs only on the owner's request): AS, TW2, app, OPS,
  S4F, mesh, A2 — review the current component doc of each area (map in `docs/README.md`), not the frozen spec; all
  already have a Claude review. Command and output paths in COMPLETED.md.

## 1. Code streams (after §0)

**Fix first (bugs found in BUILT code by the 2026-10-07 reviews):**
1. **NET-TON-FIX1** (BLOCK: unbounded forward TON drains a lane — no job API/mesh/gateway path may reach a TON lane until the node half lands), NET-TON-FIX2…4.
2. Node money safety: **NR1** breaker meters fees/value/deposits + attempt cap + grief score (R340–R342), **NR2** payload-sourced fields, value-out cap, deposit rule (R344–R346), NR3 mesh sig verify (R343, before S5), NR4 journals → `outer_tx` (R347), NR5 immutable-program check + one custody key per family (R348–R349).
3. **PAY-FIX2** node `call` target/selector table, PAY-FIX3 event-set quorum, PAY-FIX4 gateway intake, PAY-FIX5 idempotent signed report; ADW-FIX1–4.
4. DEX: DX-FIX1–5 (dust maker freeze, poison fee token, 1271 gas cap, non-EVM relayer binding).
5. Per family: R3-FIX1–15 (Cosmos passkey v2, WebAuthn vectors, event quorum, Soroban `pay_ref`, Solana build-time network, Sui `Keys`, guardians, TON domain, **R3-FIX15 immutable deploy + gate + redeploy**), WSF-FIX1–2, NET-{COSMOS,SUI,HEDERA,SOROBAN,APTOS,SOLANA}-FIXn (code-stream tables of the frozen `docs/history/specs/net-*`), ZF-FIX1–3.

Then the first feature wave: **NI P2 → P3** (money-safety core), **UA F0 → F1** (many specs depend on it), **app A1 + A0-evm**.

Stream ids are unchanged by the docs reorg. **Doc** = the current rules a stream implements; **Scope** = the frozen
stream definition (scope, gate, depends) in `docs/history/specs/` — section numbers as in those files.

| Area | Streams (spec) | Doc | Scope |
|---|---|---|---|
| Node | P2 job API + client API keys + built-in admin/CLI → P3 submit/lanes from store → P4 indexer + `/v1/events` → P6 push e2e + cutover runbook → [owner cutover] → P2b OIDC + admin routes + CORS → P1b PostgreSQL/MySQL → P7 DEX in store → S1b′ → S5 mTLS bus → S6′ → G1 libp2p/QUIC-PQ → G2 announce/exclusivity/hints → G3 DEX book gossip (home-bound + unbound) → S7″ → P9 remove pull path → S8″ docs. Plus N1/N2/N4 (app §9.6), N3 non-EVM DEX books, OPS OP1–OP8, SP1 sponsorship · DX-FIX1 dust maker skip, DX-FIX2 fee-token allowlist + pair-failure attribution, DX-FIX5 pending commitment + market re-check + IOC single-maker + late-Matched debit (DEX spec rev 1.1; fold into P7 if P7 starts first) · ZF-FIX3 Zether verifier/registry pin (gateway + clientkeys), cache key chain id, `schnorrSign` k test-only (Zether rev 1.1) | [node/](docs/node/README.md): [store](docs/node/store.md), [job-api](docs/node/job-api.md), [submit-lanes](docs/node/submit-lanes.md), [indexer-feeds](docs/node/indexer-feeds.md), [admin-auth](docs/node/admin-auth.md), [dex-venue](docs/node/dex-venue.md), [mesh](docs/node/mesh.md), [gossip](docs/node/gossip.md), [ops](docs/node/ops.md), [runbooks](docs/node/runbooks.md#cutover), [sponsorship](docs/node/sponsorship.md) | P*: `2026-10-06-node-independence-design.md` §17; S*: `2026-10-05-relayer-mesh-design.md` §14 + NI §13.2; G*/S6′/S7″/S8″: `2026-10-06-mesh-gossip-amendment.md` §17; OP*: `2026-10-06-operations-design.md` §13; SP1: `2026-10-06-tender-sponsorship-shredding.md` §8; N1–N4: `2026-10-06-scaas-app-design.md` §9.6; DX-FIX: `2026-10-03-dex-design.md` §8 (Claude review disposition); ZF-FIX: `2026-10-03-zether-design.md` (Claude review disposition) |
| Contracts | TW2 T7 (node/SDK follow-ups) · AS1–AS9 asset suite · TB1–TB3 tender, RP1–RP2 receiver-pays (RP1 before production registration O3), CS1–CS2 shredding, PL1 pool (later) · UA F0–F10 · PQZ E-S0…E-S9 (spikes first; licence gate G-LIC before production) · DX-FIX3 `SCaaSDex` 1271 gas cap + bounded returndata (redeploy), DX-FIX4 non-EVM DEX relayer binding (Cosmos/Soroban/TON) + `min_nonce` caps (Sui/Aptos/Solana) · ZF-FIX1 `ZetherMetaTx` 1271 400k/50k + FeeWouldStick + disclosure NatSpec, ZF-FIX2 Zether invariant/subgroup/`D_out = O` tests | [contracts/](docs/contracts/README.md): [token-wrappers](docs/contracts/token-wrappers.md), [asset-suite](docs/contracts/asset-suite.md), [tender](docs/contracts/tender.md), [universal-account](docs/contracts/accounts.md), [pq-zether](docs/contracts/pq-zero-knowledge.md), [dex](docs/contracts/dex.md), [zether](docs/contracts/zether.md); [networks/](docs/networks/README.md) for non-EVM | T7: `2026-10-06-token-wrappers-v2.md` §15; AS*: `2026-10-06-asset-suite-design.md` §13; TB/RP/CS/PL: `2026-10-06-tender-sponsorship-shredding.md` §8; F*: `2026-10-06-universal-account-design.md` §16; E-S*: `2026-10-06-pq-zether-design.md` §16; DX-FIX/ZF-FIX: as above |
| Clients | S4F D1–D7 · app A0–A18 (order in app spec §15) | [clients/signers-clientkeys](docs/clients/signers-clientkeys.md), [clients/app](docs/clients/app.md) | D*: `2026-10-06-signers-followups.md` §10; A*: `2026-10-06-scaas-app-design.md` §15 |

## 2. Ops / housekeeping

- [x] **Foundry 1.3.5 → 1.8.5** (machine 2026-10-21; CI pin v1.3.5 → v1.8.5 2026-10-27 — CI had been red since F185 on "Unknown evm version: amsterdam"): upgrade local and CI together; 13
  forge tests to re-measure / regenerate (gas pins, KAT addresses, `selfdestruct`); `forge script` then needs
  `--disable-code-size-limit` (EIP-3860 on the script contract: `Deploy.s.sol` initcode 368,154 B); anvil keeps
  `--code-size-limit 65536`. Full note in COMPLETED.md.

- [ ] Redeploy all dev/test contracts (tags renamed); update `blockchain.token.domain_name` / Cosmos `network_key`.
- [ ] Remove merged worktrees under `.claude/worktrees/`.
- [ ] Residual TON: a `final` from the indexer before the node's `mined` still flags `landed_elsewhere` (informational).
- [ ] Queued research: none open beyond the specs above.
- [ ] **scaas-node docker-compose** (owner 2026-10-12: after node streams P2 + P3 + P4 + P6): standalone, not tied to an
  ERP's docker — multi-stage Dockerfile (Rust 1.90), `scaas-node` + one-shot `store-init`, store volume, `.env` for
  secrets / chain RPC / chain_uid; default gateway-only config, a second sample with submit + indexer for an ERP by URL
  (legacy pull path until the push cutover). Full note in COMPLETED.md.

Owner/operator gates from `docs/history/HANDOFF-blockchain.md` §1 (O1–O8 are standing rules in
[node/runbooks.md#production-gates](docs/node/runbooks.md#production-gates)):

- [ ] O9 — Decide the DPIA / CI gate for landing on-chain payments into the ERP (SRS deltas #11).
- [ ] O10 — Write the onboarding procedure for `MandateWallet` / subject accounts (deployed outside the ERP, R29).
- [ ] O11 — Every collecting entity that receives on-chain needs a `chain` payment provider, a journal and an approved
  receiving wallet (after the territory consolidation; GA 2.4#4).

- [ ] wasm build for the app: `wasm-smoke.sh` builds `--target nodejs` only; a `--target web` build is client work
  (S4F/app) (from the 2026-10-07 doc nits).
- [ ] P5 leftovers: an EVM chain whose RPC errors on block 0 at boot still fails `Submitter::start` (adapter lanes retry with backoff); a guard-refused job rebuilt after a restart whose nonce was taken by a transaction the node no longer holds gets no report.
- [ ] **UA leftovers:** HIP-632 in a view (R19, UA-2a); FRB as a Flutter plugin with Android/iOS/web builds (does
  `scaas-ua` build for wasm?) and Qt packaging for Windows/macOS (UA-1b); T-V3-4 and the `ua*` fallback decoder wait for
  Glamsterdam (owner; real chains at 24,576 cannot take any token implementation until then); `metatx3.json` rows for
  the group kinds and `msig` (UA F3). Local Qt builds of `clients/ua-qt` need
  `QMAKE=~/usr/Qt/6.8.2/gcc_64/bin/qmake6`.
- [ ] **UA F5 (node UA jobs; paused by the priority rule):** node `ua_metatx` jobs (EVM outbox path, `uaPayMeta`, `uaRelay` and
  the `UAPaymentSettled` join BUILT on `node-ua-jobs` 2026-10-30; left: gateway `/v1/ua-metatx` and the record cache), mesh `evm.ua_meta_tx`, indexing
  (`Transfer` to/from `UA_POOL` with `UATransfer`, `UnwrappedToUA`, `UAReceiverFeePaid`, `UAPaymentSettled`); relaying
  `ua*` jobs (burn, `unwrapToUA`, `uaWrap`, `uaCancelOrder`, `uaInvalidateNonces`), a receiver-fee job with a `bytes32`
  payee; UA order intake, `bytes32` book / TradeEngine on `balanceOfUA`, settlement packing by the kinds' caps, PQ order
  gossip (UA-4, UA-5a, UA-5b open lists in COMPLETED.md).
- [ ] **UA-5** UA parity (owner 2026-10-13; record `docs/history/specs/2026-10-13-ua-parity-design.md`; rules
  CTR-UA-27/28, CTR-DEX-25/26, CTR-ZTH-51, CTR-ACC-12): UA-5a and UA-5b done (COMPLETED.md); left UA-5c below. Each
  phase ends with the size gate and the full forge suite (default and `private7622`).
  - [ ] **UA-5c split (owner 2026-10-20):** (a) confidential ops via the UA envelope + (b) unshield to a UA → 5h part A;
    (c) generic UA pipeline in `MetaTxBase` + (d) `MandateWallet` `bytes32` → step 5c′ before the node relay (5c);
    `zetherShield` via `uaExecute` already built in UA-6.
  - [ ] **UA-5c** mandates (c)(d), step 5c′: the generic UA pipeline into `MetaTxBase`; `MandateWallet` (+ Hedera) with `bytes32` owner / delegate / payees and UA builders, no ERC-1271 for a derived owner. The contracts of (a)(b) are built in 5h part A (Task 3b: the confidential ops on the UA allowlist with the UA envelope binding `SCAAS-ZETHER-UA-ENVELOPE-V1`, `mtxUnshield` / `mtxUnshieldUnwrap` with a `bytes32` recipient, no `…ToUA` entry point) and the zether-prover builds a 32-byte recipient (final fix wave m3). Independent of UA-5b (needs UA-5a's `_uaMint` and `payWithFeeToUA`); the node part after UA F5.
  - Later, with their own streams: regulated tokens key compliance by `bytes32` and hook the UA ledger (asset suite, CTR-AS-07); `SealedBidTender`, `VestingGrant`, `Distribution`, `ExchangeOffer` with UA bidders and beneficiaries when built.
- [x] ~~Zether prover gas cap: an authorization allowance by `authRef` kind in `check_gas`~~ — obsolete: UA-6 removed the Zether `authRef` and `authSig`, the allowance is gone (branch `ua6`, merge pending); full note in COMPLETED.md.
