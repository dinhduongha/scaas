# HANDOFF — scaas

## Shutdown 2026-10-10 — read this first

**State:** branch `p1b-erc20metatx` (worktree `.claude/worktrees/p1b`), P1b complete and committed; **not yet merged into `main`**.
758 forge tests pass; docs checker 0 errors; the node e2e suites (`e2e`, `e2e_hedera`) pass against the deploy scripts,
which deploy only `META_NONE` on factory v2 until P1d and default `CHAIN_UID` to block 0's hash. The bamboo-dms repoint
is done on branch `scaas-metatx-v1-kat` (commit `81cea08`) in `/home/dockers/odoo19/custom-addons/bamboo-dms` — not
merged into its main; the owner merges.

**P1b delivered:** v1 names suffixed `…V1`; `MetaTransfer` + `IERC20MetaTx`/`IERC20Payment`; `ERC20MetaTx` on `MetaTxBase`; the v2
line moved onto it (named builders, per-kind allowlists, gasless burn/wrap/unwrap; `MetaTxCore` and the op dispatch removed);
receiver-pays (`mtxPayReceiverFee`, `ReceiverFee` co-signature, token as fee recipient refused as `TransferToSelf`, HIP-632 payee
test); conformance + `msg.sender` lint; KATs `metatx_kat.json` (unchanged) and `metatransfer_kat.json` (new) written on a
`NoUnderlyingToken` clone.

**Rulings for the owner:** R3 wrappers over EIP-170 until P1d; R4 UA ledger split moved to UA F1; R7 SmartKeyAccount name on the
token side now (`SMART_KEY_ACCOUNT_IMPL`; the account contract stays `SubjectAccount` until P4).

**Sizes (runtime B):** `NoUnderlyingToken` 17,602, `HederaNoUnderlyingToken` 18,057 (both <= 20,480); over EIP-170: `Single` 26,102,
`Multi` 26,951, `HederaSingle` 27,417, `HederaMulti` 28,266, `ZetherToken` 28,849.

**Next action:** write the **P1c** plan (`MetaTokenBase` features/roles, `AdminLib`/`PayLib`/`HederaLib`, kind NONE).

## Shutdown 2026-10-09 (evening)

**State:** `main` = `1d51d22` (P1a merged), pushed; tag `ref/pre-token-tree` (→ `dc429c4`) pushed. Tree clean. 712 forge
tests pass; docs checker 0 errors (2 known budget warnings: `token-wrappers.md` 986 > 845, `dex.md` 538 > 520 — owner call).

**Next action:** write the **P1b** plan (`ERC20MetaTx` on `MetaTxBase`: `MetaTransfer` + `mtxExecuteTransfer`/`mtxBatchTransfer`,
fee classes on tokens, receiver-pays, approve only by contracts, UA path, KATs `metatransfer_kat.json`), against the code P1a
left; then execute subagent-driven like P1a. P1b notes (a)–(h) are in TODO §00 under P1.

**P1a delivered** (plan `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md`, 9 tasks + final review):
- `legacy/` (27 reference copies, not built) + tag `ref/pre-token-tree`.
- `src/common/SigCheck.sol` — one signature check (ECDSA low-s; ERC-1271 capped, ≤32 B returndata, starvation guard
  `SigCheckGasStarved`; 7702 designator = EOA); the three built bases use it; `SigLib` deleted.
- `src/common/SaltedEIP712.sol` — salt = chain_uid, clone-safe, `eip712Domain()` 0x1f, `ChainUidZero()`.
- `MetaTxLib`: v3 `MetaTransaction` (typehash pinned); built struct renamed `LegacyMetaTransaction` (digests unchanged).
- `src/metatx/MetaTxBase.sol` + `IMetaTx.sol` — `mtxExecute` (+ alias), `mtxBatch`, lanes, `cancelNonce`, transient sender +
  one-shot ticket (fail-closed: an allowlisted target without `nonReentrant` reverts), allowlist + fee classes
  (1 = ABSOLUTE, 2 = AMOUNT), `_chargeFee` NONE only, `_checkEnvelope`/`_useNonce` for the P1b `MetaTransfer` path.
  Mock `MtxRegistryMock` ≈ 9.4 KB — the 20,480 B token budget needs care in P1b/P1c.
- KAT: `metatx_kat.json` = v3; `metatx_v1_kat.json` = built v1 (node + clientkeys repointed).
- **Cross-repo breakage:** bamboo-dms `dms_blockchain/tests/test_eip712.py:14` reads the old path — repoint to
  `metatx_v1_kat.json` there (resolved 2026-10-10: branch `scaas-metatx-v1-kat`).

**Owner decisions 2026-10-09:** `OrderBookDex` → **`SCaaSDex`** (done 2026-10-09, domain `"SCaaS Dex"`); integration.md rewrite later
(TODO §0); docs: README map as per-area tables, architecture.md numbered sections + contents, §1 lists smart contracts first.

**Controller rulings during P1a** (review if you disagree): RA tag on `dc429c4`; RC/RF/RG/RH/RJ several test gaps upgraded
to required (signature refusal branches, per-flag canon, end-to-end binding, alias coverage, batch replay/rollback, fee
basis offset, fee after call, per-item fees); RE refuse zero chain_uid (NET-ALL-22); RJ feeClass ≥ 3 refused; RK
`_checkEnvelope`/`_useNonce` + fail-closed ticket added in the final review. Plan defaults: refusal error
`MetaTxUnknownMode`, ERC-1271 margin 5,000 gas, fee class checked before `supportedModes()`.

## Shutdown 2026-10-09

**State:** `main` = P0 merged and pushed (`4bad99b`) + 3 local commits (TODO note, P1a plan). Tree clean. Nothing of P1 started:
no tag `ref/pre-token-tree`, no `legacy/` yet (Task 1 of the P1a plan does both).

**Next action:** execute `docs/superpowers/plans/2026-10-09-p1a-metatxbase.md` (9 tasks; the owner has not yet chosen
subagent-driven vs native — recommended subagent-driven). Then write P1b…P1e one at a time, each against the code P1a/b/… left:

| Plan | Scope |
|---|---|
| P1a | tag + `legacy/`; `SigCheck`; `SaltedEIP712` (salt = chain_uid); `MetaTxBase` (MetaTransaction, lanes, transient sender + ticket, allowlist, `mtxExecute`/`mtxBatch`/`cancelNonce`, fee NONE only); KAT — **plan written** |
| P1b | `ERC20MetaTx` on `MetaTxBase` (`git mv MetaTxCore`): `MetaTransfer`, `mtxExecuteTransfer`/`mtxBatchTransfer`, fee classes, receiver-pays, approve-only-by-contracts, UA path, KATs |
| P1c | `MetaTokenBase`: features + owner model (`AdminLib`, regulated flags), `PayLib`, init/provenance, `IS_HEDERA` + `HederaLib`; kind `NONE` |
| P1d | `UnderlyingLib` + `UnderlyingToken` (Single+Multi merged, native-coin leg, `mtxWrap`) |
| P1e | factory `createToken`, CREATE2 deployer, deploy scripts + `chainUid()` gate, delete v1/v2 lines, CI size gate |

**P1a plan notes:** the plan's code was run in a scratch copy (692 tests pass, KAT matches `cast`). (1) The bare
`MetaTxBase` mock is 9,410 B — almost half the 20,480 B token budget (CTR-TOK-24): watch it in P1b. (2) `metatx_kat.json`
becomes the v3 vector; the v1 vector moves to `metatx_v1_kat.json` and in-repo readers are repointed — the bamboo-dms test
`dms_blockchain/tests/test_eip712.py:14` breaks until repointed there (resolved 2026-10-10: branch `scaas-metatx-v1-kat`). (3) Defaults taken in the plan: fee classes
1 = ABSOLUTE, 2 = AMOUNT; refusal error `MetaTxUnknownMode`; ERC-1271 starvation margin 5,000 gas + error
`SigCheckGasStarved`; KAT on a mock (P1b regenerates it on a real token).

**Done today (2026-10-08/09):**
- Zether code: multi-recipient transfer + three storage modes; Z9–Z13 (no attestation, `SENDER_CP`, per-transfer auditor
  opt-out, threshold auditor key = docs only, disclosure in a stateless `ZetherDisclosure`). `ZetherToken` still 28,939 B
  (over EIP-170) — solved by P3 (`ZetherLib`).
- P0 docs fold (9 tasks, each reviewed, plus a whole-branch review): ids CTR-ZTH-37…47, CTR-TOK-21…26, CTR-MTX-25,
  CTR-AS-17, CTR-DEX-24, CTR-ACC-11, CTR-PQZ-22; `docs/README.md` absorbed `SCaaS-v2.md`; `architecture.md` 421 → 879 lines.
- `smartcontracts/evm/chain-uids.json`: genesis hashes of 26 live EVM chains (two RPC sources each). ETH/ETC and
  Avalanche/Fuji share a genesis (a chain = `(chainId, chain_uid)`); Base Sepolia / Celo Sepolia official RPCs prune block 0;
  Hedera values derived from the mirror node (first 32 bytes) — confirm against the relay; Holesky and Alfajores are dead.

**Owner rulings 2026-10-08/09 (all folded):** features chosen at creation; one owner grants/revokes per-flag roles,
disables disableable flags, `renounceOwnership` (role holders keep roles; full lock = revoke all, then renounce);
`PAYABLE` default off; Hedera = per-chain parameter; Single+Multi merged; native-coin leg (some chains lack WETH-like
tokens); confidential layer over the public balance with direct wrap-shield / unshield-unwrap; minter never mints shielded;
regulated flags refused on confidential kinds; factory creates DEX clones, `isDex` advisory only (tokens never consult it);
`SubjectAccount` → `SmartKeyAccount`; keep old code (tag + `legacy/`); refactor in place.

**Controller rulings during P0 (review if you disagree):** R4/R8 budget warnings left as warnings (`token-wrappers.md`
986 > 845, `dex.md` 538 > 520 — owner to accept or ask for a split); R7 native leg on every `UNDERLYING*` kind incl.
`UNDERLYING_ZETHER`; R10 target `zetherUnshield(payload, proof, authSig, beneficiary, to, amount)` order; R12 target EIP-712
domain `"SCaaS SmartKeyAccount"` (P4); R14 `PAYABLE`/`BURNABLE` always locked (`disableFeature` reverts `FeatureLocked`);
R5 owner acts on a flag only by granting itself the role, OZ `AccessControlDefaultAdminRules` is the P1 candidate.

**Open (owner):** PQZ multi-recipient (hint-count risk with shared randomness) and PQZ Z9/Z10/Z12; the two budget
warnings; `docs/integration.md` rewrite (TODO §0, later). Deferred P0 minors are listed in TODO §0 ("P0 follow-ups").

## Session 2026-10-08 (evening)

Token-tree design accepted by the owner and folded (P0 done); record frozen at `docs/history/specs/2026-10-08-token-tree-design.md`
(Status line holds the id map). The Zether multi-recipient record is frozen too. Code is unchanged: every affected
section carries a "Transitional (BUILT)" note naming the phase.

- **Tree:** `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` → four kinds by code (`NONE`, `UNDERLYING`, `NONE_ZETHER`,
  `UNDERLYING_ZETHER`; `*_PQZ` reserved), features by flags (payable, mint, burn, adjustable rate, wrap-disable, freeze,
  force, pause, allowlist); one owner model; Hedera as an `IS_HEDERA` branch; the native coin as an underlying leg; libraries
  `AdminLib`, `PayLib`, `UnderlyingLib`, `HederaLib`, `TradeLib`, `ZetherLib`; `SCaaSDex` as a clone. Ids CTR-TOK-21…26,
  CTR-MTX-25, CTR-AS-17, CTR-DEX-24, CTR-ZTH-37…47, CTR-ACC-11, CTR-PQZ-22.
- **TODO §00 is now phases P1–P5** (P1 = MT-1…MT-4 on the new tree, P2 = MT-5, P3 = MT-6, P4 = MT-7 + rename, P5 = MT-8/9).
- **Owner decisions for P1:** (1) keep the old code for reference: git tag `ref/pre-token-tree` on the last commit before
  P1, plus the v1/v2 token sources and the old `ZetherToken` copied to `smartcontracts/evm/legacy/` (not built, not
  tested; README "reference only"); (2) P1 refactors in place (`git mv` + edit), not a rewrite — reuse map in TODO §00;
  `TradeLib` (P2) reuses the prototype in `/home/ha/work/blockchain/metatx/contracts`.
- **`smartcontracts/evm/chain-uids.json`** (genesis hashes of live EVM chains, two sources each) is linked from NET-ALL-22;
  a chain is identified by `(chainId, chain_uid)`.
- PQZ multi-recipient and PQZ Z9/Z10/Z12 are not owner-ruled: recorded as `open` only.

Next: P1 plan (one plan per phase, written against the folded rules), then P1 code.

## Session 2026-10-08 (afternoon)

Three designs accepted by the owner and folded (drafts frozen in `docs/history/specs/`), root README updated:

- **Generic meta-tx call** (`2026-10-08-metatx-generic-call-design.md`): `MetaTransaction{from, data, …}` for a call of
  any allowlisted function of **any** SCaaS contract (base `MetaTxBase`, fee `NONE` unless a token overrides it; gas
  paid by a sponsor), typed `MetaTransfer{from, to, value, entryRef, …}` on tokens; named functions kept, plus
  `mtxExecuteTransfer`/`mtxBatchTransfer`; `MandateWallet`/`SubjectAccount` on `MetaTxBase` (account signs as itself);
  UA ledger split the same way; `PqzToken` relays like Zether. Ids CTR-MTX-22…24, CTR-ACC-10, CTR-UA-26, CTR-PQZ-21.
- **DEX exchange** (`2026-10-08-dex-exchange-design.md`): `mtxExchange` (DEX calls AMM interactions) and
  `mtxExchangeVia` (solver executor) fill `TradeOrder`s against AMMs, multi-hop, `receiveToken` may equal the sell token;
  surplus to signers on chain; `DexPuller` holds outside-token allowances; allowlist via order flag `LISTED_POOLS` and
  admin `setListedOnly`; node TradeEngine keeps only the relayer share. Ids CTR-DEX-20…23, NODE-DEX-17/18, CLI-SGN-37.
- **Non-EVM** (`2026-10-08-nonevm-metacall-design.md`): `MetaCall` + `MetaTransfer` per family, one verification library
  + typed `mtx_*` entries (CosmWasm/TON one `MtxExecute`), `KeyOp`/mandate structs → `MetaCall`, EVM parity. Ids
  NET-ALL-26…29 and one per family. Streams NM-APT…NM-SOL in TODO §00.
- Owner rulings: PQZ is meant for public chains but **waits for a lattice precompile there** (CTR-PQZ-01 change);
  `contracts/metatx.md` line budget accepted. Phase 4 fixes from the lost `fix-cnc`/`fix-node` worktrees landed (`9476617`).

Next: code streams in TODO §00 (MT-1 first); Codex reviews still owed (needs credit). The Odoo side (`SCAAS_ROOT` in
four `dms_blockchain` tests, compose mount) is uncommitted in bamboo-dms/odoo19, left to another instance.

**Repo moved 2026-10-08** from `bamboo-dms/scaas/` to `/home/ha/work/ainative/scaas` (standalone). The bamboo-dms
`dms_blockchain` tests read vectors via env `SCAAS_ROOT` (fallback `../../scaas`); the Odoo container mounts the repo
read-only at `/mnt/scaas` with `SCAAS_ROOT=/mnt/scaas` (`/home/dockers/odoo19/docker-compose.yml`). Older sections
below still say `bamboo-dms/scaas/`. The move also surfaced two never-committed Phase 4 fix worktrees (`fix-cnc`,
`fix-node`); their fixes are now on `main` (`9476617`), so "28 findings fixed" below holds only from that commit.

## Shutdown 2026-10-08 — read this first

**Meta-transaction redesign accepted and folded.** Design record: `docs/history/specs/2026-10-07-metatx-generic.md`
(rev 5, two Claude reviews: `docs/reviews/specs/2026-10-07-metatx-generic-claude-review-{1,2}.md`, git-ignored). Rules
now live in the component docs (`contracts/metatx.md`, `token-wrappers.md`, `dex.md`, `zether.md`, `accounts.md`,
`mandates.md`, `node/job-api.md`, `node/dex-venue.md`, `networks/README.md`, `clients/signers-clientkeys.md`, …) and
`decisions.md` (30 new ids, 58 updated, 5 superseded: CTR-TOK-12/14, CTR-DEX-06/07, CTR-ZTH-11). **Code is unchanged**:
every affected section carries a "Transitional (BUILT)" note — the code streams below implement it.

Owner rulings 2026-10-07/08 (all in decisions.md, owner: yes):
- `mtxExecute`: the token calls **itself** with the signer's calldata on a fixed per-implementation selector allowlist
  (transient sender + one-shot ticket; all or nothing; never calls another contract). No `approve`, no role functions
  in any allowlist. `executeMetaTransaction` kept as an alias. Every signed entry point starts with `mtx`.
- **Only a contract may call `approve`** on a SCaaS token (EOAs never, in any form; outside tokens excepted); wrapping a
  SCaaS underlying by signature (`mtxWrap`).
- One base **`ERC20MetaTx`**; the v1 line (`MetaToken`, `HederaMetaToken`, v1 `OpenFactory`) is deleted; one factory.
- `salt = chain_uid` (genesis hash) in **every** EIP-712 domain; implementation immutable; deploys via **CREATE2**; a
  fork of a chain we run is a new chain.
- DEX: one signed **`TradeOrder`** (`from, receiveToken, amount, receiveAmount, minFill, fee, relayer, dex,
  destination, flags, batch, nonce, validUntil`) — the owner's old `MtxTradeOrder` modernized; no role in the order;
  funds move **only into `dex`**; `relayer` = matching party (0 = anyone); minimum fill = max(minFill, 50 %); one `fee`
  paid out by the DEX in the same call per an admin-set split; Path A (resting, `pulled[orderHash]`) and Path B
  (escrow + refund, IOC); one taker + many makers per call; DEX balance-conservation invariant. **Owner-accepted
  residual risk:** `dex` only has to be a contract — clients must refuse an unlisted `dex`, the node never routes one.
- NODE-IDX-06: a repeated `entryRef` is flagged by the node (`repeat_of`) **and** checked by the client (refund decision).
- Nothing is deployed anywhere: no compatibility/migration work.

Also today (all pushed except the meta-tx commits listed in `git log origin/main..main`):
- Docs reorg closed: Phase 4 reviews (28 findings fixed), 10 % second sample (111 items, 3 minor fixed), every diagram
  Mermaid, checker **C11** (ASCII art refused), plan in `docs/history/plans/`.
- Root `README.md` rewritten: chain as infrastructure, IaaS/BaaS comparison, contracts as API services, standards
  (incl. EIP-6963), shared code/upgradeability, Universal Accounts, fee models, transaction flow, open relayers,
  Zether/PQZ, design evolution.
- `clientkeys/` and `zether-prover/` moved to **`clients/`** (app planned at `clients/app/`); CI jobs `clientkeys` and
  `zether-prover` added (first GitHub run pending).
- `contracts/accounts.md` (Universal Account + passkeys + optional SubjectAccount) and `contracts/mandates.md`.

Open for the next session: the code streams in `TODO.md` §0; points the fold left open — PqzToken's envelope on the
self-call path, the Zether statement header now 416 bytes with `chainUid` at offset 96 (verify against the prover),
ExchangeOffer's gasless leg as a `TradeOrder`; non-EVM families' equivalent of `mtxExecute`/`mtx` names (separate
draft).

## Docs reorg 2026-10-07 — read this first

The specs, `SCaaS.md` and `integration.md` were replaced by one set of self-contained component docs (plan
`docs/history/plans/2026-10-07-docs-reorg.md`, tag `docs-pre-reorg` = state before). **Reading order:**

1. [`docs/README.md`](docs/README.md) — map, precedence (owner rulings > component docs > code > history > research),
   status tags, id scheme.
2. [`docs/SCaaS-v2.md`](docs/SCaaS-v2.md) — product introduction.
3. [`docs/architecture.md`](docs/architecture.md) — system overview.
4. Component docs for the area you touch: `docs/node/`, `docs/contracts/`, `docs/networks/`, `docs/clients/`,
   `docs/integration.md` (+ `integration-odoo-example.md`).
5. [`docs/decisions.md`](docs/decisions.md) — every ruling (`<AREA>-<TOPIC>-NN`), why, and the alias index. Old ids in
   code comments (`R91`, `RS5-9`, `CR-PD-1`, `UD:§23`) stay valid: `python3 scripts/docs_check.py resolve <id>`.
   Section refs in code (`NI §5.2`, `TW2 §7`) point into the frozen copies in `docs/history/specs/` (abbreviations:
   `docs/history/README.md`).

Frozen: `docs/history/` (specs, plans, `SCaaS-2026-10-07.md`, `integration-2026-10-07.md`, `blockchain.md` + trace,
reorg ledgers in `history/reorg/`); background: `docs/research/`. Checks (CI `docs` job): `python3 scripts/docs_check.py
check`, `… facts check`, `python3 scripts/test_docs_check.py`.

| Phase | Commits | What |
|---|---|---|
| 0 | `08250aa`…`a59909a` | history frozen (pure renames), checker, old-id inventory (746), id map, fact ledger |
| 1 | `a492fa9`…`4cc227c` | node, contracts, networks/clients/integration docs + register fragments, every fact placed |
| 2 | `2e9bf4e`…`e13be84` | README, architecture, SCaaS-v2, decisions.md (merged register + alias index), history README, `_work` retired |
| — | `9513731` | owner rulings: lane keys hold no roles (NODE-JOB-01/19), `max_inflight` tunable default (NODE-LANE-24), decisions.md budget accepted |
| 3 | this commit | outside references: README, TODO (stream table → Doc/Scope), this file, scaas-node README (English, rewritten), smartcontracts READMEs, code-comment spec paths, CI `docs` job |

Left: Phase 4 reviewer pass (§6.4, ≤ 3 read-only reviewers, fixes by area); then move the plan to `docs/history/plans/`.
New design work: draft in `docs/superpowers/specs/`, rules into the component docs on acceptance (docs/README "Ids").

## Shutdown 2026-10-07 (before the docs reorg)

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
| Layout | `smartcontracts/{evm,move/{aptos,sui},soroban,cosmos,ton,solana,scripts}`, `scaas-node/`, `clients/{clientkeys,zether-prover,app (planned)}/`, `docs/` |
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
