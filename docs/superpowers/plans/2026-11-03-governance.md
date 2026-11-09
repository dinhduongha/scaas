# `governance` (GovernanceBase on every kind and the DEX, the `Grant` record, the two-call delay, hybrid underlying, rescue, `GovernanceHolder`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-03):** plan only, nothing built from it but T0. The code on branch `governance` is the D1 + D2 prototype, written to measure. Corrected the same day to the spec as the three reviews changed it (spec §0 G30-G59, §0.1), and after `6e09e008` to the final review's nine Minor findings (spec §0.1).

**Owner words, at the top:**

| Item | State |
|---|---|
| **Hybrid underlying (CTR-GOV-12)** | **In this build, on every `WRAPPED*` kind. No owner word is needed.** CTR-GOV-12 is an owner ruling and spec §5 and step S6 build it. Its one gate was §9 and §5.6: the `Grant` on bit 1 and the bytes on the confidential kinds. CTR-GOV-19 (owner 2026-11-03) lifted that gate and builds the whole record. C1 is the owner's now: `executeRate` drops `c ≥ supply` on a hybrid, a rate fall needs no `addReserve` (CTR-GOV-12). C2 (`maxSupply` in `scaas.underlying`, a `capped` copy in leg slot a) stands unless the owner overrides it |
| **The Change to CTR-AS-17 (spec §12.1)** | **Needs the owner's word before T17 applies it.** CTR-GOV-03 records that it "waits for the owner". The accepted Change lines of §12.9 are already in the register. T17 keeps §12.1 in a separate commit, so it can land or wait alone |
| **C7 and bit 5 (spec §12.9)** | Accepted by the owner 2026-11-03, in the register. |
| **Merging `main` into `governance`** | Needs the owner's word, at a task boundary, after `ua8-soroban` lands (§"Branches"). The spec's "rebased as the owner directs" defaults to: no rebase, the build goes on top of the prototype commits |
| **The probe's outcome** | **Settled.** T0: A refuses, C passes. Owner 2026-11-03: the SCaaS testnet leaves EIP-7954 out (CTR-GOV-19). T0b measures what that route left unmeasured |
| **NET-EVM-06's Change (spec §12.10)** | Taken by that ruling: T16 and T17 apply it |

**Goal:** promote the prototype to the spec and build the rest on EVM: D1 `GovernanceBase` / `GovernanceLib` on the six token kinds and `SCaaSDex`; D2 the whole `Grant` record with the fixes of B-01 to B-12 and the findings around them; D4 the two-call delay with `termsHash`; real enum ids; D5 with `isRegisteredToken`; D6 rescue; hybrid; `GovernanceHolder` and the relay rule; the selector audit and "+0" pins; the size gate's new ceiling; the node, clients and vectors; `docs/contracts/governance.md` and the §12 Changes. D7 is a separate part, not started here. Regulated implementations are not built: enum ids and refusals only.

**Architecture:** one branch `governance` (worktree `.claude/worktrees/governance`), on top of the prototype commits. A probe and the tool chain first (T0-T2), so nothing later runs without them. Contracts in one worktree, sequentially (T3-T10: they share `GovernanceLib`, `MetaTokenBase`, `WrappedLib`, `SCaaSDex`), the holder and its rows (T11-T12), the audit (T13), then bits, node and deploy beside each other (T14-T16), docs (T17), the gate runner (T18), the whole-branch review (T19), the report (T20).

**Tech Stack:** Solidity / Foundry 1.8.5, solc 0.8.37, Amsterdam, `via_ir = false`, optimizer 200; Rust `scaas-node` (alloy 1.6, rustc 1.90); Node `node --test` (`clients/clientkeys`); `ua-rs`, `ua-c`, `ua-cxx`, `ua-qt`, `ua-cs`, `ua-py`, `ua-go`, `ua-dart`, `ua-dart-frb`; Python 3 (`docs_check`, `size_gate`); Docker for T0 and T0b only.

**Spec:** [`docs/superpowers/specs/2026-11-02-governance.md`](../specs/2026-11-02-governance.md) (§0 G1-G59, C1-C11, §0.1 the reviews). Rulings: [`docs/decisions.md`](../../decisions.md) CTR-GOV-01 to -19. Findings: `docs/research/governance/permission-model-v2-attack.md` (B-01 to B-34, R-01 to R-19). Measurement: `docs/research/governance/prototype/RESULTS.md`.

**Owner 2026-11-03, binding this plan:** size no longer blocks the build. Every kind, `WrappedZetherToken` included, first runs on the SCaaS testnet at a higher `maxCodeSize`; the whole `Grant` record is built; reducing size comes later. **No size lever is planned.** Spec §9 is the record of what a public chain still needs; S0 is now the route, T0, T0b, T2. Regulated implementations stay out: their rules stay in CTR-GOV-17 and -18 for a later round.

## Global Constraints

- Owner rulings override code. A difference between code and a ruling is a bug in the code. Follow a stated rule as stated, no added assumptions, no option tables.
- **Explicit parameters:** the holder has one named typed entry per op; `GrantTerms` is a nested typed struct, never `bytes`. **No generic path to a holder op** (B-14).
- **Every state-changing `mtx*` is relayable**, fee 0 too: no governance `mtx*` or `ua*` exists on a governed contract (spec §3.6), and every one on the holder is relayable.
- **No EIP-7702.** No assumption about a chain: no gas price 0, no block limit of ours in code; the block limit is read, the code limit is declared (GD-4).
- **Nothing deployed is upgraded. Backup, do not delete:** superseded code moves to `legacy/` (GD-11).
- **Never lose ciphertext:** nothing here touches a PQZ or Zether ciphertext. Zether ≠ PQZ: where a task names them, they are separate lines and separate tests. NEAR ≠ Algorand.
- **"+0" (CTR-GOV-11):** a plain `transfer` and `mtxTransfer` add no storage read, on every kind. Dispatcher drift in the gas figure is allowed; a read is not.
- **The node is open:** a guarantee lives in the node and its spec. Allow-lists stay equal to the contract's, per kind, both directions.
- **Pins move only with old → new in the commit message:** gas pins, `size-baseline.json` (with a reason in `_comment`), layout, typehashes, KATs by their generator. Never edit a pin, a bound or a test to go green.
- **KATs and vectors come from their generators.** Hand edits are defects. Byte formats change everywhere at once.
- **Mutants:** a negative test must be able to fail. Each mutant is one change, on a clean tree, its suite run, restored by `git checkout -- <file>`. Log them as `runs/2026-11-03-governance-t<n>-mutants.txt`, one row `mutant | test that went red | rc`. A mutant that no test catches is a finding, not a note.
- Heavy commands through `scripts/capped`, foreground, never inside `timeout`. cargo `-j2`. `dotnet build-server shutdown` after capped dotnet. Docker capped by `--memory` or compose `mem_limit`. No `nohup`, `&`, `until`, `sleep` loops, `pgrep -f`, `git stash`, `git add -f`. At most 3 agents at once, no two gate runs at once. `at-set.sh` rewrites `src/pqz/PqzSet.sol`: one run per work tree, restored after.
- No timing or gas calibration; forge gas figures are deterministic and need no go. No full `pqz-core/gate.sh`: nothing in `pqzl`, `pqzh`, `stmt`, `ffi` or a set parameter moves. If a set's `debit_min_gas` or a calibrated row moves, stop and ask.
- **Never touch the live testnet stack,** its containers or its RPC port. T0 and T0b run on a throwaway copy. **The reset is the controller's.** 22776 is the owner's.
- Commit per task on `governance`, staged by explicit path: `governance T<n>: …`, ending with the session's `Co-Authored-By` trailer. **No merge, no push.** `HANDOFF.md` stays local; no commit holding only `TODO.md`.
- English in code, commits, docs. Full output in git-ignored `.log` files; commit `step | commit | rc | counts` summaries and short evidence, no absolute paths.

## Plan decisions (GD-*; controller calls, owner may override; recorded in full by T17)

- **GD-1 "+0" first.** Spec S9 puts the pin late. It costs nothing to place first and guards every later task, so T1 lands it before any contract changes. The selector audit stays late (T13): it needs the holder.
- **GD-2 The final storage shape lands once.** T3 writes `GovernanceStorage` of spec §1.4, `ownerGeneration`, `PendingGrant.generation` and `Grant.barred` in full, with the layout pin; T5-T10 use fields and move no slot. So the layout pin moves once and later diffs stay small.
- **GD-3 One config change.** T7 adds `grantDelay`, `rescueTo` and `maxSupply` to `TokenConfig`, and `grantDelay`, `rescueTo` to `DexConfig`, in one commit, so the encoders (`script/pqz/e2e.py`'s `CFG`, `scaas-node/tests/e2e.rs`' `DexConfig`, 20 positional `DexConfig(...)` in tests) change once. Until T9 and T10 give them meaning they fail closed: `maxSupply ≠ 0` reverts `MaxSupplyInvalid()`, `rescueTo ≠ 0` reverts `RescueConfigInvalid()`.
- **GD-4 The code limit is declared, not derived from a chain id.** `DeployBase` refuses a release whose runtime exceeds `CHAIN_CODE_LIMIT` (env, default 65,536, the value of EIP-7954), naming the contract, before anything is sent. The SCaaS testnet's runbook sets 131,072. One rule on every chain, no list of chain ids. A chain's own limit stays the last word: a deploy it refuses fails closed.
- **GD-5 The list is a pin.** `size-baseline.json` gains `_above64KiB`, sorted. `size_gate.py` prints the list every run and errors when the computed list differs from it, in either direction, so a kind that crosses is named in a commit.
- **GD-6 Where new pins live.** `fs_permissions` reads `./test/vectors`, `./test/v2/layout`, `../vectors`, and writes `./test/vectors`, `../vectors/metatx`. So: `test/vectors/plus_zero_slots.json`, `test/vectors/selector_audit.json`, `test/v2/layout/namespaces.json`, `test/v2/layout/GovernanceHolder.json` (spec §10.4's `test/governance/layout/` is not readable and needs nothing of its own). `foundry.toml` gains one entry only: `{ access = "read-write", path = "../vectors/governance" }`.
- **GD-7 `setGrant` on the holder.** `_namedCall` (words ≠ call arguments) is on `ERC20MetaTx`, which the holder is not. `MetaTxBase._named` runs `_run`; the holder adds one private helper on `_metaOf`, `_namedHash`, `_run`. `_namedCallUA` already sits on `UAMetaTxBase`. Overriding `_execute` to refuse does not touch that helper: it goes to `_run`, not `_execute`. Every holder struct carries `generation`, a word and no call argument, so every op, not only `setGrant`, goes through the helper.
- **GD-8 The holder's `deploy` is relayable.** A derived UA has no gas, and spec §3.6 says no first gas is needed, so the permissionless `GovernanceHolderFactory.deploy` gets a `PLAIN` row, as `SmartKeyAccountFactory.deploy` has. New contract kind `holder_factory`, `Rule::HolderFactory`, config `holder_factories`, a list (empty: refused), so the second holder release of spec §3.2 is a config row. `IMPLEMENTATION()` read once from each gives the set of clone code hashes of `Rule::Holder`, as `SmartKeyAccountFactory` names it.
- **GD-9 What "every language" holds.** Typed-signing C7 found that only `clientkeys` and `zether-prover` build typed EVM digests, so holder rows go to `clientkeys` and the node, and spec S8's "every `ua-*`" does not apply. `governance_bits.json` goes to every language (T14), in the seats of `kindName`'s table. The DEX `admin` rename is real in one non-Solidity file, `scaas-node/tests/e2e.rs`, plus docs: a word search finds no client that reads it. No wizard exists in this repo; "wizard default 2 days" is a doc line.
- **GD-10 `maxSupply` in the indexer.** Spec S6 says the indexer reads it. `scaas-node/src/indexer.rs` reads no token parameter at all, so there is no seat. Not built; `maxSupply()` is the wallet's view. Add when a feed asks.
- **GD-11 Legacy.** T3 copies `AdminLib.sol` and `ITokenAdmin.sol` as they stand at `main`, and the prototype's `requireRole`, to `smartcontracts/evm/legacy/governance/` with a line in `legacy/README.md`; `requireRole` goes by spec G14, a ruling on that API. The prototype's own superseded lines are not legacy: they never shipped.
- **GD-12 `WRAPPED` gets a deploy path.** `DeployBase` deploys `NORMAL`, the DEX and the Zether kinds, `script/pqz/e2e.py` the PQZ kinds; nothing deploys `WRAPPED`, and CTR-GOV-19 says every kind runs on the SCaaS testnet. T16 adds `DEPLOY_WRAPPED`, in the form of `_deployZether`.
- **GD-13 `dex_order_kat.json` regenerates in each task that moves `NormalToken` or `SCaaSDex` bytecode** (`WRITE_KAT=true forge test --match-contract DexKatTest`), from T3 on, so every task ends green and every reader follows. The review check: only clone addresses, domains and signatures move in its diff.
- **GD-14 The B-06 fixture.** `normalInit` sets `features = 7`, owner 0, and takes a minter. 29 of its 51 calls pass a non-zero minter, so T5's rule refuses them. `normalInit` sets `lockedFeatures = 1 << 1` when `minter ≠ 0`: the holder survives with no owner, which is what those tests meant.
- **GD-15 Findings that stay as stated behaviour.** B-13 and B-16 are accepted by spec §1.7 and §7.4: their `test_attack_*` become `test_stated_*`, kept as pins of the behaviour.
- **GD-16 The "+0" rows on the UA path.** Spec §10.2 now pins `transfer`, `mtxTransfer`, `transferToUA` and `uaExecuteTransfer`: the first two never reach `_uaMove`, so a control there could not fail on them (Codex 11), and the last is the UA → UA branch.
- **GD-17 CTR-GOV-18's test row.** Spec §10.3's row needs `ComplianceRegistry` and the hook. Only "`ALLOWLIST` refused on the four confidential kinds" lands now; the rest goes to the regulated round with its code.
- **GD-18 The two size pins.** `Factory.t` `test_sizes` and `HederaV2.t` `test_implementationSizes` assert 39,945 and 50,770. Spec §10.4: no pin moves to go green, and B-26 is expected to clear them, so they stay red through T2 and T3 re-reads them. Later features can pass them on merit: the first task whose measured `NormalToken` passes 39,945, or `WrappedToken` 50,770, moves that literal with old → new, to read `size-baseline.json`, so the ratchet is one number.
- **GD-19 The refusal of 5-9 keeps each kind's error.** `_validBits()` loses `REGULATED` on `NormalToken` and `WrappedToken`, and their `_init` passes `_validBits() | GovernanceBits.REGULATED`, so `Features.t` and `GovernanceLib.t` keep `FeatureNotBuilt` unchanged and the confidential kinds keep `FeatureInvalidForKind`. No test moves.
- **GD-20 `_addLeg` reads the factory as `msg.sender`.** `initialize` has checked it and DELEGATECALL keeps it, so `initToken`, `ZetherWrappedLib.init` and `PqzWrappedLib.init` keep their signatures. T8 tests it through all three.

## Prototype review against the spec

Read at `d1132a40`, `src/governance/`, `src/dex/SCaaSDex.sol`, `src/metatx/`. What differs, and the task that closes it.

| # | Prototype | Spec | Task |
|---|---|---|---|
| P-1 | "Prototype" in `GovernanceBase`, `GovernanceBits`; `GovernanceLib`'s NatSpec says role holders keep their roles after a renounce | §1.7: refused while an unlocked bit has roots | T3 |
| P-2 | `use` inside `GovernanceLib`, inlined into every caller (B-26) | `GovernanceUse`, one DELEGATECALL | T3 |
| P-3 | `requireRole` open to any child (B-31) | removed; every power through `use` | T3 |
| P-4 | Storage: `holderCount` mapping, `owner` and `pendingOwner` unpacked, no `grantDelay`, `lastProposedAt`, `pending`, `rescueTo`, no `barred` | §1.4, `Counts`, `PendingGrant` | T3 (GD-2) |
| P-5 | One `TOKEN_ROLES`, `TOKEN_CONTRACT_ONLY` on every kind, passed as constants by `WrappedLib.initToken`. `grantRole(3, x)` on `NORMAL` answers `RoleWithoutFeature`, not `NoSuchRole` | §1.2 masks per kind: `NORMAL*` roles bit 1, contract-only 0 | T3 |
| P-6 | No `_scalarBits`, `_scopeBits` | §1.3 | T3 (declared), T5 (read) |
| P-7 | `init` refuses `roles.compliance` with bit 8 `ALLOWLIST`; comments say "flags 5–8", `FORCE / ALLOWLIST` | §1.2: `Roles.compliance` maps to bit 10; bits 8, 9 have no holder | T3 |
| P-8 | `NORMAL_BITS` lacks 17, `WRAPPED_BITS` lacks 1 and 17 | §1.2 | T9, T10 |
| P-9 | `init`: no B-06 loop, no B-19 refusal, no `GrantDelayTooLong`, no rescue check | §1.4, §1.7, §6.2 | T5, T7, T10 |
| P-10 | `setGrant`: `perWindow` without `window` reverts `GrantNotNarrower(3)`; `window` without `perWindow` is stored; no word masks, no budget rule; no `RoleGranted` for a new holder | §1.5, §2.2: `GrantWordRefused(bit, 3)`, both directions; B-02, -09, -10, -31 | T5 |
| P-11 | `setGrant`: no `owner ≠ 0`, no `barred`, no window rule, no epoch on a scope or delegation edit; a leaf stays a leaf | §1.5, §1.6 | T6, T7 |
| P-12 | `_narrows` subtracts `p.total - p.spentTotal`, no `window` | B-18, B-17 | T6 |
| P-13 | `revokeRole` trusts a stale `grantor`; `_grant` keeps `grantor`, bumps no epoch | B-04, B-18 | T6 |
| P-14 | `renounceOwnership` counts holders | B-07: roots | T6 |
| P-15 | `grantRole` and `setGrant` one call; `SCaaSDex.initialize` calls `grantRole` | §1.6, B-27, `initHolder` | T3 (`initHolder`), T7 |
| P-16 | DEX: four powers unguarded, no `supportsInterface`, comments say admin | B-31, §2.3 | T3 |
| P-17 | `IGovernance` lacks the views, errors and `GrantProposed` of §2.2; `GrantNotNarrower` field 8; no `IRescuable` | §2 | each with its task |
| P-18 | `test_transferTouchesNoGovernanceSlot` covers one entry, one kind, `root..root+7` | B-33, §10.2 | T1 replaces it |
| P-19 | `test/metatx/AdminLib.t.sol`, `helpers/AdminHarness.sol` keep the old name | `GovernanceLib` | T3, `git mv` |
| P-20 | `NormalToken._validBits()`, `WrappedToken._validBits()` hold `REGULATED`, so `validBits()` reports bits 5-9 (agy I-6) | §1.2 | T3 (GD-19) |
| P-21 | `_clear` returns on a non-holder, so a revoke can write nothing (Claude M-8) | §1.5 | T6 |
| P-22 | `_narrows` reads `t.maxUses > p.maxUses`; the leaf path reads no parent expiry (agy I-3) | §1.5 | T6 |
| P-23 | `WrappedLib.initToken` passes `TOKEN_ROLES`, `TOKEN_CONTRACT_ONLY` | §1.2 | T3 |

**Held, keep as they are:** `$()` and the root constant; `_debit`; `useLimited` debiting the parent with the same function; `_scopeNarrows` in the stub; a revoke keeping the record; the two guard hooks; masks passed as arguments; `_grant` idempotent on `WHOLE`; `WrappedLib` keeping `NotGuardian`, `NotRateAdmin`, `RateFixed` around `use` (no size work). `_lowest` runs only on a non-zero word on every path read.

**B-01 to B-12:** B-01 T7. B-02 T5. B-03 T4. B-04 T6. B-05 T6. B-06 T5. B-07 T6. B-08 T6. B-09 T5. B-10 T5. B-11 T6. B-12 T6. **The rest:** B-13 stated (GD-15), B-14 T11, B-15 T8, B-16 stated, B-17 and B-18 T6, B-19 T5, B-20 to B-22 T11, B-23 to B-25 Part D7 and the family rounds, B-26 T3, B-27 T7, B-28 routed to CTR-GOV-09's mask, B-29, B-30, B-32, B-34 T17 (and B-34's sentence T14), B-31 T3 and T5, B-33 T1.

**The reviews (spec §0.1), where each lands:** agy C-1, Claude M-7 T6. agy C-3, Claude M-4 (pending), M-5, M-6, Codex 2, 7, agy I-2 T7. agy I-1, I-3, Claude M-8 T6. agy I-6, M-1 T3. agy I-7, M-2.2 T10. agy M-2.1 T8. agy I-5, Claude I-9, M-14 T11, T15. Claude I-4, M-9 (reserve) T9. Codex 3, 4, Claude M-4 (envelope) T11. Codex 10 T14, T17. Codex 11 T1. Claude I-7 T7. Fable M-1 T7. M-2 T11. M-6, M-7 T9. M-8 T15. M-9 T14. M-5 T17, on the owner's word. M-3, M-4 spec text only. The regulated rows (Claude I-1, I-2, I-3, I-5, M-9, M-10, M-11, M-12, Codex 1, 5, 6, agy C-2) land as spec text only: T14's sentences and T17's docs.

## What lands for the regulated round

`ALLOWLIST`, `DENYLIST`, `requiredFlags`, `deniedFlags`: **the bits land, the parameters do not.** The regulated round needs nothing more at creation, because the factory never reads a config.

| Lands now | Task |
|---|---|
| `GovernanceBits`: `FREEZE` 5, `FORCE` 6, `PAUSE` 7, `ALLOWLIST` 8, `DENYLIST` 9, `RECORD` 10, `MODERATE` 21, `REGULATED` = bits 5-9. Already there | prototype |
| `NORMAL`, `WRAPPED`: any of 5-9 refused `FeatureNotBuilt(bit)`, one test per bit, and none of them in `validBits()` (GD-19). The four confidential kinds: `FeatureInvalidForKind(bit)`, 8 included | T3 |
| `roles.issuer ≠ 0` refused `RoleWithoutFeature(5)`, `roles.compliance ≠ 0` refused `RoleWithoutFeature(10)` | T3 |
| Enum ids 8-13, off; 6 and 7 refused | T4 |
| `test_regulatedKindPublishesOnTheSameFactory`: a mock of kind 8 decodes `abi.encode(TokenConfig, a RegulatedParams-shaped struct)` in its own `_initRaw`, then publishes, enables and creates on the same factory, is `isRegisteredToken` and `KIND_SCAAS` to the DEX | T4 |
| `governance_bits.json` rows and sentences for 5-10, 21: bits 8, 9 "no holder, parameters"; bit 5 one sentence per class of kind, bit 7 one sentence | T14 |

**Does not land:** `RegulatedParams`, `complianceRegistry`, `requiredFlags`, `deniedFlags`, `cooldownUntil`, `termsHash`, `ComplianceRegistry`, `hasFlags`, `canReceive`, `requiredFlags()`, `deniedFlags()`, `complianceRegistry()`, `NotEligible`, `RegulatedConfigInvalid`, `TokenStore.KIND_*` for 8-13, any hook in `_update` or `_uaMove`, `_delayedRelaxBits`, any storage slot, any `TokenConfig` field.

**Why nothing is owed later:** `createToken(kind, version, initArgs, salt)` passes `initArgs` opaque to `initialize` (`IFactoryToken`: "a later version may take another encoding without a factory change"), and `_initRaw` and `_init` are virtual. So a regulated implementation decodes its own encoding: `TokenConfig` plus `RegulatedParams`. What that release does owe is library bodies, not parameters: a `GovernanceLib` of its own, and a `WrappedLib`, `ZetherWrappedLib`, `PqzWrappedLib` relinked to it, each in `Env.libs` (spec §4.2). A wallet needs no view on a plain kind: `features()` says bits 8 and 9 are off, and features only lose bits.

## Code size and deploy gas

**Size gate.** `scripts/size_gate.py` has no 64 KiB check today: only per-contract limits and the ratchet. T2 adds two things, a hard ceiling and the list:

| Item | Today | After T2 |
|---|---|---|
| Runtime ceiling, baseline or not | none | 131,072 B (`maxCodeSize` `0x20000`, CTR-GOV-19): above it is an error |
| Init ceiling | none past the baseline | 131,072 B, the lower figure, until T0b reads the SCaaS testnet's route. T0: with EIP-7954 active the client refuses 131,073 B, so that limit does not follow `maxCodeSize`; without it the limit is not measured |
| List of contracts above 65,536 B | none | printed every run, pinned as `_above64KiB` (GD-5) |
| Ratchet | shrink only, 13 errors on this branch (RESULTS §1) | the same; moved in each task with old → new |

**Expected above 64 KiB:** `WrappedPqzToken` (65,520 B before D4, D6, hybrid) and `WrappedZetherToken` (64,284 B; 1,253 B more crosses). Each jumps about 4.7 KB at the crossing [I, RESULTS §3]: a task that crosses shows that jump and it is not a regression. The gate names what happens, not this estimate.

**Forge and anvil.** Under Amsterdam forge refuses a create above 65,536 B, so T2 sets `code_size_limit = 131072` in `foundry.toml` before any kind crosses. RESULTS' probe past the cliff was built, never deployed. `scripts/e2e-zether.sh` runs anvil with `--code-size-limit 65536`; T2 raises it. `deploy.sh`, `e2e.rs`, `e2e_hedera.rs` already pass `--disable-code-size-limit` to forge; T16 raises their anvil limit where a kind above 64 KiB is deployed.

**Deploy gas against the 200 M block.** Need = `runtime × 1,530 + 2^24` (`DeployBase._releaseGasNeed`, EIP-8037: `tx.gas` must fit the block). That is the deploy gate's formula, not the chain's limit: T0's arm C deployed 119,800 B at `tx.gas` 199,900,000, `gasUsed` 183,562,782. The largest size that fits at 200 M was not searched.

| Runtime | Need | 200 M block |
|---|---|---|
| 65,520 B, `WrappedPqzToken` measured D1 + D2 | 117.0 M | fits |
| 75,000 B, a guess past the cliff [est.] | 131.5 M | fits |
| **119,753 B** | 200.0 M | **the largest that fits** |
| 131,072 B, `0x20000` | 217.3 M | **does not fit** |

So at 200 M the deploy gate's ceiling is 119,753 B, not `maxCodeSize`, and it refuses first, fail closed. Nothing planned comes near it; a contract above it would need a block of its own, which is the controller's reset. `--gas-estimate-multiplier 105` asks 5 % more of the block: T16's simulated run reports `tx.gas` beside the formula. Deploy gate figures at `NormalToken` 77.2 M, `WrappedToken` 93.5 M, `NormalZetherToken` 100.8 M, `NormalPqzToken` 101.0 M, `SCaaSDex` 65.3 M all fit, from the B-26 column of spec §9.

## Review Focus (every task review reads these)

1. A stranger never reaches a power, and a grantee never widens itself: R-01, the selector audit.
2. `setGrant` is not a way round the delay: a new holder and every widened word take two calls, confirmed with the same terms, by the proposing owner, inside the window (B-01).
3. An edit never refreshes a budget, a revoke keeps the record, a leaf cannot outlive its parent's scope (B-11, B-12, B-18).
4. A hybrid's cap holds on every path that raises `totalSupply()`; a non-hybrid wrap reads no new slot.
5. No read on `transfer` or `mtxTransfer` on any kind: `PlusZero.t.sol`, not a gas figure.
6. A library split is not free: `this`, `msg.sender`, DELEGATECALL storage, reentrancy guards, `LinkClosure` pins, in `GovernanceUse` and in `WrappedLib` → `GovernanceLib`.
7. Holder: no generic path, `_subject()` checked at run time, `acceptOperator` against the pending, `generation` signed and bumped, the operator in the salt, no `receive`, one lane per target stated.
8. Allow-lists equal in both directions after every row added.
9. `Counts` by spec §1.7's table, every row, `r` read first. A pending never outlives an owner's revoke, a renounce or a change of owner, and a grantor's revoke leaves it: A → B → A revives nothing, of a pending or of an envelope.

---

## File Structure

| Path | Responsibility |
|---|---|
| `smartcontracts/evm/src/governance/{GovernanceBase,GovernanceLib,GovernanceBits,IGovernance}.sol` | promoted; `GovernanceUse` inside `GovernanceBase.sol` |
| `smartcontracts/evm/src/governance/{GovernanceHolderBase,GovernanceHolder,GovernanceHolderFactory,IRescuable}.sol` | new |
| `smartcontracts/evm/src/metatx/{MetaTokenBase,NormalToken,WrappedToken,WrappedLib}.sol`, `src/zether/{WrappedZetherToken,ZetherWrappedLib,NormalZetherToken}.sol`, `src/pqz/{WrappedPqzToken,PqzWrappedLib,NormalPqzToken}.sol` | `use`, config, hybrid, rescue |
| `smartcontracts/evm/src/factory/{IOpenFactory,OpenFactory,IFactoryToken}.sol`, `src/dex/{SCaaSDex,ISCaaSDex,DexPuller}.sol` | enum, `TokenConfig`, `DexConfig`, `DexPuller.rescue` |
| `smartcontracts/evm/test/governance/{PlusZero,CodeCeiling,GovRegulatedBits,GovDelay,GovExamples,GovLeg,GovHybrid,GovRescue,GovDeploy,Holder,HolderPqMsig,HolderTypehash,SelectorAudit,GovBitsVector}.t.sol` | new suites; `GovGrant`, `GovAttackV2`, `GovGas` kept |
| `smartcontracts/evm/test/vectors/{plus_zero_slots,selector_audit}.json`, `test/v2/layout/{namespaces,GovernanceHolder}.json` | new pins |
| `smartcontracts/vectors/governance/governance_bits.json`, `smartcontracts/vectors/typed/typed_ops.json`, `smartcontracts/evm/test/vectors/dex_order_kat.json` | new, regenerated |
| `scripts/size_gate.py`, `smartcontracts/evm/size-baseline.json`, `smartcontracts/evm/foundry.toml`, `smartcontracts/evm/script/DeployBase.sol`, `smartcontracts/scripts/deploy.sh`, `scripts/e2e-zether.sh` | ceiling, list, deploy gate |
| `scaas-node/src/{typed,guard,config,addresses}.rs`, `scaas-node/node.example.toml`, `scaas-node/tests/{e2e,e2e_hedera}.rs` | rows, rules, config, e2e |
| `clients/clientkeys/{src/evm.js,scripts/typed-ops-vectors.mjs,test/typed-ops.test.js}`, every client's bit reader (T14) | rows, bits |
| `pqz-core/nethermind/chain/{e2e.py,patch-chainspec.py,RUNBOOK.md}`, `pqz-core/nethermind/runs/2026-11-03-code-size-probe.{sh,txt}` | probe, its arm D, reset tooling: `maxCodeSize` `0x20000`, EIP-7954 out |
| `docs/contracts/governance.md`, `docs/{contracts,node,networks}/…`, `docs/decisions.md`, `README.md`, `docs/README.md`, `AGENTS.md`, `TODO.md` | T17 |
| `smartcontracts/evm/runs/2026-11-03-governance-gates.sh` | closing gates |

## Setup (before T0)

- [ ] In `.claude/worktrees/governance`: `git status` clean at `d1132a40` or the plan's commit. Local tag `ref/pre-governance-build` at that commit, never pushed.
- [ ] `smartcontracts/evm/lib`, `clients/clientkeys/node_modules`, `smartcontracts/algorand/out` as real directories (`scripts/evm_libs.sh install`, `check`; `ALGORAND_ARTIFACTS_CHECK=1 scripts/capped smartcontracts/scripts/build.sh algorand` once).
- [ ] Baseline run, recorded in `runs/2026-11-03-governance-base-summary.txt`: `cd smartcontracts/evm && ../../scripts/capped forge test`. Expected, as RESULTS §7: the prototype's three failures only (`DexKat`, `Factory.t` `test_sizes`, `HederaV2.t` `test_implementationSizes`), and `size_gate.py` 13 errors. Any other failure stops the plan: read it first.

## Order (≤ 3 agents at once)

| Stage | Tasks | How |
|---|---|---|
| Route and guards | T0 (done), T0b, T1, T2 | T0b anytime, Docker only, no forge overlap needed; T1 then T2 |
| Contracts | T3 → T4 → T5 → T6 → T7 → T8 → T9 → T10 | sequential, one worktree: same files. All four sets once at T10 |
| Holder | T11 → T12 → T13 | T12 needs T11's entries, T13 needs both |
| Beside each other | T14, T15, T16 | after T13; disjoint files. T15 needs T12's rows |
| Close | T17 → T18 → T19 → T20 | |
| Later | Part D7 | after `ua8-soroban` merges; not started here |

| Spec step | Tasks |
|---|---|
| S0 | T0, T0b, T2, T16 (the route of CTR-GOV-19) |
| S1 | T3 |
| S2 | T4 |
| S3 | T5, T6 |
| S4 | T7 |
| S5 | T8 |
| S6 | T9 |
| S7 | T10 |
| S8 | T11, T12, T16 |
| S9 | T1, T13, T14 |
| S10 | T15 |
| S11 | T17 |
| S12 | Part D7 |

Sizes are measured and logged after T3, T7, T9, T10 (spec §11), `forge build src --sizes --json`, at the default set; they decide nothing.

---

### Task T0: the local probe (CTR-GOV-19): DONE, `fee41265`

**Result** (`pqz-core/nethermind/runs/2026-11-03-code-size-probe.txt`): arm A refuses, arm C passes, on `scaas/nethermind-pqz:2.2.0-pqz6` and stock `nethermind/nethermind:2.2.0`. With EIP-7954 active the code limit is 65,536 B whatever `maxCodeSize` says. With `eip7954TransitionTimestamp` removed, `maxCodeSize` `0x20000` alone carries the code: 70,000 B with a real jump answered 42, 119,800 B deployed. **Owner 2026-11-03:** the SCaaS testnet leaves EIP-7954 out, every other Amsterdam EIP stays (CTR-GOV-19). The probe ran one node at a time, the follower by RLP import.

**Left unmeasured:** arm B ran with EIP-7954 active, so neither the code ceiling at `0x20000` nor the init limit is known on arm C's route. T0b takes both.

### Task T0b: the ceiling and the init code limit without EIP-7954 (CTR-GOV-19: "not measured")

**Question:** on arm C's route, is the code ceiling 131,072 B, and what is the init code limit? Under EIP-7954 the client refused 131,073 B of init code; without it the limit is not known, and `docs/networks/evm.md` records that it followed `maxCodeSize` before Amsterdam. Every deploy sends init code, runtime plus constructor plus arguments, so a limit below a kind's `.init` row stops that kind.

**Files:** `pqz-core/nethermind/runs/2026-11-03-code-size-probe.sh` (arm D), `…-code-size-probe.txt` (rows added, the verdict line kept)

**How:** as T0, the same limits, one node at a time, `127.0.0.1:18545`, **the live directory never read**, stock image and the local `pqz` image.

| Arm | Chainspec | Rows, each one `status`, `eth_getCode` length, `gasUsed`, or the refusal's text | Must show |
|---|---|---|---|
| D | as C, `gasLimit` and target 300 M | 131,072 deploys; 131,073 status 0; init code of 131,072, 131,073, 262,144 and 262,145 B: accepted or refused; a `WrappedPqzToken`-sized init read from `size-baseline.json`'s largest `.init` row | the ceiling, and which init limit applies |

| Outcome | Next |
|---|---|
| The ceiling is 131,072 B and the init limit is at or above every `.init` row | `size_gate.py`'s init ceiling moves to the measured limit, old → new in the commit, by T2 if it has run. T16 writes the figure into the RUNBOOK section |
| The init limit is below a `.init` row, or the ceiling is lower | **Owner word.** The build continues on forge and anvil; the gate names the kind; T16 stops short of the RUNBOOK |

- [ ] **Step 1:** Add arm D to the script; per-step `.log`, resume at the same commit; first line `# <arm> at commit <sha>`, last `rc=<n>`.
- [ ] **Step 2:** `docker ps --filter name=pqzcopy-` empty and at least 4 GB available, then run arm D, foreground, on both images.
- [ ] **Step 3:** Check `docker ps --filter name=pqzcopy-` is empty. Remove the copy through `copy.sh wipe`.
- [ ] **Step 4:** Commit script and summary: `governance T0b: ceiling and init code limit without EIP-7954, <verdict>`.

**Mutants:** arm 0 of T0 is the control; 131,073 B must fail. **Pins:** none here. **Gates:** no container of the probe left.

### Task T1: "+0" pinned on every kind (CTR-GOV-11, B-33; GD-1, GD-16)

**Files:**
- Create: `test/governance/PlusZero.t.sol`, `test/vectors/plus_zero_slots.json`
- Modify: `test/governance/GovGrant.t.sol` (`test_transferTouchesNoGovernanceSlot` removed: replaced)

**Changes:** per kind (six) and entry (`transfer`, `mtxTransfer`, `transferToUA`, `uaExecuteTransfer` UA → UA): a balance on both sides, lane past nonce 0, `vm.record()`, the call, `vm.accesses(token)`. The sorted set of read slots and of written slots is compared with the pin. Not a range around a root. Written on ABI strings and literal bits, as `GovGas.t.sol`, so the same file runs on `main`. `PLUS_ZERO_WRITE=true` writes the file. `TokenConfig` moves at T7: from then on the fixture encodes the new shape and the pin stays; re-recording needs T1's commit, and the run log says so.

- [ ] **Step 1: Failing tests:** `test_plusZero_transfer_{normal,wrapped,normalZether,wrappedZether,normalPqz,wrappedPqz}`, the same for `mtxTransfer`, `transferToUA`, `uaExecuteTransfer`: 24 tests, red: no pin yet.
- [ ] **Step 2: Record at `2a864638`.** `git worktree add .claude/worktrees/gov-pin 2a864638`, real `lib/`, copy the test in, `PLUS_ZERO_WRITE=true ../../scripts/capped forge test --match-path test/governance/PlusZero.t.sol`, copy the JSON back, `git worktree remove .claude/worktrees/gov-pin`. `main`'s checkout is not touched.
- [ ] **Step 3:** On the branch, `../../scripts/capped forge test --match-path test/governance/PlusZero.t.sol`: PASS. A difference here means the prototype added a read: stop, it is the finding this test exists for.
- [ ] **Step 4: Mutants,** each must go red on all six kinds: a `features` read and a `roles[1][from]` read in `_update`, red on `transfer` and `mtxTransfer`; the same two in `_uaMove`, red on `transferToUA` and `uaExecuteTransfer`. A mutant that goes red on no row is a finding.
- [ ] **Step 5:** Commit `governance T1: no new read on the native and UA paths, every kind, pinned at 2a864638`.

**Pins:** new, none moved. **Gates:** `forge test --match-path 'test/governance/*.t.sol'`.

### Task T2: the ceiling that lets every kind build (CTR-GOV-19; GD-4, GD-5)

**Files:**
- Modify: `scripts/size_gate.py`, `smartcontracts/evm/size-baseline.json`, `smartcontracts/evm/foundry.toml` (`code_size_limit = 131072`), `smartcontracts/evm/script/DeployBase.sol` (`_checkCodeFits(name, limit)`, called by `_requireReleaseGas`; NatSpec), `scripts/e2e-zether.sh` (anvil `--code-size-limit 131072`), `test/zether/ZetherDeploy.t.sol`
- Create: `test/governance/CodeCeiling.t.sol`

**Changes:** the table in §"Code size and deploy gas". `check()` gains the ceiling for runtime and init, baseline or not. `main()` reads `_above64KiB` before it filters `_` keys, compares it with the computed list, prints the list. `AdminLib` leaves the baseline, `GovernanceLib` enters. `Factory.t` and `HederaV2.t` are not touched here (GD-18).

- [ ] **Step 1: Failing tests:** `size_gate.py --self-test` rows: 131,072 passes with a baseline row, 131,073 fails with one; a stale `_above64KiB` fails both ways. `test_createAboveSixtyFourKiBDeploys`, `test_createAboveTheCeilingReverts`, `test_releaseAboveTheChainLimitIsRefusedByName`.
- [ ] **Step 2:** `python3 scripts/size_gate.py --self-test` and `../../scripts/capped forge test --match-path test/governance/CodeCeiling.t.sol`: FAIL.
- [ ] **Step 3: Implement.** Move the baseline to the branch's measured figures.
- [ ] **Step 4:** Both PASS. `T=$(mktemp -d); forge build src --sizes --json > "$T"/sizes.json; python3 ../../scripts/size_gate.py "$T"/sizes.json size-baseline.json`: 0 errors. Whole suite: the three known failures, no other; T3 clears them.
- [ ] **Step 5: Mutants:** the ceiling check dropped; the list compare dropped; `_checkCodeFits` not called.
- [ ] **Step 6:** Commit `governance T2: 131,072 B ceiling, the list above 64 KiB, the chain's code limit declared at deploy`.

**Deviation (controller, 2026-11-03):** `foundry.toml` gets no `code_size_limit`. forge 1.8.5 applies no code size limit in tests (131,073 B deploys), and with the key set every suite whose test contract's init code exceeds 262,144 B fails `setUp` (`UADeploy` 440,212 B, `CodeCeiling` 423,447 B). The 131,072 B ceiling is held by `size_gate.py` and by the chain; `test_createAboveTheCeilingReverts` is not written.

**Pins, old → new in the commit:** `size-baseline.json` every kind and `SCaaSDex` from `main` to measured (`NormalToken` 37,228 → 40,575, `WrappedToken` 48,015 → 50,166, `NormalZetherToken` 52,741 → 55,974, `WrappedZetherToken` 62,169 → 64,284, `NormalPqzToken` 52,891 → 56,088, `WrappedPqzToken` 63,423 → 65,520, `SCaaSDex` 27,957 → 32,757, `AdminLib` 3,272 → `GovernanceLib` 7,634), inits likewise, reason in `_comment`: CTR-GOV-19; `ZetherDeploy.t` `65536` → 131,072. **Gates:** size gate, whole `forge test`, `scripts/e2e-zether.sh`.

### Task T3: D1 promoted (spec §1.1-§1.4, §2.2, §2.3; G1, G2, G14; B-26, B-31; P-1 to P-7, P-15 to P-19; GD-2, GD-11)

**Files:**
- Modify: `src/governance/{GovernanceBase,GovernanceLib,GovernanceBits,IGovernance}.sol`, `src/metatx/{MetaTokenBase,NormalToken,WrappedToken,WrappedLib}.sol`, the four confidential tokens and two wrapped libraries (`_roleBits`, `use`), `src/dex/SCaaSDex.sol`, `test/v2/LinkClosure.t.sol`, `test/v2/Layout.t.sol`, `test/v2/Features.t.sol`
- Move: `test/metatx/AdminLib.t.sol`, `helpers/AdminHarness.sol` → `GovernanceLib*`
- Create: `smartcontracts/evm/legacy/governance/` with its `legacy/README.md` line, `test/v2/layout/namespaces.json`, `test/governance/GovRegulatedBits.t.sol`

**Changes:**
- `library GovernanceUse` in `GovernanceBase.sol`: `use`, the whole-shape fast path and one DELEGATECALL to `GovernanceLib.useLimited`. Five call sites renamed. `requireRole` gone.
- `GovernanceStorage` of §1.4 in full, `Counts`, `PendingGrant`, `Grant.barred`. `holderCount` reads `counts[bit].holders`. New fields inert until their task.
- `_scalarBits()`, `_scopeBits()`; per-kind masks: `NORMAL*` roles bit 1, contract-only 0, scalar bit 1, scope 0; `WRAPPED*` roles 1, 3, 4, contract-only 3, scalar 1, scope 0; `SCaaSDex` roles 11, 12, scalar 0, scope 0. `WrappedLib.initToken` takes the kind's masks, passed by `WrappedToken`, `ZetherWrappedLib.init`, `PqzWrappedLib.init`.
- `_validBits()` of `NormalToken`, `WrappedToken` without `REGULATED`, their `_init` passing `_validBits() | REGULATED` (GD-19).
- `init`: `roles.compliance` refused with bit 10; every "flags 5–8" in code becomes 5-9.
- `initHolder`, called only by `SCaaSDex.initialize`.
- DEX: `setMarket`, `setExchangeTarget`, `setListedOnly`, `setFeeSplit` under `governed`; `supportsInterface` answers `IGovernance` and `IERC165`; no "admin" left in `SCaaSDex.sol`. `DexCreated`'s last field reads `owner()`.
- `namespaces.json` and a labelled test for `scaas.token`, `scaas.governance`, `scaas.underlying`, `scaas.ua.ledger`, `scaas.metatx`: root, then each field's offset by a write and `vm.load`. `test_storageLayoutIsPinned` gains the two PQZ kinds and `SCaaSDex`.

- [ ] **Step 1: Failing tests:** `test_limitedUseIsOneDelegatecall`, `test_normalKindHasNoRateRole` (`NoSuchRole(3)`), `test_complianceWordIsBitTen`, `test_regulatedBitsRefusedOnPlainKinds` (5-9, each alone and all together), `test_regulatedBitsInvalidOnConfidentialKinds` (Zether two, PQZ two, apart), `test_validBitsHoldsNoRegulatedBit` (six kinds), `test_dexPowerRefusedInsideASettlement` (each of four), `test_dexAnswersIGovernance`, `test_dexInitHoldsBothBitsThroughInitHolder`, `test_namespaceRootsAndOffsetsArePinned`.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path 'test/{governance/*,v2/Layout,v2/LinkClosure}.t.sol'`: FAIL.
- [ ] **Step 3: Implement.** `grep` for `requireRole`, `AdminLib` in `src/` and `script/`: none but `legacy/`.
- [ ] **Step 4:** PASS; whole `forge test`; regenerate `dex_order_kat.json`; size gate after moving the baseline; log `runs/2026-11-03-governance-sizes-t3.txt`.
- [ ] **Step 5: Mutants:** `governed` off `setMarket`; `governed` off `setFeeSplit`; `use` skipping `LIMITED`; a `WRAPPED` mask equal to `NORMAL`'s; `compliance` back to bit 8; `| REGULATED` dropped from a plain kind's `_init`; `REGULATED` back in a plain kind's `_validBits()`; a field reordered in `GovernanceStorage`; `initHolder` replaced by `grantRole`.
- [ ] **Step 6:** Commit `governance T3: GovernanceUse, final storage, masks per kind, DEX guard and interface`.

**Pins, old → new:** `size-baseline.json` (B-26: `NormalToken` −1,096, `NormalZetherToken` −1,082, `NormalPqzToken` −1,058, `SCaaSDex` −1,065, `WrappedLib` −1,077, wrapped tokens 0, measured values in the commit); `test_libraryOpcodes` `WrappedLib` DELEGATECALL count 1 → measured; `dex_order_kat.json` (spec §10.4's failure, by its generator); `Factory.t` and `HederaV2.t` turn green with no move: B-26 brings `NormalToken` under 39,945, re-read here (GD-18); `Layout` new rows; `Features.t` comment "`pendingOwner` at slot + 3" stays (+3 holds, packed). **Gates:** whole `forge test`, size gate, T1 green. Typehashes: none move.

### Task T4: the enum (spec §4.1, §4.2; CTR-GOV-16; B-03; C4)

**Files:** `src/factory/{IOpenFactory,OpenFactory}.sol`, `test/v2/Factory.t.sol`, `test/governance/GovRegulatedBits.t.sol`, `test/governance/GovAttackV2.t.sol`, `clients/clientkeys/test/typed-ops.test.js` (the one client file naming the enum)

**Changes:** members 0-13 of §4.1, `RETIRED_6`, `RETIRED_7`, `NORMAL_ZETHER_REGULATED`, `WRAPPED_ZETHER_REGULATED`, `NORMAL_PQZ_REGULATED`, `WRAPPED_PQZ_REGULATED`. `deployImplementation` refuses 6 and 7 (`KindRetired(kind)`). `_enabled` stays 3. `createTokenUnregistered`'s `uint8(kind) >= NORMAL_ZETHER` stays. No node change: nothing there decodes `TokenKind`.

- [ ] **Step 1: Failing tests:** `test_everyKindIdDecodes` (0-13), `test_retiredKindsRefusedAtDeployImplementation`, `test_regulatedKindsOffUntilPublished` (`VersionUnknown`, `KindDisabled`), `test_unregisteredRefusesEveryKindFromTwo`, `test_regulatedKindPublishesOnTheSameFactory` (§"What lands"). `test_attack_aReservedKindDoesNotDecode` → `test_fixed_aReservedKindDecodes`; `test_attack_aSecondFactorysTokenIsOutsideToTheFirst` → `test_stated_…`: a second factory stays outside.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path 'test/{v2/Factory,governance/*}.t.sol'`: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** PASS, whole `forge test`.
- [ ] **Step 5: Mutants:** enum order swapped (8 and 9); `KindRetired` check dropped; `_enabled` starting with bit 8.
- [ ] **Step 6:** Commit `governance T4: real TokenKind members 0-13, 6 and 7 retired, 8-13 off`.

**Pins, old → new:** `OpenFactory` runtime in the baseline if its gate moves; any KAT holding factory bytecode by generator. **Gates:** whole `forge test`, size gate.

### Task T5: D2, what `setGrant` and `init` refuse (spec §1.4, §1.5; B-02, B-06, B-09, B-10, B-19; P-9, P-10; GD-14)

**Files:** `src/governance/{GovernanceBase,GovernanceLib,IGovernance}.sol`, `test/v2/helpers/V2Fixture.sol`, `test/governance/{GovGrant,GovAttackV2}.t.sol`

**Changes:** the check table of §1.5, every caller: word masks passed as arguments, `GrantWordRefused(bit, field)`, `(perWindow == 0) != (window == 0)` both directions, `scope` rule, `GrantBudgetRequired`, with the sentence of spec §1.5 in its NatSpec: the budget bounds spending, not the number of leaves. `RoleGranted` for a new holder (B-31). `OwnerAccountPool` in `init` and `transferOwnership`. `init` runs the renounce loop when `owner == 0`. `GrantNotNarrower` NatSpec gains field 8.

- [ ] **Step 1: Failing tests:** each `test_attack_*` below becomes `test_fixed_*`, with its positive control kept, and goes red first: `delegableHolderAddsAHolderWithNoOwnerCall`, `createdWithoutOwnerKeepsAnUnlockedMinter`, `noScalarMeansNoTotalAndNoWindow`, `aFloorBricksAPowerWithNoScalar`, `aScopeOnABuiltPowerBindsNothing`, `aPoolCanBeOwner`. New: `test_eachWordRefusedOnAScalarlessBit` (each of `min`, `max`, `total`, `perWindow`, `window`, on a wrapped kind and the DEX), `test_windowWithoutPerWindowRefused`, `test_newHolderEmitsRoleGranted`, `test_lockedMinterSurvivesNoOwner`.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path 'test/governance/*.t.sol'`: FAIL.
- [ ] **Step 3: Implement,** then the GD-14 fixture line.
- [ ] **Step 4:** PASS, whole `forge test`, T1 green.
- [ ] **Step 5: Mutants:** `_scalarBits` passed as 0; `_scopeBits` passed as 0; budget check dropped; B-06 loop dropped; pool refusal dropped in `transferOwnership`; `RoleGranted` dropped.
- [ ] **Step 6:** Commit `governance T5: setGrant refuses a word the contract does not bind; a token cannot be born unrevocable`.

**Pins, old → new:** baseline library and token rows; `dex_order_kat.json` if `SCaaSDex` bytecode moved; gas pins of `GovGas` if a row is asserted. **Gates:** whole `forge test`, size gate.

### Task T6: D2, leaves, revoke, roots (spec §1.5, §1.7; B-04, B-05, B-07, B-08, B-11, B-12, B-17, B-18; agy C-1, I-1, I-3, Claude M-7, M-8; P-11 to P-14, P-21, P-22)

**Files:** `src/governance/{GovernanceLib,IGovernance}.sol`, `test/governance/{GovGrant,GovAttackV2}.t.sol`

**Changes:** the leaf path of §1.5 with the table's checks, `owner ≠ 0`, `GrantBarred`, an expired parent refused (`GrantExpired(bit, caller)`), `maxUses` by what remains (`p.uses + t.maxUses ≤ p.maxUses`); `_narrows` by comparison, `window` equal (field 8); `_grant` over `LIMITED` bumps the epoch; the owner's apply, by either entry, writes `grantor = 0`, `grantorEpoch = 0`, `barred = false`; an owner edit changing `scope` or clearing `delegable` bumps the epoch; `GrantWindowInUse` by the one condition of §1.5, in `uint256`, skipped on a `WHOLE` holder; revoke by the owner, or by the grantor only while `roles == LIMITED` and the grantor still holds; a revoke by the owner writes `barred` before `_clear`'s early return, a non-holder included; `renounceOwnership` and `init` read `roots`; `Counts` by §1.7's table, every row, `r` read first, `_clear` reading `grantor` before it clears `r`.

- [ ] **Step 1: Failing tests:** to `test_fixed_*`, each red first: `revokedGrantorStripsAnOwnerGrantedHolder`, `parentGrantsBackALeafTheOwnerRevoked`, `deadLeavesBlockTheRenounce`, `afterRenounceALockedBitsHolderAddsHolders`, `leafKeepsAScopeItsParentLost`, `endingDelegationLeavesTheLeaves`, `changingTheWindowRefreshesTheBudget`, `aLeafsWindowIsNotNarrowed`, `narrowingBelowSpentPanicsTheLeafPath`, `wholeThenLimitedRevivesLeaves`. New: `test_ownerReadmitsABarredAccount`, one `test_counts_row<n>` for each of rows 1-11 of §1.7, reading `holders` and `roots` after it (row 4 and 5 then revoke the old root and try the renounce; a revoked leaf re-granted by the owner, both entries, then revoked to zero), `test_hasRoleMeansListed`, `test_leafThatRenouncesFirstIsBarred`, `test_expiredParentAddsNobody`, `test_exhaustedParentAddsNobody`, `test_leafMaxUsesByWhatRemains`, `test_windowChangeIntoASpentPeriodRefused` (agy I-1's sequence), `test_windowChangeAfterBothGridsPassed`, `test_wholeHolderStaleWindowRefusesNothing`, `test_expiredRootCountsUntilRevoked`.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path 'test/governance/*.t.sol'`: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** PASS; `test_refuted_*` still pass; whole `forge test`.
- [ ] **Step 5: Mutants,** one per check: the live-grantor check; `barred` set; `barred` after the early return; `barred` read; `roots` replaced by `holders`; `roots + 1` dropped on row 4; on row 5; `_clear` deciding on a stale `grantor`; `owner ≠ 0`; the parent's expiry; `maxUses` against `p.maxUses`, not what remains; the epoch bump on scope; on delegation end; on upgrade; `GrantWindowInUse`; its new-grid arm alone; the `WHOLE` skip; `window` equal; a subtraction back in `_narrows`. Add RESULTS' seven to the same log: no parent debit, no epoch bump, an edit refreshing spent, a wrapped power skipping `use`, no renounce rule, `narrows` skipping `total`, a leaf delegating.
- [ ] **Step 6:** Commit `governance T6: leaves die with their parent's right, a revoke bars, the renounce rule counts roots`.

**Pins, old → new:** baseline library row; `dex_order_kat.json` only if the DEX's bytecode moved (a library change does not move it). **Gates:** whole `forge test`, size gate.

### Task T7: D4, two calls, `termsHash`, `grantDelay` (spec §1.6, §1.9, §2.2, §2.3; CTR-GOV-04 and its Change; B-01, B-27; A20; Codex 2, 7, agy C-3, I-2, Claude I-7, M-5, M-6; P-15; GD-3)

**Files:** `src/governance/{GovernanceBase,GovernanceLib,IGovernance}.sol`, `src/factory/IFactoryToken.sol`, `src/metatx/{MetaTokenBase,NormalToken,WrappedLib}.sol`, the Zether and PQZ kinds' init, `src/dex/{SCaaSDex,ISCaaSDex}.sol`, `script/pqz/e2e.py` (`CFG`, `create`), `scaas-node/tests/e2e.rs` (`DexConfig { address owner; … }`, the comment at `:699`), `test/governance/{GovDelay,GovExamples}.t.sol` (new), `src/zether/ZetherWrappedLib.sol`, `src/pqz/PqzWrappedLib.sol` (they decode `TokenConfig`), positional `DexConfig(...)` in tests

**Changes:**
- The table of §1.6 in one body shared by `grantRole` and `setGrant`. Live pending: `eta ≠ 0`, `generation == ownerGeneration`, `now ≤ eta + grantDelay`. `acceptOwnership` and `renounceOwnership` bump `ownerGeneration`; `transferOwnership` does not. `termsHash = keccak256(abi.encode(GrantTerms))`, 0 for `grantRole`. Confirm deletes the pending and re-runs every check.
- Immediate cases: `grantDelay == 0`; `grantRole` on `WHOLE`; `setGrant` on a `WHOLE` root with `delegable` false; a pure field-by-field narrowing of a `LIMITED` root, where `0 → finite` narrows on each of `total`, `perWindow`, `validUntil`, `maxUses` and a new `window` comes with the limit it carries. Everything else two calls, a leaf the owner would make a root included.
- The owner's `revokeRole`, `renounceRole` and an immediate narrowing delete `pending[bit][account]`; a grantor's `revokeRole` leaves it. `cancelGrant(bit, account)`, owner, `GrantCancelled`; `pendingGrant` returns `live`.
- `GrantProposed(bit, account, proposer, eta, whole, terms)`, `pendingGrant`, `grantDelay()`, `lastProposedAt()`, `GrantNotReady`, `GrantTermsMismatch`, `GrantDelayTooLong` (30 days).
- `TokenConfig` gains `uint64 grantDelay`, `address rescueTo`, `uint256 maxSupply`; `DexConfig` becomes `{owner, relayerSharePpm, treasury, listedOnly, grantDelay, rescueTo}`. `ConfigFieldForOtherKind(5)` for `maxSupply` on `NORMAL*`. `init`'s arguments in one memory struct if the stack needs it; no `via_ir`.
- `acceptOwnership`, `revokeRole`, `disableFeature`, `renounceOwnership`, `renounceRole` stay at once.

- [ ] **Step 1: Failing tests** (`GovDelay.t.sol`): `test_newHolderTakesTwoCalls`, `test_eachWidenedWordTakesTwoCalls`, `test_eachNarrowedWordRunsAtOnce`, `test_confirmWithOtherTermsReverts`, `test_leafMadeARootTakesTwoCalls`, `test_grantRoleOnLimitedTakesTwoCalls`, `test_confirmBeforeEtaReverts`, `test_afterTheWindowThePendingIsDead`, `test_afterRenounceNobodyConfirms`, `test_afterTransferTheNewOwnerProposesAgain`, `test_delayZeroIsOneCall`, `test_aToBToAKillsThePending`, `test_cancelledTransferKillsNothing`, `test_revokeDeletesThePending` (the revoked, barred account is not restored by a confirm), `test_grantorRevokeKeepsThePending` (the confirm makes the account a root), `test_renounceDeletesThePending`, `test_narrowingDeletesThePending`, `test_cancelGrantLiveAndDead`, `test_pendingGrantSaysLive`, `test_finiteOnEachUnboundedWordRunsAtOnce`, `test_windowWithItsLimitRunsAtOnce`, `test_finiteToUnboundedTakesTwoCalls`, `test_delayAboveThirtyDaysRefused`, `test_dexInitHoldsBothBitsWithADelay`, `test_holderCountCountsInitOnceAndNeverAPending`, `test_lastProposedAtMoves`, `test_configFieldsFailClosedUntilBuilt`. `test_attack_setGrantMakesAnUnboundedHolderInOneCall` → `test_fixed_*`. `GovExamples.t.sol`, mocks of spec §1.9: `test_loanApprovalInABand`, `test_loanLeafDebitsItsManager`, `test_subtreeAddAndRemove`, `test_subtreeOutsideTheScopeRefused`, `test_subtreeHeadWithNoBudgetRefused`, `test_moveWithinAGroup`, `test_moveOutOfTheGroupRefused`.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path 'test/governance/*.t.sol'`: FAIL.
- [ ] **Step 3: Implement.** `cd scaas-node && ../scripts/capped cargo test -j2 --test e2e --no-run`: compiles; `python3 -I smartcontracts/evm/script/pqz/e2e.py --self-test`.
- [ ] **Step 4:** PASS; whole `forge test`; regenerate `dex_order_kat.json`; size gate; `_above64KiB` updated if a kind crossed (say so; expect the jump); log `runs/2026-11-03-governance-sizes-t7.txt`.
- [ ] **Step 5: Mutants:** `setGrant` applies at once; no `termsHash` compare; no window; no generation compare; generation not bumped at accept; not bumped at renounce; each of the three deletes dropped; a grantor's revoke deleting the pending; `0 → finite` read as a widening; `_scopeNarrows` accepting all, in the `FamilyTree` mock; a leaf edit treated as a narrowing; count at propose; DEX init through `grantRole`; the 30-day bound dropped.
- [ ] **Step 6:** Commit `governance T7: two calls within a window, terms bound, grantDelay at creation`.

**Pins, old → new:** baseline every kind and `SCaaSDex`; `dex_order_kat.json`; gas pins `MetaTxGasV2.t`, `DexGas.t` only by dispatcher drift. Layout: none (GD-2). Typehashes: none. **Gates:** whole `forge test`, size gate, T1 green, node e2e compiles.

### Task T8: D5, the leg check (spec §6.1; CTR-GOV-05 and its Change; B-15)

**Files:** `src/metatx/WrappedLib.sol` (`_addLeg`; GD-20), `test/governance/GovLeg.t.sol` (new), `test/governance/GovAttackV2.t.sol`

**Changes:** the check of §6.1 before the leg is stored, `u ≠ NATIVE`, reading the factory as `msg.sender`. `isRegisteredToken`, never `isToken`. Bits 5, 7, 8, 9 stay allowed.

- [ ] **Step 1: Failing tests:** `test_registeredForceLegRefused`, `test_registeredModerateLegRefused` (a mock kind 8 from T4), `test_unregisteredLegIsOutside`, `test_secondFactoryLegIsOutside`, `test_registeredPlainLegAccepted`, `test_pauseAndFreezeLegsStayAllowed`, `test_legCheckRunsOnEveryWrappedKind` (`WRAPPED`, Zether, PQZ, apart: `msg.sender` through two DELEGATECALLs). `test_attack_isTokenTrustsAnUnregisteredLeg` → `test_fixed_*`.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path 'test/governance/*.t.sol'`: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** PASS; `forge test --match-path 'test/{v2/Wrapped,v2/Multi,zether/ZetherWrapped,pqz/PqzWrapped}.t.sol'`; whole `forge test`.
- [ ] **Step 5: Mutants:** reads `isToken`; bit 21 dropped; bit 6 dropped.
- [ ] **Step 6:** Commit `governance T8: a wrapped kind refuses a registered leg with FORCE or MODERATE`.

**Pins, old → new:** baseline wrapped tokens and `WrappedLib` if listed; `createToken` of a wrapped kind gains one `isRegisteredToken` and one `features()` per leg at init (gas pins, if any assert it). **Gates:** whole `forge test`, size gate.

### Task T9: hybrid (spec §5; CTR-GOV-12, CTR-TOK-05; C1, C2; Claude I-4, M-9; GD-10)

**Files:** `src/governance/GovernanceBits.sol` (`WRAPPED_BITS` gains bit 1), `src/metatx/{WrappedLib,WrappedToken}.sol`, `IWrappedToken`, `src/zether/WrappedZetherToken.sol`, `src/pqz/WrappedPqzToken.sol`, `test/governance/GovHybrid.t.sol` (new), `test/v2/Layout.t.sol` and `namespaces.json`

**Changes:**
- `MINTABLE ⇔ maxSupply ≠ 0`, else `MaxSupplyInvalid()`. `initialSupply` stays refused.
- `Leg` slot a gains `bool capped`. `WrappedStorage` appends `uint256 maxSupply`; `reserve` keeps its offset.
- `mint`, `mintToUA`, `maxSupply()` on the wrapped kinds, `GovernanceUse.use` with the amount, public balance only.
- One cap, `totalSupply() + minted ≤ maxSupply`, `MaxSupplyExceeded`, on every row of §5.2: `wrap`, `wrapToUA`, `mtxWrapShield`; `mtxWrapOrder`, `uaWrapOrder` through `_sigQuote`'s callers; `mint`, `mintToUA`. The token passes `supply`, as `executeRate` does; `maxSupply` is read only when `L.capped`.
- `_requireCollateral`: the final `c < supply` only when the token is not capped: a rate fall needs no `addReserve` (C1, the owner's, CTR-GOV-12). `RateDecreaseWithDisabledLeg` stays, on a hybrid too (spec §5.3); the step, the delay, the window stay. `_quote`, `addReserve`, `payOutTo` unchanged, so `addReserve` stays refused on a disabled leg, on a hybrid too (spec §5.4).
- A hybrid is `maxSupply ≠ 0`. `disableFeature(MINTABLE)` leaves `maxSupply` and `capped`: units already minted are still unbacked, so the claim stays off, and the cap goes on binding wraps (spec §5.2).
- `mtxUnshieldUnwrap` of `WrappedZetherToken` and `WrappedPqzToken` quotes the leg before the proof, by the quote `payOutTo` picks. Zether and PQZ apart.

- [ ] **Step 1: Failing tests,** each path at the cap and one over: `test_capHolds_{wrap,wrapToUA,mtxWrapShieldZether,mtxWrapShieldPqz,mtxWrapOrder,uaWrapOrder,mint,mintToUA}`; `test_unwrapToEmptyThenInsufficientReserve`; `test_unitsTransferAfterTheReserveIsEmpty`; `test_executeRateOnAHybridShortOfSupply`; `test_rateFallOnAHybridNeedsNoAddReserve`; `test_rateFallWithDisabledLegStillRefusedOnAHybrid`; `test_executeRateNonHybridStillChecksSupply`; `test_disableMintableLeavesAHybrid` (`capped`, cap on wrap, no mint); `test_mintToTheCapStopsWraps`; `test_addReserveRefusedOnADisabledLegOfAHybrid`; `test_unshieldUnwrapShortReserveRevertsBeforeTheProof{Zether,Pqz}` (no verifier call); `test_mintableWithoutMaxSupplyRefused`; `test_maxSupplyWithoutMintableRefused`; `test_limitedMinterBindsOnAWrappedKind` (`total`, `perWindow`); `test_nonHybridWrapReadsNoNewSlot` (compares sets of slots at a fixed-rate wrap: `_totalSupply` is read by `_mint` on that path anyway, so passing `supply` adds no slot); `test_minterNeverMintsIntoAShieldedBalance`.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path test/governance/GovHybrid.t.sol`: FAIL.
- [ ] **Step 3: Implement.** Zether and PQZ kinds apart, each its own commit-sized diff in the same task.
- [ ] **Step 4:** PASS; whole `forge test`; T1 green; `test_reserveSlotIsWhereIndexersReadIt` unchanged; size gate; `_above64KiB`; log `runs/2026-11-03-governance-sizes-t9.txt`.
- [ ] **Step 5: Mutants:** each path without the cap, one at a time; the cap lifted on wraps once bit 1 is off; `addReserve` open on a disabled leg; `c ≥ supply` kept on a capped token; `c ≥ supply` dropped on an uncapped token; `RateDecreaseWithDisabledLeg` skipped on a capped token; `capped` removed so a plain wrap reads `maxSupply`; `reserve` raised by a mint; the quote moved after the proof, each kind.
- [ ] **Step 6:** Commit `governance T9: hybrid wrapped kinds, one cap on every path, no backing claim`.

**Pins, old → new:** baseline wrapped tokens; `wrap` gas pins (+ about 100: one warm read); `namespaces.json` new rows only, `reserve` unmoved; `wrap_rate_vectors.json` unchanged (a check, not a pin to move). **Gates:** whole `forge test`, size gate, `forge test --match-path 'test/{zether,pqz}/*.t.sol'`.

### Task T10: D6, rescue, `DexPuller` (spec §6.2; CTR-GOV-06, -14; A15, A16, R-16; agy I-7, M-2)

**Files:** `src/governance/{GovernanceBits,GovernanceLib,GovernanceBase,IRescuable}.sol` (`NORMAL_BITS`, `WRAPPED_BITS` gain bit 17), `src/metatx/{MetaTokenBase,NormalToken,WrappedToken,WrappedLib}.sol`, both confidential wrapped tokens, `src/dex/{DexPuller,SCaaSDex}.sol`, `test/governance/GovRescue.t.sol` (new)

**Changes:** `RESCUABLE ⇔ rescueTo ≠ 0`, `RescueConfigInvalid()`, which also refuses `rescueTo` as `this`, `UA_POOL`, `SHIELD_POOL`; always locked. `rescue(address asset)`: anyone, not on an allow-list, `nonReentrant`, one direct entry on every kind, `WrappedPqzToken` last. `WrappedLib.rescue` on `WRAPPED*`, `GovernanceLib` on `NORMAL*`. The table of §6.2, first match: `address(this)` refused; `address(0)` on every kind, by value, less a native leg's reserve, refused to a designator; `NORMAL*`, whole balance; a leg, `balanceOf ≥ reserve` before the subtraction and after the transfer, `balanceOf − reserve`; foreign, every leg's balance unchanged, ≤ 8 reads. `Rescued`. `IRescuable` as spec §6.2, so `IGovernance`'s interface id stays one; `MetaTokenBase.supportsInterface` answers it while bit 17 is set. `new DexPuller(cfg.rescueTo)`, `rescue(address token)`, 0 reverts `RescueOff()`; only `balanceOf` and `transfer`. **Not on `SCaaSDex`, `SealedBidTender`.**

- [ ] **Step 1: Failing tests:** `test_rescueForeignToken`, `test_rescueNativeLessReserve`, `test_rescueLegSurplusOnly`, `test_rescueAliasOfALegRefused`, `test_rescuePastAShortLeg`, `test_rescueReentrantAssetRefused`, `test_rescueOwnTokenRefused`, `test_rescueToDesignatorRefusedNative`, `test_rescueOffWithoutTheBit`, `test_rescueOnNormalTakesAll`, `test_rescueNativeOnNormal`, `test_rescueLegShortfallNamesItsError`, `test_rescueToThisOrAPoolRefusedAtInit` (three rows), `test_tokenAnswersIRescuableOnlyWithTheBit`, `test_pullerRescueWholeBalance`, `test_pullerRescueOff`, `test_pullerRescueCannotSpendAllowances`, `test_interfaceIdIsOneOnDexAndToken`.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path test/governance/GovRescue.t.sol`: FAIL.
- [ ] **Step 3: Implement,** `WrappedPqzToken` last.
- [ ] **Step 4:** PASS; whole `forge test`; regenerate `dex_order_kat.json`; size gate; `_above64KiB`; log `runs/2026-11-03-governance-sizes-t10.txt`.
- [ ] **Step 5: Mutants:** post-check dropped; `nonReentrant` dropped; the leg-alias read dropped; `reserve` not subtracted; `rescueTo` writable.
- [ ] **Step 6: All four sets, once, contract work done:** `script/pqz/at-set.sh <set> test` for `n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`, `n2816-kmax65536`, one run in this work tree, `PqzSet.sol` restored; `WrappedPqzToken`'s size per set in the log.
- [ ] **Step 7:** Commit `governance T10: rescue to an immutable rescueTo, DexPuller.rescue, four sets green`.

**Pins, old → new:** baseline; `dex_order_kat.json`; `namespaces.json` no move (GD-2). **Gates:** whole `forge test`, four sets, size gate, T1 green.

### Task T10b: identity by UA (owner 2026-11-04; CTR-GOV-01 Change; spec `2026-11-04-governance-ua-identity.md` §1, §2, §4)

**Files:** `src/governance/{GovernanceBase,GovernanceLib,IGovernance}.sol`, the six kinds and their libraries (`MetaTokenBase`, `NormalToken`, `WrappedToken`, `WrappedLib`, Zether and PQZ kinds and libraries where they touch governance), `src/dex/{SCaaSDex,ISCaaSDex,DexPuller}.sol`, `src/factory/IFactoryToken.sol` (`TokenConfig.owner`), every governance test and fixture, `test/v2/layout/` pins, `script/pqz/e2e.py`, `scaas-node/tests/e2e.rs` (`DexConfig.owner`).

**Changes:** every governance identity `bytes32` (spec §1, §4): storage keys and owner words, `Grant.grantor`, `PendingGrant.proposer`, entries, views, events, `init` and the configs. `_govSubject()` replaces `_caller()` for every governance check and every power's entry: the native id of `msg.sender`, or `IGovernanceRouter(GOV_ROUTER).subject()` when `msg.sender == GOV_ROUTER` (an immutable; the router itself is T11: until then a mock router in tests and `GOV_ROUTER` from the release config, `address(0)` meaning "no router on this chain"). `UA_POOL`, `SHIELD_POOL`, 0 refused as owner and holder. Contract-only bits: the holder must be a native id whose address has code. Payout destinations stay `address`.

- [ ] **Step 1: Failing tests:** a derived UA is owner and grants through the mock router; a native caller's id is its padded address; the router's subject is read only while `msg.sender == GOV_ROUTER`; a router subject 0 is refused; a contract-only bit to a derived UA refused; every existing governance test on `bytes32`.
- [ ] **Step 2: Implement.** Storage layout renewed (owner and pendingOwner a slot each; `grantDelay`, `ownerGeneration`, `lastProposedAt` packed in their own), layout pins regenerated.
- [ ] **Step 3:** whole `forge test`, `--isolate`, size gate, `zether-cross`, `clientkeys`, docs; `dex_order_kat.json` by its generator; `e2e.rs` compiles; `e2e.py --self-test`.
- [ ] **Step 4: Mutants:** the router branch dropped; the router subject read when `msg.sender != GOV_ROUTER`; native id computed from `tx.origin`; `UA_POOL` accepted as owner; the contract-only check skipped for a derived UA.
- [ ] **Step 5:** Commit `governance T10b: every governance identity is a UA`.

**Pins, old → new:** baseline every kind, `SCaaSDex`, `GovernanceLib`; layout pins; `dex_order_kat.json`; gas pins only by the wider words, each with its reason. **Gates:** the runner, all four PQZ sets once.

### Task T11: `GovernanceHolder` and the relay rule (spec §3; CTR-GOV-15; B-14, B-20, B-21, B-22; Codex 3, 4, Claude M-4, M-14, agy M-2; C4, C9; GD-6, GD-7)

**Files:**
- Create: `src/governance/{GovernanceHolderBase,GovernanceHolder,GovernanceHolderFactory}.sol`, `test/governance/{Holder,HolderPqMsig,HolderTypehash}.t.sol`, `test/v2/layout/GovernanceHolder.json`
- Modify: `test/metatx/MsgSenderLint.t.sol` (`FILES` gains the holder), `test/governance/GovAttackV2.t.sol` (`HolderSketch` gives way to the real holder), `test/v2/Layout.t.sol`

**Changes:**
- `GovernanceHolderBase is UAMetaTxBase`, own namespace `scaas.holder`, root `0x86d8592a976ab91a258d36c502084dc93b41b1785adce6f7419d9b3d4ee9be00`, the immutables `FACTORY`, `IMPL`, `CLONE_CODEHASH`: `operator`, `pendingOperator`, `generation`, `proposeOperator`, `acceptOperator`, a `generation` bump on every `acceptOperator`, `_execute`, `uaExecute`, `uaBatch` overridden to refuse (`MtxSelectorNotAllowed`), so `mtxExecute`, `mtxBatch`, `executeMetaTransaction` fall too; `mtxCancelNonce`, `uaCancelNonce` stay. `supportedModes() == 0x03`, no `receive`. Domain `("SCaaS GovernanceHolder", "1", chainId, holder, chain_uid)`.
- `GovernanceHolder`, the closed table of §3.2: 21 ops, `cancelGrant` included, each one direct entry starting with the `_subject()` check (`acceptOperator` exempt, against a non-zero `pendingOperator`, on all three forms), one `mtx<Op>`, one `ua<Op>`, each taking `generation` then `target`, refusing `GenerationStale` first, on the helper of GD-7 and `_namedCallUA`; `setGrant`'s `terms` nested. 42 typed structs, `<Op>` and `UA<Op>`, `generation` after `from`. `mtxCancelNonce`, `uaCancelNonce` take none.
- `GovernanceHolderFactory`: the shape of `SmartKeyAccountFactory`; salt `keccak256(abi.encode(operator, salt))`; `predict`, `deploy`, `HolderDeployed`, `IMPLEMENTATION()`, `chainUid()`; `initialize(bytes32)` by `FACTORY` only (`NotFactory`), once (`AlreadyInitialized`); operator 0 refused (`ZeroOperator`); a pool, the factory, the implementation or a padded address whose code hash is `CLONE_CODEHASH`, the holder itself included, refused there and at `proposeOperator` (`OperatorInvalid`); a token and an undeployed clone pass, disclosed (spec §3.1).
- Relay rule: stated in T17, enforced in T13: no governance selector on `mtxSelectors()` or `_uaAllowed` of a governed contract.

- [ ] **Step 1: Failing tests** (`Holder.t.sol`): `test_eachOpByOperatorDirect`, `test_eachOpByMtx`, `test_eachOpByUa` (one row per op over the 21), `test_strangerRefused`, `test_replacedOperatorsEnvelopeRefusedNonceUnspent`, `test_rotationTwoCalls`, `test_proposeZeroCancels`, `test_secondProposeOverwrites`, `test_acceptWithoutPendingRefused`, `test_acceptOperatorByThePendingOnEveryForm` (direct, `mtx`, `ua`), `test_acceptByAnyoneElseRefused`, `test_rotationKillsPresignedEnvelopes`, `test_aToBToALeavesTheEnvelopeStale` (`GenerationStale`, nonce unspent, on `mtx` and `ua`), `test_generationIsASignedWord`, `test_operatorRefused` (0, each pool, the factory, the implementation, the holder, another clone; at `initialize` and `proposeOperator`), `test_stated_aTokenOperatorIsInert`, `test_stated_aRotationToAnInertOperatorNeverCompletes`, `test_initializeOnlyByTheFactoryOnce`, `test_cancelNonceTakesNoGeneration`, `test_cancelGrantThroughTheHolder`, `test_saltBindsTheOperator` (B-20), `test_repeatDeployReturnsTheAddress`, `test_noReceive`, `test_targetReentersRefused`, `test_noCodeTargetReverts`, `test_nestedTermsRoundTrip`, `test_changedTargetRefused`, `test_replayAcrossHoldersRefused`, `test_starvedRelayerUAVerifyGasNonceUnspent`, `test_eachGenericPathRefusesEveryOp` (`mtxExecute`, `mtxBatch`, `executeMetaTransaction`, `uaExecute`, `uaBatch`; B-14). `test_attack_theHoldersOpIsReachableAsABytesBlob` → `test_fixed_*`. `HolderPqMsig.t.sol`: `test_pqMsigGrantsARoleThroughUaGrantRole`, a real PQ `msig` at threshold through the registry, which the attack round only read; `test_msigBelowAcceptedThresholdInert`; `test_msigAtTheBoundPaysNoOwnFee` (B-30, stated: fee 0 or another payer). `HolderTypehash.t.sol`: `test_<Op>TypehashIsPinned` for all 42, literal hashes from `cast keccak` over the strings, with `SetGrant`'s string of §3.2 verbatim.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path 'test/governance/Holder*.t.sol'`: FAIL.
- [ ] **Step 3: Implement.** Base first, then one group of §3.2 at a time.
- [ ] **Step 4:** PASS; `R-*` as `test_refuted_*` now on the real holder; `forge test --match-path test/metatx/MsgSenderLint.t.sol`; whole `forge test`; size gate (a baseline entry only if over a limit).
- [ ] **Step 5: Mutants:** `_execute` override removed; `uaExecute` override removed; `uaBatch` override removed; the `_subject()` check dropped on one op; `acceptOperator` without pending; `acceptOperator` under the operator check; `generation` not bumped; `generation` not compared; `generation` left out of the words; the `CLONE_CODEHASH` compare dropped; the operator out of the salt; `target` unsigned; `_mtxRule` row wrong for `setGrant`.
- [ ] **Step 6:** Commit `governance T11: GovernanceHolder, typed entries only, operator in the salt`.

**Pins:** all new; **existing typehashes must not move** (`*TypehashIsPinned` green unchanged). `dex_order_kat.json`: unaffected. **Gates:** whole `forge test`, `forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'`, size gate.

### Task T12: holder rows in `clientkeys` and `typed_ops.json` (spec §3.2; GD-9)

**Files:** `clients/clientkeys/src/evm.js` (`TYPED_OPS`, `OP_BUILDERS`), `clients/clientkeys/scripts/{typed-ops-vectors.mjs,typed-ops-cast-check.mjs}`, `clients/clientkeys/test/typed-ops.test.js`, `smartcontracts/vectors/typed/typed_ops.json` (regenerated), `smartcontracts/evm/test/metatx/TypedOps.t.sol`, `clients/zether-prover/tests/typed_ops.rs` (must still pass; it reads its own rows)

**Changes:** domain kind `holder`, the 42 rows, `generation` a named field of each, `GrantTerms` nested, `CancelNonce` and `UACancelNonce` gain `holder`. Spec S8 says the rows are written against whichever of this and `msig-nested` lands first (§"Branches"): every value comes from the generator, nothing by hand.

- [ ] **Step 1: Failing tests:** `npm test` rows over the new structs, type strings equal to `HolderTypehash.t.sol`'s; `test_holderRowsRunOnARealHolder` in `TypedOps.t.sol` (selector, calldata, digest, `from` recovered, op executed).
- [ ] **Step 2:** `cd clients/clientkeys && ../../scripts/capped npm test`: FAIL.
- [ ] **Step 3: Implement,** regenerate `typed_ops.json`, run the cast check.
- [ ] **Step 4:** PASS; `../../scripts/capped forge test --match-path test/metatx/TypedOps.t.sol`; `cd clients/zether-prover && ../../scripts/capped cargo test -j2`; generator twice, the file does not move.
- [ ] **Step 5: Mutants:** a field order swapped in one type string; `GrantTerms` moved before the primary type's references; a row on the wrong domain.
- [ ] **Step 6:** Commit `governance T12: holder rows, typed_ops.json regenerated`.

**Pins, old → new:** `typed_ops.json` rows added, **no existing row changes** (`git diff` shows additions and the `CancelNonce` domains only). **Gates:** `clientkeys`, `TypedOps.t`, `zether-prover`, vectors twice.

### Task T13: the selector audit (spec §10.1; CTR-GOV-11; GD-6)

**Files:** `test/governance/SelectorAudit.t.sol`, `test/vectors/selector_audit.json` (new)

**Changes:** on the six kinds, `SCaaSDex`, `DexPuller`, `GovernanceHolder`: read each artifact's ABI from `./out`; every non-view external is in a pinned row with one class: `BIT(n)`, `OWNER`, `HOLDER_OWN`, `OWN_BALANCE`, `SIGNED`, `FACTORY`, `PERMISSIONLESS(reason)`. An unclassified or moved selector fails. For every `BIT` and `OWNER` row a stranger's call reverts with its named error. No governance selector in `mtxSelectors()` or `_uaAllowed` of a governed contract. `initHolder` has no external entry on any contract.

- [ ] **Step 1: Failing test:** with an empty pin, `test_everySelectorIsClassified` lists every row.
- [ ] **Step 2:** Classify by reading each entry. `PERMISSIONLESS` needs its reason; `rescue`, `addReserve`, `wrap` are checked against spec §7.
- [ ] **Step 3:** `test_everySelectorIsClassified`, `test_strangerRevertsOnEveryGatedRow`, `test_noGovernanceSelectorIsRelayable`: PASS.
- [ ] **Step 4: Mutants,** each red: one ungated entry added to `NormalToken`; `grantRole` added to `mtxSelectors()`; a `BIT` row reclassified `PERMISSIONLESS`; `mint` with its `use` removed.
- [ ] **Step 5:** Commit `governance T13: selector audit on every governed contract, no governance op on an allow-list`.

**Pins:** new. **Gates:** `forge test --match-path 'test/governance/*.t.sol'`.

### Task T14: `governance_bits.json`, every language (spec §1.2, §1.8, §4.3, §5.5; B-34; Codex 10; G33; GD-9)

**Files:**
- Create: `test/governance/GovBitsVector.t.sol`, `smartcontracts/vectors/governance/governance_bits.json`
- Modify: `smartcontracts/evm/foundry.toml` (GD-6)

| Language | Seat | Test |
|---|---|---|
| JS `clientkeys` | `src/evm.js` export | `test/typed-ops.test.js` or a new `test/governance-bits.test.js` |
| Rust `ua-rs` | `src/lib.rs`: `governance_bit(bit)` over `include_str!` of the file | `tests/vectors.rs` |
| C `ua-c`, C++ `ua-cxx`, Qt `ua-qt`, Dart `ua-dart-frb` | wrappers of `ua-rs`: one call returning the row as JSON, as their `kindName`: `clients/ua-qt/src/ua_kinds.rs`, `clients/ua-dart-frb/rust/src/api/ua.rs` | `tests/test_vectors.py`, `tests/`, `tests/tst_ua.qml`, `test/vectors_test.dart` |
| Python `ua-py`, Go `ua-go`, C# `ua-cs`, Dart `ua-dart` | a constant table of `bit → name, type`, sentences read from the file by the app | `tests/test_vectors.py`, `ua_test.go`, `Scaas.Ua.Tests/VectorTests.cs`, `test/vectors_test.dart` |

`zether-prover` is no wallet: no reader.

**Changes:** the file carries `bit → name → type → one disclosure sentence`, written by a forge test from `GovernanceBits` and `_roleBits()`, `WRITE_BITS=true`. Rows 0-21; 13, 14 "unused"; 15, 16 "reserved"; bit 1 two sentences, plain and hybrid (§5.5 verbatim, its two brackets marked: the mint clause while bit 1 is set, the rate clause while bit 3 is set, keyed on `maxSupply() ≠ 0`); bit 5 two, public and confidential kinds; bit 7 one, spec §1.2's, verbatim: what the pause stops and what stays open; 8 and 9 "no holder, parameters", naming `complianceRegistry()`; the delegable holder's "can add unlimited leaves at once, sharing a remaining budget of N"; the leg sentence of §1.8 step 6 (B-34); the once-only "`grantDelay` delays an address, never who controls it" (CTR-GOV-15). The word for bits 128-255 is `bitLabel`'s, no row (CTR-GOV-10's Change, owner 2026-11-04).

- [ ] **Step 1: Failing tests:** `test_bitsVectorEqualsTheConstants`, then one reader test per row of the table, each comparing every row of the file and failing on a missing bit.
- [ ] **Step 2:** Each package's own command: FAIL (no file, no reader).
- [ ] **Step 3: Implement** the writer, the file, `ua-rs`, its wrappers, the four native tables.
- [ ] **Step 4:** Each package's gate step of the T18 runner: PASS. `dotnet build-server shutdown` after C#.
- [ ] **Step 5: Mutants:** a bit renamed in `GovernanceBits`: the writer test goes red; a sentence edited in the file: the rewrite moves it (`git diff --exit-code` in `vectors-check`); one native table with a wrong type: its test goes red.
- [ ] **Step 6:** Commit `governance T14: governance_bits.json, read by every language`.

**Pins:** new. **Gates:** `clientkeys`, `ua-rs`, `ua-py`, `ua-go`, `ua-cs`, `ua-c`, `ua-cxx`, `ua-dart`, `ua-dart-frb`, `ua-qt`.

### Task T15: node rows, guard, allow-lists (spec §3.6, §12.7; NODE-JOB-01, -19, -20; GD-8)

**Files:** `scaas-node/src/typed.rs` (`TYPED`, `PLAIN`, `NESTED`, `domain_name`), `scaas-node/src/guard.rs` (`Rule`, `rule_of`, `Facts`, `allowed`, `the_plain_rows_are_pinned`), `scaas-node/src/config.rs`, `scaas-node/src/addresses.rs`, `scaas-node/node.example.toml`, `scaas-node/tests/e2e.rs`

**Changes:**
- `typed.rs`: contract kind `holder`, `domain_name` → `"SCaaS GovernanceHolder"`; `GrantTerms` in `NESTED`; 42 `TYPED` rows; `HOLDER_FACT` and `("deploy", HOLDER_FACT, "bytes32 operator,bytes32 salt")` in `PLAIN`; `ALL` gains `holder` (only `CancelNonce` uses it); `UACancelNonce` moves from `T` to `T` plus `holder`.
- `guard.rs`: `Rule::Holder`: target's code hash is one of the clone hashes of `holder_factories`, each `IMPLEMENTATION()` read once, and `chainUid()` equals `chain.chain_uid`; `Rule::HolderFactory`: `w.to` is one of `holder_factories`. `check_named`'s relay branch today runs only `require_bound` on the inner target: when the inner call is a `holder` row it runs `Rule::Holder` too (agy I-5). None configured: refused. A lane stays no holder.
- `generation`, spec §12.7: a named `uint64` field in `args` of every `holder` row but `CancelNonce` and `UACancelNonce`, apart from `origin.generation`. The struct is built from it; missing, `422 BAD_PAYLOAD`. At lease `Rule::Holder` reads `generation()`, uncached, unlike `chainUid()`, on both paths; a job whose field differs is refused `HOLDER_GENERATION_STALE` before simulation.
- `HEX_ARGS_REFUSED` unchanged. No existing job's shape changes.
- Untrusted decode: `GrantTerms` is flat, one depth; `require_bound` as the other kinds.

- [ ] **Step 1: Failing tests:** `typed_ops_kat_every_entry` over the new rows; `a_holder_op_runs_only_on_a_clone_of_the_chains_implementation`, `a_holder_generic_entry_is_no_row`, `a_token_governance_entry_is_no_row`, `a_chain_without_holder_factory_refuses_holder_jobs`, `holder_deploy_targets_only_the_factory`, `a_holder_op_relayed_through_the_router_checks_the_inner_target`, `a_second_holder_factory_is_a_config_row`, `a_holder_job_without_generation_is_bad_payload`, `a_stale_generation_is_refused_by_name` (direct and relay, nothing sent); `the_plain_rows_are_pinned` gains `deploy`; ignored e2e `holder_grant_role_relayed_at_fee_zero_on_anvil`.
- [ ] **Step 2:** `cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test -j2 typed`: FAIL. The 6 GB run only with nothing else heavy.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `CAPPED_MEM=6G ../scripts/capped sh -c 'cargo clippy -j2 --all-targets -- -D warnings && cargo test -j2'`; `../scripts/capped cargo test -j2 --test e2e -- --ignored --test-threads=1`.
- [ ] **Step 5: Mutants:** the code-hash check dropped; the same on the relay branch; the `chainUid` check dropped; a generic `uaExecute` row added on `holder` (`a_holder_generic_entry_is_no_row` red); `Rule::HolderFactory` allowing an unconfigured factory; the `generation()` read dropped; the read cached.
- [ ] **Step 6:** Commit `governance T15: holder rows, target by clone code hash, deploy row, allow-lists equal`.

**Pins:** rows new; `submit.rs` literal selector pins unmoved. **Gates:** `cargo-scaas-node`, `node-e2e-anvil`.

### Task T16: deploy, release figures, the reset's inputs (CTR-GOV-19 and T0's result; spec S0, S8, §12.10; NET-EVM-06's Change; GD-4, GD-12)

**Files:** `smartcontracts/evm/script/DeployBase.sol` (`GovernanceHolderFactory` by CREATE2, JSON key `governance_holder_factory`; `DEPLOY_WRAPPED` path; `_requireReleaseGas` NatSpec figures), `smartcontracts/evm/test/helpers/DeployHarness.sol`, `test/governance/GovDeploy.t.sol` (new), `smartcontracts/scripts/deploy.sh` (`CHAIN_CODE_LIMIT`, comments), `pqz-core/nethermind/chain/patch-chainspec.py` (`--testnet-reset`: `RESET` gains `maxCodeSize` `0x20000`, and `eip7954TransitionTimestamp` is removed from `params`, owner 2026-11-03; its `unexpected diff` check allows exactly that removal; self-check rows), `pqz-core/nethermind/chain/e2e.py`, `pqz-core/nethermind/chain/RUNBOOK.md` (a new section for the reset: not executed; the EIP list of the 2026-10-21 section is a record and stays), `scaas-node/tests/{e2e,e2e_hedera}.rs` anvil flags where a kind above 64 KiB deploys, `smartcontracts/evm/runs/2026-11-03-governance-deploy-gas.txt`

**Changes:** the chainspec of the next reset follows arm C of T0: every Amsterdam key of `runs/2026-10-21-testnet-reset-2.2.0.sh` but `eip7954TransitionTimestamp`, `maxCodeSize` `0x20000`, with the init limit T0b read in the RUNBOOK section. That is NET-EVM-06's Change. `--testnet-reset` still refuses every chain but 7622; 22776 stays the owner's. Figures from `size-baseline.json`, no literal in code but the NatSpec line. Simulated run as `runs/2026-11-01-typed-signing-deploy-gas.txt`, profile `scaas-testnet`, `DEPLOY_ZETHER=true`, `DEPLOY_WRAPPED=true`, plus the PQZ kinds: regular + state and × 1.05 per kind, against 200 M. The reset itself is the controller's: this task leaves a tool and a runbook section, and runs nothing on the SCaaS testnet.

- [ ] **Step 1: Failing tests:** `test_deployWrappedPath`, `test_holderFactoryDeployedAndGated` (`_gate`), `test_everyKindsReleaseFitsTwoHundredMillion` (each baseline runtime through `_checkReleaseGas` at 200 M), `patch-chainspec.py --check` rows: `maxCodeSize` set, `eip7954TransitionTimestamp` gone, every other Amsterdam key kept, the removal refused without `--testnet-reset` and on any other chain.
- [ ] **Step 2:** `../../scripts/capped forge test --match-path 'test/{governance/GovDeploy,ua/UADeploy,zether/ZetherDeploy}.t.sol'`: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** PASS; `scripts/e2e-zether.sh`; `cargo test -j2 --test e2e_hedera -- --ignored`; the simulated run committed.
- [ ] **Step 5: Mutants:** `_requireReleaseGas` skipped for one kind; a release gate at the wrong key of the baseline; `patch-chainspec.py` leaving `eip7954TransitionTimestamp` in; removing a second key.
- [ ] **Step 6:** Commit `governance T16: every kind has a deploy path, figures against the 200 M block, the reset's inputs`.

**Pins, old → new:** `_requireReleaseGas` NatSpec (`NormalToken` 37,228 B = 73.7 M, `WrappedZetherToken` 62,169 B = 111.9 M, `WrappedPqzToken` 63,423 B = 113.8 M → measured). **Gates:** `GovDeploy`, `UADeploy`, `ZetherDeploy`, `e2e-zether`, `e2e_hedera`.

### Task T17: docs, decisions, status (spec §12, C6)

**Files, each change a line, the spec holds the text:**
- Create: `docs/contracts/governance.md`, from spec §1, §2, §3, §4.1, §5, §6, §7. Tags: BUILT what T3-T16 built; SPECIFIED §4.3, §4.4; PLANNED the regulated implementations, `MODERATE`, `RECORD`, family rows. Table of what a wallet reads (§1.8). The msig table of §3.5 with its status.
- `docs/contracts/token-wrappers.md` §12.2: CTR-TOK-22 rows, Administration bullet, CTR-TOK-05, -06, -10, -21, -24, -25, hybrid rows, the `scaas.admin` lines, the test plan's invariants; CTR-TOK-24's gate text and the Size row of `docs/contracts/README.md` gain the ceiling and the list.
- `docs/contracts/asset-suite.md`: §12.3 CTR-AS-03, §12.4 CTR-AS-07, §2.1, §2.2, §2.3, §2.4, §2.6, §2.7, I1, I5, A7, A15, CTR-AS-02, CTR-AS-09, §10. **§12.1 CTR-AS-17 in its own commit, on the owner's word.**
- `docs/contracts/dex.md`, `docs/contracts/README.md` §3, `architecture.md`: §12.5. `tender.md`: no word (§12.6). `zether.md` CTR-ZTH-47 and its reserve invariant, `pq-zero-knowledge.md` its two escrow lines: §12.6, apart. `metatx.md`, code comments in `MetaTxBase`, `SigCheck`, `_uaMove`: §12.8.
- `docs/node/job-api.md`: §12.7, GD-8's `deploy` row and config key, `HOLDER_GENERATION_STALE` in the error table, the operator note on `generation`. `docs/networks/evm.md`: §12.10: the Forks row, the code size row with T0b's init limit, the anvil line, the release table, `CHAIN_CODE_LIMIT`, the 119,753 B figure as the gate's; NET-EVM-06's Change, in the doc and in the register.
- `docs/decisions.md`: GD-1 to GD-20 in full, C7 to C11 of the spec; Change lines with commits; the two proposed Change lines of spec §12.9 only on the owner's word; the Change of NET-EVM-06; CTR-GOV-19's status with T0's and T0b's verdicts; CTR-GOV-02's status. `docs_check` C3: a new anchor needs its register entry in the same commit. Every rule keeps its id; `normative:` of a CTR-GOV entry moves to `contracts/governance.md` where the doc holds it.
- `README.md` §4: "What exists today" and "The design (PLANNED)" rewritten to the built state, the regulated parts PLANNED; `docs/README.md` lines 57, 147.
- `AGENTS.md`: **`CALL_TABLE` in the Node section → `typed.rs` `TYPED` / `PLAIN`**, and `guard.rs` for the rule per kind. The Size gate bullet: ceiling 131,072 B, the list, and "`WrappedPqzToken` is within about 1 KB of the stop line" goes (CTR-GOV-19). The Node row of the map gains nothing.
- The spec's status line. `TODO.md` with this commit, never alone.

- [ ] **Step 1:** Write each change. Bytes and figures quoted from T2-T16's logs.
- [ ] **Step 2:** `python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check`: 0 errors, rc read directly. `python3 scripts/docs_check.py resolve CTR-GOV-04`.
- [ ] **Step 3:** Commit `governance T17: docs/contracts/governance.md, the Changes of spec §12, status`.

### Task T18: the gate runner

**Files:** Create `smartcontracts/evm/runs/2026-11-03-governance-gates.sh`, in the form of `git show ua8-soroban:smartcontracts/evm/runs/2026-10-31-ua8-soroban-gates.sh`: not a copy, it sets `P`, `LOGEXT=log`, `STEPS`, `FAMILIES`, `NEW_TESTS`, then sources `2026-10-27-metatx-split-gates.sh`. Modify the base only for a step it lacks.

**Interfaces:**
- `P=2026-11-03-governance`
- `STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes docs clientkeys vectors-check ua-rs ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt cargo-zether-prover cargo-scaas-node node-e2e-anvil node-e2e-hedera e2e-zether named-tests summary"`. `sizes` runs `size_gate.py --self-test` first and prints `_above64KiB`; `vectors-check` gains the `typed_ops.json` and `governance_bits.json` writers with `git diff --exit-code`, `WRITE_KAT` of `dex_order_kat.json` likewise. `cargo-scaas-node` under `CAPPED_MEM=6G`, the one allowed exception, with nothing else heavy.
- `FAMILIES="ua-rs ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt"`. No Soroban step: nothing here touches it.
- `NEW_TESTS`: every name of T1-T16 in its pass form, `forge|forge|…`, `cargo-scaas-node|cargo|…`, `node-e2e-anvil|cargo|…`, `clientkeys|node|…`.

- [ ] **Step 1:** Write the runner and the names, from the diff, not from this plan.
- [ ] **Step 2: Self-check the guard:** remove one forge PASS line from a scratch copy of the logs; `NAMED_TESTS_LOG_DIR=<scratch> smartcontracts/evm/runs/2026-11-03-governance-gates.sh --only named-tests` exits non-zero.
- [ ] **Step 3: Run,** nothing else heavy, one at a time, foreground; read each step's `rc` from its log, a pipe hides it. On a failure: fix in the owning task's files, commit, re-run; a step done at the same commit with a clean tree is skipped. On resume read the existing logs first.
- [ ] **Step 4:** Commit the runner and `2026-11-03-governance-summary.txt` only: `governance T18: closing gates at <sha>`.

### Task T19: whole-branch review and fix wave

- [ ] **Step 1:** Dispatch the whole-branch review (superpowers:requesting-code-review) over `main..governance`, one reader who gets the code and the spec, not this plan's conclusions. Focus: the Review Focus list; §1.6's table cell by cell against the code; `Counts` against §1.7's table, row by row; the two generations; the cap on every path of §5.2; `use` on every power (a power reached by `hasRole` alone is a P0 here); the same-class rule: a fix to one path is checked on the other wrapped kinds, Zether and PQZ apart; the node's allow-lists in both directions; `docs_check` clean; no absolute path, secret or email in a run log.
- [ ] **Step 2: Fix wave:** each finding fixed with a failing test first, in its owning task's files; commits `governance fix: …`. A finding that changes a §0 row, a ruling or a GD goes to the controller.
- [ ] **Step 3:** Re-run T18 (steps whose inputs changed re-run at the new commit); commit the summary.
- [ ] **Step 4:** Re-review of the fixes only; repeat Steps 2-3 until "ready". Everything cryptographic stays `UNAUDITED`; this is a review by one AI reader, named as such.

### Task T20: report and the owner's go

- [ ] **Step 1:** Report to the controller: commits per task; step verdicts; the sizes of T3, T7, T9, T10; `_above64KiB`; T0's verdict; deploy figures against 200 M; the review verdict and what the fix wave changed; what stays open. State what ran and its result; a failure with its output.
- [ ] **Step 2:** Ask for the owner's go to merge `governance` into `main`, by PR (`main` is PR-only). **No merge, no push before it.** A push is a separate step after a secret scan of the outgoing diff, by explicit SHA.

---

## Part D7 (spec §6.3, S12; CTR-GOV-07 and its Change): separate, not started here

**Starts after `ua8-soroban` merges into `main`.** It touches `smartcontracts/soroban/contracts/{token,dex}`, which that branch also changes, so starting earlier is rework. It lands before the Soroban freeze, on its own branch and plan, with its own gates: `smartcontracts/scripts/build.sh soroban`, the local Protocol 30 network, the public Stellar testnet run last.

Its content, recorded here so nothing is lost: `set_admin` (records a pending), `accept_admin`, `renounce_admin` (clears the pending in the same step), `admin() → Option<Address>`, `Error::NoAdmin`, on the Soroban token and DEX; the four semantics of §6.3; persistent entries per `(bit, holder)` when roles come (B-25). The other families stay in their own rounds: NEAR and Algorand apart, TON, Solana, Cosmos, Aptos, Sui before `make_immutable`.

## Branches: what merges first, what conflicts

**State at `d1132a40`.** `msig-nested` forked from `ua8-soroban` at `159d267e`: it is 9 commits on that fork, `ua8-soroban` is 12 past it, so landing `msig-nested` carries part of `ua8-soroban`. Dry merges (`git merge-tree --write-tree`) of `governance` with each, and of the two with each other, are clean today. That says little: the prototype barely touches their files. The overlaps below appear as this plan builds.

**Order.**

1. **`ua8-soroban` into `main` first.** It is the furthest along (closing-gate summary and whole-branch review on its branch), `msig-nested` sits on its fork, and Part D7 waits for it.
2. **`main` into `governance`,** at a task boundary, on the owner's word, then regenerate `dex_order_kat.json` and `typed_ops.json` and run the gates of the next task. **Before T14 if it can be:** from T14 on the build edits the same files (table below). If the word comes later, the same conflicts land on T18 instead; nothing blocks.
3. **`msig-nested` and `governance`: neither waits for the other.** `msig-nested` is a proposal: EVM registry prototype only, no client, node or vector landed, no plan. `governance` does not stop for it. Whichever reaches its closing gates second merges the first and regenerates. Default expected: `governance` first, since `msig-nested` has its whole client and node round ahead.

| Overlap with `msig-nested` | If `msig-nested` lands first | If `governance` lands first |
|---|---|---|
| `IUARegistry.MemberSig` `{index, members, sig}`, `InnerSig`; `UAKinds.uaAuthCall`; `MtxPipelineLib` | every `ua<Op>` selector of the holder comes out of the generator on the new shape; `HolderPqMsig.t.sol`'s fixture one field | its selector count grows by the holder's 21 `ua*` names; the same one field |
| `scaas-node/src/typed.rs` `NESTED` | adjacent lines: `InnerSig`, `MemberSig` beside `GrantTerms` | the same |
| `test/v2/DexKat.t.sol`, `dex_order_kat.json`, `test/metatx/TypedOps.t.sol` | textual conflict with T3, T7, T12; take either side, regenerate | the same |
| `_membersWorst` recursive | `docs/contracts/governance.md`'s table: counts stay, worst figures move (`slhdsa128s` 11,958,373) | it updates that table |
| `size-baseline.json` | re-measure: +140 B on `WrappedPqzToken`, +136 B on `WrappedZetherToken`. No gate consequence now | the same |
| `docs/decisions.md`, `AGENTS.md` (its spec still says `guard.rs` `CALL_TABLE`) | merge; T17's fix stands | it must follow |

| Overlap with `ua8-soroban` (files both change) | Task |
|---|---|
| `script/DeployBase.sol` (`_checkGen1Kinds`, another hunk), `test/helpers/DeployHarness.sol`, `test/ua/UADeploy.t.sol`, `test/ua/UARegistryUA8.t.sol` | T2, T16 |
| `clients/ua-rs/src/lib.rs`, `clients/ua-c/src/lib.rs`, and the vector tests of `ua-c`, `ua-cxx`, `ua-py`, `ua-qt`, `ua-dart`, `ua-dart-frb` | T14: additive, a new function and a new test beside theirs |
| `scaas-node/src/config.rs`, `scaas-node/node.example.toml` | T15: one key each, `holder_factories`. `typed.rs` and `guard.rs` are not touched there |
| `docs/node/job-api.md`, `docs/contracts/accounts.md`, `docs/decisions.md`, `TODO.md` | T17 |

No contract under `src/` overlaps. S12 is Part D7.

**`token-core`:** research on size, cut from `8da45c39`, with source spikes. **Not merged here and not planned** (owner 2026-11-03). Its `size-options.md` stays where it is until the owner reads it. When size work comes it touches the lines of T3, T5, T9, T10, and the T1 pin must still pass.

**Asset-suite stream, regulated implementations, family rounds:** on top of this, later.

## Open questions for the owner

None blocks a task; each has the default the plan follows.

1. **CTR-AS-17's Change (§12.1):** apply as drafted? Default: T17 leaves it out of the main docs commit and holds it for the word. The rest of T17 proceeds.
2. **`main` into `governance` after `ua8-soroban` lands:** go? Default: wait for the word, keep building.
3. **`maxCodeSize` `0x20000`** is the controller's proposal, and at a 200 M block 119,753 B is the deploy gate's bound. Default: keep it; no contract comes near.
4. **C2 on the hybrid; GD-8 the holder factory's `deploy` row:** controller calls. Default: as written.
5. **C7, an expired root counts until it is revoked:** the definition the owner asked for, with its reason. An exact count needs a holder list or a stored expiry. Default: as written. Spec §12.9 records it and bit 5's sentences as proposed Change lines; T17 leaves them out of the register until the word.
6. **`RateDecreaseWithDisabledLeg` on a hybrid (spec §5.3):** kept, so a hybrid with a disabled leg cannot lower a rate. Default: kept.
