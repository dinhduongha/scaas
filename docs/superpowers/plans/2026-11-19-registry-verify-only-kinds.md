# Registry verify-only kinds and the line of generations: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-19):** PLANNED, nothing built. **UNAUDITED**: the verify-only verifiers, the three-state mapping, the
fallback and the PQZ home over N generations are designs; this round builds them, Fable reviews the built round (Task 21),
and the external audit reviews them later.

**Goal:** Build on EVM a `UARegistry` that forms a line of up to 16 generations, lets a later generation carry a
predecessor's single-key kind **verify-only** with its own precompile-backed verifier (fallback to the holder's verdict),
moves the PQZ attachment to a per-record PQZ home, takes the chain's per-transaction gas cap as a constructor parameter,
and carries the factory, deploy, node, SDK, client and doc changes of the spec, in one round.

**Architecture:** One registry code serves every generation. A single walk `holderOf(ua) → (holder, kind, pqzHome)`
replaces every predecessor read. Writes are always authenticated by the generation that holds the signer's record (a
`write` flag through the library's signature paths); only the three consumer entries may take a verify-only verifier, which
maps its precompile to {1, 0, `PqNoAnswer`} and falls back to the holder's entry on no answer. Bounds (`msigBound`,
`_msigDebit`, the new hard bound) read `txGasCap()`.

**Tech Stack:** Solidity 0.8.37 / Foundry 1.8.5 (Amsterdam), Python 3 deploy scripts, Rust 1.97.1 (`scaas-node` on alloy
1.6, `scaas-sdk`, `ua-rs`), the client libraries `clientkeys`, `ua-{py,go,cs,dart}` and the ua-rs bindings.

**Spec:** [`specs/2026-11-19-registry-verify-only-kinds.md`](../specs/2026-11-19-registry-verify-only-kinds.md),
revision 4 (§n below are its sections). Every task's requirements include the spec sections it names; this plan does not
repeat the spec's rules.

## Global Constraints

- Branch **`multi-gen-verify`**, cut from **`bls-multi` after its library split** (`UARegistryRegLib`: every `register*`,
  `keyUa`, `pqzHolder`, `msigBound`, `pqzProof`; `UARegistryCoreLib`: authorization and verify; `UARegistryAuxLib`: key
  writes after registration; `UARegistry`: views, walks) **and its Task 8** (the stored-path dispatch: `_single`'s
  `uint160(cfg) == 0` branch and the fourth appended word `_cfg(0x0121)`) have landed there. Pre-freeze. Merge order:
  PR A (gas) → `bls-multi` → this round, each via `ua-rs-sign`.
- Kind word per slot: `verifier | cap << 160 | verifyOnly << 224 | keyForm << 225`; readers use `_capOf(cfg) =
  uint64(cfg >> 160)` and `_registrable(cfg) = uint160(cfg) != 0 && cfg >> 224 & 1 == 0` (§2, §14 N12 list).
- `MAX_GENERATION = 16`; `generation = predecessor.generation() + 1`; EIP-712 version = the generation's decimal number
  (gen 1 `"1"`, gen 2 `"2"`: today's typehash and domain pins do not move).
- Views: `holderOf(bytes32) → (address holder, uint16 kind, address pqzHome)`, `pqzHomeOf(bytes32) → address` (third word),
  `kindHome(uint16) → address`, `verifierOf(uint16) → address`, `verifyOnly(uint16) → bool`, `txGasCap() → uint64`; error
  `UAVerifyOnly(uint16 kind)`. Native-space ids answer `(0, 0, 0)` / `kindOf = 0` / `isRegistered = false` without a walk.
- `txGasCap`: immutable constructor parameter after `verifyBudget_` (owner C1); `verifyBudget ≤ txGasCap < 2^64`
  (owner P17); replaces `UARegistryCoreLib.TX_GAS_CAP`. Tests construct with `1 << 24` unless they test the cap.
- Errors kept: `UAKeyData(0x0120)` (registration over the hard bound), `UAMsigSlots(n)` (`updateMsig` over it),
  `UAPqzHolder(ua)` (PQZ debit bound), `UAConfig(kind)` / `UAConfig(0)` (constructor), `UAVerifyGas`, `UAKeyNotCached`,
  `UAUnauthorized`, `UAKindDisabled(0x0142)`.
- Deploy refusals by name: `GEN_NOT_LATEST`, `GEN_DEPTH`, `GEN_WALK_MISMATCH`, `GEN_KEY_FORM_IMPOSSIBLE <kind>`,
  `GEN_VERIFY_ONLY_NO_PRECOMPILE <kind>`, `GEN_PQZ_OMITTED`, `GEN_PQZ_DEBIT_BOUND <kind>`, `GEN_TX_CAP_UNKNOWN`,
  `GEN_TX_CAP_MISMATCH`; node errors `UA_VERIFY_ONLY`, `UA_WRONG_GENERATION`, `UA_KEY_NOT_CACHEABLE`.
- Constants measured by the round, pinned with old → new in the commit: `UA_CONSUMER_RESERVE_GAS`, `MSIG_REGISTER_GAS`,
  `PQZ_KEY_WRITE_GAS` (owner P15), each verify-only verifier's explicit precompile gas limit (owner P20).
- **Where the walk lives (owner Y1):** the generation walk's logic is in `UARegistryCoreLib`; `UARegistry`'s `holderOf`,
  `kindHome`, `verifierOf`, `pqzHomeOf` and the forwarding readers are thin views that DELEGATECALL into it through
  `_libView` (as today's library readers). The selectors stay on the registry: the frozen interface does not change.
- Eligible verify-only kinds this round: ML-DSA `0x0130`, `0x0131`, `0x0134` only (§2, §7); every other kind waits for its
  edge-class list and vectors.
- Rule ids `CTR-UA-58` … `CTR-UA-72` are final (Task 19: checked free, no renumbering; normative in `docs/contracts/accounts.md` §1.8.1).
- New source files carry `SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0`. English. No absolute or `/tmp` path in
  any committed file. No gas price 0, no block limit of ours; nothing assumes 2^24 outside a test constant.

## Review Focus

Inputs the spec implies that no spec test row names; each has its test in the owning task.

1. **Two verify-only carriers on one line.** Gen 1 holds an `mldsa65` record, gen 2 carries `mldsa65` verify-only with an
   accept-all stand-in, gen 3 carries it verify-only with a correct verifier. A consumer check on gen 3 uses gen 3's
   verifier only; a bad signature stays refused (gen 2 is never asked). Test in Task 5.
2. **An inner `msig` under a verify-only reader.** A gen-2 `msig` names a gen-1 `msig` whose members are `mldsa65`; gen 2
   carries `mldsa65` verify-only with an accept-all stand-in. The inner `msig` is forwarded whole to gen 1 (R6); a bad
   member signature stays refused on the consumer path and on every write. Tests in Tasks 4 and 5.
3. **A verifier return that is neither `0` nor `1`.** A stand-in verify-only verifier returning `abi.encode(2)`, two words,
   or empty data with success: the registry falls back to the holder, never accepts. Test in Task 6.
4. **A fake predecessor that loops or lies about its generation.** A contract answering `predecessor() == itself`, or
   `generation()` of 0 or ≥ 16, or a chain of 16 fakes: the constructor's walk stops at `MAX_GENERATION` and refuses
   `UAConfig(0)`; no unbounded loop. Test in Task 2.
5. **A node job that needs the fallback's gas.** A consumer job whose simulation passes only with more than
   `verifyBudget` gas (the fallback path): the node sends it with the simulated limit up to the chain's `txGasCap`, never
   clamped to `verifyBudget`, and never reports `dead` on `UAVerifyGas` while a resend with the estimate may land. Test in
   Task 16.

---

## How to run this plan

- **Branch and worktree.** `multi-gen-verify` in `.claude/worktrees/multi-gen-verify`, cut from `bls-multi` once its library split
  and Task 8 are committed there (check `git log bls-multi` for both and that `UARegistryRegLib.sol` exists). Before Task 1
  re-read the split's final function placement; every file path below uses it. Agents commit locally; they do not merge
  or push.
- **Fresh worktree inputs** as real directories: `smartcontracts/evm/lib` (`scripts/evm_libs.sh install`, then `check`),
  `clients/clientkeys/node_modules` (`npm ci --ignore-scripts`), `smartcontracts/algorand/out`.
- **Order.** 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 (contracts, in order: each builds on the previous one's interfaces); 9 after 6;
  10 after 9; 11 after 8; 12 after 2; 13 after 7, 8 and 11; 14 beside 13; 15 after 13; 16 after 3 (rows) and 13 (deploy
  fields); 17 and 18 after 15; 19 after 17 and 18; 20 last before 21.
- **Tests first** in every code task: the test, red; the code; green. Every refusal test changes one thing from a valid row
  (positive control first). Mutants per task, each killed by a named test; mutant scripts and `step | commit | rc | counts`
  summaries in `smartcontracts/evm/runs/<round-start-date>-multi-gen-verify/` (owner C2; full output in git-ignored
  `.log` files, no absolute paths).
- **Gates per task** (AGENTS.md "round of several tasks"): the task's own suites at the default set, its mutants, every pin
  it moves (gas, size, typehash, layout, selector audit: old → new in the commit). Contract tasks that do not touch
  `src/pqz/` also run `script/pqz/at-set.sh others sensitive` and `others modules` when they move a set-sensitive pin.
  Task 8 changes `src/pqz/PqzStateLib.sol`: a **PQZ change** under AGENTS.md, so the round gate runs every forge directory
  at all four sets (`at-set.sh others test`), not only the set-sensitive tests (owner C3: AGENTS.md's PQZ rule). Each commit body says "full matrix pending
  (round gate)".
- **Size gate per contract task:** `T=$(mktemp -d); forge build src --sizes --json > "$T"/sizes.json; python3
  ../../scripts/size_gate.py "$T"/sizes.json size-baseline.json`. Record `UARegistry`, `UARegistryCoreLib`,
  `UARegistryRegLib`, `UARegistryAuxLib`, `OpenFactory` and each new verifier before → after in the commit. **STOP on a T-1
  line** (library 35,694 B, plain 35,286 B, release 35,386 B, module 35,570 B; `scripts/size_gate.py`): report the sizes
  and wait; no module split and no size lever without the owner's word. A baseline move needs its reason in the commit.
  Room on `bls-multi` after its split (its `size-baseline.json`, commit `383d1e2f8`; re-read before Task 1, the figures move
  with `bls-multi`'s remaining tasks):

  | Contract | Form | Runtime | T-1 line | Room | Grown by |
  |---|---|---|---|---|---|
  | `UARegistry` | plain | 33,293 B | 35,286 B | 1,993 B | Tasks 1, 2 (constructor rules, flags, probes), 3 (thin views), 5 – 6 (consumer path), 8 (PQZ views) |
  | `UARegistryCoreLib` | library | 15,737 B | 35,694 B | 19,957 B | Tasks 3 (the walk, owner Y1), 4 – 7 (write flag, consumer branch, fallback, bounds) |
  | `UARegistryRegLib` | library | 30,157 B | 35,694 B | 5,537 B | Tasks 1, 3 (step 1, `_identify`), 7 (`msigBound`, `pqzHolder`), 8 (`pqzProof`) |
  | `UARegistryAuxLib` | library | 35,417 B | 35,694 B | 277 B | Tasks 3 (`cacheExpandedKey`), 8 (the PQZ positions): **expected size stop** |
  | `OpenFactory` | plain | 34,999 B | 35,286 B | 287 B | Task 12 (the env walk): **expected size stop** |

  `UARegistry`'s 2 KB must cover the constructor rules (which run in the constructor and stay there) and one thin view
  per walked selector; every line of walk logic goes to `UARegistryCoreLib`. Where Task 8 or Task 12 crosses its line, the
  task stops at Step 4 with the sizes; the option of moving the PQZ positions' logic to `UARegistryCoreLib` (which has the
  room) is the owner's to choose, not the implementer's.
- **Heavy commands** through `scripts/capped`, foreground, never inside `timeout`; the node suite alone with
  `CAPPED_MEM=6G`. No background shells, no sleep loops, no `anvil` left running. `at-set.sh` rewrites
  `src/pqz/PqzSet.sol`: one run per worktree, restored after.
- **Commits:** one per task, staged by explicit path (`git commit --only -- <paths>`), trailers as the session gives
  them, no `Signed-off-by`.
- **Owner rulings on the plan** (2026-11-19, all as proposed): C1 – C7, marked *owner Cn* and listed at the end.

---

### Task 1: `txGasCap` constructor parameter (owner X1)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistry.sol` (constructor `uint64 txGasCap_` after `verifyBudget_`, immutable,
  view `txGasCap()`; `UAConfig(0)` unless `verifyBudget_ ≤ txGasCap_`), `smartcontracts/evm/src/ua/IUARegistry.sol`
  (`txGasCap()`), `smartcontracts/evm/src/ua/UARegistryCoreLib.sol` and `UARegistryRegLib.sol` (`TX_GAS_CAP` removed;
  `_msigDebit` and `msigBound` read `IUARegistry(address(this)).txGasCap()`), `smartcontracts/evm/script/DeployBase.sol`
  (`_deployUARegistry` passes `vm.envUint("TX_GAS_CAP")`, required, no default; `TX_REGULAR_GAS_CAP` reads the same value),
  every `new UARegistry(` site (16 files under `test/` and `script/`)
- Test: create `smartcontracts/evm/test/ua/UARegistryTxCap.t.sol`

- [ ] **Step 1: Failing tests:** `test_txGasCap_view` (returns the argument), `test_txGasCap_belowBudget_UAConfig0`
  (`verifyBudget = 12 M`, `txGasCap = 11 M` reverts `UAConfig(0)`), `test_msigBound_readsTxGasCap` (an `updateMsig`
  target accepted at `1 << 24` reverts `UAMsigSlots(n)` on a registry built with `txGasCap` 1 M below its need),
  `test_msigDebit_readsTxGasCap` (a PQZ-eligible `msig` registration accepted at `1 << 24` reverts `UAPqzHolder` at the
  smaller cap), `test_deploy_txGasCapRequired` (in `test/ua/UADeploy.t.sol`: no `TX_GAS_CAP` env, the deploy reverts).
- [ ] **Step 2: Run red:** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path
  'test/ua/{UARegistryTxCap,UADeploy}.t.sol'`.
- [ ] **Step 3: Implement**; update the 40 construction sites with `1 << 24`.
- [ ] **Step 4: Run green:** Step 2, then `../../scripts/capped forge test --match-path 'test/ua/*'` and the
  `test/pqz/helpers` users (`--match-path 'test/pqz/*'`); size gate.
- [ ] **Step 5: Mutants:** `_msigDebit` with the literal `1 << 24`; `msigBound` with the literal; the constructor check
  removed. Each red on its Step 1 test.
- [ ] **Step 6: Commit** `evm: registry txGasCap constructor parameter (X1)`.

### Task 2: kind word flags, constructor rules, the line (§2, §11.1, P11, M6)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistry.sol` (`KindConfig{uint16 kind; address verifier; uint64 cap; bool
  verifyOnly; uint8 keyForm}`, bits 224 / 225; `_capOf`, `_registrable`; the constructor rules of §2: the `⇔` rule for
  single-key kinds, `msig` / `0x0142` never flagged (M6), key form `1` refused where the home's `verifierOf(kind)` has
  `PRECOMPILE() ≠ 0` (N8), a verify-only verifier with `PRECOMPILE() == 0` refused (P11), `KEY_FORM()` equal to bit 225,
  `_groupInPredecessor` by `kindHome(j) != 0`, `0x0142` exempt; `generation = p.generation() + 1`, `MAX_GENERATION = 16`,
  the bounded walk of predecessors: these run in the constructor and stay in `UARegistry`; the thin views `kindHome`,
  `verifierOf` (`_libView` into the library), `verifyOnly` (a read of the local word); N12 masking at `_verifierCall`,
  `kindEnabled`, `_listedHere`, `requireAuthorized`, `_derived`), `smartcontracts/evm/src/ua/UARegistryCoreLib.sol`
  (`kindHome`'s recursion and `verifierOf`'s word read, owner Y1; N12 masking), `UARegistryRegLib.sol`,
  `UARegistryAuxLib.sol` (N12 masking at every site of the spec's §14 list, `_consent`'s
  `_notCached(_cfgKind(), …)` and `_single`'s `uint160(cfg) == 0` included), `smartcontracts/evm/src/ua/IUARegistry.sol`
- Test: create `smartcontracts/evm/test/ua/UARegistryLine.t.sol` (helpers: a three-generation fixture
  `_line3(bool[3] pqz)` and a stand-in verifier `VerifyOnlyStandIn` with settable `PRECOMPILE()`, `KEY_FORM()` and
  answer); modify `test/ua/UARegistry.t.sol` (T-REG-4 rows)

**Interfaces:**
- Produces: `UARegistry.KindConfig` (five fields), `kindHome`, `verifierOf`, `verifyOnly`, `_capOf`, `_registrable`
  (internal helpers in a shared place both the registry and the libraries read: `UAStore` or `UAKinds`, beside today's
  word readers), the library entries `UARegistryCoreLib.kindHome(uint16)` and `verifierOf(uint16)`, the fixture `_line3`
  used by Tasks 3 – 8.
- Size: `UARegistry` grows by the constructor rules and two thin views (expected the larger part of its 1,993 B room;
  record it, since Tasks 3, 5, 6 and 8 need the rest); `UARegistryCoreLib` by `kindHome` (small).

- [ ] **Step 1: Failing tests:** T-REG-4 changed: `test_gen2_predecessorKind_withoutFlag_UAConfig`,
  `test_gen2_flagOnUnknownKind_UAConfig`, `test_gen1_flag_UAConfig`, `test_flagOnMsig_UAConfig`,
  `test_flagOn0142_UAConfig` (M6), `test_msigAnd0142_reenabled_notRefused` (M6), `test_keyForm1_homeHasPrecompile_UAConfig`
  and `test_keyForm1_throughMiddleVerifyOnly_readsHome` (N8), `test_verifyOnly_noPrecompile_UAConfig` (P11),
  `test_keyForm_mismatch_UAConfig`, `test_groupAcrossLine_UAConfig` (a gen-3 kind whose group gen 1 enables);
  `test_generation_isPredPlusOne`, `test_depth17_UAConfig0`, `test_eip712Version_isGenerationDecimal` (gen 3 `"3"`);
  `test_n12_flaggedWord_capAndRegistrable` (a flagged word: `verifyCap` equals the cap, nothing reverts `UAVerifyGas`,
  `kindEnabled` true, `_registrable` false); Review Focus 4: `test_fakePredecessor_selfLoop_UAConfig0`,
  `test_fakePredecessor_generationOutOfRange_UAConfig0`.
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path 'test/ua/{UARegistryLine,UARegistry}.t.sol'`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** Step 2; every `test/ua/` suite; `test/v2/layout/` (no storage change); size gate.
- [ ] **Step 5: Mutants:** one per N12 site (the unmasked read put back; at least `_verifierCall`, `_single`, `_identify`,
  `_notCached` via `_consent`); the `⇔` rule without the single-key scope; the impossible-form check on the predecessor
  instead of the home; `_groupInPredecessor` on `kindEnabled`.
- [ ] **Step 6: Commit** `evm: registry kind flags, line constructor rules, MAX_GENERATION (§2, §11.1)`.

### Task 3: the one walk, forwarding readers, refusals, probes (§3, §11.1, §11.3 W3, M4, P12)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistryCoreLib.sol` (owner Y1: the walk's logic: `holderOf` three words per
  §11.1, `pqzHomeOf` as its third word, each forwarding reader of §11.1 reading at `holderOf`'s holder, forwarding
  `expandedKeyOf`, a verify-only kind's list views forwarded to `kindHome`), `smartcontracts/evm/src/ua/UARegistry.sol`
  (thin views `holderOf`, `pqzHomeOf` and the forwarding readers, each `_libView(address(UARegistryCoreLib), sel, 0)`;
  the native-space shortcut on `kindOf` / `holderOf` / `isRegistered` before the library call; `_listedHere` false for a
  verify-only kind; the constructor probes of §11.3 on every predecessor of the walk: `holderOf(0)`, `kindHome(0)`,
  `verifierOf(0)`, `verifyOnly(0)`, `pqzHomeOf(0)`, `txGasCap()`, `expandedKeyOf(0)`, plus today's three),
  `UARegistryRegLib.sol` (step 1 of every `register*`: `_registrable`, then `UAVerifyOnly(kind)`; `_identify` local for a
  single-key kind, P12), `UARegistryAuxLib.sol` (`cacheExpandedKey` of a verify-only kind reverts `UAVerifyOnly`),
  `IUARegistry.sol` (`UAVerifyOnly`, `holderOf`, `pqzHomeOf`)
- Test: `smartcontracts/evm/test/ua/UARegistryLine.t.sol`

**Interfaces:**
- Produces: `holderOf(bytes32) → (address, uint16, address)` on the registry (thin) and
  `UARegistryCoreLib.holderOf(bytes32)` (the walk, an external library entry `_libView` reaches; library-internal callers
  in Tasks 4 – 8 use an internal `_holderOf(bytes32)`), `pqzHomeOf`, `UAVerifyOnly(uint16)`.
- Size: `UARegistryCoreLib` takes the walk (expected ≈ 1 – 3 KB of its 19,957 B room [estimate]); `UARegistry` one thin view
  per walked selector (≈ 40 – 80 B each [estimate]: a selector entry and a `_libView` call); `UARegistryRegLib` step 1 and
  `_identify`; `UARegistryAuxLib` only `cacheExpandedKey`'s refusal (≈ 30 – 60 B of its 277 B).

- [ ] **Step 1: Failing tests:** `test_holderOf_ownRecord`, `test_holderOf_threeGenerations` (gen-1, gen-2, gen-3 records
  read through gen 3), `test_holderOf_miss_zero`, `test_holderOf_pqzHome_thirdWord` (both fixtures of §11.2 (a), (b)),
  `test_holderOf_oneCallPerGeneration` (§11.2 (g), M4: four generations all enabling `0x0142`, gas of a miss ≤ 4 × the
  pinned per-hop figure, the library DELEGATECALL included), `test_holderOf_viewOverhead` (the thin view's gas over the
  library entry's, pinned: the spec's "a few hundred gas" checked), `test_nativeSpace_noWalk_noStore` (every registration form with a native-space id refused,
  nothing stored; the views answer without a call: P5), `test_readers_forwardByHolder` (each reader of §11.1 on a gen-1
  record through gen 3 equals gen 1's answer), `test_expandedKeyOf_forwards`, `test_register_verifyOnly_UAVerifyOnly` (all
  four forms), `test_cacheExpandedKey_verifyOnly_UAVerifyOnly`, `test_lists_verifyOnly_forwardToHome`,
  `test_identify_singleKey_noWalk` (P12: gas of a single-key registration independent of depth),
  `test_msig_alreadyRegistered_acrossLine`, `test_keyInUse_acrossLine`, `test_probe_missingView_UAConfig0` (one
  predecessor stand-in per missing view, eight rows).
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path 'test/ua/UARegistryLine.t.sol'`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** Step 2; every `test/ua/` suite; gas pins that move (`UAGas`, `UARegistryNestedGas`), old →
  new; `at-set.sh others sensitive`; size gate.
- [ ] **Step 5: Mutants:** `holderOf` filling `pqzHome` from the newest instead of the oldest enabling generation;
  `pqzHomeOf` as a second recursive walk (the gas test); the native-space shortcut removed; step 1 order swapped
  (`UAVerifyOnly` after another check); `_identify` without the local-only rule kept walking (gas test).
- [ ] **Step 6: Commit** `evm: holderOf walk, forwarding readers, UAVerifyOnly, predecessor probes`.

### Task 4: writes are the holder's (W1, M1, N2)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistryCoreLib.sol` (`_sigOk` / `_msig` / `_memberOk` / `_portableOk` / `_single`
  take `bool write`, default the write side: every internal caller passes `true`, only `requireAuthorized`,
  `requirePortable`, `requirePortableApp` and `_portable` under them pass `false`; on a write a derived member goes
  `UAStore.via(holderOf(member), …)`; `_single` on a write forwards to `holderOf(ua)` whenever `!_registrable(cfg)`;
  `_accepted` / `_msigBytes` from `holderOf`), `UARegistryRegLib.sol` (`_consent`), `UARegistryAuxLib.sol` (the PQZ and
  KEM writes)
- Test: create `smartcontracts/evm/test/ua/UARegistryVerifyOnlyWrites.t.sol`

- [ ] **Step 1: Failing tests** (§7 (e), the N1 accept-all write tests; gen 2 carries `mldsa65` verify-only with an
  accept-all `VerifyOnlyStandIn`; each a positive control with a good signature first, then the bad one):
  `test_writes_acceptAll_registrationPop_msigWithGen1Members`, `_acceptMembership`, `_updateMsig`,
  `_setPqzKey_singleKey`, `_setPqzKey_msigHeldHere`, `_setPqzKey_msigHeldInPredecessor`, `_setPqzScopedKey_*` (same three),
  `_setKemKey_msig`: each bad signature stays refused (`UAPoP` / `UAUnauthorized`); Review Focus 2:
  `test_writes_innerMsig_forwardedWhole`. (M1's PQZ-home configuration is Task 8's `test_m1_pqzHome_singleKey_setPqzKey`.)
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path 'test/ua/UARegistryVerifyOnlyWrites.t.sol'`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** Step 2; `test/ua/UARegistry{Membership,MsigUpdate,Nested,Pq,UaPortable,Portable,PortableApp}.t.sol`,
  `test/ua/{PqzKeyVersions,PqzScopedKeys}.t.sol`; gas pins of the write paths, old → new; size gate.
- [ ] **Step 5: Mutants:** the default flipped to `false`; one internal caller passing `false` (one mutant per write
  entry); `_memberOk` on a write via `address(this)`; `_single` testing `uint160(cfg) == 0`.
- [ ] **Step 6: Commit** `evm: member and signer writes checked by the holder (W1, M1)`.

### Task 5: the consumer path (§4)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistry.sol` (`_authorized`, `_derived`, `_memberOk`: own verifier where the kind
  is verify-only here, else the holder directly; `requireAuthorized`'s `UAKeyNotCached` branch on `holderOf`'s kind;
  `requirePortable` / `requirePortableApp` by §4's table; key bytes and entry per §4 "Key bytes", key form `1` from the
  holder's `expandedKeyOf`; the walk read by a static self-call `IUARegistry(address(this)).holderOf(ua)` (plan choice C8, spec
  proposal P21; owner Y1: no walk logic in `UARegistry`)), `UARegistryCoreLib.sol` (`_portable` / `_single` / `_memberOk` verify-only branch from consumer
  entries only; `_notCached` on `holderOf`'s kind; failed predecessor reads re-raise `UAVerifyGas`)
- Test: create `smartcontracts/evm/test/ua/UARegistryVerifyOnly.t.sol`

- [ ] **Step 1: Failing tests:** one per row of §4's table (signer, own `msig` member at either level, inner `msig` held
  elsewhere, `requirePortable`, `requirePortableApp`, the stored paths, a predecessor's `msig` forwarded whole);
  `test_kindNotCarried_goesToHolderDirectly` (three generations, §7 (f): gen 2's accept-all never asked);
  Review Focus 1: `test_twoVerifyOnlyCarriers_readerUsesOwn`; `test_memberKind_fromHolderOf`;
  `test_keyForm1_incompleteCache_UAKeyNotCached`; `test_failedRead_UAVerifyGas`; `test_pop_neverCheckedByLater`.
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path 'test/ua/UARegistryVerifyOnly.t.sol'`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** Step 2; every `test/ua/` suite; gas pins, old → new; size gate.
- [ ] **Step 5: Mutants:** a hand-off to `predecessor` instead of the holder; the verify-only branch taken for a kind not
  carried here; `requirePortableApp` falling back through `requirePortable` with the derived purpose; the member's kind
  read locally.
- [ ] **Step 6: Commit** `evm: consumer entries verify verify-only kinds, else the holder directly (§4)`.

### Task 6: three-state call and fallback (§5, P10, M7)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UAStore.sol` (a verify-only call next to `capped`: the same gas rule, cap, hold and
  `UAVerifyGas`, then exactly one word `1` accepts, exactly one word `0` refuses, any revert or any other return ⇒
  fallback), `UARegistry.sol` and `UARegistryCoreLib.sol` (the fallback to the holder's entry of §4's last column, under
  the holder's hold; the hold on every verify-only call, the group kinds' portable path included, P10)
- Test: `smartcontracts/evm/test/ua/UARegistryVerifyOnly.t.sol`

- [ ] **Step 1: Failing tests:** stand-ins that answer `1`, `0`, revert `PqNoAnswer`, revert empty, run out of gas at the
  cap, return empty with success, return two words, return `abi.encode(2)` (Review Focus 3): `1` accepts, `0` refuses with
  no fallback, every other case falls back (good signature accepted by the holder, bad refused); `test_gasBelowCap_UAVerifyGas`
  (no fallback bought below the cap); `test_groupKind_verifyOnly_holds` (P10); `test_fallback_entry_perPath` (each entry of
  §4's last column, the caller's `auth` unchanged).
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path 'test/ua/UARegistryVerifyOnly.t.sol'`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** Step 2; every `test/ua/` suite; gas pins, old → new; size gate.
- [ ] **Step 5: Mutants:** a return of `2` read as accept; any revert read as refuse (no fallback); fallback on word `0`;
  the hold dropped on the group kinds' path.
- [ ] **Step 6: Commit** `evm: verify-only three-state call and fallback to the holder (§5, M7)`.

### Task 7: the bounds (P9, M2, M10)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistryCoreLib.sol` (`_slotCap`: a verify-only member at this cap plus its reads,
  a member not carried here at the holder's cap plus one hand-off (N3); the hard bound = max(consumer mode, write mode)
  ≤ `txGasCap`, §4; constants `UA_CONSUMER_RESERVE_GAS`, `MSIG_REGISTER_GAS`, `PQZ_KEY_WRITE_GAS` with their measurement
  comment), `UARegistryRegLib.sol` (`msigBound` and the registration bound: `UAKeyData(0x0120)` at registration,
  `UAMsigSlots(n)` at `updateMsig`; `pqzHolder` / `_msigDebit` with `w` the fallback worst, `UAPqzHolder`),
  `UARegistry.sol` (constructor: the single-key fallback against `_msigDebit`'s bound per verify-only kind where `0x0142` is
  on the line, `UAConfig(kind)`, M10 d)
- Test: create `smartcontracts/evm/test/ua/UARegistryHardBound.t.sol`

- [ ] **Step 1: Measure** the three constants (`forge test --isolate`, the dearest case of each write; intrinsic and
  calldata excluded as §4 counts them separately) and write them with the figures in the test's pin.
- [ ] **Step 2: Failing tests** (P9 refusal tests): `test_treasury_mldsa65x3_t2_fits` (registration and `updateMsig`),
  `test_mldsa87x2_t2_registration_UAKeyData0120`, `test_mldsa65x3_t3_registration_UAKeyData0120`,
  `test_updateMsig_toOverBound_UAMsigSlots`, `test_bound_isMaxNotSum` (a structure whose two modes each fit and whose sum
  does not is accepted), `test_writeMode_dearestOfThree` (a structure that fits `updateMsig`'s constants but not
  `MSIG_REGISTER_GAS`'s is refused), `test_acceptMembership_oneSlot`; M2: `test_treasury_withPqzKey_UAPqzHolder`
  (registration and `setPqzKey`), `test_mldsa44x2_pqzKey_fitsAtDefaultSet`, `test_msigDebit_wIsFallbackWorst`
  (a single-key holder held in gen 1, kind verify-only in gen 2); M10 d:
  `test_constructor_verifyOnlyFallback_overDebitBound_UAConfig` (a stand-in cap that pushes `mldsa87` over the bound),
  `test_constructor_debitCheck_skippedWithout0142`.
- [ ] **Step 3: Run red:** `../../scripts/capped forge test --match-path 'test/ua/UARegistryHardBound.t.sol'`.
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run green:** Step 3; `test/ua/{UARegistryMsigUpdate,UARegistryNestedGas,UARegistryPqzBound,UARegistryCoreLibMsig}.t.sol`;
  `at-set.sh others sensitive` (the debit bound reads `PQZ_DEBIT_MIN_GAS` per set: the M2 rows must hold at each set as
  the spec's numbers say: `mldsa44 ×2` fits at `n2304-kmax4096` and `n2048-kmax1024`, refused at the other two); gas pins;
  size gate.
- [ ] **Step 6: Mutants:** sum instead of max; the write mode on `updateMsig`'s constants only; `_msigDebit` with the
  write-mode `w`; the consumer reserve dropped; the M10 d check on the reader's numbers instead of the fallback.
- [ ] **Step 7: Commit** `evm: hard bound by txGasCap, consumer reserve, PQZ debit at the fallback worst (P9, M2, M10)`.

### Task 8: the PQZ home over N generations (§11.2, P7, P8, M1, M5)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistry.sol` (`_pqzHost` per UA, the PQZ views by §11.2's one rule, `0x0142`
  list views on this generation's own list, M5), `UARegistryAuxLib.sol` (`_host`, `_away`, `_scopedFrom`, `_pqzRecord`,
  `_pqzNext`, `_kemHash`, `_registerKeyMessage`, `registrationOf`'s patch, per §11.2's table), `UARegistryCoreLib.sol` /
  `UARegistryRegLib.sol` (`pqzProof` with the line-wide `keyOwner` walk; A5-I1 (3) by `kindHome(0x0142)`),
  `smartcontracts/evm/src/pqz/PqzStateLib.sol` (`_auditorChecks`: `kindHome(0x0142) != 0`). The PQZ positions read the
  walk through `_holderOf` (the library internal reached by `UARegistryCoreLib`, or `IUARegistry(address(this)).holderOf`
  from `UARegistryAuxLib`). Size: `UARegistryAuxLib` has 277 B: if Step 4's size gate crosses its T-1 line, STOP and report
  (see "Size gate per contract task").
- Test: create `smartcontracts/evm/test/ua/UARegistryPqzHome.t.sol`; modify `test/pqz/PqzAuditor.t.sol`

- [ ] **Step 1: Failing tests:** §11.2 (a) – (e), (g) – (h): `test_pqzHome_a_gen1With_gen2Without_gen3With` (gen 2 built
  directly, as under the owner override), `test_pqzHome_b_gen1Without_gen2With_gen3With`, `test_pqzHome_c_residualPinned`,
  `test_pqzHome_d_scopedListsAndLatest`, `test_pqzHome_e_auditorChecks_lineWide` (in `PqzAuditor.t.sol`),
  `test_0142List_perGeneration_stablePositions` (M5: gen 1's `uaAt` positions unchanged after gen 3 adds entries),
  `test_m1_pqzHome_singleKey_setPqzKey` (§7 (e): the accept-all generation is the verify-only carrier and the PQZ home; a
  gen-1 single-key `setPqzKey` / `setPqzScopedKey` with a bad signature stays refused), `test_pqzWrites_onlyAtHome`
  (`UAUnauthorized` elsewhere). P8's code check is Step 4's `git grep`, recorded in the commit.
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path 'test/ua/UARegistryPqzHome.t.sol'` and
  `--match-path test/pqz/PqzAuditor.t.sol`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** Step 2; `git grep -n keyOwner -- smartcontracts/evm/src/pqz` empty (P8: if it is not empty,
  or the implementer finds a `PqzCore` property relying on one key per UA, STOP and report: the owner's ruling then takes
  the reader-side rule of §11.2); `test/ua/{PqzKeyVersions,PqzScopedKeys,UARegistryPq,UARegistryPqzBound}.t.sol`,
  every `test/pqz/` suite at the default set; `at-set.sh others sensitive` and `others modules` (a PQZ change: the full
  four-set run is the round gate's); gas pins; size gate.
- [ ] **Step 5: Mutants:** the home as the newest enabling generation; `_away` forwarding to `predecessor`; `0x0142` lists
  concatenated on chain; `_auditorChecks` back on `kindEnabled`; `_pqzRecord` from `predecessor`.
- [ ] **Step 6: Commit** `evm: PQZ home per record over the line (§11.2, P7, M5), auditor check line-wide`.

### Task 9: ML-DSA verify-only verifiers (§2, §5, §9, M7)

**Files:**
- Create: `smartcontracts/evm/src/ua/MlDsaVerifyOnly.sol` (one contract per kind, `MldsaVerifyOnly44` / `65` / `87`,
  owner C4: one file, a shared base): constructor probe at a candidate address list (valid / flipped pair plus one negative
  row per §7 ML-DSA edge class, `PRECOMPILE = 0` on any miss), `PRECOMPILE()`, `KEY_FORM()` (`0`, or `1` for an
  EIP-8051-style precompile), `verify` / `verifyPop` / `verifyCached` as the holder's entries; lengths and encodings first
  (the holder's decoding code reused unchanged), the precompile called with an explicit gas limit, the alive-check,
  `PqNoAnswer()`
- Test: create `smartcontracts/evm/test/ua/MlDsaVerifyOnly.t.sol` (stand-in precompiles at the candidate address:
  correct, empty-on-invalid, revert-on-malformed, **burn-all** on malformed input, absent)

- [ ] **Step 1: Failing tests:** `test_probe_allRows_setsPrecompile`, `test_probe_edgeRowWrong_precompileZero` (one per
  edge class), `testFuzz_noPqNoAnswer_onWorkingStandIn` (N5: no caller-chosen `sig`, key or message gives `PqNoAnswer` or a
  revert, for each working stand-in), `test_burnAll_aliveCheckKeepsGas` (M7), `test_absentPrecompile_PqNoAnswer`,
  `test_malformed_answersZero`, `test_cap_coversWorstInput` (failed call at its limit plus the alive-check, pinned).
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path 'test/ua/MlDsaVerifyOnly.t.sol'`.
- [ ] **Step 3: Implement**; measure the explicit gas limit per kind against the stand-in and the P6f copy figures (spec
  §13 Gas) and pin it.
- [ ] **Step 4: Run green:** Step 2; size gate (each verifier's runtime and init).
- [ ] **Step 5: Mutants:** the alive-check removed (red on the fuzz test); the explicit gas limit removed (red on
  `test_burnAll_aliveCheckKeepsGas`); one edge-class row dropped from the probe; the length check after the call.
- [ ] **Step 6: Commit** `evm: ML-DSA verify-only verifiers (three-state, alive-check, explicit gas limit)`.

### Task 10: equivalence (§7)

**Files:**
- Create: `smartcontracts/evm/test/ua/VerifyOnlyEquivalence.t.sol`
- Modify: `smartcontracts/vectors/` only through its generator if a row is missing (then regenerate and let every reader
  read it; no hand edit)

- [ ] **Step 1: Tests:** (a) every row of `pq_kat.json`, `pq_external.json`, `pq_signatures.json`, the EIP-8355 cases and
  the ACVP / Wycheproof ML-DSA sigVer sets gives the same verdict on the holder's `MldsaVerifier` (cache path) and the
  verify-only verifier (stand-in precompile backed by the same Solidity code); (b) the verifier-level differential: the
  edge classes plus every byte of `sig`, `pk`, message flipped, lengths ± 1, trailing bytes; (c) the registry-level
  differential: `requireAuthorized` (signer and `msig` member), `requirePortable`, `requirePortableApp` under every purpose,
  gen 1 directly against gen 2; (d) one mutant stand-in per edge class (accepts that class) makes the suite fail; form `1`:
  `test_cacheLayout_equalsPrecompileInput` for every KAT key.
- [ ] **Step 2: Run:** `../../scripts/capped forge test --match-path 'test/ua/VerifyOnlyEquivalence.t.sol'`. A difference
  in either direction stops the kind and goes to the owner with its rows (R5); no tolerance is added.
- [ ] **Step 3: Mutants:** the per-class stand-ins of (d), each killed.
- [ ] **Step 4: Commit** `evm: verify-only equivalence suite (§7 a–d, form 1 layout)`.

The run against a real precompile is on a local chain whose client has it (never the live testnet), in Task 13's probe.

### Task 11: the frozen interface pin (§11.3, P13, M8)

**Files:**
- Create: `smartcontracts/evm/test/ua/RegistryWalkInterface.t.sol`
- Modify: `smartcontracts/evm/test/vectors/selector_audit.json` (the new views)

- [ ] **Step 1: Test** `RegistryWalkInterfaceIsPinned`: the list of §11.3 (full signatures with return types, `txGasCap`
  included), their selectors, the error selectors (`UAVerifyGas`, `UAKeyNotCached`, `UAKeyCache`, `UAKeyData`, `UAPoP`,
  `UAUnauthorized`, `UAVerifyOnly`), the type strings of `UASig` and `MemberSig`, the verifier getters `PRECOMPILE()` and
  `KEY_FORM()`, the hold constants (`cap/63`, `GAS_MARGIN = 5_000`), the `expandedKeyOf` return type `address[3]`, and the
  keccak of the whole list, each against a literal.
- [ ] **Step 2: Run:** `../../scripts/capped forge test --match-path 'test/ua/RegistryWalkInterface.t.sol'` and
  `test/governance/SelectorAudit.t.sol`.
- [ ] **Step 3: Mutant:** one return type changed in `IUARegistry` (red).
- [ ] **Step 4: Commit** `evm: frozen walk interface pin (P13, M8)`.

### Task 12: factory binds a later generation (§10, CTR-UA-67)

**Files:**
- Modify: `smartcontracts/evm/src/factory/OpenFactory.sol` (the env check: 0, `uaRegistry()`, or a registry whose
  predecessor walk reaches it within `MAX_GENERATION − 1` steps, each a contract; `chainUid` equal; `smartKeyCloneHash()`
  equal; else `EnvRegistryMismatch`). Size: `OpenFactory` has 287 B: if Step 4's size gate crosses its T-1 line, STOP
  and report.
- Test: `smartcontracts/evm/test/v2/FactoryDirectory.t.sol`

- [ ] **Step 1: Failing tests:** `test_env_gen3OfRouterLine_accepted`, `test_env_otherChainUid_refused`,
  `test_env_nonRegistry_refused`, `test_env_otherCloneHash_refused`, `test_env_walkOverDepth_refused`,
  `test_env_routerRegistry_unchanged`.
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path test/v2/FactoryDirectory.t.sol`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** `../../scripts/capped forge test --match-path 'test/v2/*'` and `--match-path 'test/factory/*'`;
  size gate (`OpenFactory`).
- [ ] **Step 5: Mutants:** no clone-hash check; an unbounded walk; the `chainUid` check dropped.
- [ ] **Step 6: Commit** `evm: OpenFactory accepts the router registry's line (CTR-UA-67)`.

### Task 13: deploy: later-generation mode, tx-cap probe, book (§9, X1, M9, M10 d, W5)

**Files:**
- Create: `smartcontracts/evm/script/tx_gas_cap.py` (the probe of §9: `eth_call` of a cheap call at `2^24` and `2^24 + 1`
  through the node list under strict majority, then the binary search up to the block gas limit; prints the value and the
  rows; `GEN_TX_CAP_UNKNOWN` when no cap is found and the book has no owner-set value; `GEN_TX_CAP_MISMATCH` when the
  book's value differs)
- Modify: `smartcontracts/evm/script/DeployBase.sol` (`_deployUARegistry` later-generation mode: predecessor = the book's
  latest (`GEN_NOT_LATEST`, owner override from the book), `GEN_DEPTH`, the walk check of every address, code hash and
  library against the book (`GEN_WALK_MISMATCH`), `0x0142` enabled whenever a predecessor enables it (`GEN_PQZ_OMITTED`,
  owner override from the book), `GEN_KEY_FORM_IMPOSSIBLE`, `GEN_VERIFY_ONLY_NO_PRECOMPILE`, `GEN_PQZ_DEBIT_BOUND`, the
  verify-only verifiers by CREATE2, `TX_GAS_CAP` from the probe), `smartcontracts/evm/script/DeployBook.sol` and
  `script/deploybook.py` (book fields: registry address, generation, predecessor, code hash, libraries and their code
  hashes, `txGasCap` and its probe rows, `0x0142` and any override, per verify-only kind `{kind, verifier, cap, keyForm,
  precompile, eip, status, probe_rows_hash, probe_rows}`, the probe's node list and client versions, the walk check's
  result, owner overrides with reasons, the binding router and factory, Blockscout verification), `script/test_deploybook.py`,
  `smartcontracts/evm/script/deploy_batch.py` (runs `tx_gas_cap.py` first), the differential probe of §9 (holder entry per
  kind, `eth_call` against the home's verifier through the node list under strict majority) in `script/pq_verifiers.py`
- Test: `smartcontracts/evm/test/ua/UADeploy.t.sol`, `script/test_deploybook.py`, create `script/test_tx_gas_cap.py`
  (a fake RPC: cap at 2^24, cap at 30 M, no cap, nodes disagreeing)

- [ ] **Step 1: Failing tests:** `test_deploy_gen2_overGen1_fromBook`, `test_deploy_notLatest_GEN_NOT_LATEST`,
  `test_deploy_notLatest_ownerOverride`, `test_deploy_gen17_GEN_DEPTH`, `test_deploy_walkMismatch_codeHash`,
  `test_deploy_omits0142_GEN_PQZ_OMITTED` and `_ownerOverride` (M9, §11.2 (f)), `test_deploy_keyForm1_precompileHome_named`,
  `test_deploy_verifyOnlyNoPrecompile_named`, `test_deploy_debitBound_named` (M10 d), `test_deploy_txGasCap_fromProbe`;
  in Python: `probe_cap_2_24`, `probe_cap_30m`, `probe_no_cap_unknown`, `probe_book_mismatch`, `probe_nodes_disagree_refused`,
  `book_fields_roundtrip`.
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path test/ua/UADeploy.t.sol`;
  `python3 -I script/test_deploybook.py`; `python3 -I script/test_tx_gas_cap.py`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** Step 2; a local end-to-end: gen 1 then gen 2 on a local anvil (`script/deploy_batch.py`
  against it; anvil started and stopped in the same foreground command), the book read back.
- [ ] **Step 5: Mutants:** the walk check on addresses only (no code hash); `0x0142` omitted silently; `TX_GAS_CAP`
  defaulting to `1 << 24`.
- [ ] **Step 6: Commit** `deploy: later-generation mode, tx-cap probe, M9 and walk checks, book fields`.

### Task 14: Draft precompile probe flag (CTR-UA-69, R9)

**Files:**
- Modify: `smartcontracts/evm/script/pq_verifiers.py` and `smartcontracts/evm/script/DeployBase.sol`
  (`_mldsaCandidates`: by default the Final EIP addresses and the chain-own `0x…5caa0012` / `13` / `14`; the Draft
  `0x12` / `0x13` / `0x14` only when the chain's row in `smartcontracts/evm/chain-uids.json` has
  `"probe_draft_precompiles": true` (owner C5) and the book records the owner's confirmation, then with the fuller
  probe: valid row, flipped row, the edge-class vectors), `chain-uids.json` (the field, absent on every chain today)
- Test: `smartcontracts/evm/test/ua/UADeploy.t.sol`, the Python self-test of `pq_verifiers.py` (create
  `script/test_pq_verifiers.py` if none exists)

- [ ] **Step 1: Failing tests:** `test_candidates_default_noDraft`, `test_candidates_flag_withoutBook_refused`,
  `test_candidates_flag_fullerProbe`; Python `draft_not_probed_by_default`, `draft_probed_under_flag_and_book`.
- [ ] **Step 2: Run red:** `../../scripts/capped forge test --match-path test/ua/UADeploy.t.sol`;
  `python3 -I script/test_pq_verifiers.py`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run green:** Step 2.
- [ ] **Step 5: Mutant:** Draft first again (red).
- [ ] **Step 6: Commit** `deploy: Draft PQ precompiles probed only under the owner-confirmed flag (R9)`.

### Task 15: gas rows and pins (T-GAS)

**Files:**
- Modify: `smartcontracts/evm/test/ua/UAGas.t.sol`, `test/ua/UARegistryNestedGas.t.sol`, `test/gas/SdkGas*.t.sol`,
  `smartcontracts/evm/test/vectors/sdk_gas.json`
- [ ] **Step 1: Rows:** per verify-only kind, the consumer path (precompile stand-in), the fallback, the write path of W1,
  per depth 1 – 4 and the miss at depth 16; `msig` members at the budget; T-AUTH-4 on the new path
  (`--isolate`: `../../scripts/capped forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'`).
- [ ] **Step 2:** every moved pin old → new in the commit; the spec's [estimate] figures (§11.1 Gas, §13) compared in the
  commit body.
- [ ] **Step 3: Commit** `evm: verify-only and line gas rows (T-GAS)`.

### Task 16: node (§12 CTR-UA-65)

**Files:**
- Modify: `scaas-node/src/config.rs` (`ua_registries: Vec<Address>` replaces `ua_registry`; validated at start on chain:
  one `chainUid`, exactly one generation 1, one line, consecutive, ≤ 16; order free), `scaas-node/src/main.rs`,
  `scaas-node/src/guard.rs` (`Rule::UaRegistry` as the set; per-registry allow-list; `UA_VERIFY_ONLY` with the target
  `kindHome(kind)`; `UA_WRONG_GENERATION` for a key write off `holderOf(ua)` and a PQZ write off `pqzHomeOf(ua)`;
  NODE-JOB-29's target and `UA_KEY_NOT_CACHEABLE`), `scaas-node/src/indexer.rs` (every generation; PQZ events of every
  `0x0142` generation; the duplicate-hash flag), `scaas-node/src/submit.rs` (Review Focus 5: a registry-checked job's gas
  limit from the simulation up to `txGasCap`), `scaas-node/node.example.toml`
- Test: unit tests in those files; `scaas-node/tests/e2e.rs` (gen 1 + gen 2 on a local anvil)

- [ ] **Step 1: Failing tests:** `config_ua_registries_validated` (wrong `chainUid`, two generation 1, a gap, a fork, 17
  entries: each refused by name), `config_order_free`, `guard_register_verifyOnly_UA_VERIFY_ONLY`,
  `guard_keyWrite_wrongGeneration`, `guard_pqzWrite_wrongHome`, `guard_allow_lists_per_registry`,
  `nodejob29_target_holder`, `indexer_reads_every_generation`, `indexer_duplicate_pqz_hash_flag`,
  `submit_gas_up_to_tx_cap` (Review Focus 5).
- [ ] **Step 2: Run red:** `cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test` (alone).
- [ ] **Step 3: Implement**; a note for operators in the commit body and in `docs/node/ops.md` (config shape change).
- [ ] **Step 4: Run green:** Step 2; `cargo clippy --all-targets -- -D warnings`; `CAPPED_MEM=6G ../scripts/capped cargo
  test --test e2e -- --ignored`.
- [ ] **Step 5: Mutants:** the order taken as given; the guard on one registry only; the duplicate flag off.
- [ ] **Step 6: Commit** `node: ua_registries line, guard per registry, UA_VERIFY_ONLY, UA_WRONG_GENERATION`.

### Task 17: scaas-sdk (§12)

**Files:**
- Modify: `clients/scaas-sdk/src/config.rs` (verify rows keyed by chain, registry address and signer kind; columns path
  `cache` / `precompile` / `fallback`, depth, write path; the chain's `txGasCap` row), the SDK's registration and key-write
  targets (`kindHome`, `holderOf`, `pqzHomeOf`), the PQZ decoy draw (the `0x0142` list of every enabling generation on the
  token registry's walk, concatenated, by distinct key hash: owner P19), `clients/scaas-sdk/gas/{inputs.json,reference.json,generate.py}`
- Test: `clients/scaas-sdk/src/op/gas.rs` tests, `clients/scaas-sdk/tests/account.rs`

- [ ] **Step 1: Failing tests:** `verify_row_keyed_by_registry`, `quote_takes_bound_registry_row`,
  `register_target_is_kindHome`, `key_write_target_is_holder`, `pqz_write_target_is_home`,
  `decoys_concatenated_distinct_hash`, `reference_rows_hold_their_sources` extended.
- [ ] **Step 2: Run red**, implement, **run green:** `cd clients/scaas-sdk && ../../scripts/capped cargo test --locked`;
  clippy; `tests/feature_tree.rs`.
- [ ] **Step 3: Commit** `scaas-sdk: per-registry verify rows, line targets, decoys over the line`.

### Task 18: clients (§12)

**Files:**
- Modify: `clients/ua-rs/src/lib.rs` (a pure check `registration_target_ok(kind, registry, kind_home) -> Result<(),
  VerifyOnly>`: the caller passes the `kindHome(kind)` it read; owner C6: no RPC in the libraries), the same check in
  `clients/clientkeys`, `clients/ua-py`, `clients/ua-go`, `clients/ua-cs`, `clients/ua-dart` (the ua-rs bindings `ua-c`,
  `ua-cxx`, `ua-qt`, `ua-dart-frb` re-export ua-rs's); `docs/clients/ua-libraries.md`
- [ ] **Step 1: Failing tests** per language: `target_equal_ok`, `target_other_verify_only`. No byte format changes: no
  vectors move.
- [ ] **Step 2: Run red / implement / run green:** each client's CI header commands.
- [ ] **Step 3: Commit** `clients: registration target check (kindHome)`.

### Task 19: docs and decisions (rule ids final)

**Files:**
- Modify: `docs/contracts/accounts.md` (§1.8 "Generations", §1.9, T-REG-4, CTR-UA-05's sentence, CTR-UA-29's lists, the PQZ
  attachment rule; the rules `CTR-UA-58` … `-72` with their anchors), `docs/decisions.md` (an entry with spec §0 verbatim:
  every owner ruling with `owner: yes`, the rest without; A5-I1 / A6-I1 as §11.2), `docs/networks/evm.md` (chain-own
  precompiles, the Draft flag, the keep commitment, `txGasCap` and its probe), `docs/node/job-api.md`,
  `docs/node/ops.md` (`ua_registries`), `docs/networks/evm.md` also the differential probe re-run after every client
  upgrade (§9, an operations check), `docs/networks/README.md` (CTR-UA-66's principle per family, PLANNED),
  `docs/superpowers/specs/2026-11-17-scaas-sdk.md` (verify rows),
  `docs/superpowers/specs/2026-11-10-admin-not-owner.md` §13.4 (one registry line per factory), the spec's status line
  (BUILT (EVM) with the commits; the other families PLANNED)
- [ ] **Step 1: Final ids:** `python3 scripts/docs_check.py resolve CTR-UA-58` … `CTR-UA-72`; if any is taken by then (the
  `bls-multi` round lands `CTR-UA-47` … `-57` first), take the next free ones and rewrite the placeholders in the spec,
  this plan and every code comment (`git grep -nE 'CTR-UA-(5[89]|6[0-9]|7[0-2])'`).
- [ ] **Step 2: Write** the docs; BUILT only where Tasks 1 – 18 built code and tests.
- [ ] **Step 3: Gates:** `python3 scripts/docs_check.py check` (0 errors), `paths`, `consumer`, `python3
  scripts/test_docs_check.py`.
- [ ] **Step 4: Commit** `docs: registry line and verify-only rules CTR-UA-<ids>, decisions, node and SDK docs`.

### Task 20: round gate (full matrix, once)

On the final tree, after Task 19; per-step logs, resume per step (read the gate's `last` file first); summary
`smartcontracts/evm/runs/<round-start-date>-multi-gen-verify/gate-summary.txt` (`step | commit | rc | counts`, no absolute
paths).

| Step | Command |
|---|---|
| forge, default set | `cd smartcontracts/evm && ../../scripts/capped forge test` (every test directory) |
| cold gas | `../../scripts/capped forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'` |
| PQZ change, four sets | `../../scripts/capped script/pqz/at-set.sh others test` (every forge directory at the other three sets; `PqzStateLib` changed), then `at-set.sh others modules` |
| generated set file | `python3 -I pqz-core/params/sets/gen_set.py --all --check` |
| testnet profile | `FOUNDRY_PROFILE=scaas-testnet forge build` |
| size | `forge build src --sizes --json > "$T"/sizes.json; python3 ../../scripts/size_gate.py "$T"/sizes.json size-baseline.json` |
| deploy scripts | `python3 -I script/test_deploybook.py`; `python3 -I script/test_tx_gas_cap.py`; `script/test_pq_verifiers.py` |
| node | `cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test` (alone); clippy; `CAPPED_MEM=6G ../scripts/capped cargo test --test e2e -- --ignored` |
| scaas-sdk | `cargo test --locked`; clippy |
| clients | ua-rs and ua-rs-targets matrix; clientkeys `npm test`; ua-py, ua-go, ua-cs, ua-c, ua-cxx, ua-qt, ua-dart, ua-dart-frb (CI header) |
| vectors | `pqz-vectors --check`, `pqz_kat.py --check` and the UA vector generators' `--check` (nothing should move) |
| format | `scripts/format.sh --check` |
| docs | `python3 scripts/docs_check.py check`; `paths`; `consumer`; `python3 scripts/test_docs_check.py`; `! git grep -nE '/[t]mp/' -- . ':!*/legacy/*' ':!docs/history/*'` |

A red step is reported with its output; no pin, bound or test is edited to go green. Commit the summary:
`runs: multi-gen-verify round gate`.

### Task 21: review before merge

- **Fable review** of the built round (design, security, cryptography): the write flag at every signature path (no write
  reaches a verify-only verifier), `_single` on writes (M1), the three-state mapping, the alive-check and the explicit gas
  limit, the fallback, the hard bound's two modes and reserves, `txGasCap`, the one walk and the PQZ home, the per-generation
  `0x0142` lists, the constructor's trust in predecessors, the factory walk; and P8's question: does any `PqzCore` property
  rely on one PQZ key per UA (if yes, the reader-side rule of §11.2 is built before merge). Beside it the review set the
  owner names (Codex and agy only on the owner's word). Findings are fixed in their own commits with the affected task's
  tests and mutants re-run, then the affected Task 20 steps.
- Every report and doc keeps **UNAUDITED** on the cryptography.
- Merge only on the owner's word, by merge commits via `ua-rs-sign` after `bls-multi` (`main` is PR-only).

---

## Owner rulings on the plan (2026-11-19)

The owner on the plan's choices C1 – C7: **all as proposed**.

| # | Ruling |
|---|---|
| C1 | `txGasCap` is the constructor's argument right after `verifyBudget_` (one ABI change; the 40 construction sites updated in Task 1) |
| C2 | The round's runs folder is `smartcontracts/evm/runs/<round-start-date>-multi-gen-verify/` |
| C3 | Because `src/pqz/PqzStateLib.sol` changes, the round gate runs every forge directory at all four sets (AGENTS.md's PQZ rule), not only the set-sensitive tests |
| C4 | The three ML-DSA verify-only verifiers live in one new file `src/ua/MlDsaVerifyOnly.sol` with a shared base |
| C5 | The Draft probe flag is a field of the chain's row in `smartcontracts/evm/chain-uids.json` (`probe_draft_precompiles`), and the owner's confirmation is a book field |
| C6 | The client libraries check the registration target from a `kindHome` value the caller passes; only scaas-sdk reads it from the chain (no RPC in `ua-*`) |
| C7 | Task order: writes (Task 4) before the consumer path (Task 5), so no build of the round lets a verify-only verifier near a write |

Open (plan choice, controller may override; the spec's proposal P21):

| # | Choice |
|---|---|
| C8 | `UARegistry`'s consumer path (Task 5) reads the walk by a static self-call to its own thin `holderOf` view |
