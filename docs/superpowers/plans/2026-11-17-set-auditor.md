# `setAuditor` on bit 32 `AUDITOR`: plan

**Status (2026-11-17):** PLANNED, nothing built. Spec: [`specs/2026-11-17-set-auditor.md`](../specs/2026-11-17-set-auditor.md)
(rules [CTR-GOV-31](../../decisions.md#CTR-GOV-31), [CTR-ZTH-95](../../contracts/zether.md#CTR-ZTH-95),
[CTR-PQZ-43](../../contracts/pq-zero-knowledge.md#CTR-PQZ-43)), revised after the Fable review of the same day (spec §16).
Owner 2026-11-17: "Do format phải chạy lại rất nhiều, tiện thể làm luôn '- setAuditor', dùng 1 bit cho việc này. Gom chung vào
format code, để chạy gate .v.v. 1 lần" (build `setAuditor` now, on one bit, bundled with the formatting so the gates run
once), then "Làm luôn" (do it now); on the holder "Vẫn UA như bình thường chứ, bao gồm cả contract và msig" (any UA); on the
open points "Ok, theo đề xuất cả O1, O2, O4" (the delay `max(noticePeriod(), grantDelay)`; kind 4 stays in
`NormalPqzTokenQ`; a delay of 0 applies at once and the wallet says so).

## How to run this plan

- **Where in the bundled round** ([code-format plan](2026-11-17-code-format.md), "Bundled: `setAuditor` on one governance
  bit"): after PqVault Part R (R1–R4, [plan](2026-11-17-pqvault.md)), **before** F2 (`forge fmt`) with `bytecode_hash =
  "none"` and before the re-pin. Branch: the round's branch after Part R (`prefreeze-contracts` today); another agent may share
  the worktree: commit with `git commit --only -- <paths>`, never `git add -A`, never stash.
- **Order.** A0 first. A1 before everything else that reads the bit. A2 → A3 (Zether) and A4 (PQZ) are independent of each
  other; A5 after A2 and A4; A6 after A5; A7 and A8 after A6; A9 after A6; A10 last.
- **Green per commit, except the code-hash pins.** Every code-hash pin (the factory catalogue's init-code hashes,
  `LinkClosure`'s release pins, the `*_CODEHASH` constants, `test/v2/module-opcodes.json`) moves only at the closing re-pin.
  A0 lists the tests that pin them by name; between A1 and the re-pin those, and only those, may be red, and each commit
  message names the ones it leaves red.
- **Tests first** in every code task: write the tests, run them red, then the code, then green. Every refusal test has a
  positive control and changes one thing. Mutants per check, killed by a named test; scripts and results in
  `smartcontracts/evm/runs/2026-11-17-set-auditor/` (summary lines only, no absolute paths).
- **Heavy commands** go through `scripts/capped`, foreground, never inside `timeout`. PQZ per-set runs by
  `script/pqz/at-set.sh <set> test` (it rewrites `src/pqz/PqzSet.sol`: one run per work tree, restored after).
- **Gates in the tasks** (owner ruling 2026-11-18, "Theo đề xuất"): a task runs only its own suites at the default set, its
  mutants, and every test that pins what it changed (code-hash, typehash, layout, gas or size pins it moves, old → new in the
  commit). No full forge sweep and no per-set sweep per task. A task is committed once its own tests and mutants are green; its
  commit body says "full matrix pending (bundle gate)". The **one full matrix** runs after A10, bundled with F2 (`forge fmt`,
  `bytecode_hash = "none"`) and the re-pin: one compile, one re-pin, one full gate (Closing). After the 2026-11-18 reboot lost
  the per-task snapshots, A1-A8 are one commit (the byte formats change in contracts, clients and node at once), A9 and A10
  their own.
- **Lanes** (owner ruling 2026-11-18, "Đồng ý. Làm luôn"; `runs/2026-11-17-set-auditor/gates.sh`, `LANE=<name>`): fixed
  directories under the git-ignored `scratchpad/lanes/` on `/home`, one per PQZ set (`n2304-kmax4096`, `n2048-kmax1024`,
  `n2560-kmax16384`, `n2816-kmax65536`, each with its own `PqzSet.sol`) and one for mutants (`mutants`). A run syncs the tree
  under test into its lane with `rsync -a --delete`, excluding `out/`, `cache/`, `target/`, `lib/`, `node_modules/` (and `.git/`,
  `scratchpad/`, the lane's own run logs), so forge's `cache/` + `out/` and cargo's `target/` stay and build incrementally; `lib/`,
  `clientkeys/node_modules` and `algorand/out` are plain copies made once; no hardlinks or symlinks between lanes or with the
  worktree. One process per lane at a time (`flock` on `scratchpad/lanes/<name>.lock`, beside `capped`). Before use, the cache
  proof (`proof-forge`, `proof-cargo`): build in a lane, change one source file, rebuild incrementally, build the same tree clean
  in a fresh directory; every contract's init and runtime bytecode identical (forge), the `cargo test` outcomes identical
  (ua-rs); a failed proof stops incremental use. Incremental builds serve the per-task loop only; the full matrix after A10 and
  every pre-merge gate build in a fresh or `forge clean`ed tree, and each summary row names its build kind.
- **Lane sync defect and fix (2026-11-18).** The first lane runner excluded bare names (`lib/`, `out/`, `cache/`, `target/`,
  `node_modules/`, `.git/`), which match at any depth: `lib/` also dropped the Dart clients' `lib/` sources (`ua-dart`,
  `ua-dart-frb` failed to resolve their own package), `.git/` let the worktree's `.git` file through, and with no `build/`
  exclude the worktree's CMake caches came along (`ua-cxx`, `ua-qt` refused them). The fix (coordinator 2026-11-18): every exclude
  is anchored at the root (the fixed ones, and each `out/`, `cache/`, `target/`, `build/`, `node_modules/` that holds no file of
  the tree, written to `scratchpad/lanes/<lane>.excludes`), and after the rsync every file of `git ls-files -co
  --exclude-standard` outside them must be in the lane and byte-identical, or the sync fails. Every cell run on a lane synced
  before the fix was run again. The cache proofs stand: they built `smartcontracts/evm` and `clients/ua-rs`, which the bare
  excludes did not touch beyond the `smartcontracts/evm/lib/` copy.
- **`pqz-core` stays untouched** (spec §10): no file of `pqz-core/ffi/src`, `pqzl`, `pqzh/ligero/src`, `stmt` or the set
  parameters changes; the callers pass the entry's `pk_a` into the recovery. If a task finds an `ffi` change needed after all,
  it says so in its commit and runs the affected steps of `pqz-core/gate.sh` (not the full gate, unless a core input changes).
- **Stops.** A contract measured over its T-1 line stops the build with the figures (owner ruling O2: kind 4's setter stays in
  `NormalPqzTokenQ`, and the work stops and asks only if a figure crosses T-1; no module split without the owner, only
  `NormalPqzRegulatedTokenQ` may be split automatically). A layout pin that moves stops the task. A gas pin moves only with old
  → new figures in the commit. `mtxSetAuditorUA` not compiling (stack too deep) stops A6 with a report.

## A0 — measure and read

Files: none committed but the summary `runs/2026-11-17-set-auditor/a0.txt`.

1. `cd smartcontracts/evm && scripts/capped forge build src --sizes --json > <tmp>/sizes.json`; `size_gate.py` as today (green).
2. Record the measured sizes of the rows of spec §12 and project each with the spec's estimate; `NormalPqzTokenQ` against T-2
   and T-1 (expected 34.2–34.9 K). **Stop and ask** if any projects over T-1.
3. List by name the tests that pin code hashes (the allowed-red set until the re-pin).
4. Record the confidential transfer gas pins the round will move (Zether single and multi, PQZ op 1 and op 7, at n2304) as the
   "old" column.
5. Read `isValidPoint` of both curves: can two encodings of one G1 point pass (review I4)? Write the answer; A2 compares the
   decoded point if they can.
6. Read the registry for a view that says whether a PQZ key record (registry, shared or scoped version) carries its `R_REG`
   proof (`checkedPqzPop`); write its name, or "none" (A4 step 1).

## A1 — the bit, the masks, the vector row

Spec §3, §8, CTR-GOV-31. Files: `src/governance/GovernanceBits.sol` (`AUDITOR = 32`; **not** in `REGULATED_ROLES`, not
contract-only), the cores of kinds 2, 3, 4, 5 and 10–13 (`_validBits`, `_roleBits` only), `src/governance/GovernanceLib.sol`
(`setGrant` refuses `delegable` on 32, `DelegableRefused(32)`), `src/governance/IGovernance.sol` (`DelegableRefused`,
`FeatureNeedsAdmin`), `ZetherLib.init*` and `PqzStateLib.init` (`BadAuditorMode(0)` for bit 32 on NONE, `FeatureNeedsAdmin(32)`
with admin 0), `test/governance/GovAuditorBit.t.sol` (new), `test/governance/GovBitsVector.t.sol` (row 32 with `holder: any`
and its four sentences, the note "33-127"), then `smartcontracts/vectors/governance/governance_bits.json` regenerated by it
(`WRITE_BITS=true`), never by hand.

1. Tests (spec §13 "Bits and masks": every holder kind accepted, `NoSuchRole(32)` on kinds 8 and 9, never
   `RoleWithoutFeature(32)`), red.
2. Code; green. `GovRegulatedBits`, `GovRelax` (32 not delay-relaxed), `PlusZero.t.sol` unchanged and green.
3. Regenerate `governance_bits.json`; the clients that read it (clientkeys `test/governance-bits.test.js`, `ua-rs`
   `tests/vectors.rs`, `ua-c`, `ua-cxx`, `ua-qt`, `ua-cs`, `ua-py`, `ua-go`) green with the new row, each hand-kept bit table
   updated to name bit 32; the wallets' bit printers select `atOnce`, `singleKey` and `locked` by the row's `sentencesWhen`.
4. Mutants: 32 in `_delayedRelaxBits()`; 32 in `REGULATED_ROLES`; the NONE check dropped; the admin-0 check dropped;
   `delegable` accepted on 32; 32 in `ENABLEABLE`.
5. Commit `governance: bit 32 AUDITOR, the confidential kinds, any holder (CTR-GOV-31)`.

## A2 — Zether: storage, setter, consent, per-entry epoch, views

Spec §4–§8, CTR-ZTH-95. Files: `src/zether/ZetherLib.sol` (the fields of spec §6, the state machine of §5.1 with
`AUDITOR_CONFIRM_WINDOW = 7 days`, the delay `max(IOpenFactory(FACTORY).noticePeriod(), grantDelay)`, the epoch check, the
checks and the proof of possession of §5.2 with the `AuditorConsent` digest, the apply, the per-entry write in the record
writers of both formats, the views' bodies), `src/zether/ZetherLayer.sol` (`_setAuditorKeyBody`, `_auditorKeyOfBody`,
`_auditorStateBody`), `src/zether/IZetherToken.sol` (entries, views, events, errors), `test/zether/ZetherAuditor.t.sol` (new),
`test/v2/Layout.t.sol` and `test/v2/layout/namespaces.json` (the new rows; every old row unchanged).

1. Tests (spec §13 "Setter", "The way back", "Epochs and disclosure", Zether rows; the layout rows), red. Include: the delay
   `max` both ways; zero notice with `grantDelay > 0` confirms within the 7-day window; a confirm after the window proposes
   afresh; a new proposal refused before expiry and allowed after; the holder's cancel; `auditorState().status` 1 to 4; wrong
   epoch; consent refusals at both steps; an epoch-0 audited transfer writes nothing (`vm.load`); an opt-out writes nothing;
   three epochs.
2. The proof of possession reads its known answers from `smartcontracts/vectors/zether/auditor_pop.json` (A3 generates them;
   until then the test builds them inline and A3 swaps in the vector file).
3. Code; green. `test/zether/**`, `test/as/confidential/Zether*`, `ZetherGasLimit.t.sol` (`ZETHER_GAS_PROBE=1`: the edge cells
   at epoch 0 unchanged; new probe rows at epoch ≠ 0, regular gas within the cap less the margin), the layout test.
4. Mutants: spec §13's list for Zether (window, expiry, cancel, delay sources, epoch, consent at each step, proof checks,
   per-entry write, history, layout).
5. Commit `zether: setAuditorKey on bit 32, consent, auditor epochs and history (CTR-ZTH-95)`.

## A3 — `ZetherDisclosure`, the Zether prover and its vectors

Spec §5.2, §9. Files: `src/zether/ZetherDisclosure.sol` (`auditorKeyOf(entryRef)`), `test/zether/ZetherAuditor.t.sol`
(disclosure rows), `clients/zether-prover/src/` (the proof of possession `auditor_pop` with its hedged nonce and its verifier;
`state.rs`: slot 0's `modes` with the epoch bytes, the `entryAuditorEpoch` and `auditorKeys` words for `recoverTransfer` and
`openDisclosure`; `api.rs`: `yAud` of the entry; the reader's refusal of an entry of another epoch before the secret is used),
its generator writing `smartcontracts/vectors/zether/auditor_pop.json` (never by hand), its tests,
`clients/ua-rs/src/facade/zether.rs` (the word list, the reader's refusal), `ua-rs` tests.

1. Tests: an epoch-0 entry opens with the old key after the replacement and not with the new; the reverse for an epoch-1 entry;
   single and multi-recipient; the prover recovers an epoch-1 transfer with the epoch-1 key and fails with the epoch-0 key; the
   proof of possession to its vectors and its refusals; the old auditor's handle refuses an epoch-1 entry and the new one an
   epoch-0 entry, before the secret is applied. Red.
2. Code; green. `test/zether/**`; zether-prover: `cargo clippy --all-targets -- -D warnings` (default and `--features hazmat`),
   `cargo test` (both), `./wasm-smoke.sh`, the `read_balance` test against anvil; `ua-rs` the facade cells.
3. Mutants: the disclosure reads the current key; the prover's recovery uses the current key; the reader uses the current
   auditor; the reader applies its secret before the epoch check; the proof's challenge drops `Y_a` or `d`.
4. Commit `zether: disclosure, recovery and the auditor's reader by the entry's key; proof-of-possession vectors (CTR-ZTH-43, CTR-ZTH-95)`.

## A4 — PQZ: storage, setter, consent, three-key checks, per-entry epoch, disclosure, the reader

Spec §5–§10, CTR-PQZ-43. Files: `src/pqz/PqzCore.sol` (the fields of spec §6; `_legOf`'s `AUDITOR` owner by the entry's
epoch), `src/pqz/PqzStateLib.sol` (the state machine with the same window, delay and epoch check; never
`PqzStorage.noticePeriod`; the consent through `requireAuthorized(newAuditor, PURPOSE_AUDITOR_CONSENT, d, consent)`; the checks
through `_keyPtrV`; the proven-key check of step 1; the apply), `src/ua/UAKinds.sol` (`PURPOSE_AUDITOR_CONSENT = keccak256("scaas.ua.purpose.auditor-consent.v1")`, the string form of
the other purposes; no registry change: `requireAuthorized` takes any purpose and the closed portable list is unchanged),
`test/ua/UAKinds.t.sol` (the drift test gains the constant), `src/pqz/PqzTransferLib.sol` and the op 1 body (the per-entry
write), `src/pqz/PqzLayer.sol` (bodies), `src/pqz/IPqzToken.sol`, `test/pqz/PqzAuditor.t.sol` (new),
`test/as/confidential/AuditorKinds.t.sol` (new, kinds 10–13), the layout files, `clients/ua-rs/src/facade/pqz.rs` (the words
`auditorEpoch`, `entryAuditorEpoch[V]`, `auditorUAs[E]`; `auditor()` reads the entry's auditor pinned to the tail's `kv_a`;
`only_low` widened to the new slot 0; `auditRead` and `proveDisclose AUDITOR` refuse an entry of another epoch before the
secret is applied), its tests; the sender recovery's callers pass `pk_a` of `(auditorUAOf(entryRef), kv_a)` (no `pqz-core`
change).

1. A0's proven-key answer: if the registry exposes the flag, the setter requires the new auditor's key record proven; if
   "none", stop and report to the owner before step 3 (the key-copy residual, spec T3, stands until decided).
2. Tests first (spec §13, PQZ rows): before anything else, `auditRead` on an `OFFCHAIN` and a `LOG` token at epoch 0 (review
   I1: today's `only_low(&w, 22)` may refuse them); then every class (`PRECOMPILE`, `offchain-shared`, `offchain-token` with
   and without the opening): an auditor without the class's key, without its token key, without an opening KEM key refused at
   the proposal and at the apply; consent refused at both steps; a stranger's shield into the proposed UA does not block the
   apply; **a `PRECOMPILE` token with the factory notice not 0 waits it**; the window, expiry, cancel and status rows as A2;
   the `AUDITOR` disclosure at three epochs on a `PRECOMPILE` token; an opening token's `SENDER_S` unchanged; op 7 with the
   auditor at epoch 1 writes 1; the reader at epoch 1 on both handles, and the old handle refusing an epoch-1 entry and the new
   an epoch-0 entry before the secret is applied. Red.
3. Code; green at the four sets: `script/pqz/at-set.sh <set> test` for `n2048-kmax1024`, `n2304-kmax4096`,
   `n2560-kmax16384`, `n2816-kmax65536` (`PqzSet.sol` restored after each); `test/as/confidential/**`; the op 7 cells nearest
   the EIP-7825 cap at each set measured at epoch ≠ 0 (forge does not enforce the cap: assert the reported regular gas);
   `ua-rs` the PQZ facade cells (`facade_pqz_state facade_pqz pqz_backup no_oracle`).
4. Mutants: as A2's for PQZ, plus read `PqzStorage.noticePeriod`; check the consent under `PURPOSE_ZETHER_AUTH`; `_legOf` reads the current auditor; the `_keyPtrV` check
   dropped at the apply; the opening KEM key check dropped; the reader uses the current auditor; the reader applies its secret
   before the epoch check.
5. Commit `pqz: setAuditorUA on bit 32, consent, auditor epochs, disclosure and reader by the entry's auditor (CTR-PQZ-43)`.

## A5 — faces, modules, selector audit, sizes

Files: `script/modules/entries.json` (one setter and two views on each confidential kind; kind 4's in Q, owner ruling O2), the
regenerated faces and modules (`script/modules/gen_faces.py`, never by hand), `test/vectors/selector_audit.json`,
`test/v2/module-opcodes.json` if it moves, `test/modules/Groups.t.sol`, `size-baseline.json` (old → new for every grown row; a
new row and its `_forms` entry for every contract that first passes 24,576 B, `PqzStateLib` expected; the reason: this plan and
the owner's rulings).

1. Regenerate; `test/modules/**`, `ConfidentialSelectors.t.sol`, the selector audit green.
2. Size gate green; record old → new per row. A T-2 notice is reported (`NormalPqzTokenQ`: expected); a T-1 error stops and
   asks. `OpenFactory`, `SCaaSDex`, `UARegistryCoreLib`, `UARegistryAuxLib` must not move.
3. Commit `modules: setAuditorKey / setAuditorUA entries on the eight confidential kinds; sizes old -> new`.

## A6 — the router ops

Spec §8. Files: `src/governance/GovernanceRouter.sol` / `GovernanceRouterBase.sol` (`mtxSetAuditorKey`, `mtxSetAuditorUA` with
`uint32 epoch` in the struct and the consent forwarded beside it, their typehashes, the closed table),
`test/governance/GovRouter.t.sol` (binding matrix rows, a sibling word refused, a wrong epoch refused),
`GovRouterTypehash.t.sol` (the two typehashes and `AuditorConsent`'s pinned), `GovDeploy.t.sol` (router deploy gas old → new).

1. Tests, red; code; green. `test/governance/**`.
2. Mutants: the word not forwarded; the epoch not in the struct; `keccak256(newKey)` replaced by the raw bytes in the struct
   hash; the consent not forwarded.
3. Commit `router: mtxSetAuditorKey, mtxSetAuditorUA (CTR-GOV-31)`.

## A7 — clientkeys, `ua-rs`, the typed vectors

Files: `clients/clientkeys/src/evm.js` (the two router builders and the `AuditorConsent` typed data),
`clients/clientkeys/src/ua.js` and `clients/ua-rs/src/lib.rs` (the purpose `PURPOSE_AUDITOR_CONSENT` and the PQZ consent's
UA signature under it), `smartcontracts/vectors/ua/kinds.json` (the purpose row, from its generator), the consent signature
rows in `typed_ops.json` (a native and a derived signer), `clients/clientkeys/test/pqz-verdict.test.js`'s sibling for the
consent; clientkeys' reader, where it reads auditor entries, with the same refusal of an entry of another epoch;
`clients/clientkeys/scripts/typed-ops-vectors.mjs` → `smartcontracts/vectors/typed/typed_ops.json` (regenerated, never by
hand: the two router rows, the `AuditorConsent` row and its signed rows), `clients/clientkeys/test/typed-ops.test.js`,
`clients/ua-rs/src/wallet/eip712.rs` (the three structs), `clients/ua-rs/tests/wallet_typed.rs`,
`clients/zether-prover/tests/typed_ops.rs`.

1. Builders to the vector bytes in both languages (one generator, every language reads the same rows). Old rows unchanged.
2. Gates: clientkeys `npm ci --ignore-scripts; npm test`; `ua-rs` every feature cell (`cargo clippy --locked --all-targets
   <features> -- -D warnings`, `cargo test --locked <features>`); zether-prover `cargo test`.
3. Commit `clients: the setAuditor router ops and AuditorConsent in clientkeys and ua-rs; typed_ops rows`.

## A8 — the node

Spec §8 (node verdicts). Files: `scaas-node/src/typed.rs` (two `gov_router` rows), `scaas-node/src/guard.rs` (the counts and
the struct pins), `scaas-node/src/submit.rs` (`AuditorNotReady` `queued`, the rest `dead`), `docs/node/job-api.md` (the
router rows), `docs/node/submit-lanes.md` (the verdicts), `docs/node/ops.md` (the operator row's status to BUILT: transfers
proven against the outgoing auditor; revoke before `eta`; never `disableFeature(32)` after a hostile apply; the way back).

1. Tests, red; code; green: `scripts/capped cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo test --test e2e --
   --ignored` (alone: 6 GB; e2e rows for both ops, propose and apply after a local delay).
2. Commit `node: the setAuditor router rows and verdicts`.

## A9 — scripts and the matrix rows

Files: `script/DeployBase.sol` (the new `ZetherDisclosure`), `script/pqz/e2e.py` and the matrix runner (new rows: a token with
bit 32, grant to a single-key UA and to an `msig`, the new auditor's consent, propose, apply after the local delay, an audited
transfer, an `AUDITOR` disclosure at both epochs), `scripts/e2e-zether.sh` if it names the disclosure.

1. Local anvil run of the new rows (capped; no live testnet touched). Runs print progress lines.
2. Commit `scripts: setAuditor matrix rows`.

## A10 — docs

Files: `docs/contracts/zether.md` (§14.1, CTR-ZTH-09's and CTR-ZTH-43's Change tags), `docs/contracts/pq-zero-knowledge.md`
(§9.7, CTR-PQZ-24's and CTR-PQZ-14's Change tags), `docs/decisions.md` (Status of CTR-GOV-31, CTR-ZTH-95, CTR-PQZ-43 and of the
Changes: SPECIFIED → BUILT with commits), the spec's status line, `docs/integration.md` if a client step changes. `python3
scripts/docs_check.py check` at 0 errors; `python3 scripts/test_docs_check.py`.

Commit `docs: setAuditor built (CTR-GOV-31, CTR-ZTH-95, CTR-PQZ-43)`.

## Closing (the bundled round, not this plan's tasks)

1. F2: `forge fmt` (one commit by the tool alone) and `bytecode_hash = "none"` (code-format plan).
2. One compile; one re-pin of every code hash (catalogue, `LinkClosure`, `*_CODEHASH`, `size-baseline.json`) and every gas pin,
   old → new in the commit; A0's allowed-red set is green again.
3. **One full gate:** every forge directory at `n2304-kmax4096`; the four PQZ sets by `script/pqz/at-set.sh <set> test`;
   `forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'`; the size gate; the node (`cargo test`, clippy,
   e2e); every client job of `.github/workflows/ci.yml`. `pqz-core/gate.sh` does not run: no core input changes (if a task
   changed `ffi` after all, its affected steps ran in that task). Per-step logs, resumable; summary `step | commit | rc |
   counts` committed.
4. **One SCaaS testnet reset** with deploy, Blockscout verify of every contract (the new `ZetherDisclosure` and router included)
   and the matrix, the `setAuditor` rows of A9 among them.
5. **Closing review:** Fable (design, security, crypto: the new proof of possession included) over the spec and the built
   diff; Codex only on the owner's word. Findings go into the spec and `decisions.md`; then the owner's word to merge. No push,
   no merge by an agent.
