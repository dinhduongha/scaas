# Pre-freeze AI audit: plan

The AI audit of [ARCH-POS-14](../decisions.md#ARCH-POS-14) at the pre-freeze tag. This directory holds the plan (this file),
the [unit index](INDEX.md) and the 35 self-contained [prompts](prompts/); that is all the repository holds of the audit, except the records of separate audit streams the owner asked to keep in
[`audited/`](audited/) (owner 2026-11-26: `vendor-falcon-rs` only). The
results, the run ledger and the closure tables are local and git-ignored, under `scratchpad/ai-audit/` (owner 2026-11-24). The
repository is public: anyone can rerun the audit on the same tag with the same prompts
(owner 2026-11-24). Every review here covers the 13 dimensions of [review.md](../review.md#ARCH-POS-22) (ARCH-POS-22).
Everything under audit stays `UNAUDITED` until a round covers it at its commit; the reviewers are AI models, each named in its report
and in the ledger, never called independent or external. Each tool's model and effort are read from its config at run time
and the owner may change any reviewer's model (owner 2026-11-24; Codex today: GPT-6.2-astra, effort high); a round's
`AI-AUDITED (<models of the round>)` label names the models its ledger records.

**Status:** plan; the target is the pre-freeze tag `<TAG>` (`<SHA>`), not cut yet. Owner rulings: pre-freeze tag, then the
audit, then the audit fixes and their gates, then the freeze (2026-11-12, with the freeze after P6-PUB, the SDK and scaas-app
before it: 2026-11-16); scope widened on 2026-11-05 (regulated kinds, `PqChat`, `ua-rs` as the only signer), on 2026-11-12
(`pqz-core`, the Nethermind precompiles, `ua-rs` as audit units) and on 2026-11-22 / 2026-11-24 (the node, the SDK, PqVault, the
app cores, the layer units 22-24 and the cross-cutting units 25-31), and on 2026-11-26 (unit 32 `vendor-falcon-rs`,
a controller call), and on 2026-11-28 (units 33-35 `scaas-matrix`, `scaas-profile`, `scaas-tui`, and the code landed or
pending since unit 32 added to the units that hold it, a controller call; see [Pending landing](#pending-landing)). Prompts in the repository, Codex on every unit in a fixed
order, the ledger, and the results kept local: owner 2026-11-24.

## Target

**The pre-freeze tag `<TAG>` on `main`, commit `<SHA>`.** It is cut once the code in scope is complete on `main`: PR #18
(`ua-mtx-merge`, the `ua*` / `mtx*` merge and everything it carries) is merged, and `ua-rs-sign` merges after it by merge
commits with the rounds it still carries (SDK, PqVault, the app cores).

After the tag, only audit fixes land before the freeze. The audit reads one frozen, detached worktree,
`.claude/worktrees/audit-<TAG>` at `<SHA>` (repo-relative, made with `git worktree add --detach .claude/worktrees/audit-<TAG>
<TAG>`). **The whole of each unit is in scope, not the delta.** Reviewers are read-only: no builds, tests, gas or timing runs,
no commits. Figures come from the gate logs of the tag. The audit does not wait for `zether-soroban` or the calibration, since
neither touches the code in scope.

## Units

Each unit has one self-contained prompt, [prompts/prompt-&lt;unit&gt;.md](prompts/), with the 13-row dimension table of
[review.md §1](../review.md#1-dimensions). The [index](INDEX.md) lists the units with their finding-id prefixes and which units
lead each dimension. Sizes are lines at `ua-mtx-merge` `f13d322e2` / `ua-rs-sign` `9c12e1aac` (units 18-31: at the day they were
added); the rows changed on 2026-11-26 and unit 32: at `b202a6fa2`; units 33-35: on 2026-11-28, at `dev` or at their branch.

| Unit | Files (under the tag) | Size |
|---|---|---|
| `evm-ua-registry` | `smartcontracts/evm/src/ua/{UARegistry,UARegistryCoreLib,UARegistryAuxLib,UARegistryRegLib,UAStore,UAKinds,IUARegistry,IUAVerifier}.sol`, `src/account/`, `src/wallet/`, `src/hedera/`, `src/governance/UAAdmin.sol` | ~5.9 K |
| `evm-ua-verifiers` | `src/ua/{MlDsa,MlDsaVerifyOnly,FnDsa,SlhDsa,Shake,PqNtt,PqUA}.sol`, `src/ua/verifiers/`, `src/common/{Bls12381,BlsMultiKeyData,HashToCurve,Ed25519,Sha512,CurveSigs,SigCheck,WebAuthnClientData,MultiSig}.sol`, `src/pqz/PqzKeyVerifier.sol` | ~5.0 K |
| `evm-metatx-factory` | `src/metatx/`, `src/common/{MetaTxLib,FeePolicy,SaltedEIP712,SSTORE2,ERC7739Lib}.sol`, `src/factory/` | ~9.5 K |
| `evm-tokens-pqz` | `src/pqz/` (but `PqzKeyVerifier.sol`), `src/confidential/`; `PqzSet.sol` at all four sets | ~7.4 K |
| `evm-tokens-zether` | `src/zether/` | ~6.6 K |
| `evm-regulated-public` | `src/regulated/{RegulatedBase,RegulatedLib,ComplianceRegistry,IComplianceRegistry,IRegulatedToken}.sol`, the Normal / Wrapped regulated tokens, cores and modules | ~4.0 K |
| `evm-regulated-confidential` | `src/regulated/` the four PQZ / Zether regulated kinds, cores and modules | ~8.0 K |
| `evm-dex-gov` | `src/dex/`, `src/trade/`, `src/governance/` | ~5.3 K |
| `evm-pqchat` | `src/pqchat/` (with `PqChatTree`, `PqChatTreeMembers`, `PqChatTreeViews`), `src/pqgroup/{PqGroupBase,PqGroupTree,IPqGroupTree}.sol` (+ the registry's `requirePortable` and KEM records, read) | ~4 K |
| `evm-pqvault` | `src/pqvault/` (+ `PqGroupBase` read for PqVault's use) | ~1 K |
| `pqz-core-pqzl` | `pqz-core/pqzl/rust/src/` (production), `pqzl/src/*.{c,h}` (the C oracle), `pqzl/rust/tests/` | ~17 K |
| `pqz-core-pqzh-stmt-ffi` | `pqz-core/pqzh/ligero/src/`, `ligero_params.py`, `pqz-core/stmt/src/`, `pqz-core/ffi/src/`, `ffi/{wasm,wallet-wasm,offchain}/` | ~10 K |
| `pqz-core-params-vectors` | `pqz-core/params/sets/` (generator, `set.toml` per set, generated files), `smartcontracts/vectors/pqz/` and `ffi/src/bin/pqz-vectors.rs` | generator ~2 K + generated |
| `nethermind-precompiles` | `pqz-core/nethermind/Nethermind.Pqz/` (PQZ, ML-DSA-44 / -65 / -87), `chain/{patch-chainspec,add-schedule,check-provisional-ids}.py`, `engine-pqz*.json`, `Dockerfile` | ~1 K C# + scripts |
| `ua-rs-sign` | `clients/ua-rs/src/wallet/{sign,signer,pqsign,uasig,webauthn,tx}.rs`, `src/{falcon,pq,verify,keydata,musig2,frost,groups}.rs`, `src/falcon/soft.rs`, `src/ua_portable.rs`, `src/ua8.rs` (group keys) | ~8 K |
| `ua-rs-custody` | `clients/ua-rs/src/wallet/{vault,store,aead,seal,kem,derive,pairing,manifest,bounded,policy,service_pull}.rs`, `wallet/mod.rs`, `wallet/{tree,tree_public}.rs`, `wallet/appkey.rs` (2026-11-28); pending landing: `wallet/profile.rs` and the `key-handles` feature | ~13 K + ~0.6 K |
| `ua-rs-digests` | `clients/ua-rs/src/wallet/eip712.rs`, `src/{pay,regulated,factory,admin,wraplimit,pqzfee,pqz3k,algorand,near,mldsa_cache}.rs`, `src/facade/`, `src/wallet/{pqchat,pqchat_keys,pqchat_file,pqvault}.rs` | ~12 K |
| `ua-rs-boundary` | `clients/ua-rs/src/{json,lib}.rs`, `src/bin/`, `clients/ua-c/`, the wrappers at their FFI boundary (`ua-cxx`, `ua-qt`, `ua-cs`, `ua-py`, `ua-go`, `ua-dart-frb`), `Cargo.lock`, `deny.toml`, `fuzz/` | ~5 K + wrappers |
| `scaas-node` | `scaas-node/src/` (gateway, job API, lanes, indexer, mesh, DEX venue, adapters per family), `migrations/`, `node.example.toml` | ~102 K with in-file tests |
| `scaas-sdk` | `clients/scaas-sdk/src/` (incl. `line.rs`, `app_core/`), `ffi/`, `bindings/`, `clients/scaas-rpc/src/` | ~53 K + FFI (mostly generated) |
| `app-cores` | `clients/pqchat-core/` (with its Dart binding `ffi/`; its TreeKEM layer `src/tree.rs` in scope since 2026-11-28; pending landing: `src/confirm.rs` and the topic changes), `clients/pqvault-core/` (with `src/item.rs`, sign after confirm) | ~14 K + ~1 K pending |
| `clientkeys-vectors` | `clients/clientkeys/src/`, `scripts/` (the generators), the generators beside `smartcontracts/vectors/`, `pqz-core/ffi/src/bin/pqz-vectors.rs`, `clients/zether-prover/src/vectors.rs`; the vector files `smartcontracts/vectors/`, `smartcontracts/evm/test/vectors/` | ~13 K + ~15 K generators + data |
| `pqz-verifier-deploy` | `scaas-pqz-verifier/`; `smartcontracts/evm/script/` (deploy scripts, release list, books), the factory catalogue as the scripts use it, `release-data/`; the git-ignored books `deployments/<key>.json` (local) | ~2 K + ~33 K scripts |
| `bindings-cli-ci` | the `ua-*` bindings over `libscaas_ua_c` beyond their FFI edge (`ua-c`, `ua-cxx`, `ua-qt`, `ua-cs`, `ua-py`, `ua-go`, `ua-dart`, `ua-dart-frb`), `clients/scaas-cli/`, `.github/workflows/ci.yml`, `.github/ci_changes.py`, every `deny.toml` / lockfile, `scripts/{evm_libs.sh,vendor.sh,mutant_guard.py,format.sh,capped,check_test_features.py,docs_check.py,size_gate.py}` | ~32 K bindings + ~7 K CLI, CI, scripts |
| `crypto-signatures` | read vertically: every signature kind through Solidity, the ML-DSA precompile, the Soroban host, `ua-rs`, clientkeys; purposes and domains | cross-cutting |
| `crypto-pqz` | read vertically: PQZ statements, relations, transcripts, `pqzl` / `pqzh` / `stmt` / `ffi` in C, Rust, wasm, the precompile, the verifier service, the sets, the three-key model | cross-cutting |
| `crypto-kem-seal` | read vertically: KEM scheme 1, seal / open, vault derivation, the PqVault and PqChat wraps, the file seal, the sealed PQZ leaf | cross-cutting |
| `crypto-zether` | read vertically: Zether on BLS12-381 in the contract, `zether-prover`, `ua-rs`, clientkeys, the SDK; MSM; disclosure | cross-cutting |
| `crypto-pqchat-tree` | read vertically: the PqChat TreeKEM schedule, tree hash, node-key admission, PCS on removal; `treekem.js`, `wallet/tree.rs`, `PqGroupTree`, `PqChatTreeMembers` | cross-cutting, ~5 K |
| `cross-layer` | dimension 8 end to end: the vectors and every writer and reader, the node allow-lists against the contracts, records followed both ways, sibling checks | cross-cutting |
| `adversarial` | every role against the whole target: subject / holder / member, admin, relayer, lying RPC (below and above the majority option), front-runner, removed party | cross-cutting |
| `scaas-matrix` | `clients/scaas-matrix/` (`src/{lib,policy,transport}.rs`, tests, `Cargo.lock`, `deny.toml`), `clients/pqchat-transport/` | ~2.8 K + ~1 K tests |
| `scaas-profile` | pending landing (`user-profiles`): `clients/scaas-profile/` (`src/`, tests, `Cargo.lock`, `deny.toml`) | ~5 K + ~4.8 K tests |
| `scaas-tui` | pending landing (`scaas-tui`): `clients/scaas-tui/` (`src/`, `build.rs`, `profiles/`, tests and golden screens, `Cargo.lock`, `deny.toml`) | ~18 K + tests |
| `vendor-falcon-rs` | `vendor/falcon-rs-0.3.1/` (git-ignored, installed and checked by `scripts/vendor.sh`) with its `VENDORED.md`; the `ua-rs` glue `src/falcon/soft.rs`, `src/falcon.rs`, `build.rs` / `Cargo.toml`, `tests/fndsa_vrfy.rs`, `tests/fndsa/`; the reference `vendor/pqclean-falcon-seeded/`, `vendor/pqclean-falcon-seeded.local/seeded.c` (read) | ~14.7 K + glue |

The units of the earlier EVM plan map as follows. A1 is `evm-ua-verifiers`, A2 `evm-tokens-pqz`, A3 `evm-tokens-zether`, A4
`evm-ua-registry`, A5 `evm-metatx-factory`, A6 `evm-dex-gov` (with governance), A7 the two `evm-regulated-*` units, A8
`evm-pqchat`, B1 the four `ua-rs-*` units. There is no separate design unit: each EVM prompt carries the replay matrix (chain
id, `chainUid`, generation, token, release, kind, op, nonce lane) and the library-split checks. The `ua-rs` split follows the
five parts of the T21 review (parts 1 and 2 are `ua-rs-sign`). `pqz-core` follows the units of its 2026-11-13 review (u1
`pqzl`, u2 + u3 `pqzh-stmt-ffi`, u5 `params-vectors`; u4, the plugin, is `nethermind-precompiles`).

**Falcon-1024:** `fndsa1024` (0x0135) verifies in pure Solidity on every EVM chain (CTR-UA-40), so it is audited in
`evm-ua-verifiers`. The Nethermind plugin has no Falcon precompile; `nethermind-precompiles` confirms that nothing wires one. On wasm32 `ua-rs`
keys, signs and verifies both Falcon kinds through the vendored falcon-rs 0.3.1 (CLI-UAL-66); that third-party code is
audited as code, against PQClean's round-3 C, in its own unit `vendor-falcon-rs` (it had no audit before the owner's
stream of 2026-11-26, whose record is its prior review); `crypto-signatures` reads the two paths' parity, `ua-rs-sign` the
glue's use.

Across units: every optimisation that replaced code with shared code, a library or a module must keep behaviour, and the report
says so when it does not.

## Out of scope

- The non-EVM contracts (`smartcontracts/{soroban,solana,near,algorand,move,ton,cosmos}/`). Soroban gets its audit after
  `zether-soroban` and Part D7. NEAR, Algorand and the later families get add-on audits when their UA rounds finish (owner
  2026-10-31, confirmed 2026-11-24).
- `smartcontracts/evm/test/` (read only for what a test can and cannot fail), the deploy runbooks, the SCaaS testnet stack
  (outside this repository).
- Every `*/legacy/` directory, `pqz-core/pqzh/stark-backup/`, `pqz-core/glic/`, `pqz-core/artifact/`, `pqz-core/pqzl/params/`
  (the estimator studies), every `research/` and `history/` directory (background only).
- Gas prices and calibration figures, code size against 24 KiB (the ceiling is 64 KiB), the `UNAUDITED` labels themselves.
- What the owner accepted (each prompt's section 7 lists it, from `docs/decisions.md` and the owner's rulings).

## Reviewers

| Reviewer | Units | How |
|---|---|---|
| **Fable** | all 35, in parallel | one read-only agent per unit, written before reading any other reviewer's report |
| **Codex** (CLI, read-only sandbox, the model and effort of its config, no override; today GPT-6.2-astra, high) | all 35, **one after another** | credits are limited per window, so the units run in the fixed order of [Running order](#running-order), with the local ledger `scratchpad/ai-audit/LEDGER.md` so the run resumes after a credit stop |
| **agy** (Gemini) | all 35, in parallel | the same prompts |
| **Claude workflow** | all 35, in parallel | per unit: finders by lens, three refuters, each with a fresh context, on each finding, rounds until two add nothing, a completeness critic |
| **Fable, a fresh agent** | adjudication and consolidation | every P0-P2 reported by one source checked against the frozen tree; it did not write the unit reports it judges |

Same model family as the implementers: fresh context and refutation reduce that; Codex and agy are what is different.

## How to run

1. Cut `<TAG>` on `main` (see [Target](#target)) and make the frozen worktree:
   `git worktree add --detach .claude/worktrees/audit-<TAG> <TAG>`. Its git-ignored inputs are real directories, not
   symlinks: `scripts/evm_libs.sh install` then `check`, `clients/clientkeys/node_modules`, and `scripts/vendor.sh install`
   then `check` (`vendor/`, which unit `vendor-falcon-rs` reads).
2. Copy `docs/audit/prompts/` into a local, git-ignored folder (for example `scratchpad/ai-audit/run-<TAG>/`) and fill in the
   placeholders there: `sed -i 's/<TAG>/.../g; s/<SHA>/.../g' prompt-*.md`. Replace each prompt's gate-evidence list with the
   tag's own closing-gate summaries. The committed prompts keep `<TAG>` and `<SHA>`.
3. Add the round's rows to the local ledger `scratchpad/ai-audit/LEDGER.md` with the tag filled in.
4. Run each prompt from the root of the main checkout, one terminal per run, in the order of [Running order](#running-order).
   Use the tool's configured model and effort.
5. After each run, update its ledger row (status, counts, date).

## Result naming

`scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-<unit>.md` (local date and hour at the start, lower case, no
spaces, unit last; for example `20261120-09-codex-gpt-6.2-astra-high-evm-pqvault.md`). A tool whose sandbox cannot write files
prints the report, and the runner saves it under that name. The reports, the ledger and each round's closure table (finding id, severity, dimension, verdict,
fix commit) stay local and git-ignored under `scratchpad/ai-audit/`; none of them is committed.

Each report lists findings P0-P3 / info with file:line, the dimension number, the failure scenario, the fix, the evidence and
the confidence; a closure table for the earlier findings in its unit; what it checked and found sound; what it did not cover
(prompt section 9). Then: owner rulings on the findings, a fix round on `main`, the re-audit below, gates at the four sets,
the [audit-rounds table](../decisions.md#audit-rounds) updated (target and status), and the `AI-AUDITED` relabel of what the round covered.

## Pending landing

Code that the audit must cover but that is on a branch, not on `dev`, when a prompt was written is marked **PENDING
LANDING (`<branch>`)** in its prompt: a whole unit (`scaas-profile`: `user-profiles`; `scaas-tui`: `scaas-tui`) or a part of
a unit (`pqchat-core-confirm`: `app-cores`, `scaas-sdk`, `scaas-node`, `bindings-cli-ci`; `pqchat-no-fallback`:
`evm-pqchat`, `pqz-verifier-deploy`; `user-profiles`: `ua-rs-custody`, `scaas-sdk`, `clientkeys-vectors`,
`crypto-kem-seal`, `bindings-cli-ci`). No prompt pins a commit: the round's one pin is the tag's SHA. When the tag is cut,
the controller checks each marked branch: landed in the tag, the mark is dropped in the run copy of the prompts; not landed,
the marked part (or the whole unit) is cut from the run copy, its ledger rows say `not landed`, and the round's summary lists
it as not covered. The [index](INDEX.md#code-added-after-unit-32) lists every such path with its unit.

## Running order

**Fable, agy and Claude** run all 35 units in parallel after the tag. A cross-cutting unit run before its layer units has no
layer reports to read for leads; it is complete without them.

**Codex** runs all 35 units in sequence: tier 1, then tiers 2, 3 and 4. Within a tier, a unit with a Fable P0 or P1 goes first;
the others keep the order listed.

| Tier | What it guards | Units, in order |
|---|---|---|
| 1 | keys, plaintext, value, forgery | `crypto-pqz`, `crypto-signatures`, `crypto-kem-seal`, `nethermind-precompiles`, `ua-rs-custody`, `evm-ua-verifiers`, `evm-tokens-pqz`, `vendor-falcon-rs` |
| 2 | authorization and integrity | `adversarial`, `cross-layer`, `evm-ua-registry`, `evm-metatx-factory`, `scaas-node`, `scaas-sdk`, `clientkeys-vectors`, `scaas-profile` |
| 3 | — | `crypto-pqchat-tree`, `crypto-zether`, `evm-pqchat`, `evm-pqvault`, `ua-rs-sign`, `ua-rs-digests`, `ua-rs-boundary`, `pqz-core-pqzl`, `pqz-core-pqzh-stmt-ffi`, `pqz-core-params-vectors`, `scaas-matrix` |
| 4 | — | `evm-dex-gov`, `evm-regulated-public`, `evm-regulated-confidential`, `evm-tokens-zether`, `app-cores`, `pqz-verifier-deploy`, `bindings-cli-ci`, `scaas-tui` |

The four tiers name each of the 35 units exactly once (8 + 8 + 11 + 8). The units of 2026-11-28 go last in their tiers:
`scaas-profile` in tier 2 (the store's integrity: rollback, the journal, the lock, hidden profiles; its keys are the arena in
`ua-rs-custody`, tier 1), `scaas-matrix` in tier 3 beside the other chat units, `scaas-tui` in tier 4 beside the other
front-end code. This order replaces the earlier "what Codex saw least
first" order. A FRAME part of a prompt (since 2026-11-28 only `app-cores`: the biometric unlock) is
finalized before its run, or the run covers the rest and lists the FRAME part as not covered.

**Resume.**
- A run stopped by credits is marked `aborted-credits` and reruns the whole unit; its partial output is not trusted.
- The next run is the first unit in this order without a `done` row for that tool at that tag in
  `scratchpad/ai-audit/LEDGER.md`.
- A unit too big for one Codex run is split in two prompts, each with its own ledger row. The candidates are the largest
  units, `scaas-node` and `scaas-sdk` (then `evm-metatx-factory` and `evm-regulated-confidential`). None is split now.

**Re-audit after the fixes.**
- The runs above are on the frozen tag.
- After the fixes, only the units whose scope files changed rerun; each rerun reads the tag→fix diff plus the unit.
- An unchanged unit keeps its result, marked "unchanged since `<SHA>`".

**Later rounds** (the non-EVM add-on audits, the gate before mainnet 22777) add their units here and follow the same order
rules and the same local ledger.

## Prior reviews each unit reads (closure table in every report)

Folders under `scratchpad/` are local and not in the repository; the prompts name them so a run on the owner's machine reads
them. A rerun elsewhere reads the committed records only.

- **EVM:** `pqz-core/research/code-review-2026-10-26/README.md` (at `64549aa4`), `code-review-2026-10-19/README.md`;
  `docs/research/security-review-record.md`; `docs/research/{regulated-kinds,paytax,pqzver,attest}-{codex,fable}-review.md`,
  `zether-msm-crypto-review.md`, `eip7702-audit-2026-10-30.md`; local `scratchpad/review-ua-mtx-merge/` (A-E, recheck,
  recheck2).
- **pqz-core and the plugin:** `pqz-core/research/code-review-2026-10-19/`, `-10-25/`, `-10-26/`, `-11-13/fix-round.md`,
  `-11-15/fix-round.md`; local `scratchpad/review-3w/` and `scratchpad/review-3zh/`.
- **ua-rs:** local `scratchpad/review-t21/` (T21 at `806f4f2c2`: scope, ledger of 71 rows, owner decisions O1-O8, Fable and Codex
  parts 1-5) and the fix waves after it; `docs/research/ua-rs-sign-fable-review.md`, `ua-rs-sign-codex-review.md`.
- **Node, SDK, PqVault, app cores, TreeKEM:** each prompt's section 8 names its own (local review folders and the committed
  specs' review sections).
- **The review-fix round (2026-11-24 to -26):** local `scratchpad/treekem-g1-review-20261124-1550/` (the TreeKEM and G1
  code review), `scratchpad/review-fix-review-20261125-1959/` (the re-review) and `scratchpad/review-fix-check-20261126-0429/`
  (the fix check), each with its `STATUS.md`; every changed unit names them.
- **falcon-rs:** the committed record [audited/vendor-falcon-rs.md](audited/vendor-falcon-rs.md) (unit `vendor-falcon-rs`).

## Gate evidence

Each report reads the tag's gate summaries for what was run. A green gate is not evidence of soundness. When the tag is cut, the
controller replaces each prompt's list with the tag's own closing gates: every forge directory at the default set and the
set-sensitive tests at the other three sets, the size gate, the node suite and e2e, the client gates, and the pqz-core full gate
at the four sets on the final core tree (`pqz-core/runs/gate/`).

## Open

- Whether one run per unit fits each tool's context. A tool that stops early lists what it did not cover, and the controller
  splits that unit (see Resume).
- A unit no reviewer reaches is listed as not covered in the round's summary.
