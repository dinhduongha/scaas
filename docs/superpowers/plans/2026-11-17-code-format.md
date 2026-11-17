# Code formatting in every language: plan

**Status (2026-11-17):** PLANNED, a frame; nothing formatted yet. Owner 2026-11-17: "Ok, theo đề xuất" (format in one
mechanical commit per component after the open branches merge; Solidity with the code-hash re-pin before the pre-freeze tag),
then "Về format, làm cho cả các ngôn ngữ khác: dart, cs .v.v." (do it for the other languages too: Dart, C#, and so on),
then "Ok, theo đề xuất, ghi vào plan" (`bytecode_hash = "none"` with F2; the CI job checks only), then "Format code tất cả
luôn chứ. Sao chỉ format code mỗi Solidity? Cập nhật cấu hình format code luôn, như bảng config trên kia?" (format every
language now, with every config file of the table, in the same round).

**Why.** No formatter runs anywhere: no `rustfmt.toml`, no `[fmt]` in `foundry.toml`, no format step in CI. Measured
2026-11-17 on `ua-rs-sign` (`cargo fmt -- --check -l`, `forge fmt --check`):

| Component | Files that differ / files |
|---|---|
| `pqz-core/pqzl` | 0 / 71 |
| `scaas-node` | 59 / 125 |
| `clients/ua-rs` | 98 / 112 |
| `clients/zether-prover` | 29 / 38 |
| `scaas-pqz-verifier` | 6 / 7 |
| `smartcontracts/evm/src` (Solidity) | about 134 / 153 |

The other languages were not measured yet; task F0 measures them.

## Where each tool reads its settings

Every setting lives in a committed config file, never only in a command line, so a developer, an editor and CI format the same
way (owner 2026-11-17: "nhớ đặt trong cấu hình luôn"):

| Language | Config file | Note |
|---|---|---|
| Rust | `rustfmt.toml` at the repository root | not `Cargo.toml`: rustfmt reads no Cargo section; it looks for `rustfmt.toml` in the crate's directory and every parent, so one root file covers every crate; the toolchain is already pinned by `rust-toolchain.toml` |
| Solidity | `[fmt]` in `smartcontracts/evm/foundry.toml` | beside `bytecode_hash = "none"` in `[profile.*]` |
| JavaScript | `clients/clientkeys/.prettierrc` | Prettier pinned in `package.json` `devDependencies` |
| Python | `[tool.ruff]` in a root `pyproject.toml`, or `ruff.toml` | one file for every Python directory |
| Go | none | `gofmt` has no settings |
| C# | `clients/ua-cs/.editorconfig` | `dotnet format` reads it |
| Dart | `analysis_options.yaml` of each package (`formatter: page_width`) | |
| C / C++ / Qt | `.clang-format` at the repository root | clang-format looks in parent directories too |

## Bundled: `setAuditor` on one governance bit (owner 2026-11-17)

Owner 2026-11-17: "Do format phải chạy lại rất nhiều, tiện thể làm luôn '- setAuditor', dùng 1 bit cho việc này. Gom chung vào
format code, để chạy gate .v.v. 1 lần" (since formatting forces a long re-run anyway, build `setAuditor` now, on one bit, and
bundle it with the formatting so the gates run once). This replaces the "no setter" Change of CTR-ZTH-41 (2026-11-17) for the
built setter; CTR-ZTH-09 changes with it.

| Item | Proposal (controller calls, owner may override) |
|---|---|
| Bit | **32 `AUDITOR`**, the next free bit of the global table (`smartcontracts/vectors/governance/governance_bits.json`: 0–31 allocated, 13 and 14 never reused) |
| Power | the holder replaces the auditor key of a confidential token: the Zether auditor key, the PQZ auditor UA; on the confidential kinds and their regulated twins only, refused (`FeatureInvalidForKind`) elsewhere |
| Mode | `auditorMode` stays immutable (CTR-ZTH-49, CTR-PQZ-24): a NONE token never gains an auditor; FULL and OPTIONAL keep one, so the new key is never empty |
| Delay | never delay-relaxed, like `TAX`; the change takes effect after the governance delay that applies to the bit, announced by an event first, so holders can leave before it reads their later amounts |
| History | every operation records the auditor key version it encrypted to (PQZ already writes the auditor's version in the operation tail; Zether gains an auditor version counter and keeps every earlier key), so a disclosure of an old operation checks against the key of its time |
| Entries | the token's direct entry (admin and chain word rules of CTR-GOV-27 / CTR-GOV-28) and a router `mtx*` op with its typed struct; node rows, `ua-rs` / clientkeys builders, vectors |
| Size | `WrappedPqzToken` and the regulated kinds are near the 64 KiB line: count bytes first; a module split is asked of the owner before it is made |
| Risk, stated | a bit holder can move every later amount's readability to a key of its choice; the delay, the event and an `msig` holder are the guard |

Its own spec section and tasks follow this frame (contract, prover / `zether-prover`, `ua-rs`, clientkeys, node, docs), tests
first and mutants per check. **One run for everything:** F2 (forge fmt), `bytecode_hash = "none"` and `setAuditor` land together,
then one compile, one re-pin of every code hash, one full gate (every forge directory, the four PQZ sets, node e2e, clients), one
SCaaS testnet reset with deploy, verify and matrix, before the pre-freeze tag.

## Rules for every task

- **Formatting only.** One commit per component, made by the tool alone: `<component>: format (<tool> <version>), no other
  change`. No hand edit in the same commit. Every gate of the component runs after it with the same counts as before.
- **Excluded:** `*/legacy/*` (not edited), generated files (`pqz-core/params/sets/*/PqzSet.sol` and `smartcontracts/evm/src/pqz/PqzSet.sol`,
  flutter_rust_bridge output, cbindgen and UniFFI headers, generated vectors under `smartcontracts/vectors/`), vendored code
  (`smartcontracts/evm/lib/`, `node_modules/`). Existing Vietnamese comments stay as they are (formatters do not rewrite comment
  text; a tool option that would is off).
- **One pinned tool version per language**, written in the config file or the CI step.
- **When (owner 2026-11-17):** every language in the pre-freeze contract round, branch `prefreeze-contracts`, after PqVault Part R
  and `setAuditor` are built and before the one full gate: the config files first (the table above), then one commit per
  component, then the CI job. **Open branches** (`scaas-rpc` code on `scaas-sdk`, and any other) run the same formatters with the
  same pinned configs on their own tree before they merge: lines they did not change then become identical on both sides and
  merge cleanly, so conflicts stay where a branch really changed code.
- **CI:** one `format` job that runs every check below and fails on a difference; added in the last task, after every component
  is clean.

## Tasks

| Task | Language / component | Tool | Config | Notes |
|---|---|---|---|---|
| F0 | all | — | — | measure each language below (`--check` modes only), pin the versions, list the generated files to exclude |
| F1 | Rust: `scaas-node`, `clients/ua-rs`, `clients/zether-prover`, `scaas-pqz-verifier`, `clients/scaas-*`, `pqz-core` crates, the family contracts' Rust (Soroban, Solana, NEAR, Cosmos) | `rustfmt` (the toolchain's) | one `rustfmt.toml` at the root (`max_width` about 120, the code's current width; edition from each crate) | **panic locations** (`file:line` in the binary) move: contract wasm hashes and pinned deploy hashes of the families change. Every family is test-only and deployed only to local networks, so the family contracts are formatted in this round too and every pinned wasm hash is regenerated in the same gate run |
| F2 | Solidity: `smartcontracts/evm/src`, `test/`, `script/` | `forge fmt` (Foundry 1.8.5) | `[fmt]` in `foundry.toml` (`line_length` about 120, the code's style) | **The bytecode changes:** without `bytecode_hash = "none"` the metadata hash of the source is in the runtime code, so every pinned code hash (the factory catalogue, `LinkClosure`, the `*_CODEHASH` constants, `size-baseline.json`) moves, and deployed contracts no longer verify on Blockscout. Do it once, **before the pre-freeze tag**, with the re-pin and the SCaaS testnet reset. **Same task (owner 2026-11-17): `bytecode_hash = "none"` in `foundry.toml`** (every profile), so the runtime code no longer carries the metadata's IPFS hash: later comment, NatSpec or format edits move no code hash, each contract is about 40 B smaller, builds reproduce across hosts. Costs: Sourcify gives only a partial match (Blockscout's verify, `verify.sh`, is unaffected: it compiles with the same settings); every code hash, initcode hash and CREATE2 / CREATE3 address moves once, so the re-pin and the reset carry both changes together. A record of the sizes before and after (`size-baseline.json` moved with old → new figures) |
| F3 | JavaScript: `clients/clientkeys`, scripts | Prettier, pinned in `clients/clientkeys/package.json` devDependencies | `.prettierrc` | the generator scripts' output (vectors) must not change |
| F4 | Python: scripts, `clients/ua-py`, `pqz-core` tools | `ruff format` | `ruff.toml` or `pyproject.toml` | |
| F5 | Go: `clients/ua-go` | `gofmt` | none | |
| F6 | C#: `clients/ua-cs` | `dotnet format` | `.editorconfig` | run `dotnet build-server shutdown` after (AGENTS.md) |
| F7 | Dart: `clients/ua-dart`, `clients/ua-dart-frb` (hand-written files only) | `dart format` | `analysis_options.yaml` / the page width | |
| F8 | C / C++ / Qt: `clients/ua-c` (tests, smoke), `clients/ua-cxx`, `clients/ua-qt`, `pqz-core` C oracle | `clang-format`, pinned (not installed on this host: a pinned pip wheel or the distribution's package) | `.clang-format` | the C oracle's KAT outputs must not change |
| F9 | the CI `format` job and `scripts/format.sh` | all of the above, **check modes only** in CI: `cargo fmt --check`, `forge fmt --check`, `prettier --check`, `ruff format --check`, `gofmt -l` (non-empty fails), `dotnet format --verify-no-changes`, `dart format --output=none --set-exit-if-changed`, `clang-format --dry-run -Werror` | `.github/workflows/ci.yml` (header list updated); `scripts/format.sh` fixes locally, `scripts/format.sh --check` runs what CI runs | owner 2026-11-17 ("Sửa cả CI luôn"): the CI change lands in this round, in the same PR as F1–F8, so the PR's CI already runs it green. The job installs each tool at its pinned version: the `rustfmt` component of `rust-toolchain.toml`, Foundry 1.8.5, Prettier from `clients/clientkeys/package-lock.json` (`npm ci`), `ruff` pinned by pip, the .NET SDK of `ua-cs`, the Dart SDK of `ua-dart`, `clang-format` as a pinned pip wheel, Go of `ua-go`; the `ci.yml` header list of every job's commands gains the `format` row. CI never rewrites code, it fails on any difference; the tools at their pinned versions; no build, so the job is light and runs on every PR; enabled only after F1–F8 left every component clean; a pre-commit hook is optional, not required |
| F10 | the other repositories | the same tools | scaas-app (Rust, Dart, C++), the Qt repository (C++, QML: `qmlformat`) | on their own branches, with the same rules |

Not covered yet: Move (Aptos, Sui) and TON sources, whose formatters are not installed; F0 reports what exists.
