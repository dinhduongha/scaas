# Code formatting in every language: plan

**Status (2026-11-17):** PLANNED, a frame; nothing formatted yet. Owner 2026-11-17: "Ok, theo đề xuất" (format in one
mechanical commit per component after the open branches merge; Solidity with the code-hash re-pin before the pre-freeze tag),
then "Về format, làm cho cả các ngôn ngữ khác: dart, cs .v.v." (do it for the other languages too: Dart, C#, and so on),
then "Ok, theo đề xuất, ghi vào plan" (`bytecode_hash = "none"` with F2; the CI job checks only).

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

## Rules for every task

- **Formatting only.** One commit per component, made by the tool alone: `<component>: format (<tool> <version>), no other
  change`. No hand edit in the same commit. Every gate of the component runs after it with the same counts as before.
- **Excluded:** `*/legacy/*` (not edited), generated files (`pqz-core/params/sets/*/PqzSet.sol` and `smartcontracts/evm/src/pqz/PqzSet.sol`,
  flutter_rust_bridge output, cbindgen and UniFFI headers, generated vectors under `smartcontracts/vectors/`), vendored code
  (`smartcontracts/evm/lib/`, `node_modules/`). Existing Vietnamese comments stay as they are (formatters do not rewrite comment
  text; a tool option that would is off).
- **One pinned tool version per language**, written in the config file or the CI step.
- **When:** after the open branches (`ua-rs-native`, `scaas-rpc` on `scaas-sdk`, and any code branch then open) have merged into
  `ua-rs-sign`, so no branch carries a conflict on every line; then each later branch formats before it merges.
- **CI:** one `format` job that runs every check below and fails on a difference; added in the last task, after every component
  is clean.

## Tasks

| Task | Language / component | Tool | Config | Notes |
|---|---|---|---|---|
| F0 | all | — | — | measure each language below (`--check` modes only), pin the versions, list the generated files to exclude |
| F1 | Rust: `scaas-node`, `clients/ua-rs`, `clients/zether-prover`, `scaas-pqz-verifier`, `clients/scaas-*`, `pqz-core` crates, the family contracts' Rust (Soroban, Solana, NEAR, Cosmos) | `rustfmt` (the toolchain's) | one `rustfmt.toml` at the root (`max_width` about 120, the code's current width; edition from each crate) | **panic locations** (`file:line` in the binary) move: contract wasm hashes and pinned deploy hashes of the families change. Format the family contracts only with their next redeploy, and re-pin |
| F2 | Solidity: `smartcontracts/evm/src`, `test/`, `script/` | `forge fmt` (Foundry 1.8.5) | `[fmt]` in `foundry.toml` (`line_length` about 120, the code's style) | **The bytecode changes:** without `bytecode_hash = "none"` the metadata hash of the source is in the runtime code, so every pinned code hash (the factory catalogue, `LinkClosure`, the `*_CODEHASH` constants, `size-baseline.json`) moves, and deployed contracts no longer verify on Blockscout. Do it once, **before the pre-freeze tag**, with the re-pin and the SCaaS testnet reset. **Same task (owner 2026-11-17): `bytecode_hash = "none"` in `foundry.toml`** (every profile), so the runtime code no longer carries the metadata's IPFS hash: later comment, NatSpec or format edits move no code hash, each contract is about 40 B smaller, builds reproduce across hosts. Costs: Sourcify gives only a partial match (Blockscout's verify, `verify.sh`, is unaffected: it compiles with the same settings); every code hash, initcode hash and CREATE2 / CREATE3 address moves once, so the re-pin and the reset carry both changes together. A record of the sizes before and after (`size-baseline.json` moved with old → new figures) |
| F3 | JavaScript: `clients/clientkeys`, scripts | Prettier, pinned in `clients/clientkeys/package.json` devDependencies | `.prettierrc` | the generator scripts' output (vectors) must not change |
| F4 | Python: scripts, `clients/ua-py`, `pqz-core` tools | `ruff format` | `ruff.toml` or `pyproject.toml` | |
| F5 | Go: `clients/ua-go` | `gofmt` | none | |
| F6 | C#: `clients/ua-cs` | `dotnet format` | `.editorconfig` | run `dotnet build-server shutdown` after (AGENTS.md) |
| F7 | Dart: `clients/ua-dart`, `clients/ua-dart-frb` (hand-written files only) | `dart format` | `analysis_options.yaml` / the page width | |
| F8 | C / C++ / Qt: `clients/ua-c` (tests, smoke), `clients/ua-cxx`, `clients/ua-qt`, `pqz-core` C oracle | `clang-format`, pinned (not installed on this host: a pinned pip wheel or the distribution's package) | `.clang-format` | the C oracle's KAT outputs must not change |
| F9 | the CI `format` job and `scripts/format.sh` | all of the above, **check modes only** in CI: `cargo fmt --check`, `forge fmt --check`, `prettier --check`, `ruff format --check`, `gofmt -l` (non-empty fails), `dotnet format --verify-no-changes`, `dart format --output=none --set-exit-if-changed`, `clang-format --dry-run -Werror` | `.github/workflows/ci.yml` (header list updated); `scripts/format.sh` fixes locally, `scripts/format.sh --check` runs what CI runs | owner 2026-11-17: CI never rewrites code, it fails on any difference; the tools at their pinned versions; no build, so the job is light and runs on every PR; enabled only after F1–F8 left every component clean; a pre-commit hook is optional, not required |
| F10 | the other repositories | the same tools | scaas-app (Rust, Dart, C++), the Qt repository (C++, QML: `qmlformat`) | on their own branches, with the same rules |

Not covered yet: Move (Aptos, Sui) and TON sources, whose formatters are not installed; F0 reports what exists.
