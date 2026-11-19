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

### F0 measurement (2026-11-17, `prefreeze-contracts`, the committed configs below, check modes only)

Files that differ / files, generated, vendored and `legacy/` files left out. Rust at rustfmt's default width 100, every
other language at 120 (owner rulings below). The earlier "`pqz-core/pqzl` 0 / 71" (top table) does not reproduce: `pqzl` is
47 / 70 at 100 and 46 / 70 at 120.

**Widths (owner 2026-11-17).** "Dùng độ rộng mặc định 100, không dùng 120" then "Chỉ cho rust thôi": Rust uses rustfmt's
default `max_width` 100 (the root `rustfmt.toml` has no `max_width` line); every other language keeps 120 (`.clang-format`
`ColumnLimit`, `.prettierrc` `printWidth`, ruff `line-length`, Dart `page_width`, taplo `column_width`, and F2's
`foundry.toml` `[fmt]` `line_length = 120`).

**Gate for a format-only commit (owner 2026-11-17).** "Đổi format code không phải chạy full gate": a format-only commit runs
the affected steps of the component, never the full `gate.sh`; for the pqz-core C core that is kat, tbox, sv, fnv, rust and
fuzz, plus `pqz-vectors --check` and `pqz_kat.py --check`, with outputs (KAT JSON, fnv digests, vectors) byte-identical to
the baseline. A formatted file that changes any output stops the work and is reported.

| Language | Tool (pin) | Differ / files | Largest components |
|---|---|---|---|
| Rust | rustfmt 1.9.0 (toolchain 1.97.1), width 100 | 412 / 449 | `clients/ua-rs` 102 / 105, `scaas-node` 59 / 61, `pqz-core/pqzl` 47 / 70, `pqz-core/pqzh` 39 / 39, `smartcontracts/near` 31 / 33, `clients/zether-prover` 29 / 30, `pqz-core/ffi` 27 / 27, `smartcontracts/soroban` 26 / 27 |
| Solidity | forge fmt (Foundry 1.8.5, no `[fmt]` yet) | 517 / 568 | `src` 134 / 166, `test` 359 / 378, `script` 24 / 25 |
| JavaScript / TS | Prettier 3.3.3 | 119 / 119 | `clients/clientkeys` 89 / 89, `smartcontracts/ton` 9 / 9 |
| Python | ruff 0.16.4 | 369 / 372 | `smartcontracts/evm` 231 / 231, `smartcontracts/algorand` 28 / 28, `pqz-core` 68 / 69 |
| Go | gofmt (Go 1.22.2) | 2 / 6 | `clients/ua-go` |
| C# | dotnet format whitespace (SDK 10.0.115) | 4 / 23 | `clients/ua-cs` 2 / 6, `pqz-core/nethermind` 2 / 17 |
| Dart | dart format (SDK 3.12.2) | 8 / 12 | `clients/ua-dart` 4 / 8, `clients/ua-dart-frb` 4 / 4 |
| C / C++ / Qt | clang-format 19.1.7 | 61 / 62 | `pqz-core/pqzl` 33 / 33 (GNU style today), `pqz-core/research` 13 / 13, `clients/ua-cxx` 5 / 5 |
| YAML | Prettier 3.3.3 | 5 / 8 | `.github` 1 / 1 (one workflow file), `pqz-core/nethermind` 2 / 2, `smartcontracts/algorand` 2 / 2 |
| Shell | shfmt 3.10.0 | 301 / 312 | `smartcontracts/evm` 132 / 132, `pqz-core` 138 / 144 |
| TOML | taplo 0.9.3 | 22 / 87 | `smartcontracts/near` 5 / 10, `pqz-core/params` 4 / 4 |
| Dockerfiles | hadolint 2.15.1 (lint) | 3 / 3 with findings | DL3008, DL4006, DL3003 |
| Workflows | actionlint 1.7.12 (lint) | 0 / 1 with findings | |

Excluded and why: `legacy/`; vendored LaZer (`pqz-core/pqzl/lazer/`), PQClean (`clients/ua-rs/vendor/`); generated: the set
headers and Rust of `pqz-core/params/sets/` (gen_set.py, to_rust.py), `pqz-core/pqzl/rust/src/params/mod.rs`,
`pqz-core/stmt/src/sets.rs`, `pqz-core/nethermind/Nethermind.Pqz/PqzSetIds.cs`, `pqz-core/pqzl/params/*/` and
`pqz_aes_gen.h`, the cbindgen header `clients/ua-c/include/scaas_ua.h`, flutter_rust_bridge output
(`clients/ua-dart-frb/lib/src/rust/`, `rust/src/frb_generated.rs`), `smartcontracts/evm/src/pqz/PqzSet.sol`, the vectors'
JSON. **Text read by a harness** stays unformatted until the harness matches the new text: `pqzl/src/pqz_sv.c`
(`sv/check_sv_fixes.sh` and `sv/review/review.sh` revert lines by `sed`), `pqzl/src/pqz_rel.c` (`artifact/reproduce.sh`),
`ffi/pqz_ffi.h` (`ffi/tests/ffi.rs` `header_matches` reads its declarations) (owner 2026-11-18, "Như đề xuất"). They are
listed in the root `.clang-format-ignore`, which both the format runs and F9's `clang-format --dry-run -Werror` read.
**Generated Rust behind `#[path]`** (owner 2026-11-18): `#[rustfmt::skip]` on the `mod` lines that reach it (`pqzl/rust/src/lib.rs`
`mod params`, the seven `mod lattice` / `mod pqzh` of `pqzh/ligero/src/set.rs`; `stmt` reads its `sets.rs` by `include!`, which
rustfmt does not follow), so `cargo fmt` and `cargo fmt --check` leave `params/sets/*/` and `pqzl/rust/src/params/mod.rs`
alone; the attribute changes no compiled output. Move and TON sources: no formatter installed.

Pins and where they live: rustfmt by `rust-toolchain.toml`; Prettier 3.3.3 in `clients/clientkeys/package.json`
`devDependencies`; ruff 0.16.4 by `required-version` in `pyproject.toml`; clang-format 19.1.7 (PyPI wheel, sha256
`f4906fb4…667f11c`), shfmt 3.10.0, taplo 0.9.3 (the release has no checksums: built from crates.io with
`cargo install --locked`), actionlint 1.7.12, hadolint 2.15.1 (each release binary checked against the release's published
sha256) in F9's CI step and `scripts/format.sh`. Locally they sit in the git-ignored `scratchpad/tools/`.

## Where each tool reads its settings

Every setting lives in a committed config file, never only in a command line, so a developer, an editor and CI format the same
way (owner 2026-11-17: "nhớ đặt trong cấu hình luôn"):

| Language | Config file | Note |
|---|---|---|
| Rust | `rustfmt.toml` at the repository root | not `Cargo.toml`: rustfmt reads no Cargo section; it looks for `rustfmt.toml` in the crate's directory and every parent, so one root file covers every crate; the toolchain is already pinned by `rust-toolchain.toml` |
| Solidity | `[fmt]` in `smartcontracts/evm/foundry.toml` | beside `bytecode_hash = "none"` in `[profile.*]` |
| JavaScript | `.prettierrc` and `.prettierignore` at the repository root | Prettier pinned in `clients/clientkeys/package.json` `devDependencies`; at the root because Prettier also formats the YAML of F8b and the scripts outside clientkeys (the same place as scaas-app) |
| Python | `[tool.ruff]` in a root `pyproject.toml`, or `ruff.toml` | one file for every Python directory |
| Go | none | `gofmt` has no settings |
| C# | `.editorconfig` at the repository root (`[*.cs]`) | `dotnet format` reads it; the same file holds the shell section shfmt reads |
| Dart | `analysis_options.yaml` of each package (`formatter: page_width`) | |
| C / C++ / Qt | `.clang-format` and `.clang-format-ignore` at the repository root | clang-format looks in parent directories too; `ReflowComments: false` beside scaas-app's values, so comment text is never rewritten |

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
| F1 | Rust: `scaas-node`, `clients/ua-rs`, `clients/zether-prover`, `scaas-pqz-verifier`, `clients/scaas-*`, `pqz-core` crates, the family contracts' Rust (Soroban, Solana, NEAR, Cosmos) | `rustfmt` (the toolchain's) | one `rustfmt.toml` at the root, rustfmt's default width 100 (owner 2026-11-17, Rust only); edition from each crate. The pqz-core core crates (`pqzl`, `pqzh/ligero`, `stmt`, `ffi`) were not clean at 100 (46, 21, 3, 22 hand-written files); owner 2026-11-18 ("Như đề xuất"): `#[rustfmt::skip]` on the `mod` lines that reach generated code (see the exclusions above), then formatted at 100 (`71a974bc9`), verified by the affected steps: every output byte-identical to the baseline, `pqz-core/runs/gate/format-71a974bc9-summary.txt` (2026-11-18) | **panic locations** (`file:line` in the binary) move: contract wasm hashes and pinned deploy hashes of the families change. Every family is test-only and deployed only to local networks, so the family contracts are formatted in this round too and every pinned wasm hash is regenerated in the same gate run |
| F2 | Solidity: `smartcontracts/evm/src`, `test/`, `script/` | `forge fmt` (Foundry 1.8.5) | `[fmt]` in `foundry.toml` (`line_length = 120`, owner 2026-11-17) | **The bytecode changes:** without `bytecode_hash = "none"` the metadata hash of the source is in the runtime code, so every pinned code hash (the factory catalogue, `LinkClosure`, the `*_CODEHASH` constants, `size-baseline.json`) moves, and deployed contracts no longer verify on Blockscout. Do it once, **before the pre-freeze tag**, with the re-pin and the SCaaS testnet reset. **Same task (owner 2026-11-17): `bytecode_hash = "none"` in `foundry.toml`** (every profile), so the runtime code no longer carries the metadata's IPFS hash: later comment, NatSpec or format edits move no code hash, each contract is about 40 B smaller, builds reproduce across hosts. Costs: Sourcify gives only a partial match (Blockscout's verify, `verify.sh`, is unaffected: it compiles with the same settings); every code hash, initcode hash and CREATE2 / CREATE3 address moves once, so the re-pin and the reset carry both changes together. A record of the sizes before and after (`size-baseline.json` moved with old → new figures) |
| F3 | JavaScript: `clients/clientkeys`, scripts | Prettier, pinned in `clients/clientkeys/package.json` devDependencies | `.prettierrc` | the generator scripts' output (vectors) must not change |
| F4 | Python: scripts, `clients/ua-py`, `pqz-core` tools | `ruff format` | `ruff.toml` or `pyproject.toml` | |
| F5 | Go: `clients/ua-go` | `gofmt` | none | |
| F6 | C#: `clients/ua-cs` | `dotnet format` | `.editorconfig` | run `dotnet build-server shutdown` after (AGENTS.md) |
| F7 | Dart: `clients/ua-dart`, `clients/ua-dart-frb` (hand-written files only) | `dart format` | `analysis_options.yaml` / the page width | |
| F8 | C / C++ / Qt: `clients/ua-c` (tests, smoke), `clients/ua-cxx`, `clients/ua-qt`, `pqz-core` C oracle | `clang-format`, pinned (not installed on this host: a pinned pip wheel or the distribution's package) | `.clang-format` | the C oracle's KAT outputs must not change |
| F8b | CI / CD and build files: `.github/workflows/*.yml` (8 YAML files), the shell scripts (314 `*.sh`: `scripts/`, `smartcontracts/*/scripts`, gate runners, `runs/*.sh`), the TOML configs (87: `Cargo.toml`, `foundry.toml`, `node.example.toml`, …), the Dockerfiles (5) | YAML: Prettier (the pinned one of F3); shell: `shfmt` (pinned binary, `-i 4 -ci`, POSIX `sh` scripts parsed as `posix`, `bash` ones as `bash`); TOML: `taplo fmt` (pinned); Dockerfiles: `hadolint` as a lint, no formatter exists; workflows also linted by `actionlint` (pinned) | `.prettierrc` (YAML overrides), `.editorconfig` (shell indent read by `shfmt`), `taplo.toml` | owner 2026-11-17: "Ý tôi là sửa format code trong CI/DI luôn" (format the CI / CD code too). A reformatted script must behave the same: every gate runner the round uses runs after its format commit; `node.example.toml` keeps its comments; a TOML reorder is off (`reorder_keys = false`), so `Cargo.toml` feature lists and pins keep their order; none of these tools is installed on this host, so F0 pins and fetches them |
| F9 | the CI `format` job and `scripts/format.sh` | all of the above, F8b included (`prettier --check` on YAML, `shfmt -d`, `taplo fmt --check`, `actionlint`, `hadolint`), **check modes only** in CI: `cargo fmt --check`, `forge fmt --check`, `prettier --check`, `ruff format --check`, `gofmt -l` (non-empty fails), `dotnet format --verify-no-changes`, `dart format --output=none --set-exit-if-changed`, `clang-format --dry-run -Werror` | `.github/workflows/ci.yml` (header list updated); `scripts/format.sh` fixes locally, `scripts/format.sh --check` runs what CI runs | owner 2026-11-17 ("Sửa cả CI luôn"): the CI change lands in this round, in the same PR as F1–F8, so the PR's CI already runs it green. The job installs each tool at its pinned version: the `rustfmt` component of `rust-toolchain.toml`, Foundry 1.8.5, Prettier from `clients/clientkeys/package-lock.json` (`npm ci`), `ruff` pinned by pip, the .NET SDK of `ua-cs`, the Dart SDK of `ua-dart`, `clang-format` as a pinned pip wheel, Go of `ua-go`; the `ci.yml` header list of every job's commands gains the `format` row. CI never rewrites code, it fails on any difference; the tools at their pinned versions; no build, so the job is light and runs on every PR; enabled only after F1–F8 left every component clean; a pre-commit hook is optional, not required |
| F10 | the other repositories | the same tools | scaas-app: done 2026-11-17 (owner "cập nhật luôn bên scaas-app"; its `rustfmt.toml`, `.clang-format`, `.editorconfig`, `.prettierrc`, `taplo.toml` and a check-only `format.yml`, before any code exists). F0 here takes the **same values** (`ColumnLimit` / `printWidth` / `column_width` 120, LLVM base with 4-space indent, no TOML reorder) so both repositories format alike, except Rust: rustfmt's default 100 here (owner 2026-11-17, Rust only); scaas-app's `rustfmt.toml` still says `max_width = 120` and follows when the owner says so. The Qt repository (C++, QML: `qmlformat`) on its own branch | the same rules |
| F11 | the rest of C#, JavaScript / TypeScript and Python (owner 2026-11-18: before the merge, after the bundle) | `dotnet format whitespace`; Prettier 3.3.3; `ruff format` 0.16.4 | `.editorconfig`, `.prettierrc`, `pyproject.toml` (the existing ones) | **done** (`prefreeze-contracts`): `bfdf3ec0d` C# `pqz-core/nethermind` (Nethermind.Pqz.Test 71 / 71 before and after); `840878348` JS / TS outside clientkeys, runs/ and docs/ (structural AST identical 24 / 24, TON npm test 54 / 54, `mldsa_cache.json` unchanged); `f72ad2bff` Python outside `clients/ua-py`, `pqz-core`, runs/ and docs/ (AST identical but two usage docstrings; Algorand approval, clear and executor programs byte-identical, localnet pytest 110 passed; generators' `--check` ok); `5d11b1bb9` `gen_faces.py` passes its output through `forge fmt`, so its `--check` holds after F2. Each part is in `scripts/format.sh`, so the CI `format` job checks it |
| F12 | the family contracts' Rust: `smartcontracts/{soroban,solana,near,cosmos}` (owner 2026-11-18) | rustfmt 1.9.0, width 100 | `rustfmt.toml` | **done**: each family's deployable artifacts built before and after with `smartcontracts/scripts/build.sh <family>`. Soroban `dcd5437d4`: every wasm identical. Cosmos `dee436c3e`, Solana `e4cb01ed7`, NEAR `23aa1a7d7`: some artifacts moved, and `058436a47` proves each differs only in source line / column numbers (wasm: code section identical, data bytes only in panic `Location` line / column fields; SBF: `.text` only in the `line` immediates of Anchor's error origin, `.data.rel.ro` only in `Location` fields; each old position holds the same code in the old source as the new position in the new; scripts in `smartcontracts/scripts/fmt-proof/`). No artifact hash is pinned; the network docs and TODO note that the next redeploy carries the formatted build |
| F13 | Move: `smartcontracts/move/aptos` (owner 2026-11-18) | movefmt 1.5.3 (the aptos-labs release Aptos CLI 9.6.0 installs, sha256 checked) | root `movefmt.toml` (width 120) | **done** `f7d2fd387`: bytecode of the 7 modules identical, `test.sh aptos` 140 / 140 before and after. **Sui not formatted**: Prettier with `@mysten/prettier-plugin-move` 0.5.0 changes the bytecode of the 5 `scaas` modules (its `#[error]` constants are Sui clever errors, whose abort codes carry the source line); owner 2026-11-19 ("as proposed"): Sui's Move stays out of the formatter |
| F14 | Tact: `smartcontracts/ton` (owner 2026-11-18) | tact-fmt of `@tact-lang/compiler` 1.6.13 (its lockfile) | none (tact-fmt takes no settings) | **done** `0df8d3607`: the 14 code cells (`*.code.boc`) and the generated FunC / Fift identical, `npm test` 54 / 54 before and after |

Not covered: Python and JavaScript under `docs/` (research and history notes); Sui's Move stays out by owner ruling (F13).
