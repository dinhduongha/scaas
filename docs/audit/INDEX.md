# Pre-freeze AI audit: unit index

The 32 units of the [plan](README.md), their prompts, finding-id prefixes and places in Codex's order, and which units lead each
of the 13 dimensions of [review.md §1](../review.md#1-dimensions) (ARCH-POS-22). Runs are recorded in the local ledger
`scratchpad/ai-audit/LEDGER.md` (git-ignored).

## Units

**Codex** is Codex's place in the [running order](README.md#running-order): tier, then position within the tier (a unit with a
Fable P0 or P1 moves to the front of its tier). Fable, agy and Claude run every unit in parallel. Each run uses the model
and effort of its tool's config at run time, recorded in the ledger (owner 2026-11-24: the owner may change any
reviewer's model; Codex today: GPT-6.2-astra, high).

| # | Unit | Codex | Prompt | Id prefix | What |
|---|---|---|---|---|---|
| 1 | `evm-ua-registry` | 2.3 | [prompt-evm-ua-registry.md](prompts/prompt-evm-ua-registry.md) | UAR | `UARegistry` + Core / Aux libs, `UAKinds`, `UAStore`, `SmartKeyAccount`, `MandateWallet`, Hedera |
| 2 | `evm-ua-verifiers` | 1.6 | [prompt-evm-ua-verifiers.md](prompts/prompt-evm-ua-verifiers.md) | UAV | every kind's verifier: ML-DSA (Solidity and precompile path), SLH-DSA, Falcon-1024, Ed25519, BIP-340, P-256 / WebAuthn, MuSig2 / FROST, BLS, `PqzKeyVerifier` |
| 3 | `evm-metatx-factory` | 2.4 | [prompt-evm-metatx-factory.md](prompts/prompt-evm-metatx-factory.md) | MTX | meta-tx pipeline, typed entries, nonces, fees, `RelayFeeRouter`, ERC-7739, base token kinds and modules, wrap caps, factory and chain-neutral releases |
| 4 | `evm-tokens-pqz` | 1.7 | [prompt-evm-tokens-pqz.md](prompts/prompt-evm-tokens-pqz.md) | PQZ | PQZ kinds at all four sets: statements, proof path, key versions, three-key model, OFFCHAIN verdicts, rollover |
| 5 | `evm-tokens-zether` | 4.4 | [prompt-evm-tokens-zether.md](prompts/prompt-evm-tokens-zether.md) | ZTH | classical Zether on BLS12-381, merged MSM, multi-recipient, auditor, disclosure |
| 6 | `evm-regulated-public` | 4.2 | [prompt-evm-regulated-public.md](prompts/prompt-evm-regulated-public.md) | RGP | regulated Normal / Wrapped kinds, flags 5-9, compliance registry, tax, operator transfer |
| 7 | `evm-regulated-confidential` | 4.3 | [prompt-evm-regulated-confidential.md](prompts/prompt-evm-regulated-confidential.md) | RGC | the four regulated PQZ / Zether kinds (CTR-GOV-16, -17) |
| 8 | `evm-dex-gov` | 4.1 | [prompt-evm-dex-gov.md](prompts/prompt-evm-dex-gov.md) | DXG | DEX, liquidity, executors, trade lib, governance, router, `RescueVault` |
| 9 | `evm-pqchat` | 3.3 | [prompt-evm-pqchat.md](prompts/prompt-evm-pqchat.md) | PQC | `PqChat` sessions, epochs, wraps, messages, topics, entries, the TreeKEM mode (`PqGroupTree`, `IPqGroupTree`, `PqChatTree`, `PqChatTreeMembers`, `PqChatTreeViews`), the exits at the head |
| 10 | `pqz-core-pqzl` | 3.8 | [prompt-pqz-core-pqzl.md](prompts/prompt-pqz-core-pqzl.md) | PQL | lattice core: Rust production + C oracle |
| 11 | `pqz-core-pqzh-stmt-ffi` | 3.9 | [prompt-pqz-core-pqzh-stmt-ffi.md](prompts/prompt-pqz-core-pqzh-stmt-ffi.md) | PQH | Ligero `pqzh`, `stmt`, `pqz-ffi` (dispatch, opening / seal, wasm32, wallet-wasm) |
| 12 | `pqz-core-params-vectors` | 3.10 | [prompt-pqz-core-params-vectors.md](prompts/prompt-pqz-core-params-vectors.md) | PQP | `params/sets` generator and the four sets, PQZ vectors |
| 13 | `nethermind-precompiles` | 1.4 | [prompt-nethermind-precompiles.md](prompts/prompt-nethermind-precompiles.md) | NMP | `Nethermind.Pqz`: PQZ and ML-DSA-44 / -65 / -87 precompiles, gas, activation (Falcon-1024 has no precompile: CTR-UA-40) |
| 14 | `ua-rs-sign` | 3.5 | [prompt-ua-rs-sign.md](prompts/prompt-ua-rs-sign.md) | URS | ua-rs single-signer schemes + MuSig2 / FROST / DKG (T21 parts 1, 2); the Falcon glue `src/falcon/soft.rs` and `src/ua_portable.rs` with the `msig` reader rule (2026-11-26) |
| 15 | `ua-rs-custody` | 1.5 | [prompt-ua-rs-custody.md](prompts/prompt-ua-rs-custody.md) | URC | vault, seal, KEM, derivation, pairing, policy (T21 part 3); the TreeKEM secrets `wallet/{tree,tree_public}.rs` (2026-11-26) |
| 16 | `ua-rs-digests` | 3.6 | [prompt-ua-rs-digests.md](prompts/prompt-ua-rs-digests.md) | URD | digests = contracts, ERC-7739, PQZ / Zether facades, proof path client (T21 part 4); the PqChat / PqVault record digests `wallet/{pqchat,pqchat_keys,pqchat_file,pqvault}.rs` (2026-11-26) |
| 17 | `ua-rs-boundary` | 3.7 | [prompt-ua-rs-boundary.md](prompts/prompt-ua-rs-boundary.md) | URB | JSON / C ABI / bindings, decode bounds, secrets, supply chain (T21 part 5) |
| 18 | `scaas-node` | 2.5 | [prompt-scaas-node.md](prompts/prompt-scaas-node.md) | SND | the open relayer and indexer: allow-lists both ways, decode bounds, rebuilt job bytes, never `dead` while a tx may land, no keys, no oracle, RPC lists, gateway, indexer, adapters, store (added 2026-11-22; ready) |
| 19 | `scaas-sdk` | 2.6 | [prompt-scaas-sdk.md](prompts/prompt-scaas-sdk.md) | SDK | `scaas-sdk`, its FFI and bindings, `scaas-rpc`: decryption reads by majority, digests, refusals before signing, no oracle, handles across the FFI, profiles, hand-off, Arweave payer path (added 2026-11-22; ready; the uniffi bindings by `<BINDING_SHA>` if `sdk-binding` is not merged at the tag) |
| 20 | `evm-pqvault` | 3.4 | [prompt-evm-pqvault.md](prompts/prompt-evm-pqvault.md) | PQV | `PqVault` (PR #27): admin model (b), membership and wraps, `sealedInfo` bounds, ciphertexts in state, relayable writes, NET-ALL-25, pins, the share box; `PqGroupBase` audited in unit 9 (added 2026-11-22; ready) |
| 21 | `app-cores` | 4.5 | [prompt-app-cores.md](prompts/prompt-app-cores.md) | APC | `pqchat-core` and `pqvault-core` (added 2026-11-22; final 2026-11-24, both built on `ua-rs-sign`; **FRAME** only for pqchat-core's TreeKEM layer and the biometric unlock) |
| 22 | `clientkeys-vectors` | 2.7 | [prompt-clientkeys-vectors.md](prompts/prompt-clientkeys-vectors.md) | CKV | layer unit: `clients/clientkeys` (the JS reference) and every vector generator, with the vector files: generator correctness, frozen rows, canonical forms, the `relayer` / `feeRecipient` zeroing (added 2026-11-24; `ua-group.js`, the group kinds, 2026-11-26) |
| 23 | `pqz-verifier-deploy` | 4.6 | [prompt-pqz-verifier-deploy.md](prompts/prompt-pqz-verifier-deploy.md) | PVD | layer unit: `scaas-pqz-verifier` (key handling, typed `PqzVerdict` signing, the three-key model) and `smartcontracts/evm/script/` with the factory catalogue and the deployment books (addresses, parameters, immutability, init-code hash) (added 2026-11-24) |
| 24 | `bindings-cli-ci` | 4.7 | [prompt-bindings-cli-ci.md](prompts/prompt-bindings-cli-ci.md) | BCC | layer unit: the `ua-*` bindings over `libscaas_ua_c` beyond their FFI edge, `clients/scaas-cli`, CI (`ci.yml`, `ci_changes.py`) and the supply chain (`cargo deny` / `npm audit`, pins, `evm_libs.sh`, `format.sh`, the secret and temp-path checks) (added 2026-11-24) |
| 25 | `crypto-signatures` | 1.2 | [prompt-crypto-signatures.md](prompts/prompt-crypto-signatures.md) | CSG | crypto, read vertically: ML-DSA-44 / -65 / -87, Falcon / FN-DSA, SLH-DSA, Ed25519, secp256k1 (ECDSA, BIP-340), P-256 / WebAuthn, MuSig2 / FROST / DKG, BLS; purposes and domains (added 2026-11-24) |
| 26 | `crypto-pqz` | 1.1 | [prompt-crypto-pqz.md](prompts/prompt-crypto-pqz.md) | CPZ | crypto, read vertically: PQZ statements and relations, transcripts, `pqzl` / `pqzh` / `stmt`, C / Rust / wasm, the on-chain answer, the parameter sets, the three-key model (added 2026-11-24) |
| 27 | `crypto-kem-seal` | 1.3 | [prompt-crypto-kem-seal.md](prompts/prompt-crypto-kem-seal.md) | CKS | crypto, read vertically: KEM scheme 1 (ML-KEM-1024 + X25519), seal / open, vault derivation, the PqVault and PqChat wraps, the file seal, the sealed PQZ leaf (added 2026-11-24) |
| 28 | `crypto-zether` | 3.2 | [prompt-crypto-zether.md](prompts/prompt-crypto-zether.md) | CZT | crypto, read vertically: classical Zether on BLS12-381 in the contract, `zether-prover`, `ua-rs`, clientkeys; the merged MSM; disclosure (added 2026-11-24) |
| 29 | `crypto-pqchat-tree` | 3.1 | [prompt-crypto-pqchat-tree.md](prompts/prompt-crypto-pqchat-tree.md) | CTK | crypto, read vertically: the PqChat TreeKEM key schedule, path secrets from the seed, the tree hash, node-key admission, PCS on removal (added 2026-11-24; finalized 2026-11-26, the TreeKEM build merged) |
| 30 | `cross-layer` | 2.2 | [prompt-cross-layer.md](prompts/prompt-cross-layer.md) | XLY | cross-cutting: leads dimension 8 end to end: byte formats from the vectors in every layer, node allow-lists both ways, records followed both ways, sibling checks, the registry line (added 2026-11-24) |
| 31 | `adversarial` | 2.1 | [prompt-adversarial.md](prompts/prompt-adversarial.md) | ADV | cross-cutting: every role against the whole system (subject / holder / member, admin, relayer, lying RPC below and above the majority option, front-runner, removed party), the rules that do not bend, recovery from state alone (added 2026-11-24) |
| 32 | `vendor-falcon-rs` | 1.8 | [prompt-vendor-falcon-rs.md](prompts/prompt-vendor-falcon-rs.md) | VFR | the vendored falcon-rs 0.3.1 (the wasm32 Falcon of `ua-rs`, CLI-UAL-66) audited as code, function by function against the round-3 C, and its `ua-rs` glue; prior record [audited/vendor-falcon-rs.md](audited/vendor-falcon-rs.md) (added 2026-11-26, controller call) |

## Running order

Codex, tier by tier (the [plan](README.md#running-order) holds the rules: resume, re-audit, later rounds):

1. `crypto-pqz`, `crypto-signatures`, `crypto-kem-seal`, `nethermind-precompiles`, `ua-rs-custody`, `evm-ua-verifiers`, `evm-tokens-pqz`, `vendor-falcon-rs`
2. `adversarial`, `cross-layer`, `evm-ua-registry`, `evm-metatx-factory`, `scaas-node`, `scaas-sdk`, `clientkeys-vectors`
3. `crypto-pqchat-tree`, `crypto-zether`, `evm-pqchat`, `evm-pqvault`, `ua-rs-sign`, `ua-rs-digests`, `ua-rs-boundary`, `pqz-core-pqzl`, `pqz-core-pqzh-stmt-ffi`, `pqz-core-params-vectors`
4. `evm-dex-gov`, `evm-regulated-public`, `evm-regulated-confidential`, `evm-tokens-zether`, `app-cores`, `pqz-verifier-deploy`, `bindings-cli-ci`

This replaces the order of the earlier drafts (units 5, 1, 3, 2, 4, 8, 6, 7, 9, then the cores, then the clients, the
cross-cutting units after their layer units; owner 2026-11-24).

## Coverage check

ARCH-POS-22: no dimension dropped in silence. Every unit applies all 13 dimensions within its scope; this table names the units
that **lead** each one (a cross-cutting unit leads it across the system, a layer unit within its layer).

| # | Dimension | Leads across the system | Leads within a layer |
|---|---|---|---|
| 1 | Conformance | every unit, for its own rule ids; `cross-layer` for rules that name several layers | all |
| 2 | Cryptography | `crypto-signatures`, `crypto-pqz`, `crypto-kem-seal`, `crypto-zether`, `crypto-pqchat-tree` (read vertically) | `evm-ua-verifiers`, `evm-tokens-pqz`, `evm-tokens-zether`, `evm-pqchat`, `pqz-core-pqzl`, `pqz-core-pqzh-stmt-ffi`, `nethermind-precompiles`, `ua-rs-sign`, `ua-rs-custody`, `clientkeys-vectors`, `vendor-falcon-rs` (the library itself) |
| 3 | Security | `adversarial` | `evm-ua-registry`, `evm-metatx-factory`, `evm-regulated-public`, `evm-regulated-confidential`, `evm-dex-gov`, `evm-pqvault`, `scaas-node`, `scaas-sdk`, `pqz-verifier-deploy` |
| 4 | Rules that do not bend | `adversarial` (every role against every rule) | all (section 5 of every prompt) |
| 5 | Secrets and privacy | `crypto-kem-seal` (keys in the arena) | `ua-rs-custody`, `ua-rs-boundary`, `app-cores`, `bindings-cli-ci`, `scaas-node`, `scaas-sdk` |
| 6 | Robustness and denial of service | `adversarial` (griefing by role) | `ua-rs-boundary`, `scaas-node`, `scaas-sdk`, every EVM unit (gas, EIP-8037, EIP-7825) |
| 7 | Failure handling | `adversarial` (recovery from state alone) | `scaas-node` (never `dead` while a tx may land), every EVM unit, `pqz-core-pqzh-stmt-ffi`, `nethermind-precompiles` |
| 8 | Consistency across languages and layers | `cross-layer` (end to end) | `clientkeys-vectors` (the bytes' source), `pqz-core-params-vectors`, `ua-rs-digests`, `scaas-sdk`, `scaas-node` (allow-lists) |
| 9 | Contract specifics | none needed: contract-only | every EVM unit; `evm-metatx-factory` (modules, factory), `evm-ua-registry` (library split), `pqz-verifier-deploy` (deploy, catalogue, init-code hash) |
| 10 | Performance and cost | none: per layer | every EVM unit (gas pins), `nethermind-precompiles` (prices), `pqz-core-*` (from gate logs), `scaas-sdk`, `app-cores` |
| 11 | Interfaces and misuse | none: per layer | `ua-rs-boundary`, `bindings-cli-ci`, `scaas-sdk`, `app-cores` |
| 12 | Tests | every unit for its own tests | `clientkeys-vectors` (vectors and their `--check`), `pqz-core-pqzl` (cheating fixtures), `bindings-cli-ci` (CI steps that cannot fail) |
| 13 | Operations and the supply chain | `bindings-cli-ci` (CI, pins, `cargo deny` / `npm audit`, secret and path checks) | `scaas-node`, `nethermind-precompiles`, `pqz-verifier-deploy`, `ua-rs-boundary`, `clientkeys-vectors`, `vendor-falcon-rs` (its pins and provenance) |

## Prompt sections

Every prompt has the same sections. Sections 1-5 are common: role and read-only limits, the target and its check, the result
file name, which source wins, the absolute rules (ciphertext, no oracle, explicit parameters, relayable `mtx*`, no EIP-7702, no chain
assumption, one rule on every chain, EIP-8037, EIP-7825, no upgrades, fail closed, Zether ≠ PQZ). Section 6 is the threat model
(EVM / core / plugin / ua-rs; since 2026-11-22 also node / SDK / app cores). Section 7 lists what not to report (the owner-accepted risks). Section 8 is the unit itself: scope,
specs, invariants, prior reports, gate evidence and (since 2026-11-24) the dimension table. Section 9 is the report format:
P0-P3 / info, file:line, the dimension number, failure scenario, fix, evidence, confidence, a closure table, checked and sound,
not covered. The cross-cutting and new layer units (22-31) use the same sections; their section 6 is the whole-system threat
model (or their layer's), and their section 7 the common list.

## Changes to the prompts

**Amendments 2026-11-22** (owner approvals of that day):
- `pqz-core-pqzl` (unit 10): invariant 6, the specialised verifier's norm checks equal the general verifier's line by line
  (z1, z3, z4, h, hint, the whole z2, the exact-l2 bounds), at the four sets, C and Rust; bound sources, widths, and the
  one-norm cheating fixtures (to use or to request). The rest of the prompt is unchanged.
- `ua-rs-custody` (unit 15): invariant 6, the sealed PQZ leaf `sealPqKey` / `openPqKey` (P6h (3), before the tag),
  marked **FRAME: finalize when P6h (3) lands**. Custody is the unit for it (vault v2 leaves, seal / open).
- `evm-pqchat` (unit 9): scope gains `src/pqgroup/PqGroupBase.sol`, the base shared with `PqVault`, audited there once
  (invariant 7); unit 20 reads it only for PqVault's use.

**Amendment 2026-11-24** (owner, ARCH-POS-22, `docs/review.md` on `ua-rs-sign`, commits `5f3603512`, `4a579bfba`,
`a3152b8ac`): every review, the AI audit rounds of ARCH-POS-14 included, covers the 13 dimensions of `docs/review.md` §1,
divided into areas (§2), and every finding names its dimension (§3).
- Every unit's section 8 gains a **dimension table**: the 13 rows of §1 in order, each saying what to hunt in that unit's
  scope; a row may say `N/A: <reason>` but is never deleted; rows 2 and 3 are filled in for every contract unit. Section 9
  gains a `Dimension:` line per finding and asks for the rows not reached under "Not covered".
- `evm-pqchat` (unit 9): scope gains the signature storage (`sigStore`, CTR-CHAT-23), several keys per member (CTR-CHAT-24),
  `groupMode` (CTR-CHAT-25), all on `ua-rs-sign` since the `pqchat-sigs` merge, and the TreeKEM mode (`PqGroupTree.sol`,
  `PqChatTree.sol`, spec `2026-11-23-pqchat-treekem.md`, CTR-CHAT-26 / -27 / -28), the TreeKEM part marked **FRAME: finalize
  when the TreeKEM build merges** (branch `pqchat-treekem`); invariants 8 and 9 added.
- `scaas-sdk` (unit 19): invariant (j), the T26 review fixes and the F2 shared line reader `clients/scaas-sdk/src/line.rs`;
  the T26 review dir `scratchpad/sdk-review-20261123-0621/` (local, not in the repo) in the prior reports; the T26 gate and mutant rows.
- `app-cores` (unit 21): dimension table added; **finalized** (controller call, owner: no): both crates are built on
  `ua-rs-sign`, pqchat-core's file list, mutant records and review rounds are in; FRAME only for pqchat-core's TreeKEM layer
  (CLI-PQC-17, with the TreeKEM build) and the biometric unlock (scaas-app, TODO 8b-3).
- Controller calls of 2026-11-24 (owner: no), closing the gaps the update found: unit 1's scope gains
  `UARegistryRegLib.sol`; unit 2's gains `MlDsaVerifyOnly.sol` and `BlsMultiKeyData.sol`; unit 15's invariant 6 (the sealed
  PQZ leaf, CLI-SGN-55) is finalized on the landed paths and is no longer FRAME; the plan's Out of scope drops
  `scaas-node`, the other clients and `pqchat-core` (units 18, 19, 21, 24 cover them).
- New cross-cutting units (owner agreed): 30 `cross-layer` (XLY), 31 `adversarial` (ADV), and the crypto units read
  vertically, 25-29 (CSG, CPZ, CKS, CZT, CTK; CTK is FRAME until the TreeKEM build merges).
- **Owner ruling 2026-11-24: three more layer units**, 22 `clientkeys-vectors` (CKV), 23 `pqz-verifier-deploy` (PVD), 24
  `bindings-cli-ci` (BCC). The plan's Out of scope list drops what they cover (`clientkeys`, the `script/` deploy
  scripts, `scaas-pqz-verifier`); the non-EVM families stay deferred (owner 2026-10-31, confirmed 2026-11-24); `test/` and
  `legacy/` stay out.

**Amendment 2026-11-26** (controller calls under the owner's auto-run grant of 2026-11-25; the owner may veto): the prompts
follow the review-fix round (`6ba93164d..b202a6fa2`, branch `review-fix-contract`) and what landed after the prompts were
written (the TreeKEM build, G1, the keyed cancel). The committed prompts keep `<TAG>` / `<SHA>`. Every changed unit names the
round's reviews as prior reports: the TreeKEM and G1 code review `scratchpad/treekem-g1-review-20261124-1550/`, the
re-review `scratchpad/review-fix-review-20261125-1959/` and the fix check `scratchpad/review-fix-check-20261126-0429/`
(their `STATUS.md`), and the round's gate rows.
- **New unit 32 `vendor-falcon-rs` (VFR)**, Codex tier 1, last: the vendored falcon-rs 0.3.1 and its `ua-rs` glue
  (CLI-UAL-66, ARCH-POS-24), audited as code against PQClean's round-3 C; its prior review is the record
  [audited/vendor-falcon-rs.md](audited/vendor-falcon-rs.md) (FR-1 to FR-12). Why a unit of its own: about 14.7 K lines of
  third-party code with its own method (a port read against its reference, function by function) and its own open findings,
  which would crowd `crypto-signatures`, the largest tier-1 unit; `crypto-signatures` keeps the vertical parity (invariant 7)
  and `ua-rs-sign` the glue's use (invariant 6).
- `evm-pqchat` (9): the TreeKEM part finalized (no longer FRAME); scope gains `IPqGroupTree.sol`, `PqChatTreeMembers.sol`
  (the tree exits and mode 0's `leave` / `remove`), `PqChatTreeViews.sol` and the tree tests; bounds `TREE_LEAVES_MAX` 512
  (depth 9) and `TREE_CHANGES_MAX` 20; invariants 10 (exits at the head, `EXIT_LAG_MAX` 16, E-2, the replica rule) and 11
  (A-15, C38-C40, the `msig` tag in records and replica copies).
- `evm-pqvault` (20): invariant 11 (the same exits with `PqVault*` errors, A-15 `addVaultWraps`, A-1 replica copies).
- `evm-ua-registry` (1): CTR-UA-73, -74; invariant 12 (`msigAt`, the version tag on every path, the registration bound, the
  walked-interface pin); the registry round's gate and mutant rows.
- `evm-metatx-factory` (3): `OpenFactoryLib.sol` named; invariant 10 (G-1 on every creation path, G-3's `checkRouter`, the
  library split).
- `evm-dex-gov` (8): CTR-GOV-31 to -33, CTR-UA-73; invariant 5 (G1's keyed nonce map, the keyed cancel and G-7).
- `scaas-node` (18): invariant m (A-5, the tree bounds at 512 / 20, E-6, `mtxNonceFor`, the `msig` tag passed through, D2-5).
- `clientkeys-vectors` (22): `ua-group.js`, `treekem.js`, `pqchat-tree.js` in scope; invariant h (the group kinds, the
  `msig` reader rule, the new rows).
- `crypto-signatures` (25): Falcon on wasm32 through falcon-rs (the tree itself is unit 32), the group verifiers in
  clientkeys, the `msig` tag; invariant 7.
- `crypto-pqchat-tree` (29): finalized (no longer FRAME, pqchat-core's tree layer still SPECIFIED); invariant 8 (depth 9,
  20 changes, the readers' fixes); bounds in the dimension table.
- `crypto-kem-seal` (27): `PqGroupTree.sol` no longer FRAME.
- `ua-rs-sign` (14), `ua-rs-custody` (15), `ua-rs-digests` (16): gaps closed, as no layer unit held these files: `ua-rs-sign`
  gains `src/falcon/soft.rs`, the Falcon routing and `src/ua_portable.rs` (invariants 5, 6); `ua-rs-custody` gains
  `wallet/{tree,tree_public}.rs` (invariant 7); `ua-rs-digests` gains `wallet/{pqchat,pqchat_keys,pqchat_file,pqvault}.rs`.
- `ua-rs-boundary` (17), `bindings-cli-ci` (24): the vendored crates' `path` entries and `scripts/vendor.sh` (invariant h),
  `scripts/mutant_guard.py`.
- `pqz-verifier-deploy` (23): invariant k (the round's deploy changes, NET-EVM-20 as docs only).
- `scaas-sdk` (19): invariant k (the `msig` tag and reads, step 6, CLI-SDK-34). `app-cores` (21): invariant k (the walk, step
  6 in both cores, `ExitLag`); still FRAME for pqchat-core's TreeKEM layer and the biometric unlock.
- `cross-layer` (30): invariant g (the round's seams). `adversarial` (31): the lag, the replica, the `msig` version and the
  keyed cancel in the roles.
