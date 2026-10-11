# P6a — PQ signature verifiers on the EIP formats; clientkeys PQ signing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** the first sub-phase of P6 ([roadmap](2026-10-12-p6-roadmap.md), TODO.md §00 row P6): the post-quantum UA
signing kinds as stateless `IUAKindVerifier` contracts, compatible with the Ethereum drafts in both directions —
`mldsa44` / `mldsa65` (FIPS 204 over `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the **empty** context, so an EIP-8355
precompile verifies SCaaS signatures unchanged and SCaaS uses one found by probe; the EIP-8051 expanded key computed on
chain and accepted by the core), `fndsa512` (Falcon-512 with EIP-8052's SHAKE256 hash-to-point over the 32-byte
`ua_msg`, EIP-8052's 666-byte padded signatures) and `slhdsa128s` (FIPS 205 SLH-DSA-SHA2-128s on the SHA-256 precompile,
**gas gate measured: passes**); clientkeys `src/pq.js` (keys from the BIP-39 seed by the specified HKDF, `signUA`, the
expanded key); cross-language vectors from the published sources (NIST ACVP FIPS 204/205 sigVer, the EIP-8051 and
EIP-8052 KATs, the EIP-8355 cases) and SCaaS vectors with a mutation set; measured gas (T-GAS for the PQ kinds); the
docs. Not here: the UA registry (`UARegistry`, UA F1 — P6c), any precompile on chain 7622 (P6f), PQ Zether.

**Architecture:** Three layers under `smartcontracts/evm/src/ua/`. (1) **Shared**: `PqUA.sol` (`IUAKindVerifier`,
kind numbers and tags, `ua_msg`, `pq_msg`, `M' = 0x00 ‖ 0x00 ‖ pq_msg`, the exact-answer precompile probe),
`Shake.sol` (Keccak-f[1600] sponge, SHAKE128/256, state at fixed memory claimed by `reserve()`), `PqNtt.sol` (negacyclic
NTT for any `(n, q)`, FIPS 204 Algorithms 41/42, lazy reduction). (2) **Schemes** as libraries over calldata:
`SlhDsaSha2128s` (FIPS 205 Algorithms 8, 11, 13, 17, 20; tweakable hashes on `0x02` from two memory buffers),
`Falcon512` (hash-to-point, reference `comp_decode`, `s1 = c − s2·h` by NTT, `‖·‖² ≤ 34,034,726`), `MlDsa`
(Algorithm 8 with one core for the FIPS 204 key and the EIP-8051 expanded key, `expandKey`). (3) **Verifiers**:
`UASlhdsaVerifier`, `UAFndsaVerifier`, `UAMldsaVerifier(kind, candidate, probeValid, probeInvalid)` — the last uses the
candidate precompile only if it answers a valid EIP-8355 input with exactly the 32-byte word 1 and a flipped one with
exactly 0. Every verdict is pinned twice: by the published vectors and by `pq_kat.json`, which clientkeys generates and
noble (an independent implementation) re-verifies, mutations included.

**Tech Stack:** Solidity 0.8.37 (`osaka`, legacy codegen, optimizer 200), Foundry (forge 1.3.5), forge-std 1.16.2;
`clients/clientkeys` (`node --test`, `@noble/post-quantum` **0.7.1** (MIT, 2026-08-27) next to `@noble/hashes` /
`@noble/curves` 2.4.0); `scripts/docs_check.py`.

**Spec:** `docs/contracts/accounts.md` CTR-UA-12 (`ua_msg`), CTR-UA-17 (verification through the registry, `IUAKindVerifier`,
stored PQ keys), CTR-UA-23 (PQ kinds, `pq_msg`, empty context, probe, `UA_VERIFY_BUDGET`, the ~50 % bound, the
`slhdsa128s` gas gate), the kind table (0x0130–0x0133), §1.9 verifiers and enablement, §1.15 gas, §1.16 vectors (T-FUZZ,
T-GAS); `docs/contracts/pq-zether.md` §9.2 (`MLDSA65` in EIP-8355's layout), §9.4, the self-test paragraph;
`docs/clients/signers-clientkeys.md` "PQ seeds"; `docs/research/pq-eips-vs-scaas.md` Q1–Q5; the EIP texts
(EIP-8051, EIP-8052, EIP-8355, read at `ethereum/EIPs@3aea9f3`), FIPS 202/204/205, the Falcon specification v1.2.

**Base:** `main` at the commit that adds this plan (parent `9305f37`; forge 890 passed / 10 skipped; clientkeys
62 / 60 / 2). Every block below was applied task by task to a scratch worktree from that base and run green: forge
**894 / 900 / 911** passed (10 skipped) after Tasks 2 / 3 / 4 (+3 + 1 gas, +5 + 1, +10 + 1), size gate 0 errors after
each (56 / 60 / 62 contracts), `FOUNDRY_PROFILE=private7622 forge build` green; clientkeys **74** (72 pass, 2 skipped) after
Task 1; the vector files reproduce byte for byte (`pq_kat.json` SHA-256 `95b1a6ee…`, `pq_external.json` `55d1f03d…`);
docs checkers 0 errors, 0 fact misses after Task 5.

**Measured (T-GAS, `test/ua/PqGas.t.sol`, execution gas of one `verify` call, valid signature):**

| Kind | Gas | Against `UA_VERIFY_BUDGET` 12 M (EIP-7825 chains), the ~50 % bound 6 M |
|---|---|---|
| `slhdsa128s` | 787,953 valid; **1,321,231 worst case** (WOTS+ message 0 on all 7 layers: 510 chain steps each) | gate passes: 11 % of 12 M, 13 % of Hedera's 10.5 M; calldata 7,856 B ≈ 126–314 k on top |
| `fndsa512` | 2,266,836 | fits (19 %) |
| `mldsa44` | 11,378,749 on the FIPS 204 key; 4,093,690 on the EIP-8051 expanded key | FIPS key: over the bound (95 % of 12 M); expanded: fits (34 %) |
| `mldsa65` | 18,894,952 on the FIPS 204 key; 5,771,110 on the expanded key | FIPS key: over EIP-7825's 16.78 M cap; expanded: fits (48 %) |
| Keccak-f[1600] | 66,394 per permutation | `ExpandA` is ~80 / ~150 permutations (44 / 65) |

With an EIP-8355 precompile the ML-DSA check is the precompile's price (6,500 / 9,000 + 6 per word) plus the cost
of the call.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; worktree `.claude/worktrees/p6a` on branch `p6a-pq-verifiers` from
  `main`. forge in `smartcontracts/evm` of the worktree: `lib/` is not tracked — `mkdir lib`, copy
  `smartcontracts/evm/lib/forge-std` into it, symlink `lib/openzeppelin-contracts → /home/ha/work/blockchain/openzeppelin-contracts`.
  clientkeys: **copy** (not symlink) `node_modules` from the main checkout, because Task 1 installs a package into it
  (never `git add` it). Heavy commands (forge, npm) only through `scripts/capped`, one at a time. `/usr/bin/grep`; in
  worktrees a hook blocks bare `git`: use `/usr/bin/git`.
- Gates: `forge build` then `forge test` in `smartcontracts/evm`; size gate `forge build src --sizes --json >
  /tmp/sizes.json; python3 scripts/size_gate.py /tmp/sizes.json smartcontracts/evm/size-baseline.json`;
  `FOUNDRY_PROFILE=private7622 forge build`; `npm test` in `clients/clientkeys`; `python3 scripts/docs_check.py check`
  and `python3 scripts/docs_check.py facts check`.
- `Shake.reserve()` must be the first memory allocation of the external call frame (it claims `[0x80, 0xaa0)`); every
  entry point that reaches `Shake` calls it first, and a misuse reverts `ShakeMemory()` instead of corrupting memory.
  Test harnesses do the same.
- Vector files are generated, never edited by hand: `pq_kat.json` by `node scripts/pq-vectors.mjs` (deterministic),
  `pq_external.json` by `node scripts/pq-external.mjs <dir>` from the SHA-256-pinned downloads of Task 1. Forge reads
  them per test (`vm.readFile`; a storage copy of 2 MB of JSON does not fit a block) and long loops run under
  `vm.pauseGasMetering()` (correctness tests; gas is `PqGasTest`'s).
- Owner rules: every chain is a test chain (no migration); code size is not a concern (ratchet baseline); gas
  optimisation later; open questions stay open unless blocking; no hybrid (classical + PQ) kind; rulings are P1–P12
  here, component docs say "controller ruling, pending the owner", never a P-id; `SmartKeyAccount` names contract
  accounts only.
- Pages over their line budget (`accounts.md`, `pq-zether.md`, `signers-clientkeys.md`) change by net 0 lines;
  `docs/history/` and `docs/decisions.md` are records (untouched).
- Commit trailer (both lines): `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01GBLbPyQuG5HXALewwBZ7Bb`. Never `git add claude-code-api.txt`.

## Review Focus

- **Both directions of EIP compatibility.** A SCaaS ML-DSA signature is a FIPS 204 pure signature with the empty
  context over the 32-byte `pq_msg`: an EIP-8355 precompile verifies it as `pk ‖ sig ‖ pq_msg`
  (`test_probe_usesOnlyAnExactEip8355Answer` runs it through an EIP-8355 emulator for both levels), and the EIP's own
  vectors pass the SCaaS core (`test_eip8355_cases`, `test_eip8051_nistKat`: the 100-record EIP-8051 KAT file is FIPS 204
  with the empty context, M' = `0x00 ‖ 0x00 ‖ msg`). Falcon: EIP-8052's SHAKE256 hash-to-point and the NIST KATs published
  with it (`test_falcon_nistKat`); SLH-DSA: ACVP (`test_acvp_slhdsa`).
- **Never permissive.** Every ACVP *failing* case fails (ML-DSA 48 of 60: modified message, commitment, `z`, hint;
  SLH-DSA 24 of 28: modified message, `R`, `SIG_FORS`, `SIG_HT`, too small, too large); the SCaaS mutation sets (flipped first / middle / last byte,
  flipped key, flipped message, truncated signature) fail with noble's verdict; malformed encodings are refused, never
  reduced (`test_malformed_*`: Falcon coefficient ≥ q, wrong headers, non-zero padding; ML-DSA hint count > ω,
  expanded coefficient ≥ q, a 65 key on the 44 verifier; wrong lengths everywhere).
- **The probe takes nothing on trust.** No code, a contract answering 1 to everything, or any non-32-byte answer ⇒ pure
  Solidity; the precompile path keeps the fixed `pk ‖ sig` split (lengths checked before the call).
- **Messages.** `ua_msg` (CTR-UA-12), `pq_msg` (CTR-UA-23) and the signed message per kind equal clientkeys'
  (`_uaVector` in `test/ua/PqVectors.sol`; `seed → key, UA id, ua_msg, signed message = vectors` in `test/pq.test.js`).
- **Gas gate.** `test_gas_slhdsa`: the worst case any input can force (510 WOTS+ steps on each of 7 layers) is 1.32 M,
  asserted < 1.46 M; ML-DSA on the FIPS 204 key is asserted *over* 6 M so a change that makes it fit forces a review
  of ruling P10.
- **Memory discipline.** `Shake` writes only `[0x80, 0xaa0)` after `reserve()`; all other buffers are bump-allocated
  (`PqNtt.alloc`, `SlhDsaSha2128s.buf`); every `assembly` block is `memory-safe`.

## Rulings (docs vs code) and defaults taken

- **P1 — Scope without the registry.** The UA registry (`UARegistry`, UA F1) is not built; P6a ships the per-kind
  verifiers the registry will call (`IUAKindVerifier` exactly as accounts.md §1.8), stateless, with no registry code.
  `verifyCap`s and per-chain enablement are registry deploy parameters (P6c) fed by `PqGasTest`.
- **P2 — The signed message per kind.** ML-DSA and SLH-DSA: FIPS 204 / 205 pure signing with the empty context over
  `pq_msg`, i.e. `M' = 0x00 ‖ 0x00 ‖ pq_msg` (CTR-UA-23). Falcon: `ua_msg` itself (32 bytes, EIP-8052's message size;
  Falcon has no context string and `ua_msg` already carries `TAG(kind)`), as the kind table implies.
- **P3 — `fndsa512` is Falcon-512 v1.2 as EIP-8052.** No FIPS 206 draft is public, so the "FIPS 206 draft encoding" of
  CTR-UA-23 is read as the Falcon specification v1.2 with EIP-8052's choices: public key 897 B `0x09 ‖ h` (EIP-8052's
  896-byte key after the header; each coefficient `< q`), signature the padded format 666 B `0x39 ‖ salt ‖ compressed ‖
  zero padding` (EIP-8052's "padded signature size"), hash-to-point SHAKE256(`salt ‖ msg`), bound `≤ 34,034,726` (the
  reference code and noble; EIP-8052's text says `<`). No Keccak-PRNG (ETHFALCON) variant. A final FIPS 206 that
  differs is `fndsa512.v2` (CTR-UA-23 unchanged).
- **P4 — ML-DSA key forms.** `keyData` stays the FIPS 204 public key (CTR-UA-17: `vk = pk`); the core also verifies
  against the EIP-8051 expanded key and `expandedKey(pk)` computes it on chain. Layout: `Â` (k·l polynomials,
  row-major) ‖ `tr` (64) ‖ `NTT(t1·2^13)` (k), coefficients u32 big-endian — 20,544 B (44), 36,928 B (65): the content of
  EIP-8051's reference implementation (64-byte `tr`, `2^d` folded in), not its text (20,512 B with a 32-byte `tr`). What
  the registry stores is P6c's (owner) decision with the measured numbers.
- **P5 — Probing.** ML-DSA only, EIP-8355 layout `pk ‖ sig ‖ pq_msg`, one candidate per verifier, probed in the
  constructor with a valid and a one-bit-flipped vector (exact 32-byte 1 / 0); a failed probe means pure Solidity, not a
  revert (one contract serves every chain; the chain-7622 deploy requires `PRECOMPILE() != 0`). Not probed: EIP-8051
  (it needs the expanded key per call, which only a stored-key registry has; and a precompile built from its text's μ
  would fail the probe), EIP-8052 (no addresses), SLH-DSA (no EIP).
- **P6 — SHAKE in Solidity.** Our own Keccak-f[1600] (lanes at fixed memory, round body unrolled, theta / rho-pi / chi
  as Yul functions for the legacy code generator's stack), 66 k gas per permutation; no helper contract, no assembly
  bytecode blob. Optimisation is later (owner).
- **P7 — NTT.** One generic routine for both moduli with constant `zetas` tables (FIPS 204's for ML-DSA, `ψ = 11^12` for
  Falcon; both recomputed by the tests) and lazy reduction in the forward transform.
- **P8 — clientkeys.** `src/pq.js`: HKDF-SHA256(seed, `"scaas.ua.pq.v1"`, `kind_tag ‖ u32 account ‖ u32 index`) with
  length 32 (ML-DSA, FIPS 204 `KeyGen_internal`), 48 (SLH-DSA: `SK.seed ‖ SK.prf ‖ PK.seed`, FIPS 205
  `slh_keygen_internal`; ACVP keyGen agrees) and 48 (Falcon: noble's seeded keygen, implementation-specific, pinned by
  the vectors). `signUA(kind, sk, purposeTag, digest)` builds `ua_msg` itself (no raw-digest entry, CTR-UA-10);
  hedged signing by default, deterministic only for the vectors. Not in the portal bundle (key-worker budget; UA F3).
- **P9 — Vectors.** New directory `smartcontracts/vectors/ua/` (accounts.md §1.16): `pq_kat.json` (generated) and
  `pq_external.json` (imported from commit-pinned URLs, SHA-256 of every input recorded, every entry re-checked with
  noble before it is written). `foundry.toml` gains `{ access = "read", path = "../vectors" }`.
- **P10 — ML-DSA on precompile-less chains.** On the FIPS 204 key the measured Solidity check is over CTR-UA-23's bound
  on every chain (ML-DSA-65 over EIP-7825's per-transaction cap), so under the spec as written `mldsa44/65` are disabled
  wherever no EIP-8355 precompile is probed; the expanded key would fit. The docs record this; the choice is P6c's.
- **P11 — Docs.** accounts.md / pq-zether.md / signers-clientkeys.md say BUILT (P6a) for the verifiers and clientkeys,
  replace the estimates by the measurements, drop the transitional `ctx = kind_tag` sentences; pq-zether.md's
  self-test paragraph no longer has `UAMldsaVerifier` call `OP_SELFTEST` (its probe is its self-test); the research
  note records the findings (EIP-8051's μ / `tr` / `2^d`, EIP-8052's gaps, the gas) and keeps its questions open.
- **P12 — Test hooks.** `SlhDsaSha2128s.buf`, `forsPk`, `xmssPk` and the layout constants are `internal` (not `private`) so
  the gas test composes the worst case from the production code.

## Open questions (not blocking)

- **Q1** EIP-8051's text vs its vectors and reference implementation (μ without the `M'` prefix, 32-byte `tr`, `t1`
  without `2^d`): worth an upstream comment; SCaaS follows the vectors.
- **Q2** What the registry stores for ML-DSA (FIPS 204 key vs expanded key) and how a stored expanded key is proven at
  registration within one transaction — P6c, owner (roadmap §3).
- **Q3** EIP-8052's 666-byte split (salt 40 ‖ 626 vs header 1 ‖ salt 40 ‖ 625), `h` in the NTT domain for `FALCON_CORE`,
  `<` vs `≤`: only relevant once 8052 has addresses (then a new verifier in a new registry generation).
- **Q4** Keccak-f at 66 k gas; a dedicated permutation helper (~44 k reported by Fireblocks) or a tighter round would
  cut ML-DSA and Falcon by 10–30 %.
- **Q5** Continuous differential fuzzing (T-FUZZ) against noble through `ffi`: P6a ships the deterministic mutation
  sets only.

## Out of scope (next sub-phases)

The registry and its `verifyCap`s (P6c), the chain-7622 ML-DSA precompile in the EIP-8355 layout and the address move
(P6f), `UAPqzVerifier` and `PqzToken` (P6g), the node's PQ intents (P6i); bamboo-dms has nothing to change for P6a.

### Task 1: clientkeys PQ keys and signing; the PQ vectors

`@noble/post-quantum` 0.7.1 (ACVP-checked: it agrees with every ML-DSA-44/65 and SLH-DSA-SHA2-128s sigVer case and
keyGen vector used here) gives the keys and signatures; `src/pq.js` adds the SCaaS layer (HKDF seeds, tags, `ua_msg`,
`pq_msg`, the EIP-8051 expanded key). Two scripts write the vector files the forge tests read: `pq-vectors.mjs` (SCaaS
vectors, deterministic) and `pq-external.mjs` (the published vectors, from commit-pinned URLs, each entry re-checked with
noble). `npm install` also corrects the lock file's stale root `name`/`license` to `package.json`'s.

**Files:** modify `clients/clientkeys/package.json`, `clients/clientkeys/package-lock.json`; create
`clients/clientkeys/src/pq.js`, `clients/clientkeys/scripts/pq-vectors.mjs`, `clients/clientkeys/scripts/pq-external.mjs`,
`clients/clientkeys/test/pq.test.js`; generate `smartcontracts/vectors/ua/pq_kat.json`, `smartcontracts/vectors/ua/pq_external.json`.

- [ ] **Step 1: Install.** `cd clients/clientkeys && ../../scripts/capped npm install --no-audit --no-fund --save-exact @noble/post-quantum@0.7.1`
  — `package.json` and `package-lock.json` then equal the diff below (`@noble/ciphers` 2.4.0 comes with it).
- [ ] **Step 2: Apply the diff below** (the four new files).
- [ ] **Step 3: Download the published vectors** into an empty scratch directory `$D` (outside the repo) and check them:

  ```bash
  A=https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files
  E=https://raw.githubusercontent.com/ethereum/EIPs/3aea9f3673a684dddfcc17c0d1f74d484e20e6ac/assets
  mkdir -p $D/ML-DSA-sigVer-FIPS204 $D/SLH-DSA-sigVer-FIPS205
  curl -sSfL -o $D/ML-DSA-sigVer-FIPS204/internalProjection.json $A/ML-DSA-sigVer-FIPS204/internalProjection.json
  curl -sSfL -o $D/SLH-DSA-sigVer-FIPS205/internalProjection.json $A/SLH-DSA-sigVer-FIPS205/internalProjection.json
  curl -sSfL -o $D/mldsa_nist.rsp $E/eip-8051/mldsa_nist.rsp
  curl -sSfL -o $D/test-vectors.json $E/eip-8355/test-vectors.json
  curl -sSfL -o $D/kat_FALCONCORE_512.rsp $E/eip-8052/kat_FALCONCORE_512.rsp
  curl -sSfL -o $D/kat_HASHTOPOINT_512.rsp $E/eip-8052/kat_HASHTOPOINT_512.rsp
  (cd $D && sha256sum ML-DSA-sigVer-FIPS204/internalProjection.json SLH-DSA-sigVer-FIPS205/internalProjection.json \
     mldsa_nist.rsp test-vectors.json kat_FALCONCORE_512.rsp kat_HASHTOPOINT_512.rsp)
  # 47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437  ML-DSA-sigVer-FIPS204/internalProjection.json
  # a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792  SLH-DSA-sigVer-FIPS205/internalProjection.json
  # 1d29c3b4ec68e3455f87f49b3386a2a6fc5e167c76e476c4770317ffbb97d242  mldsa_nist.rsp
  # 2029f73ffa8f514b4a105e6c93522d55bbbe0370c3ed5644773a88c1a91aeabd  test-vectors.json
  # c79c1dd457a92760ef30bbd63f1783aa634b9817acd2c1f1c3885c0c668b15ad  kat_FALCONCORE_512.rsp
  # 05b0ac54f4b329b9a778c826a81cb4184ce4c03b637607383b435efaf2899fcb  kat_HASHTOPOINT_512.rsp
  ```
- [ ] **Step 4: Generate the vectors.** In `clients/clientkeys`: `node scripts/pq-vectors.mjs` then
  `node scripts/pq-external.mjs $D` (prints `acvp_mldsa 60 cases, 12 valid`, `acvp_slhdsa 28 cases, 4 valid`,
  `eip8051_nist_kat 10 cases, 10 valid`, `eip8355 3 cases, 1 valid`, `falcon_kat 10 cases, 10 valid`). Check:
  `sha256sum ../../smartcontracts/vectors/ua/*.json` →
  `55d1f03d47911e93cfe1e9e097ba6314260f45f833e6f6bfbc9b1713e40b4694  pq_external.json` and
  `95b1a6ee6a896940195af0fe6fa3c577efdd4049cb9a0e01e59eaa3b71424dd3  pq_kat.json` (both scripts are deterministic; a
  different hash means a different input or noble version).
- [ ] **Step 5: Test.** `../../scripts/capped npm test` — 74 tests, 72 pass, 2 skipped (62 / 60 / 2 before: +12 in
  `test/pq.test.js`).
- [ ] **Step 6: Commit** `P6a T1: clientkeys PQ keys and signing (src/pq.js); PQ vectors (pq_kat.json, pq_external.json)`
  (the two vector files included; never `node_modules`).

``````diff
diff --git a/clients/clientkeys/package-lock.json b/clients/clientkeys/package-lock.json
index eec4747..4d38918 100644
--- a/clients/clientkeys/package-lock.json
+++ b/clients/clientkeys/package-lock.json
@@ -1,16 +1,17 @@
 {
-  "name": "clientkeys",
+  "name": "@scaas/clientkeys",
   "version": "1.0.0",
   "lockfileVersion": 3,
   "requires": true,
   "packages": {
     "": {
-      "name": "clientkeys",
+      "name": "@scaas/clientkeys",
       "version": "1.0.0",
-      "license": "ISC",
+      "license": "LGPL-3.0",
       "dependencies": {
         "@noble/curves": "2.4.0",
         "@noble/hashes": "2.4.0",
+        "@noble/post-quantum": "0.7.1",
         "@scure/base": "2.4.0",
         "@scure/bip32": "2.4.0",
         "@scure/bip39": "2.4.0"
@@ -461,6 +462,18 @@
         "node": ">=18"
       }
     },
+    "node_modules/@noble/ciphers": {
+      "version": "2.4.0",
+      "resolved": "https://registry.npmjs.org/@noble/ciphers/-/ciphers-2.4.0.tgz",
+      "integrity": "sha512-AnjFn0Jv92laAkvMrghlFZq4qQCIN/4DxFV/eooqtC2YTjB7kBeLMS2T9KJX4Dn+ZVXLOwK0lSgqDtx9gvxtiw==",
+      "license": "MIT",
+      "engines": {
+        "node": ">= 20.19.0"
+      },
+      "funding": {
+        "url": "https://paulmillr.com/funding/"
+      }
+    },
     "node_modules/@noble/curves": {
       "version": "2.4.0",
       "resolved": "https://registry.npmjs.org/@noble/curves/-/curves-2.4.0.tgz",
@@ -488,6 +501,23 @@
         "url": "https://paulmillr.com/funding/"
       }
     },
+    "node_modules/@noble/post-quantum": {
+      "version": "0.7.1",
+      "resolved": "https://registry.npmjs.org/@noble/post-quantum/-/post-quantum-0.7.1.tgz",
+      "integrity": "sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q==",
+      "license": "MIT",
+      "dependencies": {
+        "@noble/ciphers": "2.4.0",
+        "@noble/curves": "2.4.0",
+        "@noble/hashes": "2.4.0"
+      },
+      "engines": {
+        "node": ">= 20.19.0"
+      },
+      "funding": {
+        "url": "https://paulmillr.com/funding/"
+      }
+    },
     "node_modules/@scure/base": {
       "version": "2.4.0",
       "resolved": "https://registry.npmjs.org/@scure/base/-/base-2.4.0.tgz",
diff --git a/clients/clientkeys/package.json b/clients/clientkeys/package.json
index 0889461..0370a6a 100644
--- a/clients/clientkeys/package.json
+++ b/clients/clientkeys/package.json
@@ -13,6 +13,7 @@
   "dependencies": {
     "@noble/curves": "2.4.0",
     "@noble/hashes": "2.4.0",
+    "@noble/post-quantum": "0.7.1",
     "@scure/base": "2.4.0",
     "@scure/bip32": "2.4.0",
     "@scure/bip39": "2.4.0"
diff --git a/clients/clientkeys/scripts/pq-external.mjs b/clients/clientkeys/scripts/pq-external.mjs
new file mode 100644
index 0000000..4c9a2bf
--- /dev/null
+++ b/clients/clientkeys/scripts/pq-external.mjs
@@ -0,0 +1,94 @@
+// Imports the published PQ vectors into smartcontracts/vectors/ua/pq_external.json (input: a directory holding the
+// downloaded files, see docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md Task 1; each section records its source
+// URL and the file's SHA-256). Every entry is also checked here with @noble/post-quantum, so the file only holds vectors
+// that two implementations (noble and the Solidity verifiers) must agree on.
+//   node scripts/pq-external.mjs <download dir>
+import { readFileSync, writeFileSync } from 'node:fs';
+import { createHash } from 'node:crypto';
+import { ml_dsa44, ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
+import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
+import { falcon512padded } from '@noble/post-quantum/falcon.js';
+
+const dir = process.argv[2];
+if (!dir) throw new Error('usage: node scripts/pq-external.mjs <download dir>');
+const raw = (f) => readFileSync(`${dir}/${f}`);
+const sha = (f) => createHash('sha256').update(raw(f)).digest('hex');
+const h = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
+const x = (u) => '0x' + Buffer.from(u).toString('hex');
+const rsp = (f) => raw(f).toString('utf8').split('count = ').slice(1)
+  .map((r) => Object.fromEntries([...r.matchAll(/^(\w+) ?= ?(.*)$/gm)].map((m) => [m[1], m[2].trim()])));
+const ACVP = 'https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/';
+const EIPS = 'https://raw.githubusercontent.com/ethereum/EIPs/3aea9f3673a684dddfcc17c0d1f74d484e20e6ac/assets/';
+const ALG = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'SLH-DSA-SHA2-128s': slh_dsa_sha2_128s };
+
+/** ACVP sigVer, pure (external) and internal groups: `mprime` is the formatted message M' the core verifies. */
+function acvp(file, sets) {
+  const j = JSON.parse(raw(file));
+  const cases = [];
+  for (const g of j.testGroups) {
+    if (!sets.includes(g.parameterSet) || g.preHash === 'preHash' || g.externalMu) continue;
+    for (const t of g.tests) {
+      const ctx = h(t.context || '');
+      const m = h(t.message);
+      const mprime = g.signatureInterface === 'internal' ? m : Uint8Array.from([0, ctx.length, ...ctx, ...m]);
+      const a = ALG[g.parameterSet];
+      let ok;
+      try { ok = a.internal.verify(h(t.signature), mprime, h(t.pk)); } catch { ok = false; }
+      if (ok !== t.testPassed) throw new Error(`noble disagrees with ACVP ${g.parameterSet} tc ${t.tcId}`);
+      cases.push({ set: g.parameterSet, tc: t.tcId, iface: g.signatureInterface, pk: x(h(t.pk)), mprime: x(mprime),
+        sig: x(h(t.signature)), valid: t.testPassed, reason: t.reason });
+    }
+  }
+  return { source: ACVP + file, sha256: sha(file), cases };
+}
+
+// EIP-8051 `mldsa_nist.rsp`: FIPS 204 ML-DSA-44 KATs (sm = sig ‖ msg), the empty context ⇒ M' = 0x00 ‖ 0x00 ‖ msg.
+function eip8051(file, n) {
+  const cases = rsp(file).slice(0, n).map((r) => {
+    const sm = h(r.sm), mlen = +r.mlen, sig = sm.slice(0, sm.length - mlen), msg = sm.slice(sm.length - mlen);
+    if (!ml_dsa44.verify(sig, msg, h(r.pk))) throw new Error('8051 KAT fails in noble');
+    return { pk: x(h(r.pk)), mprime: x(Uint8Array.from([0, 0, ...msg])), sig: x(sig), valid: true };
+  });
+  return { source: EIPS + 'eip-8051/' + file, sha256: sha(file), cases };
+}
+
+// EIP-8355 test cases: input = pk (1312) ‖ sig (2420) ‖ msg for VERIFY_MLDSA44.
+function eip8355(file) {
+  const cases = JSON.parse(raw(file)).map((c) => {
+    const inp = h(c.Input), valid = BigInt('0x' + c.Expected) === 1n;
+    if (inp.length < 3732) return { name: c.Name, input: x(inp), valid };
+    const pk = inp.slice(0, 1312), sig = inp.slice(1312, 3732), msg = inp.slice(3732);
+    if (ml_dsa44.verify(sig, msg, pk) !== valid) throw new Error('8355 case disagrees in noble');
+    return { name: c.Name, input: x(inp), pk: x(pk), mprime: x(Uint8Array.from([0, 0, ...msg])), sig: x(sig), valid };
+  });
+  return { source: EIPS + 'eip-8355/' + file, sha256: sha(file), cases };
+}
+
+// Falcon-512 NIST round-3 KATs as published with EIP-8052: pk and the compressed s2 from kat_FALCONCORE_512.rsp
+// (`s2` = msg ‖ 0x29 ‖ compressed), the salt from kat_HASHTOPOINT_512.rsp (same seeds), rebuilt as padded signatures
+// 0x39 ‖ salt ‖ compressed ‖ zeros (666 bytes).
+function falcon(coreFile, h2pFile, n) {
+  const core = rsp(coreFile), h2p = rsp(h2pFile);
+  const cases = [];
+  for (let i = 0; i < n; i++) {
+    const c = core[i], p = h2p[i];
+    if (c.seed !== p.seed) throw new Error('falcon KAT seeds differ');
+    const mlen = +p.mlen, s2 = h(c.s2), msg = s2.slice(0, mlen), comp = s2.slice(mlen + 1);
+    const sig = new Uint8Array(666);
+    sig[0] = 0x39; sig.set(h(p.salt), 1); sig.set(comp, 41);
+    if (!falcon512padded.verify(sig, msg, h(c.pk))) throw new Error('falcon KAT fails in noble');
+    cases.push({ count: i, pk: x(h(c.pk)), msg: x(msg), sig: x(sig), valid: true });
+  }
+  return { sources: [EIPS + 'eip-8052/' + coreFile, EIPS + 'eip-8052/' + h2pFile], sha256: [sha(coreFile), sha(h2pFile)], cases };
+}
+
+const out = {
+  note: 'Imported by clients/clientkeys/scripts/pq-external.mjs; every entry re-checked with @noble/post-quantum 0.7.1.',
+  acvp_mldsa: acvp('ML-DSA-sigVer-FIPS204/internalProjection.json', ['ML-DSA-44', 'ML-DSA-65']),
+  acvp_slhdsa: acvp('SLH-DSA-sigVer-FIPS205/internalProjection.json', ['SLH-DSA-SHA2-128s']),
+  eip8051_nist_kat: eip8051('mldsa_nist.rsp', 10),
+  eip8355: eip8355('test-vectors.json'),
+  falcon_kat: falcon('kat_FALCONCORE_512.rsp', 'kat_HASHTOPOINT_512.rsp', 10),
+};
+writeFileSync(new URL('../../../smartcontracts/vectors/ua/pq_external.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
+for (const [k, v] of Object.entries(out)) if (v.cases) console.log(k, v.cases.length, 'cases,', v.cases.filter((c) => c.valid).length, 'valid');
diff --git a/clients/clientkeys/scripts/pq-vectors.mjs b/clients/clientkeys/scripts/pq-vectors.mjs
new file mode 100644
index 0000000..ccf7a3d
--- /dev/null
+++ b/clients/clientkeys/scripts/pq-vectors.mjs
@@ -0,0 +1,63 @@
+// Generates smartcontracts/vectors/ua/pq_kat.json: for each PQ kind, the key pair derived from the SEP-0005 test mnemonic
+// (account 0, index 0) by src/pq.js, the UA id, ua_msg / signed message for purpose `pop` over a fixed digest, a
+// deterministic signature (ML-DSA, SLH-DSA: extraEntropy false; Falcon: a fixed `random`), the EIP-8051 expanded key
+// (ML-DSA), the EIP-8355 probe inputs (ML-DSA) and a mutation set with noble's verdict for each entry (the forge test
+// requires the Solidity verifier to give the same verdict: differential parity, T-FUZZ's deterministic part).
+//   node scripts/pq-vectors.mjs
+import { writeFileSync, mkdirSync } from 'node:fs';
+import { shake256 } from '@noble/hashes/sha3.js';
+import { seedFromWords } from '../src/seed.js';
+import { PQ_KINDS, pqKeygen, kindTag, uaMessage, signedMessage, signUA, verifyUA, purposeTag, mldsaExpandedKey } from '../src/pq.js';
+import { hex, keccak_256, utf8ToBytes, concatBytes } from '../src/bytes.js';
+
+const M = 'bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author '
+  + 'capable act festival slice deposit sauce coconut afford frown better';
+const seed = seedFromWords(M);
+const digest = keccak_256(utf8ToBytes('scaas p6a pq vector digest'));
+const purpose = purposeTag('pop');
+const fixed = (n) => shake256(utf8ToBytes('scaas p6a falcon randomness'), { dkLen: n });
+const opts = (name) => (name === 'fndsa512' ? { random: fixed } : { extraEntropy: false });
+const flip = (b, i, bit = 1) => { const c = Uint8Array.from(b); c[i] ^= bit; return c; };
+
+const out = {
+  note: 'Generated by clients/clientkeys/scripts/pq-vectors.mjs with @noble/post-quantum 0.7.1 (src/pq.js). '
+    + 'Mutations carry noble\'s verdict; the Solidity verifiers must agree on every entry.',
+  shake256_200: hex(shake256(Uint8Array.from({ length: 200 }, (_, i) => i), { dkLen: 32 })),
+  mnemonic: M, account: 0, index: 0, purpose: 'pop', purpose_tag: hex(purpose), digest: hex(digest), kinds: {},
+};
+for (const name of Object.keys(PQ_KINDS)) {
+  const { kind } = PQ_KINDS[name];
+  const kp = pqKeygen(seed, name, 0, 0);
+  const ua = uaMessage(name, purpose, digest);
+  const msg = signedMessage(name, purpose, digest);
+  const sig = signUA(name, kp.secretKey, purpose, digest, opts(name));
+  if (!verifyUA(name, kp.publicKey, purpose, digest, sig)) throw new Error(`${name}: own signature fails`);
+  const n = sig.length;
+  const cases = [
+    ['sig[0] ^ 0x01', kp.publicKey, flip(sig, 0), ua],
+    ['sig[mid] ^ 0x80', kp.publicKey, flip(sig, n >> 1, 0x80), ua],
+    ['sig[last] ^ 0x01', kp.publicKey, flip(sig, n - 1), ua],
+    ['pk[last] ^ 0x01', flip(kp.publicKey, kp.publicKey.length - 1), sig, ua],
+    ['ua_msg[0] ^ 0x01', kp.publicKey, sig, flip(ua, 0)],
+    ['truncated sig', kp.publicKey, sig.slice(0, n - 1), ua],
+  ];
+  const mutations = cases.map(([what, pk, s, u]) => {
+    const m2 = PQ_KINDS[name].pq ? keccak_256(concatBytes(kindTag(name), u)) : u;
+    let valid;
+    try { valid = PQ_KINDS[name].alg.verify(s, m2, pk); } catch { valid = false; }
+    return { what, pk: hex(pk), sig: hex(s), ua_msg: hex(u), valid };
+  });
+  const k = {
+    kind: '0x' + kind.toString(16).padStart(4, '0'), tag: PQ_KINDS[name].tag, tag_hash: hex(kindTag(name)),
+    pk: hex(kp.publicKey), ua: hex(kp.ua), ua_msg: hex(ua), signed_message: hex(msg), sig: hex(sig), mutations,
+  };
+  if (name.startsWith('mldsa')) {
+    k.expanded_key = hex(mldsaExpandedKey(name, kp.publicKey));
+    k.eip8355_probe_valid = hex(concatBytes(kp.publicKey, sig, msg));
+    k.eip8355_probe_invalid = hex(concatBytes(kp.publicKey, flip(sig, 0), msg));
+  }
+  out.kinds[name] = k;
+}
+mkdirSync(new URL('../../../smartcontracts/vectors/ua/', import.meta.url), { recursive: true });
+writeFileSync(new URL('../../../smartcontracts/vectors/ua/pq_kat.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
+console.log('wrote smartcontracts/vectors/ua/pq_kat.json');
diff --git a/clients/clientkeys/src/pq.js b/clients/clientkeys/src/pq.js
new file mode 100644
index 0000000..998c2f9
--- /dev/null
+++ b/clients/clientkeys/src/pq.js
@@ -0,0 +1,145 @@
+// Post-quantum UA kinds (accounts.md CTR-UA-23, signers-clientkeys.md "PQ seeds"): mldsa44 / mldsa65 (FIPS 204),
+// fndsa512 (Falcon-512, round 3, padded signatures: EIP-8052's 666 bytes), slhdsa128s (FIPS 205 SLH-DSA-SHA2-128s).
+// Keys come from the BIP-39 seed by HKDF; ML-DSA and SLH-DSA sign pq_msg = keccak256(TAG(kind) ‖ ua_msg) with the empty
+// context, Falcon signs ua_msg (the 32-byte message of EIP-8052). There is no "sign this digest" entry: signUA takes the
+// purpose tag and the operation digest and builds ua_msg itself (CTR-UA-10 layer 1).
+import { ml_dsa44, ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
+import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
+import { falcon512padded } from '@noble/post-quantum/falcon.js';
+import { hkdf } from '@noble/hashes/hkdf.js';
+import { shake128, shake256 } from '@noble/hashes/sha3.js';
+import { keccak_256, sha256, concatBytes, utf8ToBytes } from './bytes.js';
+
+/** kind number, tag string, scheme, HKDF output length, signed message. */
+export const PQ_KINDS = {
+  mldsa44: { kind: 0x0130, tag: 'scaas.ua.mldsa44.v1', alg: ml_dsa44, seedLen: 32, pq: true },
+  mldsa65: { kind: 0x0131, tag: 'scaas.ua.mldsa65.v1', alg: ml_dsa65, seedLen: 32, pq: true },
+  fndsa512: { kind: 0x0132, tag: 'scaas.ua.fndsa512.v1', alg: falcon512padded, seedLen: 48, pq: false },
+  slhdsa128s: { kind: 0x0133, tag: 'scaas.ua.slhdsa128s.v1', alg: slh_dsa_sha2_128s, seedLen: 48, pq: true },
+};
+
+const MSG_TAG = keccak_256(utf8ToBytes('scaas.ua.msg.v1'));
+
+function spec(name) {
+  const s = PQ_KINDS[name];
+  if (!s) throw new Error(`unknown PQ kind ${name}`);
+  return s;
+}
+
+const u32 = (v) => new Uint8Array([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
+const b32 = (x, what) => {
+  if (!(x instanceof Uint8Array) || x.length !== 32) throw new Error(`${what} must be 32 bytes`);
+  return x;
+};
+
+/** TAG(kind) = keccak256(kind_tag). */
+export const kindTag = (name) => keccak_256(utf8ToBytes(spec(name).tag));
+
+/** UA = keccak256(TAG(kind) ‖ key data); key data = the public key (FIPS 204 / round-3 Falcon / FIPS 205 encoding). */
+export const uaId = (name, publicKey) => keccak_256(concatBytes(kindTag(name), publicKey));
+
+/** purposeTag = keccak256("scaas.ua.purpose.<p>.v1"). */
+export const purposeTag = (p) => keccak_256(utf8ToBytes(`scaas.ua.purpose.${p}.v1`));
+
+/** ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest) (CTR-UA-12). */
+export const uaMessage = (name, purpose, digest) =>
+  keccak_256(concatBytes(MSG_TAG, kindTag(name), b32(purpose, 'purposeTag'), b32(digest, 'digest')));
+
+/** pq_msg = keccak256(TAG(kind) ‖ ua_msg) (CTR-UA-23). */
+export const pqMessage = (name, uaMsg) => keccak_256(concatBytes(kindTag(name), b32(uaMsg, 'ua_msg')));
+
+/** ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = kind_tag ‖ u32 account ‖ u32 index). */
+export function pqSeed(seed, name, account, index) {
+  const s = spec(name);
+  return hkdf(sha256, seed, utf8ToBytes('scaas.ua.pq.v1'), concatBytes(utf8ToBytes(s.tag), u32(account), u32(index)), s.seedLen);
+}
+
+/** Deterministic key pair of a PQ kind. Falcon keys are implementation-specific: pinned to @noble/post-quantum 0.7.1 by the vectors. */
+export function pqKeygen(seed, name, account, index) {
+  const xi = pqSeed(seed, name, account, index);
+  const { publicKey, secretKey } = spec(name).alg.keygen(xi);
+  xi.fill(0);
+  return { kind: name, publicKey, secretKey, ua: uaId(name, publicKey) };
+}
+
+/** The bytes the scheme signs: pq_msg (ML-DSA, SLH-DSA; empty context) or ua_msg (Falcon). */
+export function signedMessage(name, purpose, digest) {
+  const ua = uaMessage(name, purpose, digest);
+  return spec(name).pq ? pqMessage(name, ua) : ua;
+}
+
+/** Signs (purpose, digest) for a PQ UA. `opts` goes to noble (e.g. { extraEntropy: false } for vectors). */
+export const signUA = (name, secretKey, purpose, digest, opts) =>
+  spec(name).alg.sign(signedMessage(name, purpose, digest), secretKey, opts);
+
+export const verifyUA = (name, publicKey, purpose, digest, sig) =>
+  spec(name).alg.verify(sig, signedMessage(name, purpose, digest), publicKey);
+
+// ------------------------------------------------------------------ EIP-8051 expanded key (ML-DSA-44 and -65)
+
+const Q = 8380417;
+const ZETAS = (() => {
+  const z = new Array(256);
+  let pw = 1n;
+  for (let i = 0; i < 256; i++) {
+    let r = 0;
+    for (let b = 0; b < 8; b++) r = (r << 1) | ((i >> b) & 1);
+    z[r] = Number(pw);
+    pw = (pw * 1753n) % BigInt(Q);
+  }
+  return z;
+})();
+const mulq = (a, b) => Number((BigInt(a) * BigInt(b)) % BigInt(Q));
+
+function ntt(w) {
+  let m = 0;
+  for (let len = 128; len >= 1; len >>= 1) {
+    for (let start = 0; start < 256; start += 2 * len) {
+      const z = ZETAS[++m];
+      for (let j = start; j < start + len; j++) {
+        const t = mulq(z, w[j + len]);
+        w[j + len] = (w[j] - t + Q) % Q;
+        w[j] = (w[j] + t) % Q;
+      }
+    }
+  }
+  return w;
+}
+
+function rejNttPoly(seed34) {
+  const out = [];
+  const xof = shake128.create();
+  xof.update(seed34);
+  while (out.length < 256) {
+    const b = xof.xof(168);
+    for (let o = 0; o < 168 && out.length < 256; o += 3) {
+      const v = b[o] | (b[o + 1] << 8) | ((b[o + 2] & 0x7f) << 16);
+      if (v < Q) out.push(v);
+    }
+  }
+  return out;
+}
+
+/** EIP-8051 expanded key: Â (k·l polynomials, row-major) ‖ tr (64, FIPS 204) ‖ NTT(t1·2^13) (k), coefficients u32 big-endian. */
+export function mldsaExpandedKey(name, pk) {
+  const [k, l] = name === 'mldsa44' ? [4, 4] : name === 'mldsa65' ? [6, 5] : [0, 0];
+  if (!k || pk.length !== 32 + 320 * k) throw new Error('mldsaExpandedKey: ML-DSA-44 or -65 public key required');
+  const out = new Uint8Array((k * l + k) * 1024 + 64);
+  const dv = new DataView(out.buffer);
+  let o = 0;
+  const put = (poly) => { for (const c of poly) { dv.setUint32(o, c); o += 4; } };
+  for (let i = 0; i < k; i++) for (let j = 0; j < l; j++) put(rejNttPoly(concatBytes(pk.subarray(0, 32), new Uint8Array([j, i]))));
+  out.set(shake256(pk, { dkLen: 64 }), o);
+  o += 64;
+  for (let i = 0; i < k; i++) {
+    const t = new Array(256);
+    const base = 32 + 320 * i;
+    for (let c = 0; c < 256; c++) {
+      const bit = 10 * c, by = base + (bit >> 3);
+      const v = ((pk[by] | (pk[by + 1] << 8)) >> (bit & 7)) & 0x3ff;
+      t[c] = mulq(v, 8192);
+    }
+    put(ntt(t));
+  }
+  return out;
+}
diff --git a/clients/clientkeys/test/pq.test.js b/clients/clientkeys/test/pq.test.js
new file mode 100644
index 0000000..4cd46eb
--- /dev/null
+++ b/clients/clientkeys/test/pq.test.js
@@ -0,0 +1,75 @@
+// PQ UA kinds (src/pq.js) against smartcontracts/vectors/ua/pq_kat.json, the vectors the forge suite verifies on chain
+// (test/ua/PqVerifiers.t.sol): same keys from the seed, same ids and messages, the same deterministic signatures.
+import { test } from 'node:test';
+import assert from 'node:assert/strict';
+import { readFileSync } from 'node:fs';
+import { seedFromWords } from '../src/seed.js';
+import {
+  PQ_KINDS, pqSeed, pqKeygen, kindTag, uaId, uaMessage, pqMessage, signedMessage, signUA, verifyUA, purposeTag, mldsaExpandedKey,
+} from '../src/pq.js';
+import { hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';
+import { shake256 } from '@noble/hashes/sha3.js';
+
+const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/ua/pq_kat.json', import.meta.url)));
+const seed = seedFromWords(V.mnemonic);
+const purpose = fromHex(V.purpose_tag);
+const digest = fromHex(V.digest);
+
+test('purpose tag and digest of the vectors', () => {
+  assert.equal(hex(purposeTag('pop')), V.purpose_tag);
+  assert.equal(hex(digest), hex(keccak_256(utf8ToBytes('scaas p6a pq vector digest'))));
+});
+
+for (const name of Object.keys(PQ_KINDS)) {
+  const v = V.kinds[name];
+  test(`${name}: seed → key, UA id, ua_msg, signed message = vectors`, () => {
+    const kp = pqKeygen(seed, name, V.account, V.index);
+    assert.equal(hex(kp.publicKey), v.pk);
+    assert.equal(hex(kp.ua), v.ua);
+    assert.equal(hex(uaId(name, kp.publicKey)), v.ua);
+    assert.equal(hex(kindTag(name)), v.tag_hash);
+    assert.equal(hex(uaMessage(name, purpose, digest)), v.ua_msg);
+    const signed = signedMessage(name, purpose, digest);
+    assert.equal(hex(signed), v.signed_message);
+    // ML-DSA and SLH-DSA sign pq_msg; Falcon signs ua_msg itself
+    assert.equal(hex(signed), PQ_KINDS[name].pq ? hex(pqMessage(name, fromHex(v.ua_msg))) : v.ua_msg);
+  });
+
+  test(`${name}: deterministic signature = vector; verifies; tampering fails`, () => {
+    const kp = pqKeygen(seed, name, V.account, V.index);
+    const opts = name === 'fndsa512'
+      ? { random: (n) => shake256(utf8ToBytes('scaas p6a falcon randomness'), { dkLen: n }) }
+      : { extraEntropy: false };
+    const sig = signUA(name, kp.secretKey, purpose, digest, opts);
+    assert.equal(hex(sig), v.sig);
+    assert.ok(verifyUA(name, kp.publicKey, purpose, digest, sig));
+    assert.ok(!verifyUA(name, kp.publicKey, purposeTag('metatx'), digest, sig), 'another purpose');
+    const other = name === 'mldsa44' ? 'mldsa65' : 'mldsa44';
+    assert.notEqual(hex(signedMessage(other, purpose, digest)), hex(signedMessage(name, purpose, digest)), 'kind-tagged');
+    // hedged signing (the default) still verifies
+    assert.ok(verifyUA(name, kp.publicKey, purpose, digest, signUA(name, kp.secretKey, purpose, digest)));
+  });
+}
+
+test('PQ seeds: HKDF per kind, account and index; lengths per scheme', () => {
+  assert.equal(pqSeed(seed, 'mldsa44', 0, 0).length, 32);
+  assert.equal(pqSeed(seed, 'slhdsa128s', 0, 0).length, 48);
+  assert.equal(pqSeed(seed, 'fndsa512', 0, 0).length, 48);
+  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa44', 0, 1)));
+  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa44', 1, 0)));
+  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa65', 0, 0)));
+});
+
+test('EIP-8051 expanded key = vectors (the forge suite derives the same bytes on chain)', () => {
+  for (const name of ['mldsa44', 'mldsa65']) {
+    assert.equal(hex(mldsaExpandedKey(name, fromHex(V.kinds[name].pk))), V.kinds[name].expanded_key);
+  }
+  assert.throws(() => mldsaExpandedKey('fndsa512', fromHex(V.kinds.fndsa512.pk)));
+});
+
+test('no raw-digest signing: purpose and digest must be 32 bytes', () => {
+  const kp = pqKeygen(seed, 'mldsa44', 0, 0);
+  assert.throws(() => signUA('mldsa44', kp.secretKey, purpose, new Uint8Array(31)), /32 bytes/);
+  assert.throws(() => signUA('mldsa44', kp.secretKey, new Uint8Array(5), digest), /32 bytes/);
+  assert.throws(() => signUA('rsa', kp.secretKey, purpose, digest), /unknown PQ kind/);
+});
``````

### Task 2: `PqUA`, SLH-DSA-SHA2-128s and its gas gate

The shared layer (`IUAKindVerifier`, tags, `ua_msg`, `pq_msg`, `M'`, the probe) and the hash-based kind first: it needs
no Keccak, and its gas gate is the owner's precondition for public chains. SLH-DSA verifies FIPS 205's
`slh_verify_internal` with every tweakable hash `Trunc16(SHA-256(PK.seed ‖ 0^48 ‖ ADRSc ‖ M))` on `0x02`: one 160-byte
buffer for F and H (the 22-byte `ADRSc` is written by one `mstore` at offset 54, which also re-zeroes the padding), one
704-byte buffer for `T_k` / `T_len`. The worst case is measured by running the same `forsPk` / `xmssPk` with every
layer's WOTS+ message forced to 0 (510 chain steps per layer, the maximum: Σ(15 − m_i) = 480 plus the checksum chains
14 + 1 + 15).

**Files:** modify `smartcontracts/evm/foundry.toml`; create `smartcontracts/evm/src/ua/PqUA.sol`,
`smartcontracts/evm/src/ua/SlhDsa.sol`, `smartcontracts/evm/test/ua/PqVectors.sol`, `smartcontracts/evm/test/ua/SlhDsa.t.sol`,
`smartcontracts/evm/test/ua/PqGas.t.sol`.

- [ ] **Step 1: Apply the diff below.**
- [ ] **Step 2: The new tests.** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/ua/*' -vv`
  — `SlhDsaTest` 3 passed (`test_kat_slhdsa128s`, `test_acvp_slhdsa`: 28 ACVP cases, `test_malformed_slhdsa`) and
  `PqGasTest.test_gas_slhdsa` logs `slhdsa128s verify (valid) 787953` and `worst case … 1321231` (< 1,460,000).
- [ ] **Step 3: Full suite.** `../../scripts/capped forge test` — **894** passed, 10 skipped; size gate 0 errors.
- [ ] **Step 4: Commit** `P6a T2: PqUA (IUAKindVerifier, tags, pq_msg, probe); SLH-DSA-SHA2-128s verifier; gas gate 1.32 M worst case`.

``````diff
diff --git a/smartcontracts/evm/foundry.toml b/smartcontracts/evm/foundry.toml
index 3583cd6..135465e 100644
--- a/smartcontracts/evm/foundry.toml
+++ b/smartcontracts/evm/foundry.toml
@@ -21,6 +21,7 @@ fs_permissions = [
   { access = "read", path = "./test/v2/layout" },
   { access = "read", path = "./out" },
   { access = "read", path = "./src" },
+  { access = "read", path = "../vectors" },
 ]
 
 [invariant]
diff --git a/smartcontracts/evm/src/ua/PqUA.sol b/smartcontracts/evm/src/ua/PqUA.sol
new file mode 100644
index 0000000..7acfa44
--- /dev/null
+++ b/smartcontracts/evm/src/ua/PqUA.sol
@@ -0,0 +1,76 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+/// @title Per-kind UA verifier (accounts.md CTR-UA-17 "Verifiers").
+/// @notice Stateless. The registry has matched `keyData` against the id (or read the stored key from `keyPtr`);
+///         `message` is the 32-byte `ua_msg` (CTR-UA-12). A malformed input returns false, never true.
+interface IUAKindVerifier {
+    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
+}
+
+/// @title PQ signing kinds: tags, the PQ message and the precompile probe (accounts.md CTR-UA-23).
+/// @notice ML-DSA and SLH-DSA sign `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the empty FIPS 204 / FIPS 205
+///         context, so the signed message is `M' = 0x00 ‖ 0x00 ‖ pq_msg`; FN-DSA (Falcon) signs `ua_msg` itself,
+///         the 32-byte message of EIP-8052. A precompile is used only when it answers a known vector exactly:
+///         a valid input ⇒ 32 bytes equal to 1, a one-bit-flipped input ⇒ 32 bytes equal to 0 (EIP-8355
+///         "Security Considerations"); an empty account, another precompile at a contested address (EIP-7932 and
+///         EIP-8051 also claim 0x12) or a different message convention fails the probe.
+library PqUA {
+    uint16 internal constant MLDSA44 = 0x0130;
+    uint16 internal constant MLDSA65 = 0x0131;
+    uint16 internal constant FNDSA512 = 0x0132;
+    uint16 internal constant SLHDSA128S = 0x0133;
+
+    bytes32 internal constant MSG_TAG = keccak256("scaas.ua.msg.v1");
+
+    error PqUAUnknownKind(uint16 kind);
+
+    /// `TAG(kind) = keccak256(kind_tag)`, `kind_tag = "scaas.ua.<name>.v1"` (accounts.md §1.6).
+    function tag(uint16 kind) internal pure returns (bytes32) {
+        if (kind == MLDSA44) return keccak256("scaas.ua.mldsa44.v1");
+        if (kind == MLDSA65) return keccak256("scaas.ua.mldsa65.v1");
+        if (kind == FNDSA512) return keccak256("scaas.ua.fndsa512.v1");
+        if (kind == SLHDSA128S) return keccak256("scaas.ua.slhdsa128s.v1");
+        revert PqUAUnknownKind(kind);
+    }
+
+    /// `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)` (CTR-UA-12).
+    function uaMessage(bytes32 kindTag, bytes32 purposeTag, bytes32 digest) internal pure returns (bytes32) {
+        return keccak256(abi.encodePacked(MSG_TAG, kindTag, purposeTag, digest));
+    }
+
+    /// `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` (CTR-UA-23).
+    function pqMessage(bytes32 kindTag, bytes32 uaMsg) internal pure returns (bytes32) {
+        return keccak256(abi.encodePacked(kindTag, uaMsg));
+    }
+
+    /// FIPS 204 / FIPS 205 pure signing with the empty context: `M' = 0x00 ‖ 0x00 ‖ pq_msg`.
+    function emptyContext(bytes32 pqMsg) internal pure returns (bytes memory) {
+        return abi.encodePacked(bytes2(0), pqMsg);
+    }
+
+    /// True iff `target` answers `valid` with exactly the 32-byte word 1 and `invalid` with exactly the word 0.
+    function probe(address target, bytes memory valid, bytes memory invalid) internal view returns (bool) {
+        if (target == address(0)) return false;
+        return _answer(target, valid) == 1 && _answer(target, invalid) == 0;
+    }
+
+    /// The 32-byte answer of `target`, or 2 (neither 0 nor 1) on a failed call or any other returndata length.
+    function _answer(address target, bytes memory input) private view returns (uint256 w) {
+        assembly ("memory-safe") {
+            mstore(0, 2)
+            let ok := staticcall(gas(), target, add(input, 0x20), mload(input), 0, 0x20)
+            w := mload(0)
+            if iszero(and(ok, eq(returndatasize(), 0x20))) { w := 2 }
+        }
+    }
+
+    /// One precompile call on the verify path: true only on exactly 32 bytes equal to 1 (EIP-8355 output rule).
+    function callBool(address target, bytes memory input) internal view returns (bool ok) {
+        assembly ("memory-safe") {
+            mstore(0, 0)
+            let s := staticcall(gas(), target, add(input, 0x20), mload(input), 0, 0x20)
+            ok := and(and(s, eq(returndatasize(), 0x20)), eq(mload(0), 1))
+        }
+    }
+}
diff --git a/smartcontracts/evm/src/ua/SlhDsa.sol b/smartcontracts/evm/src/ua/SlhDsa.sol
new file mode 100644
index 0000000..526afac
--- /dev/null
+++ b/smartcontracts/evm/src/ua/SlhDsa.sol
@@ -0,0 +1,164 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {IUAKindVerifier, PqUA} from "./PqUA.sol";
+
+/// @title SLH-DSA-SHA2-128s verification (FIPS 205, Algorithms 8, 11, 13, 17, 20; SHA2 category 1, §11.2.1).
+/// @notice n = 16, h = 63, d = 7, h' = 9, a = 12, k = 14, lg w = 4, len = 35, m = 30; pk = PK.seed ‖ PK.root (32 B),
+///         sig = R ‖ SIG_FORS ‖ SIG_HT (7,856 B). Every tweakable hash is `Trunc16(SHA-256(PK.seed ‖ 0^48 ‖ ADRSc ‖ M))`
+///         on the SHA-256 precompile 0x02, with one memory buffer per input shape: `PK.seed ‖ 0^48` (64 B), then the
+///         22-byte compressed address `ADRSc`, then the message. **UNAUDITED.**
+/// @dev Gas is linear in the WOTS+ chain steps an input forces: at most 510 per layer (checksum included), 3,570 in all,
+///      plus 182 FORS hashes; the measured worst case is in `test/ua/PqGas.t.sol`.
+library SlhDsaSha2128s {
+    uint256 internal constant SIG_LEN = 7856;
+    uint256 private constant HI16 = 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;
+    // ADRS types (FIPS 205 §4.2)
+    uint256 private constant WOTS_HASH = 0;
+    uint256 private constant WOTS_PK = 1;
+    uint256 private constant TREE = 2;
+    uint256 private constant FORS_TREE = 3;
+    uint256 private constant FORS_ROOTS = 4;
+    // signature layout: R (16) ‖ FORS 14 × (sk 16 ‖ auth 12 × 16) ‖ HT 7 × (WOTS 35 × 16 ‖ auth 9 × 16)
+    uint256 private constant FORS_OFF = 16;
+    uint256 internal constant HT_OFF = 16 + 14 * 13 * 16; // 2928
+    uint256 internal constant XMSS_LEN = (35 + 9) * 16; // 704
+
+    /// `slh_verify_internal(M', SIG, PK)`. `mPrime` is the formatted message (pure interface: `0 ‖ |ctx| ‖ ctx ‖ M`).
+    function verify(bytes calldata pk, bytes memory mPrime, bytes calldata sig) internal view returns (bool) {
+        if (pk.length != 32 || sig.length != SIG_LEN) return false;
+        bytes32 seed = bytes32(pk[0:16]);
+        bytes32 root = bytes32(pk[16:32]);
+        bytes16 r = bytes16(sig[0:16]);
+        // H_msg = MGF1-SHA-256(R ‖ PK.seed ‖ SHA-256(R ‖ PK.seed ‖ PK.root ‖ M'), 30)
+        bytes32 inner = sha256(abi.encodePacked(r, bytes16(seed), bytes16(root), mPrime));
+        uint256 dg = uint256(sha256(abi.encodePacked(r, bytes16(seed), inner, uint32(0))));
+        uint256 md = dg >> 88; // 21 bytes = 14 × 12-bit FORS indices
+        uint256 idxTree = (dg >> 32) & ((1 << 54) - 1); // bytes 21..27 mod 2^54
+        uint256 idxLeaf = (dg >> 16) & 0x1ff; // bytes 28..29 mod 2^9
+
+        uint256 b = buf(seed, 160); // tweakable hashes F and H: 64 + 22 + 32
+        uint256 t = buf(seed, 704); // T_k (FORS roots) and T_len (WOTS+ public keys): 64 + 22 + 35 × 16
+        uint256 node = forsPk(sig, md, idxTree, idxLeaf, b, t);
+        for (uint256 j; j < 7; ++j) {
+            if (j != 0) {
+                idxLeaf = idxTree & 0x1ff;
+                idxTree >>= 9;
+            }
+            node = xmssPk(sig, HT_OFF + j * XMSS_LEN, node, j, idxTree, idxLeaf, b, t);
+        }
+        return bytes32(node) == root;
+    }
+
+    /// A buffer starting with `PK.seed ‖ 0^48`.
+    function buf(bytes32 seed, uint256 len) internal pure returns (uint256 p) {
+        assembly ("memory-safe") {
+            p := mload(0x40)
+            mstore(0x40, add(p, len))
+            mstore(p, seed)
+            mstore(add(p, 0x20), 0)
+        }
+    }
+
+    /// ADRSc = layer (1) ‖ tree (8) ‖ type (1) ‖ word1 (4) ‖ word2 (4) ‖ word3 (4), right-aligned in a word, so
+    /// `mstore(buf + 54, adrs)` writes it at buf + 64 and re-zeroes the last 10 padding bytes.
+    function _adrs(uint256 layer, uint256 tree, uint256 typ, uint256 w1) private pure returns (uint256) {
+        return (layer << 168) | (tree << 104) | (typ << 96) | (w1 << 64);
+    }
+
+    /// Algorithm 17 `fors_pkFromSig` then `T_k` (internal: the gas test composes the worst case from it).
+    function forsPk(bytes calldata sig, uint256 md, uint256 tree, uint256 leaf, uint256 b, uint256 t)
+        internal view returns (uint256 pk)
+    {
+        uint256 base = _adrs(0, tree, FORS_TREE, leaf);
+        assembly ("memory-safe") {
+            let s := add(sig.offset, FORS_OFF)
+            for { let i := 0 } lt(i, 14) { i := add(i, 1) } {
+                let idx := and(shr(sub(156, mul(i, 12)), md), 0xfff)
+                let ti := add(shl(12, i), idx)
+                let o := add(s, mul(i, 208))
+                // leaf: F(PK.seed, ADRS(height 0, index ti), sk)
+                mstore(add(b, 54), or(base, ti))
+                calldatacopy(add(b, 86), o, 16)
+                if iszero(staticcall(gas(), 2, b, 102, 0, 0x20)) { revert(0, 0) }
+                let nd := and(mload(0), HI16)
+                for { let j := 0 } lt(j, 12) { j := add(j, 1) } {
+                    let au := and(calldataload(add(o, mul(add(j, 1), 16))), HI16)
+                    let odd := and(shr(j, idx), 1)
+                    ti := shr(1, ti) // (ti - odd) / 2 == ti >> 1
+                    mstore(add(b, 54), or(or(base, shl(32, add(j, 1))), ti))
+                    switch odd
+                    case 0 { mstore(add(b, 86), nd) mstore(add(b, 102), au) }
+                    default { mstore(add(b, 86), au) mstore(add(b, 102), nd) }
+                    if iszero(staticcall(gas(), 2, b, 118, 0, 0x20)) { revert(0, 0) }
+                    nd := and(mload(0), HI16)
+                }
+                mstore(add(t, add(86, shl(4, i))), nd)
+            }
+        }
+        uint256 rootsAdrs = _adrs(0, tree, FORS_ROOTS, leaf);
+        assembly ("memory-safe") {
+            mstore(add(t, 54), rootsAdrs)
+            if iszero(staticcall(gas(), 2, t, 310, 0, 0x20)) { revert(0, 0) } // 64 + 22 + 14 × 16
+            pk := and(mload(0), HI16)
+        }
+    }
+
+    /// Algorithm 11 `xmss_pkFromSig` (with Algorithm 8 `wots_pkFromSig` inline) at hypertree layer `layer`; the work
+    /// is largest for `m = 0` (510 chain steps).
+    function xmssPk(bytes calldata sig, uint256 off, uint256 m, uint256 layer, uint256 tree, uint256 leaf,
+        uint256 b, uint256 t) internal view returns (uint256 node)
+    {
+        uint256 chainBase = _adrs(layer, tree, WOTS_HASH, leaf);
+        uint256 pkAdrs = _adrs(layer, tree, WOTS_PK, leaf);
+        uint256 treeBase = _adrs(layer, tree, TREE, 0);
+        assembly ("memory-safe") {
+            let s := add(sig.offset, off)
+            // message nibbles (high nibble first) and the checksum Σ(15 − m_i), 3 nibbles
+            let csum := 0
+            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
+                csum := add(csum, sub(15, and(shr(sub(252, shl(2, i)), m), 15)))
+            }
+            for { let i := 0 } lt(i, 35) { i := add(i, 1) } {
+                let v
+                switch lt(i, 32)
+                case 1 { v := and(shr(sub(252, shl(2, i)), m), 15) }
+                default { v := and(shr(shl(2, sub(34, i)), csum), 15) }
+                calldatacopy(add(b, 86), add(s, shl(4, i)), 16)
+                let a := or(chainBase, shl(32, i))
+                for { let j := v } lt(j, 15) { j := add(j, 1) } {
+                    mstore(add(b, 54), or(a, j))
+                    if iszero(staticcall(gas(), 2, b, 102, add(b, 86), 0x20)) { revert(0, 0) }
+                }
+                mstore(add(t, add(86, shl(4, i))), and(mload(add(b, 86)), HI16))
+            }
+            mstore(add(t, 54), pkAdrs)
+            if iszero(staticcall(gas(), 2, t, 646, 0, 0x20)) { revert(0, 0) } // 64 + 22 + 35 × 16
+            node := and(mload(0), HI16)
+            // authentication path, h' = 9
+            let au0 := add(s, 560)
+            let ti := leaf
+            for { let k := 0 } lt(k, 9) { k := add(k, 1) } {
+                let au := and(calldataload(add(au0, shl(4, k))), HI16)
+                let odd := and(shr(k, leaf), 1)
+                ti := shr(1, ti)
+                mstore(add(b, 54), or(or(treeBase, shl(32, add(k, 1))), ti))
+                switch odd
+                case 0 { mstore(add(b, 86), node) mstore(add(b, 102), au) }
+                default { mstore(add(b, 86), au) mstore(add(b, 102), node) }
+                if iszero(staticcall(gas(), 2, b, 118, 0, 0x20)) { revert(0, 0) }
+                node := and(mload(0), HI16)
+            }
+        }
+    }
+}
+
+/// @title `slhdsa128s` UA verifier (accounts.md CTR-UA-23, kind 0x0133): SLH-DSA-SHA2-128s over `pq_msg` with the empty
+///        context, pure Solidity on SHA-256 `0x02` (no EIP proposes an SLH-DSA precompile). **UNAUDITED.**
+contract UASlhdsaVerifier is IUAKindVerifier {
+    bytes32 public constant TAG = keccak256("scaas.ua.slhdsa128s.v1");
+
+    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
+        return SlhDsaSha2128s.verify(keyData, PqUA.emptyContext(PqUA.pqMessage(TAG, message)), sig);
+    }
+}
diff --git a/smartcontracts/evm/test/ua/PqGas.t.sol b/smartcontracts/evm/test/ua/PqGas.t.sol
new file mode 100644
index 0000000..fa17896
--- /dev/null
+++ b/smartcontracts/evm/test/ua/PqGas.t.sol
@@ -0,0 +1,64 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {Test, console2} from "forge-std/Test.sol";
+import {SlhDsaSha2128s, UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
+
+/// SLH-DSA with every hypertree layer's WOTS+ message forced to 0: 510 chain steps per layer, the most work any input
+/// can force (a valid signature reaching it needs seven 2^-128 events). Same code as `verify` otherwise.
+contract SlhWorstCase {
+    function run(bytes calldata pk, bytes calldata mprime, bytes calldata sig) external view returns (uint256 node) {
+        bytes32 seed = bytes32(pk[0:16]);
+        bytes32 inner = sha256(abi.encodePacked(bytes16(sig[0:16]), bytes16(seed), bytes16(pk[16:32]), mprime));
+        uint256 dg = uint256(sha256(abi.encodePacked(bytes16(sig[0:16]), bytes16(seed), inner, uint32(0))));
+        uint256 idxTree = (dg >> 32) & ((1 << 54) - 1);
+        uint256 idxLeaf = (dg >> 16) & 0x1ff;
+        uint256 b = SlhDsaSha2128s.buf(seed, 160);
+        uint256 t = SlhDsaSha2128s.buf(seed, 704);
+        node = SlhDsaSha2128s.forsPk(sig, dg >> 88, idxTree, idxLeaf, b, t);
+        for (uint256 j; j < 7; ++j) {
+            if (j != 0) {
+                idxLeaf = idxTree & 0x1ff;
+                idxTree >>= 9;
+            }
+            node = SlhDsaSha2128s.xmssPk(sig, SlhDsaSha2128s.HT_OFF + j * SlhDsaSha2128s.XMSS_LEN, 0, j, idxTree, idxLeaf, b, t);
+        }
+    }
+}
+
+/// T-GAS for the PQ kinds (accounts.md CTR-UA-23): execution gas of one `verify` call (the registry's capped
+/// `staticcall`), valid signature; SLH-DSA also at its worst case. `forge test --match-contract PqGasTest -vv` prints the
+/// numbers. Budget on EIP-7825 chains: `UA_VERIFY_BUDGET` = 12,000,000; an enabled kind on a public chain ≤ ~50 % =
+/// 6,000,000. The bounds are the values measured on 2026-10-12 (solc 0.8.37, osaka) plus ~10 %.
+contract PqGasTest is Test {
+    function _kat() internal view returns (string memory) {
+        return vm.readFile("../vectors/ua/pq_kat.json");
+    }
+
+    /// Gas of `verifier.verify(pk, ua_msg, sig)` for the vector of kind `name` (must be valid).
+    function _one(string memory kat, string memory name, address verifier) internal view returns (uint256 used) {
+        string memory k = string.concat(".kinds.", name);
+        bytes memory call = abi.encodeWithSignature("verify(bytes,bytes32,bytes)", vm.parseJsonBytes(kat, string.concat(k, ".pk")),
+            bytes32(vm.parseJsonBytes(kat, string.concat(k, ".ua_msg"))), vm.parseJsonBytes(kat, string.concat(k, ".sig")));
+        uint256 g = gasleft();
+        (bool ok, bytes memory ret) = verifier.staticcall(call);
+        used = g - gasleft();
+        require(ok && abi.decode(ret, (bool)), "not valid");
+    }
+
+    function test_gas_slhdsa() public {
+        string memory kat = _kat();
+        uint256 valid = _one(kat, "slhdsa128s", address(new UASlhdsaVerifier()));
+        SlhWorstCase w = new SlhWorstCase();
+        bytes memory pk = vm.parseJsonBytes(kat, ".kinds.slhdsa128s.pk");
+        bytes memory sig = vm.parseJsonBytes(kat, ".kinds.slhdsa128s.sig");
+        bytes memory mprime = abi.encodePacked(bytes2(0), vm.parseJsonBytes(kat, ".kinds.slhdsa128s.signed_message"));
+        uint256 g = gasleft();
+        w.run(pk, mprime, sig);
+        uint256 worst = g - gasleft();
+        console2.log("slhdsa128s verify (valid)", valid);
+        console2.log("slhdsa128s worst case (510 steps x 7 layers)", worst);
+        assertLt(valid, worst);
+        assertLt(worst, 1_460_000, "SLH-DSA gas gate: the worst case stays far inside 6,000,000");
+    }
+}
diff --git a/smartcontracts/evm/test/ua/PqVectors.sol b/smartcontracts/evm/test/ua/PqVectors.sol
new file mode 100644
index 0000000..0327a70
--- /dev/null
+++ b/smartcontracts/evm/test/ua/PqVectors.sol
@@ -0,0 +1,76 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {Test} from "forge-std/Test.sol";
+import {PqUA} from "../../src/ua/PqUA.sol";
+
+interface IVerify {
+    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
+}
+
+/// Shared reader of the PQ vectors: `pq_kat.json` (SCaaS: keys from clientkeys `src/pq.js`, UA messages, a mutation set
+/// with noble's verdicts) and `pq_external.json` (ACVP FIPS 204 / 205 sigVer, the EIP-8051 / EIP-8052 KATs, the EIP-8355
+/// cases), both under `smartcontracts/vectors/ua/`. The files are read per test (a storage copy would not fit a block).
+abstract contract PqVectors is Test {
+    function _kat() internal view returns (string memory) {
+        return vm.readFile("../vectors/ua/pq_kat.json");
+    }
+
+    function _ext() internal view returns (string memory) {
+        return vm.readFile("../vectors/ua/pq_external.json");
+    }
+
+    function _b(string memory json, string memory key) internal pure returns (bytes memory) {
+        return vm.parseJsonBytes(json, key);
+    }
+
+    function _k(string memory kat, string memory name, string memory field) internal pure returns (bytes memory) {
+        return _b(kat, string.concat(".kinds.", name, ".", field));
+    }
+
+    function _case(string memory section, uint256 i) internal pure returns (string memory) {
+        return string.concat(".", section, ".cases[", vm.toString(i), "]");
+    }
+
+    function _cases(string memory ext, string memory section) internal view returns (uint256 n) {
+        while (vm.keyExistsJson(ext, _case(section, n))) ++n;
+    }
+
+    /// The UA-level vector of one kind through its verifier: TAG, UA id, ua_msg, the signed message, the signature,
+    /// and every mutation with noble's verdict.
+    function _uaVector(string memory name, address verifier, uint16 kind) internal view {
+        string memory kat = _kat();
+        bytes memory pk = _k(kat, name, "pk");
+        bytes32 tag = PqUA.tag(kind);
+        assertEq(tag, bytes32(_k(kat, name, "tag_hash")), "TAG(kind)");
+        assertEq(keccak256(abi.encodePacked(tag, pk)), bytes32(_k(kat, name, "ua")), "UA id");
+        bytes32 uaMsg = PqUA.uaMessage(tag, bytes32(_b(kat, ".purpose_tag")), bytes32(_b(kat, ".digest")));
+        assertEq(uaMsg, bytes32(_k(kat, name, "ua_msg")), "ua_msg");
+        bytes32 signed = kind == PqUA.FNDSA512 ? uaMsg : PqUA.pqMessage(tag, uaMsg);
+        assertEq(signed, bytes32(_k(kat, name, "signed_message")), "signed message");
+        assertTrue(IVerify(verifier).verify(pk, uaMsg, _k(kat, name, "sig")), "valid signature");
+        for (uint256 i; i < 6; ++i) {
+            string memory m = string.concat(".kinds.", name, ".mutations[", vm.toString(i), "]");
+            bool got = IVerify(verifier).verify(_b(kat, string.concat(m, ".pk")),
+                bytes32(_b(kat, string.concat(m, ".ua_msg"))), _b(kat, string.concat(m, ".sig")));
+            assertEq(got, vm.parseJsonBool(kat, string.concat(m, ".valid")), vm.parseJsonString(kat, string.concat(m, ".what")));
+        }
+    }
+
+    /// `t` (n entries of `width` bytes, big-endian) is `root^brv(k) mod q`, and root^n = −1 (a primitive 2n-th root).
+    function _zetas(bytes memory t, uint256 width, uint256 n, uint256 q, uint256 root) internal pure {
+        assertEq(t.length, n * width);
+        uint256 bits;
+        while ((1 << bits) < n) ++bits;
+        uint256 pw = 1;
+        for (uint256 i; i < n; ++i) {
+            uint256 r;
+            for (uint256 b; b < bits; ++b) r = (r << 1) | ((i >> b) & 1);
+            uint256 v;
+            for (uint256 j; j < width; ++j) v = (v << 8) | uint8(t[r * width + j]);
+            assertEq(v, pw);
+            pw = mulmod(pw, root, q);
+        }
+        assertEq(pw, q - 1);
+    }
+}
diff --git a/smartcontracts/evm/test/ua/SlhDsa.t.sol b/smartcontracts/evm/test/ua/SlhDsa.t.sol
new file mode 100644
index 0000000..51554f3
--- /dev/null
+++ b/smartcontracts/evm/test/ua/SlhDsa.t.sol
@@ -0,0 +1,44 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {PqVectors} from "./PqVectors.sol";
+import {PqUA} from "../../src/ua/PqUA.sol";
+import {SlhDsaSha2128s, UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
+
+contract SlhHarness {
+    function verify(bytes calldata pk, bytes calldata mprime, bytes calldata sig) external view returns (bool) {
+        return SlhDsaSha2128s.verify(pk, mprime, sig);
+    }
+}
+
+/// `slhdsa128s` (CTR-UA-23): ACVP SLH-DSA-SHA2-128s sigVer (pure and internal interfaces) and the SCaaS UA vector.
+contract SlhDsaTest is PqVectors {
+    function test_kat_slhdsa128s() public {
+        _uaVector("slhdsa128s", address(new UASlhdsaVerifier()), PqUA.SLHDSA128S);
+    }
+
+    function test_acvp_slhdsa() public {
+        vm.pauseGasMetering(); // 28 full verifications: correctness only (gas is PqGasTest's)
+        string memory ext = _ext();
+        SlhHarness h = new SlhHarness();
+        uint256 n = _cases(ext, "acvp_slhdsa");
+        assertEq(n, 28);
+        for (uint256 i; i < n; ++i) {
+            string memory c = _case("acvp_slhdsa", i);
+            bool got = h.verify(_b(ext, string.concat(c, ".pk")), _b(ext, string.concat(c, ".mprime")), _b(ext, string.concat(c, ".sig")));
+            assertEq(got, vm.parseJsonBool(ext, string.concat(c, ".valid")), vm.parseJsonString(ext, string.concat(c, ".reason")));
+        }
+    }
+
+    function test_malformed_slhdsa() public {
+        string memory kat = _kat();
+        UASlhdsaVerifier v = new UASlhdsaVerifier();
+        bytes memory pk = _k(kat, "slhdsa128s", "pk");
+        bytes memory sig = _k(kat, "slhdsa128s", "sig");
+        bytes32 m = bytes32(_k(kat, "slhdsa128s", "ua_msg"));
+        assertTrue(v.verify(pk, m, sig));
+        assertFalse(v.verify(bytes.concat(pk, hex"00"), m, sig));
+        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")));
+        assertFalse(v.verify(pk, m, ""));
+    }
+}
``````

### Task 3: SHAKE, the NTT and Falcon-512

`Shake` is a Keccak-f[1600] sponge whose 25 lanes, rho/pi temporaries, round constants and padding block live at fixed
memory `[0x80, 0xaa0)`; `absorb` XORs the padded last block without permuting and every `squeeze` permutes first, so no
permutation is wasted. `PqNtt` is FIPS 204's NTT for any `(n, q)` with a constant zeta table (lazy reduction forward,
reduced output inverse). `Falcon512.verify` is Algorithm 16 of the specification: decode (reference `comp_decode`, the
padding must be zero), `HashToPoint(salt ‖ msg)` by SHAKE256 (`t < 61445`), `s1 = c − s2·h` in `Z_q[X]/(X^512 + 1)`,
accept iff `‖s1‖² + ‖s2‖² ≤ 34,034,726`.

**Files:** create `smartcontracts/evm/src/ua/Shake.sol`, `smartcontracts/evm/src/ua/PqNtt.sol`,
`smartcontracts/evm/src/ua/FnDsa.sol`, `smartcontracts/evm/test/ua/FnDsa.t.sol`; modify `smartcontracts/evm/test/ua/PqGas.t.sol`.

- [ ] **Step 1: Apply the diff below.**
- [ ] **Step 2: The new tests.** `../../scripts/capped forge test --match-path 'test/ua/*' -vv` — `FnDsaTest` 5 passed
  (`test_shake_knownAnswers`: FIPS 202's SHAKE128("") and SHAKE256(""), a 200-byte two-block input against noble;
  `test_zetaTable_falcon`; `test_kat_fndsa512`; `test_falcon_nistKat`: 10 NIST KATs, each also with non-zero padding;
  `test_malformed_fndsa`) and `test_gas_fndsa` logs `keccak-f[1600] permutation 66394`, `fndsa512 verify (valid) 2266836`.
- [ ] **Step 3: Full suite.** **900** passed, 10 skipped; size gate 0 errors.
- [ ] **Step 4: Commit** `P6a T3: SHAKE128/256 and NTT in Solidity; Falcon-512 verifier (EIP-8052 hash-to-point, padded signatures)`.

``````diff
diff --git a/smartcontracts/evm/src/ua/FnDsa.sol b/smartcontracts/evm/src/ua/FnDsa.sol
new file mode 100644
index 0000000..681a387
--- /dev/null
+++ b/smartcontracts/evm/src/ua/FnDsa.sol
@@ -0,0 +1,161 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {IUAKindVerifier} from "./PqUA.sol";
+import {Shake} from "./Shake.sol";
+import {PqNtt} from "./PqNtt.sol";
+
+/// @title Falcon-512 verification (round-3 specification v1.2 Algorithm 16; EIP-8052 `FALCON_HASH_TO_POINT_SHAKE256`
+///        + `FALCON_CORE`): `c = HashToPoint(salt ‖ msg)` by SHAKE256, `s1 = c − s2·h`, accept iff
+///        `‖s1‖² + ‖s2‖² ≤ ⌊β²⌋ = 34,034,726` (the reference code's bound; EIP-8052's text says `<`).
+/// @notice pk (897 B) = `0x09 ‖ h` (512 × 14-bit big-endian, each `< q`); sig (666 B) = the round-3 padded format
+///         `0x39 ‖ salt (40) ‖ compressed s2`, zero-padded (EIP-8052's 666-byte "padded signature"). The decoder is
+///         the reference `comp_decode`: sign bit, 7 low bits, unary high part, `|v| ≤ 2047`, no "−0", every bit after
+///         the last coefficient zero. **UNAUDITED.**
+library Falcon512 {
+    uint256 internal constant N = 512;
+    uint256 internal constant Q = 12289;
+    uint256 internal constant PK_LEN = 897;
+    uint256 internal constant SIG_LEN = 666;
+    uint256 internal constant BOUND = 34034726;
+    /// `zetas[k] = 10302^brv9(k) mod q`, k = 0..511, u16 big-endian (10302 = 11^12: a primitive 1024-th root of unity).
+    bytes internal constant ZETAS = hex"000105c72036141a102619992d2f051916e40c7b04bc29930e25261022510dd61c8f2aba23011691139f193d166011ef0bbe2549023324620a412c4c12d50a4f2f75073d02d612032b68109f0ad006630b931ce1093e241623ee2fb02c191f21222012c52bdb08f6254612ee23c22181243b0c811c232ad3049226f203bb2ceb20942321095c11641b030b1500821eff2c480ea4197a2cc613cb276c2f8b26551f4b068914d31c842a9c26241051220101e024e703fe2ff8169f2de1265d2eae2f701a5b21cc0d830aab20a518ea1ce729220e7b2193143b0d360163108709f423582d280cd92824232d24c013e427d819861218112404ec014e097a059429610d48095f144723c1243900f30bb8029f0dcb2e250f911cd8277f29f91a4a2e5d23520a7e0b990f8a224b1b2d24d009422031273824bd2b800c72151f27b3065e0cc72028296822dd113e0b1f278311142525144b1ce22a3527001c4f0fd525ac2f901337087620b62f6123b41eac000305921dd32910067f21cd134a0a9014ab149d04902b4a2351085f2bd82e6d122510002e141544094d2a9f077810f12e4e137029ba2c96213d2c1713931f4513e0267c21c32456187b09761797088b0a062a61214e2407001b1c2506601cec03f9102f1d972f0f2a0021890a761c662de00ef90ec22e7b030513ed2bd626a001ba24a119bf01621d04139409b1041524d6283e295b22142d731bab159923822fc918081354019006c0191b17f81ada0e3b2ab2153b04e62c3428100f9e287f20da2e2d206d2e83013c1b26154617cd0e7e1e8e12b51d7415a10ecd009315501ea02be71e4915450f14258604a6211717e6172503fa2247041107b515c62b0309280feb14c310e4133427882df71c2a234318892c8c1c7007a42c160dcc2f102fc704512f731631226c22930b1c03cf107421ef17b401a520110e100cbf1df117bd12ae1903242c15da1f8c2e09025d2703155c03f2031322671479249923ca1fb813c11da70d751d5508011cd12ad800c001af29d609c917122f6a27b2208c24ea190f02a5185a0d082fcd239b052b0ace0c4e0527203302c51f71220f2cbe1850039a2e482012042207a61f1f27e32ba9004021b92d562666196b061e0b84263a18e21eb00efa1489292e23ce2413156e057c2ebc047a2c4d0e902030189b048717d3012716862d75214f0b67205120140d011f37257d00a829c707aa13f218b814b1181a0f7405502b511bc12606181724bf070d07a2080317fe098f0f7b2dc12297223824a500da26c828ce242b101314d5281216f408e9009c253220800f9701c518ed2e5f214512a61acc1281050d27f814f9237f1e74015e05e828ea1afa05d109c4062f18cb2b122fd018e605cb0bc1069d02d300ae0ab219150a5f199a284a0ead24942ea61d6f28bf01aa0cf3";
+
+    /// Verifies `sig` over `msg` (32 bytes on the UA path; any length here). Requires `Shake.reserve()` first.
+    function verify(bytes calldata pk, bytes memory message, bytes calldata sig) internal pure returns (bool) {
+        if (pk.length != PK_LEN || sig.length != SIG_LEN || pk[0] != 0x09 || sig[0] != 0x39) return false;
+        (bool ok, uint256 s2) = _decompress(sig[41:]);
+        if (!ok) return false;
+        uint256 h = PqNtt.alloc(N);
+        if (!_decodePk(pk[1:], h)) return false;
+        return _short(s2, h, _hashToPoint(sig[1:41], message));
+    }
+
+    /// ‖c − s2·h‖² + ‖s2‖² ≤ ⌊β²⌋, with `s1` centred in (−q/2, q/2].
+    function _short(uint256 s2, uint256 h, uint256 c) private pure returns (bool) {
+        uint256 z = PqNtt.table(ZETAS, 2);
+        uint256 t = PqNtt.alloc(N); // s2 mod q
+        uint256 norm;
+        assembly ("memory-safe") {
+            for { let i := 0 } lt(i, shl(5, N)) { i := add(i, 32) } {
+                let v := mload(add(s2, i)) // signed, |v| ≤ 2047
+                norm := add(norm, mul(v, v))
+                mstore(add(t, i), mod(add(v, Q), Q)) // wraps a negative v into [0, q)
+            }
+        }
+        PqNtt.ntt(t, N, Q, z);
+        PqNtt.ntt(h, N, Q, z);
+        PqNtt.mulPoint(t, h, N, Q);
+        PqNtt.intt(t, N, Q, z); // t = s2·h
+        assembly ("memory-safe") {
+            for { let i := 0 } lt(i, shl(5, N)) { i := add(i, 32) } {
+                let v := addmod(mload(add(c, i)), sub(Q, mload(add(t, i))), Q) // s1 = c − s2·h
+                if gt(v, 6144) { v := sub(Q, v) }
+                norm := add(norm, mul(v, v))
+            }
+        }
+        return norm <= BOUND;
+    }
+
+    /// SHAKE256(salt ‖ msg): 16-bit big-endian draws, keep `t < 61445 = 5q`, `c_i = t mod q`.
+    function _hashToPoint(bytes calldata salt, bytes memory message) private pure returns (uint256 c) {
+        bytes memory input = abi.encodePacked(salt, message);
+        uint256 inPtr;
+        assembly ("memory-safe") {
+            inPtr := add(input, 32)
+        }
+        Shake.absorb(Shake.SHAKE256, inPtr, input.length);
+        c = PqNtt.alloc(N);
+        uint256 buf = PqNtt.alloc(6); // one 136-byte block + slack
+        uint256 i;
+        while (i < N) {
+            Shake.squeeze(Shake.SHAKE256, buf);
+            assembly ("memory-safe") {
+                for { let o := 0 } and(lt(o, 136), lt(i, N)) { o := add(o, 2) } {
+                    let t := shr(240, mload(add(buf, o)))
+                    if lt(t, 61445) {
+                        mstore(add(c, shl(5, i)), mod(t, Q))
+                        i := add(i, 1)
+                    }
+                }
+            }
+        }
+    }
+
+    /// 512 × 14-bit big-endian coefficients, each `< q`.
+    function _decodePk(bytes calldata enc, uint256 h) private pure returns (bool ok) {
+        ok = true;
+        assembly ("memory-safe") {
+            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
+                let bit := mul(i, 14)
+                let v := and(shr(sub(242, and(bit, 7)), calldataload(add(enc.offset, shr(3, bit)))), 0x3fff)
+                if iszero(lt(v, Q)) { ok := 0 }
+                mstore(add(h, shl(5, i)), v)
+            }
+        }
+    }
+
+    /// Reference `comp_decode` over the 625 bytes after the salt; s2 as signed words (two's complement).
+    function _decompress(bytes calldata comp) private pure returns (bool ok, uint256 s2) {
+        s2 = PqNtt.alloc(N);
+        ok = true;
+        uint256 src;
+        uint256 pos;
+        assembly ("memory-safe") {
+            src := comp.offset
+            // n bits (n ≤ 8) at bit position p, most significant bit first
+            function rd(from, p, n) -> v {
+                v := and(shr(sub(256, add(and(p, 7), n)), calldataload(add(from, shr(3, p)))), sub(shl(n, 1), 1))
+            }
+            let limit := shl(3, comp.length)
+            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
+                if gt(add(pos, 8), limit) { ok := 0 break }
+                let b := rd(src, pos, 8)
+                pos := add(pos, 8)
+                let m := and(b, 0x7f)
+                for {} 1 {} {
+                    if iszero(lt(pos, limit)) { ok := 0 break }
+                    let bit := rd(src, pos, 1)
+                    pos := add(pos, 1)
+                    if bit { break }
+                    m := add(m, 128)
+                    if gt(m, 2047) { ok := 0 break }
+                }
+                if iszero(ok) { break }
+                b := shr(7, b) // sign
+                if and(b, iszero(m)) { ok := 0 break } // "−0"
+                if b { m := sub(0, m) }
+                mstore(add(s2, shl(5, i)), m)
+            }
+        }
+        if (ok) ok = _zeroTail(comp, pos);
+    }
+
+    /// Every bit of `comp` from bit `pos` on is zero (the unused bits of the last byte, then the padding).
+    function _zeroTail(bytes calldata comp, uint256 pos) private pure returns (bool ok) {
+        ok = true;
+        assembly ("memory-safe") {
+            if and(pos, 7) {
+                let cur := byte(0, calldataload(add(comp.offset, shr(3, pos))))
+                if and(cur, sub(shl(sub(8, and(pos, 7)), 1), 1)) { ok := 0 }
+                pos := and(add(pos, 7), not(7))
+            }
+            for { let o := shr(3, pos) } lt(o, comp.length) { o := add(o, 32) } {
+                let w := calldataload(add(comp.offset, o))
+                let left := sub(comp.length, o)
+                if lt(left, 32) { w := shr(shl(3, sub(32, left)), w) }
+                if w { ok := 0 }
+            }
+        }
+    }
+}
+
+/// @title `fndsa512` UA verifier (accounts.md CTR-UA-23, kind 0x0132): Falcon-512 over the 32-byte `ua_msg`, the message
+///        size of EIP-8052 (Falcon has no context string; `ua_msg` already carries `TAG(kind)`). Pure Solidity: EIP-8052
+///        has no addresses yet. **UNAUDITED.**
+contract UAFndsaVerifier is IUAKindVerifier {
+    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external pure returns (bool) {
+        Shake.reserve();
+        return Falcon512.verify(keyData, abi.encodePacked(message), sig);
+    }
+}
diff --git a/smartcontracts/evm/src/ua/PqNtt.sol b/smartcontracts/evm/src/ua/PqNtt.sol
new file mode 100644
index 0000000..441296c
--- /dev/null
+++ b/smartcontracts/evm/src/ua/PqNtt.sol
@@ -0,0 +1,101 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+/// @title Negacyclic NTT over Z_q[X]/(X^n + 1) on memory polynomials (one coefficient per 32-byte word).
+/// @notice `ntt` / `intt` are FIPS 204 Algorithms 41 / 42 for any n, q with `zetas[k] = root^brv(k)`, root a
+///         primitive 2n-th root of unity, brv over log2 n bits (ML-DSA: n = 256, q = 8380417, root 1753; Falcon:
+///         n = 512, q = 12289, root 10302 = 11^12); the callers keep the tables as constants (`test/ua/PqVerifiers.t.sol`
+///         recomputes them). Inputs must be reduced (< q).
+library PqNtt {
+    /// A new polynomial of `n` zero coefficients (memory pointer to its first word).
+    function alloc(uint256 n) internal pure returns (uint256 p) {
+        assembly ("memory-safe") {
+            p := mload(0x40)
+            mstore(0x40, add(p, shl(5, n)))
+            calldatacopy(p, calldatasize(), shl(5, n)) // zero fill
+        }
+    }
+
+    /// The zeta table `zetas[k] = root^brv(k)` from its packed big-endian form (`width` bytes per entry), one word each.
+    function table(bytes memory packed, uint256 width) internal pure returns (uint256 z) {
+        uint256 n = packed.length / width;
+        z = alloc(n);
+        assembly ("memory-safe") {
+            let sh := sub(256, shl(3, width))
+            let src := add(packed, 32)
+            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
+                mstore(add(z, shl(5, i)), shr(sh, mload(add(src, mul(i, width)))))
+            }
+        }
+    }
+
+    /// Forward NTT with lazy reduction: outputs are congruent mod q but only bounded by (1 + log2 n)·q. Every consumer
+    /// reduces (mulmod / addmod / `reduce`).
+    function ntt(uint256 a, uint256 n, uint256 q, uint256 z) internal pure {
+        assembly ("memory-safe") {
+            let k := 0
+            for { let len := shr(1, n) } gt(len, 0) { len := shr(1, len) } {
+                let off := shl(5, len)
+                for { let start := 0 } lt(start, n) { start := add(start, shl(1, len)) } {
+                    k := add(k, 1)
+                    let zeta := mload(add(z, shl(5, k)))
+                    let e := add(a, shl(5, add(start, len)))
+                    for { let p := add(a, shl(5, start)) } lt(p, e) { p := add(p, 32) } {
+                        let t := mulmod(zeta, mload(add(p, off)), q)
+                        let x := mload(p)
+                        mstore(add(p, off), add(x, sub(q, t)))
+                        mstore(p, add(x, t))
+                    }
+                }
+            }
+        }
+    }
+
+    /// Inverse NTT (any input below 2^200); outputs reduced (< q).
+    function intt(uint256 a, uint256 n, uint256 q, uint256 z) internal pure {
+        assembly ("memory-safe") {
+            let big := shl(220, q) // above every intermediate, keeps t − u + big positive
+            let k := n
+            for { let len := 1 } lt(len, n) { len := shl(1, len) } {
+                let off := shl(5, len)
+                for { let start := 0 } lt(start, n) { start := add(start, shl(1, len)) } {
+                    k := sub(k, 1)
+                    let zeta := sub(q, mload(add(z, shl(5, k))))
+                    let e := add(a, shl(5, add(start, len)))
+                    for { let p := add(a, shl(5, start)) } lt(p, e) { p := add(p, 32) } {
+                        let t := mload(p)
+                        let u := mload(add(p, off))
+                        mstore(p, add(t, u))
+                        mstore(add(p, off), mulmod(zeta, add(t, sub(big, u)), q))
+                    }
+                }
+            }
+            // n^-1 mod q (q prime): n^(q-2) by square-and-multiply
+            let f := 1
+            let b := n
+            for { let x := sub(q, 2) } gt(x, 0) { x := shr(1, x) } {
+                if and(x, 1) { f := mulmod(f, b, q) }
+                b := mulmod(b, b, q)
+            }
+            let e := add(a, shl(5, n))
+            for { let p := a } lt(p, e) { p := add(p, 32) } { mstore(p, mulmod(mload(p), f, q)) }
+        }
+    }
+
+    /// a[i] mod q, in place.
+    function reduce(uint256 a, uint256 n, uint256 q) internal pure {
+        assembly ("memory-safe") {
+            let e := add(a, shl(5, n))
+            for { let p := a } lt(p, e) { p := add(p, 32) } { mstore(p, mod(mload(p), q)) }
+        }
+    }
+
+    /// c[i] = a[i] · b[i] mod q (pointwise, in place into `a`).
+    function mulPoint(uint256 a, uint256 b, uint256 n, uint256 q) internal pure {
+        assembly ("memory-safe") {
+            for { let i := 0 } lt(i, shl(5, n)) { i := add(i, 32) } {
+                mstore(add(a, i), mulmod(mload(add(a, i)), mload(add(b, i)), q))
+            }
+        }
+    }
+}
diff --git a/smartcontracts/evm/src/ua/Shake.sol b/smartcontracts/evm/src/ua/Shake.sol
new file mode 100644
index 0000000..b751f7f
--- /dev/null
+++ b/smartcontracts/evm/src/ua/Shake.sol
@@ -0,0 +1,233 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+/// @title SHAKE128 / SHAKE256 (FIPS 202) for the PQ verifiers: a Keccak-f[1600] sponge at fixed memory.
+/// @notice The 25 lanes (A[x + 5y] at 0x80 + 32·(x + 5y), each a clean 64-bit value), the rho/pi temporaries, the
+///         round constants and one padding block live in [0x80, END). `reserve()` claims that region and must be the
+///         first allocation of the call frame (an external `verify`); otherwise it reverts `ShakeMemory`, never
+///         corrupting memory. The round body is unrolled from the FIPS 202 rotation table (theta, rho + pi, chi as Yul
+///         functions to stay within the legacy code generator's stack); `reserve()` writes the 24 round constants.
+/// @dev Byte order: a lane is the little-endian reading of its 8 bytes; `_bswap` reverses the bytes of the four
+///      64-bit groups of a word, so a 32-byte read of the stream becomes four lanes and back.
+library Shake {
+    uint256 internal constant SHAKE128 = 168;
+    uint256 internal constant SHAKE256 = 136;
+    uint256 private constant S = 128;
+    uint256 private constant RCT = 1728;
+    uint256 private constant PAD = 0x9c0; // one padding block: 168 bytes + 56 slack
+    uint256 internal constant END = 0xaa0;
+
+    error ShakeMemory();
+
+    function reserve() internal pure {
+        assembly ("memory-safe") {
+            if iszero(eq(mload(0x40), 0x80)) {
+                mstore(0, 0xddb10a0e) // ShakeMemory()
+                revert(0x1c, 4)
+            }
+            mstore(0x40, END)
+            mstore(1728, 0x1)
+            mstore(1760, 0x8082)
+            mstore(1792, 0x800000000000808a)
+            mstore(1824, 0x8000000080008000)
+            mstore(1856, 0x808b)
+            mstore(1888, 0x80000001)
+            mstore(1920, 0x8000000080008081)
+            mstore(1952, 0x8000000000008009)
+            mstore(1984, 0x8a)
+            mstore(2016, 0x88)
+            mstore(2048, 0x80008009)
+            mstore(2080, 0x8000000a)
+            mstore(2112, 0x8000808b)
+            mstore(2144, 0x800000000000008b)
+            mstore(2176, 0x8000000000008089)
+            mstore(2208, 0x8000000000008003)
+            mstore(2240, 0x8000000000008002)
+            mstore(2272, 0x8000000000000080)
+            mstore(2304, 0x800a)
+            mstore(2336, 0x800000008000000a)
+            mstore(2368, 0x8000000080008081)
+            mstore(2400, 0x8000000000008080)
+            mstore(2432, 0x80000001)
+            mstore(2464, 0x8000000080008008)
+        }
+    }
+
+    /// Keccak-f[1600], 24 rounds (theta, rho + pi into the temporaries, chi back, iota).
+    function permute() internal pure {
+        assembly ("memory-safe") {
+            function theta() -> d0, d1, d2, d3, d4 {
+                mstore(928, xor(xor(xor(xor(mload(128), mload(288)), mload(448)), mload(608)), mload(768)))
+                mstore(960, xor(xor(xor(xor(mload(160), mload(320)), mload(480)), mload(640)), mload(800)))
+                mstore(992, xor(xor(xor(xor(mload(192), mload(352)), mload(512)), mload(672)), mload(832)))
+                mstore(1024, xor(xor(xor(xor(mload(224), mload(384)), mload(544)), mload(704)), mload(864)))
+                mstore(1056, xor(xor(xor(xor(mload(256), mload(416)), mload(576)), mload(736)), mload(896)))
+                { let cp := mload(960) d0 := xor(mload(1056), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
+                { let cp := mload(992) d1 := xor(mload(928), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
+                { let cp := mload(1024) d2 := xor(mload(960), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
+                { let cp := mload(1056) d3 := xor(mload(992), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
+                { let cp := mload(928) d4 := xor(mload(1024), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
+            }
+            function rhoPi(d0, d1, d2, d3, d4) {
+                mstore(928, xor(mload(128), d0))
+                { let v := xor(mload(160), d1) mstore(1248, and(or(shl(1, v), shr(63, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(192), d2) mstore(1568, and(or(shl(62, v), shr(2, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(224), d3) mstore(1088, and(or(shl(28, v), shr(36, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(256), d4) mstore(1408, and(or(shl(27, v), shr(37, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(288), d0) mstore(1440, and(or(shl(36, v), shr(28, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(320), d1) mstore(960, and(or(shl(44, v), shr(20, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(352), d2) mstore(1280, and(or(shl(6, v), shr(58, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(384), d3) mstore(1600, and(or(shl(55, v), shr(9, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(416), d4) mstore(1120, and(or(shl(20, v), shr(44, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(448), d0) mstore(1152, and(or(shl(3, v), shr(61, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(480), d1) mstore(1472, and(or(shl(10, v), shr(54, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(512), d2) mstore(992, and(or(shl(43, v), shr(21, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(544), d3) mstore(1312, and(or(shl(25, v), shr(39, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(576), d4) mstore(1632, and(or(shl(39, v), shr(25, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(608), d0) mstore(1664, and(or(shl(41, v), shr(23, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(640), d1) mstore(1184, and(or(shl(45, v), shr(19, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(672), d2) mstore(1504, and(or(shl(15, v), shr(49, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(704), d3) mstore(1024, and(or(shl(21, v), shr(43, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(736), d4) mstore(1344, and(or(shl(8, v), shr(56, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(768), d0) mstore(1376, and(or(shl(18, v), shr(46, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(800), d1) mstore(1696, and(or(shl(2, v), shr(62, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(832), d2) mstore(1216, and(or(shl(61, v), shr(3, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(864), d3) mstore(1536, and(or(shl(56, v), shr(8, v)), 0xffffffffffffffff)) }
+                { let v := xor(mload(896), d4) mstore(1056, and(or(shl(14, v), shr(50, v)), 0xffffffffffffffff)) }
+            }
+            function chi() {
+                {
+                    let b0 := mload(928)
+                    let b1 := mload(960)
+                    let b2 := mload(992)
+                    let b3 := mload(1024)
+                    let b4 := mload(1056)
+                    mstore(128, xor(b0, and(not(b1), b2)))
+                    mstore(160, xor(b1, and(not(b2), b3)))
+                    mstore(192, xor(b2, and(not(b3), b4)))
+                    mstore(224, xor(b3, and(not(b4), b0)))
+                    mstore(256, xor(b4, and(not(b0), b1)))
+                }
+                {
+                    let b0 := mload(1088)
+                    let b1 := mload(1120)
+                    let b2 := mload(1152)
+                    let b3 := mload(1184)
+                    let b4 := mload(1216)
+                    mstore(288, xor(b0, and(not(b1), b2)))
+                    mstore(320, xor(b1, and(not(b2), b3)))
+                    mstore(352, xor(b2, and(not(b3), b4)))
+                    mstore(384, xor(b3, and(not(b4), b0)))
+                    mstore(416, xor(b4, and(not(b0), b1)))
+                }
+                {
+                    let b0 := mload(1248)
+                    let b1 := mload(1280)
+                    let b2 := mload(1312)
+                    let b3 := mload(1344)
+                    let b4 := mload(1376)
+                    mstore(448, xor(b0, and(not(b1), b2)))
+                    mstore(480, xor(b1, and(not(b2), b3)))
+                    mstore(512, xor(b2, and(not(b3), b4)))
+                    mstore(544, xor(b3, and(not(b4), b0)))
+                    mstore(576, xor(b4, and(not(b0), b1)))
+                }
+                {
+                    let b0 := mload(1408)
+                    let b1 := mload(1440)
+                    let b2 := mload(1472)
+                    let b3 := mload(1504)
+                    let b4 := mload(1536)
+                    mstore(608, xor(b0, and(not(b1), b2)))
+                    mstore(640, xor(b1, and(not(b2), b3)))
+                    mstore(672, xor(b2, and(not(b3), b4)))
+                    mstore(704, xor(b3, and(not(b4), b0)))
+                    mstore(736, xor(b4, and(not(b0), b1)))
+                }
+                {
+                    let b0 := mload(1568)
+                    let b1 := mload(1600)
+                    let b2 := mload(1632)
+                    let b3 := mload(1664)
+                    let b4 := mload(1696)
+                    mstore(768, xor(b0, and(not(b1), b2)))
+                    mstore(800, xor(b1, and(not(b2), b3)))
+                    mstore(832, xor(b2, and(not(b3), b4)))
+                    mstore(864, xor(b3, and(not(b4), b0)))
+                    mstore(896, xor(b4, and(not(b0), b1)))
+                }
+            }
+            for { let r := 0 } lt(r, 24) { r := add(r, 1) } {
+                let d0, d1, d2, d3, d4 := theta()
+                rhoPi(d0, d1, d2, d3, d4)
+                chi()
+                mstore(128, xor(mload(128), mload(add(1728, shl(5, r)))))
+            }
+        }
+    }
+
+    /// Fresh sponge: absorbs `len` bytes at memory `p` with the SHAKE padding (0x1F … 0x80); the padded last block is
+    /// XORed in but not permuted (every `squeeze` permutes first, so no permutation is wasted).
+    function absorb(uint256 rate, uint256 p, uint256 len) internal pure {
+        assembly ("memory-safe") {
+            for { let i := 0 } lt(i, 25) { i := add(i, 1) } { mstore(add(S, shl(5, i)), 0) }
+        }
+        while (len >= rate) {
+            _xorBlock(rate, p);
+            permute();
+            p += rate;
+            len -= rate;
+        }
+        assembly ("memory-safe") {
+            for { let i := 0 } lt(i, 224) { i := add(i, 32) } { mstore(add(PAD, i), 0) }
+            mcopy(PAD, p, len)
+            mstore8(add(PAD, len), 0x1f)
+            let last := add(PAD, sub(rate, 1))
+            mstore8(last, xor(byte(0, mload(last)), 0x80))
+        }
+        _xorBlock(rate, PAD);
+    }
+
+    /// Permutes, then writes the next `rate` output bytes at `out` (it may write up to 31 bytes past them).
+    function squeeze(uint256 rate, uint256 out) internal pure {
+        permute();
+        assembly ("memory-safe") {
+            let n := shr(5, add(rate, 31))
+            for { let m := 0 } lt(m, n) { m := add(m, 1) } {
+                let l := add(S, shl(7, m))
+                let w := or(or(shl(192, mload(l)), shl(128, mload(add(l, 32)))), or(shl(64, mload(add(l, 64))), mload(add(l, 96))))
+                mstore(add(out, shl(5, m)), _bswap(w))
+            }
+            function _bswap(w) -> v {
+                v := or(shr(8, and(w, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)), shl(8, and(w, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)))
+                v := or(shr(16, and(v, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)), shl(16, and(v, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)))
+                v := or(shr(32, and(v, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)), shl(32, and(v, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)))
+            }
+        }
+    }
+
+    /// SHAKE over `len` bytes at `p`, `outLen` bytes written at `out` (whole blocks: up to rate + 31 bytes past).
+    function hash(uint256 rate, uint256 p, uint256 len, uint256 out, uint256 outLen) internal pure {
+        absorb(rate, p, len);
+        for (uint256 o; o < outLen; o += rate) squeeze(rate, out + o);
+    }
+
+    function _xorBlock(uint256 rate, uint256 p) private pure {
+        assembly ("memory-safe") {
+            let lanes := shr(3, rate)
+            for { let m := 0 } lt(shl(2, m), lanes) { m := add(m, 1) } {
+                let w := mload(add(p, shl(5, m)))
+                w := or(shr(8, and(w, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)), shl(8, and(w, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)))
+                w := or(shr(16, and(w, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)), shl(16, and(w, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)))
+                w := or(shr(32, and(w, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)), shl(32, and(w, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)))
+                for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
+                    let i := add(shl(2, m), j)
+                    if lt(i, lanes) {
+                        let a := add(S, shl(5, i))
+                        mstore(a, xor(mload(a), and(shr(sub(192, shl(6, j)), w), 0xffffffffffffffff)))
+                    }
+                }
+            }
+        }
+    }
+}
diff --git a/smartcontracts/evm/test/ua/FnDsa.t.sol b/smartcontracts/evm/test/ua/FnDsa.t.sol
new file mode 100644
index 0000000..382b62c
--- /dev/null
+++ b/smartcontracts/evm/test/ua/FnDsa.t.sol
@@ -0,0 +1,89 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {PqVectors} from "./PqVectors.sol";
+import {PqUA} from "../../src/ua/PqUA.sol";
+import {Shake} from "../../src/ua/Shake.sol";
+import {Falcon512, UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
+
+contract FnHarness {
+    function verify(bytes calldata pk, bytes calldata m, bytes calldata sig) external pure returns (bool) {
+        Shake.reserve();
+        return Falcon512.verify(pk, m, sig);
+    }
+
+    function shake(uint256 rate, bytes calldata input, uint256 outLen) external pure returns (bytes memory out) {
+        Shake.reserve();
+        bytes memory inp = input;
+        out = new bytes(outLen + 200); // whole blocks are written
+        uint256 p;
+        uint256 o;
+        assembly {
+            p := add(inp, 32)
+            o := add(out, 32)
+        }
+        Shake.hash(rate, p, input.length, o, outLen);
+        assembly {
+            mstore(out, outLen)
+        }
+    }
+}
+
+/// `fndsa512` (CTR-UA-23): SHAKE (FIPS 202), the NTT table, the NIST Falcon-512 KATs published with EIP-8052 rebuilt
+/// as padded signatures, the SCaaS UA vector, malformed encodings.
+contract FnDsaTest is PqVectors {
+    function test_shake_knownAnswers() public {
+        FnHarness h = new FnHarness();
+        // SHAKE128("") and SHAKE256("") (FIPS 202 examples), and a 200-byte input spanning a SHAKE256 block (noble)
+        assertEq(h.shake(168, "", 32), hex"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
+        assertEq(h.shake(136, "", 64),
+            hex"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
+        bytes memory long = new bytes(200);
+        for (uint256 i; i < 200; ++i) long[i] = bytes1(uint8(i));
+        assertEq(h.shake(136, long, 32), _b(_kat(), ".shake256_200"));
+    }
+
+    function test_zetaTable_falcon() public pure {
+        _zetas(Falcon512.ZETAS, 2, 512, 12289, 10302);
+    }
+
+    function test_kat_fndsa512() public {
+        _uaVector("fndsa512", address(new UAFndsaVerifier()), PqUA.FNDSA512);
+    }
+
+    function test_falcon_nistKat() public {
+        vm.pauseGasMetering();
+        string memory ext = _ext();
+        FnHarness h = new FnHarness();
+        assertEq(_cases(ext, "falcon_kat"), 10);
+        for (uint256 i; i < 10; ++i) {
+            string memory c = _case("falcon_kat", i);
+            bytes memory pk = _b(ext, string.concat(c, ".pk"));
+            bytes memory m = _b(ext, string.concat(c, ".msg"));
+            bytes memory sig = _b(ext, string.concat(c, ".sig"));
+            assertTrue(h.verify(pk, m, sig));
+            sig[665] = 0x01; // non-zero padding
+            assertFalse(h.verify(pk, m, sig));
+        }
+    }
+
+    /// Malformed inputs are refused, never reduced: a coefficient ≥ q, the headers, the lengths.
+    function test_malformed_fndsa() public {
+        string memory kat = _kat();
+        UAFndsaVerifier v = new UAFndsaVerifier();
+        bytes memory pk = _k(kat, "fndsa512", "pk");
+        bytes memory sig = _k(kat, "fndsa512", "sig");
+        bytes32 m = bytes32(_k(kat, "fndsa512", "ua_msg"));
+        assertTrue(v.verify(pk, m, sig));
+        bytes memory bad = bytes.concat(pk);
+        bad[1] = 0xff; // first 14-bit coefficient ≥ 0x3fc0 > q
+        assertFalse(v.verify(bad, m, sig));
+        bad = bytes.concat(pk);
+        bad[0] = 0x0a; // logn header
+        assertFalse(v.verify(bad, m, sig));
+        bad = bytes.concat(sig);
+        bad[0] = 0x29; // the unpadded (NIST API) header
+        assertFalse(v.verify(pk, m, bad));
+        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")));
+    }
+}
diff --git a/smartcontracts/evm/test/ua/PqGas.t.sol b/smartcontracts/evm/test/ua/PqGas.t.sol
index fa17896..9ac88f4 100644
--- a/smartcontracts/evm/test/ua/PqGas.t.sol
+++ b/smartcontracts/evm/test/ua/PqGas.t.sol
@@ -3,6 +3,8 @@ pragma solidity ^0.8.24;
 
 import {Test, console2} from "forge-std/Test.sol";
 import {SlhDsaSha2128s, UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
+import {Shake} from "../../src/ua/Shake.sol";
+import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
 
 /// SLH-DSA with every hypertree layer's WOTS+ message forced to 0: 510 chain steps per layer, the most work any input
 /// can force (a valid signature reaching it needs seven 2^-128 events). Same code as `verify` otherwise.
@@ -26,6 +28,13 @@ contract SlhWorstCase {
     }
 }
 
+contract Permuter {
+    function run(uint256 n) external pure {
+        Shake.reserve();
+        for (uint256 i; i < n; ++i) Shake.permute();
+    }
+}
+
 /// T-GAS for the PQ kinds (accounts.md CTR-UA-23): execution gas of one `verify` call (the registry's capped
 /// `staticcall`), valid signature; SLH-DSA also at its worst case. `forge test --match-contract PqGasTest -vv` prints the
 /// numbers. Budget on EIP-7825 chains: `UA_VERIFY_BUDGET` = 12,000,000; an enabled kind on a public chain ≤ ~50 % =
@@ -61,4 +70,18 @@ contract PqGasTest is Test {
         assertLt(valid, worst);
         assertLt(worst, 1_460_000, "SLH-DSA gas gate: the worst case stays far inside 6,000,000");
     }
+
+    function test_gas_fndsa() public {
+        Permuter p = new Permuter();
+        uint256 g0 = gasleft();
+        p.run(1);
+        uint256 g1 = gasleft();
+        p.run(11);
+        uint256 perm = ((g1 - gasleft()) - (g0 - g1)) / 10;
+        uint256 fn = _one(_kat(), "fndsa512", address(new UAFndsaVerifier()));
+        console2.log("keccak-f[1600] permutation", perm);
+        console2.log("fndsa512 verify (valid)", fn);
+        assertLt(perm, 73_000);
+        assertLt(fn, 2_500_000);
+    }
 }
``````

### Task 4: ML-DSA-44 / -65, the EIP-8051 expanded key, the EIP-8355 probe

`MlDsa` is FIPS 204 Algorithm 8 with one core for both key forms: the FIPS 204 key (`ExpandA`, `tr = H(pk, 64)`,
`NTT(t1·2^13)` per call) and the EIP-8051 expanded key (`Â ‖ tr ‖ NTT(t1·2^13)`, u32 big-endian, every coefficient
checked `< q`). Per row: `Σ_j Â[i][j]∘ẑ_j − ĉ∘t̂1_i`, inverse NTT, UseHint, `w1Encode` straight into the final hash
input. `UAMldsaVerifier` checks the fixed lengths, then either calls the probed EIP-8355 precompile with
`pk ‖ sig ‖ pq_msg` (true only on exactly the word 1) or runs the core on `0x00 ‖ 0x00 ‖ pq_msg`.

**Files:** create `smartcontracts/evm/src/ua/MlDsa.sol`, `smartcontracts/evm/test/ua/MlDsa.t.sol`; modify
`smartcontracts/evm/test/ua/PqGas.t.sol`.

- [ ] **Step 1: Apply the diff below.**
- [ ] **Step 2: The new tests.** `../../scripts/capped forge test --match-path 'test/ua/*' -vv` — `MlDsaTest` 10 passed
  (`test_zetaTable_mldsa`, `test_kat_mldsa44`, `test_kat_mldsa65`, `test_expandedKey`: Solidity's expanded key equals
  clientkeys' byte for byte, verifies, refuses a flipped signature and a coefficient ≥ q; `test_acvp_mldsa`: 60 ACVP cases;
  `test_eip8051_nistKat`; `test_eip8355_cases`; `test_probe_usesOnlyAnExactEip8355Answer`; `test_refusesOtherKinds`;
  `test_malformed_mldsa`) and `test_gas_mldsa` logs 11378749 / 18894952 (FIPS key) and 4093690 / 5771110 (expanded key).
- [ ] **Step 3: Full suite.** **911** passed, 10 skipped; size gate 0 errors (`UAMldsaVerifier` 9.7 KB, `UAFndsaVerifier`
  5.7 KB, `UASlhdsaVerifier` 2.2 KB runtime); `FOUNDRY_PROFILE=private7622 ../../scripts/capped forge build` green.
- [ ] **Step 4: Commit** `P6a T4: ML-DSA-44/65 verifier (FIPS 204 key and EIP-8051 expanded key, EIP-8355 probe)`.

``````diff
diff --git a/smartcontracts/evm/src/ua/MlDsa.sol b/smartcontracts/evm/src/ua/MlDsa.sol
new file mode 100644
index 0000000..85894e1
--- /dev/null
+++ b/smartcontracts/evm/src/ua/MlDsa.sol
@@ -0,0 +1,458 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {IUAKindVerifier, PqUA} from "./PqUA.sol";
+import {Shake} from "./Shake.sol";
+import {PqNtt} from "./PqNtt.sol";
+
+/// @title ML-DSA-44 / ML-DSA-65 verification (FIPS 204 Algorithm 8 `ML-DSA.Verify_internal`).
+/// @notice Two key forms, one core: the FIPS 204 public key `ρ ‖ t1` (EIP-8355's encoding; `Â = ExpandA(ρ)`,
+///         `tr = H(pk, 64)` and `NTT(t1·2^d)` computed per call) and the EIP-8051 expanded key
+///         `Â ‖ tr ‖ NTT(t1·2^d)` (coefficients u32 big-endian, `Â` row-major, the FIPS 64-byte `tr`: the layout of
+///         EIP-8051's reference implementation; its text says a 32-byte `tr`, 20,512 B). `mPrime` is the formatted
+///         message `M'` (pure interface: `0 ‖ |ctx| ‖ ctx ‖ M`). Requires `Shake.reserve()` first. **UNAUDITED.**
+library MlDsa {
+    uint256 internal constant Q = 8380417;
+    uint256 internal constant N = 256;
+    /// FIPS 204 `zetas[k] = 1753^brv8(k) mod q`, k = 0..255, u32 big-endian (ζ = 1753, a primitive 512-th root of unity).
+    bytes internal constant ZETAS = hex"0000000100495e020039756700396569004f062b0053df73004fe033004f066b0076b1ae00360dd50028edb000207fe4003972830070894a00088192006d3dc8004c72940041e0b40028a3d20066528a004a18a700794034000a52ee006b7d81004e9f1d001a2877002571df001649ee007611bd00492bb7002af6970022d8d50036f72a0030911e0029d13f004926730050685f002010a2003887f70011b2c3000603a4000e2bed0010b72c004a5f35001f9d1500428cd4003177f40020e61200341c1d001ad873007366810049553f003952f60062564a0065ad0500439a1c0053aa5f0030b62200087f38003b0e6d002c83da001c496e00330e2b001c5b70002ee3f100137eb90057a930003ac6ef003fd54c004eb2ea00503ee1007bb175002648b4001ef256001d90a20045a6d4002ae59b0052589c006ef1f5003f72880017510200075d59001187ba0052aca900773e9e000296d8002592ec004cff1200404ce8004aa582001e54e6004f16c1001a7e790003978f004e48170031b859005884cc001b4827005b63d0005d787a0035225e00400c7e006c09d1005bd532006bc4d300258ecb002e534c00097a6c003b8820006d285c002ca4f800337caa0014b2a0005585360028f1860055795d004af67000234a860075e8260078de660005528c007adf59000f6e17005bf3da00459b7e00628b34005dbecb001a9e7b000006d9006257c500574b3c0069a8ef002898380064b5fe007ef8f5002a4e7800120a23000154a80009b7ff00435e8700437ff8005cd5b4004dc04e004728af007f735d000c8d0d000f66d5005a6d800061ab9800185d9600437f310046829800662960004bd5790028de0600465d8d0049b0e30009b434007c0db3005a68b000409ba90064d3d50021762a0065859100246e390048c39b007bc759004f585900392db2002309230012eb6700454df20030c31c002854240013232e007faf80002dbfcb00022a0b007e832c0026587a006b337500095b76006be1cc005e061e0078e00d00628c37003da604004ae53c001f1d68006330bb007361b8005ea06c00671ac700201fc6005ba4ff0060d7720008f201006de02400080e6d0056038e00695688001e6d3e002603bd006a9dfa0007c017006dbfd40074d0bd0063e1e300519573007ab60d002867ba002decd40058018c003f4cf5000b700900427e23003cbd370027333300673957001a4b5d00196926001ef2060011c14e004c76c8003cf42f007fb19a006af66c002e1669003352d6000347600008526000741e78002f6316006f0a110007c0f100776d0b000d1ff000345824000223d40068c559005e8885002faa320023fc65005e69420051e0ed0065adb3002ca5e60079e1fe007b40640035e1dd00433aac00464ade001cfe140073f1ce0010170e0074b6d7";
+
+    struct Params {
+        uint256 k;
+        uint256 l;
+        uint256 tau;
+        uint256 beta;
+        uint256 gamma1;
+        uint256 gamma2;
+        uint256 omega;
+        uint256 ctLen; // λ/4: length of c~
+        uint256 zBits; // 1 + log2 γ1
+        uint256 w1Bits; // bitlen((q − 1)/(2γ2) − 1)
+        uint256 pkLen;
+        uint256 sigLen;
+    }
+
+    function params44() internal pure returns (Params memory) {
+        return Params(4, 4, 39, 78, 1 << 17, (Q - 1) / 88, 80, 32, 18, 6, 1312, 2420);
+    }
+
+    function params65() internal pure returns (Params memory) {
+        return Params(6, 5, 49, 196, 1 << 19, (Q - 1) / 32, 55, 48, 20, 4, 1952, 3309);
+    }
+
+    /// Length of the EIP-8051-style expanded key: `Â` (k·l polynomials) ‖ tr (64) ‖ NTT(t1·2^d) (k polynomials).
+    function expandedLen(Params memory P) internal pure returns (uint256) {
+        return (P.k * P.l + P.k) * 1024 + 64;
+    }
+
+    /// Verify against the FIPS 204 public key.
+    function verify(Params memory P, bytes calldata pk, bytes memory mPrime, bytes calldata sig)
+        internal pure returns (bool)
+    {
+        if (pk.length != P.pkLen) return false;
+        return _verify(P, pk, false, mPrime, sig);
+    }
+
+    /// Verify against the expanded key (every coefficient must be `< q`).
+    function verifyExpanded(Params memory P, bytes calldata ek, bytes memory mPrime, bytes calldata sig)
+        internal pure returns (bool)
+    {
+        if (ek.length != expandedLen(P)) return false;
+        return _verify(P, ek, true, mPrime, sig);
+    }
+
+    /// The expanded key of a FIPS 204 public key (what EIP-8051's precompile and a stored-key verifier take).
+    function expandKey(Params memory P, bytes calldata pk) internal pure returns (bytes memory ek) {
+        require(pk.length == P.pkLen, "MlDsa: pk length");
+        ek = new bytes(expandedLen(P));
+        uint256 dst;
+        assembly ("memory-safe") {
+            dst := add(ek, 32)
+        }
+        uint256 z = PqNtt.table(ZETAS, 4);
+        uint256 a = PqNtt.alloc(N);
+        uint256 buf = PqNtt.alloc(6);
+        for (uint256 i; i < P.k; ++i) {
+            for (uint256 j; j < P.l; ++j) {
+                _expandA(bytes32(pk[0:32]), j, i, a, buf);
+                dst = _put(a, dst);
+            }
+        }
+        Shake.hash(Shake.SHAKE256, _copy(pk), pk.length, dst, 64);
+        dst += 64;
+        for (uint256 i; i < P.k; ++i) {
+            _t1Hat(pk, i, a, z);
+            PqNtt.reduce(a, N, Q);
+            dst = _put(a, dst);
+        }
+    }
+
+    // ------------------------------------------------------------------ core
+
+    /// Working buffers of one verification (memory pointers; keeps the stack shallow).
+    struct Work {
+        uint256 zetas;
+        uint256 c; // NTT(c)
+        uint256 acc;
+        uint256 a;
+        uint256 buf;
+        uint256 w; // μ ‖ w1Encode(w'_1)
+        uint256[] zh; // NTT(z_j)
+        uint256[] h; // hint masks
+    }
+
+    function _verify(Params memory P, bytes calldata key, bool expanded, bytes memory mPrime, bytes calldata sig)
+        private pure returns (bool)
+    {
+        if (sig.length != P.sigLen) return false;
+        Work memory W;
+        bool ok;
+        (ok, W.h) = _hints(P, sig[P.ctLen + P.l * 32 * P.zBits:]);
+        if (!ok) return false;
+        W.zetas = PqNtt.table(ZETAS, 4);
+        W.zh = new uint256[](P.l);
+        for (uint256 j; j < P.l; ++j) {
+            W.zh[j] = PqNtt.alloc(N);
+            if (!_decodeZ(P, sig[P.ctLen + j * 32 * P.zBits:], W.zh[j])) return false; // ‖z‖∞ ≥ γ1 − β
+            PqNtt.ntt(W.zh[j], N, Q, W.zetas);
+        }
+        W.w = PqNtt.alloc(3 + P.k * P.w1Bits);
+        _mu(P, key, expanded, mPrime, W.w); // μ in the first 64 bytes of w
+        W.c = _sampleInBall(P, sig[0:P.ctLen]);
+        PqNtt.ntt(W.c, N, Q, W.zetas);
+        W.acc = PqNtt.alloc(N);
+        W.a = PqNtt.alloc(N);
+        W.buf = PqNtt.alloc(6);
+        for (uint256 i; i < P.k; ++i) {
+            if (!_row(P, key, expanded, W, i)) return false;
+        }
+        Shake.hash(Shake.SHAKE256, W.w, 64 + P.k * 32 * P.w1Bits, W.buf, P.ctLen);
+        return _sameCt(W.buf, sig[0:P.ctLen]);
+    }
+
+    /// μ = H(tr ‖ M', 64) written at `out` (`tr` from the expanded key, or H(pk, 64)).
+    function _mu(Params memory P, bytes calldata key, bool expanded, bytes memory mPrime, uint256 out) private pure {
+        uint256 trm = PqNtt.alloc(3 + (mPrime.length + 31) / 32);
+        if (expanded) {
+            uint256 o = P.k * P.l * 1024;
+            assembly ("memory-safe") {
+                calldatacopy(trm, add(key.offset, o), 64)
+            }
+        } else {
+            uint256 tmp = PqNtt.alloc(6);
+            Shake.hash(Shake.SHAKE256, _copy(key), key.length, tmp, 64);
+            assembly ("memory-safe") {
+                mcopy(trm, tmp, 64)
+            }
+        }
+        assembly ("memory-safe") {
+            mcopy(add(trm, 64), add(mPrime, 32), mload(mPrime))
+        }
+        uint256 tmp2 = PqNtt.alloc(6);
+        Shake.hash(Shake.SHAKE256, trm, 64 + mPrime.length, tmp2, 64);
+        assembly ("memory-safe") {
+            mcopy(out, tmp2, 64)
+        }
+    }
+
+    /// Row i: w'_i = INTT(Σ_j Â[i][j]∘ẑ_j − ĉ∘NTT(t1_i·2^d)), then UseHint and w1Encode into `W.w`.
+    function _row(Params memory P, bytes calldata key, bool expanded, Work memory W, uint256 i)
+        private pure returns (bool)
+    {
+        uint256 acc = W.acc;
+        uint256 a = W.a;
+        assembly ("memory-safe") {
+            calldatacopy(acc, calldatasize(), 8192) // zero
+        }
+        for (uint256 j; j < P.l; ++j) {
+            if (expanded) {
+                if (!_get(key, (i * P.l + j) * 1024, a)) return false;
+            } else {
+                _expandA(bytes32(key[0:32]), j, i, a, W.buf);
+            }
+            _mulAcc(acc, a, W.zh[j]);
+        }
+        if (expanded) {
+            if (!_get(key, P.k * P.l * 1024 + 64 + i * 1024, a)) return false;
+        } else {
+            _t1Hat(key, i, a, W.zetas);
+        }
+        PqNtt.mulPoint(a, W.c, N, Q); // c·t1·2^d in the NTT domain
+        _sub(acc, a);
+        PqNtt.intt(acc, N, Q, W.zetas);
+        _useHintEncode(P, acc, W.h[i], W.w + 64 + i * 32 * P.w1Bits);
+        return true;
+    }
+
+    /// The first `ct.length` (32 or 48) bytes at `buf` equal `ct`.
+    function _sameCt(uint256 buf, bytes calldata ct) private pure returns (bool same) {
+        assembly ("memory-safe") {
+            same := eq(mload(buf), calldataload(ct.offset))
+            if eq(ct.length, 48) {
+                let hi := not(sub(shl(128, 1), 1))
+                same := and(same, eq(and(mload(add(buf, 32)), hi), and(calldataload(add(ct.offset, 32)), hi)))
+            }
+        }
+    }
+
+    // ------------------------------------------------------------------ pieces
+
+    /// RejNTTPoly(ρ ‖ s ‖ r) (Algorithms 30, 32) into `a`.
+    function _expandA(bytes32 rho, uint256 s, uint256 r, uint256 a, uint256 buf) private pure {
+        uint256 seed = PqNtt.alloc(2);
+        assembly ("memory-safe") {
+            mstore(seed, rho)
+            mstore8(add(seed, 32), s)
+            mstore8(add(seed, 33), r)
+        }
+        Shake.absorb(Shake.SHAKE128, seed, 34);
+        uint256 i;
+        while (i < N) {
+            Shake.squeeze(Shake.SHAKE128, buf);
+            assembly ("memory-safe") {
+                for { let o := 0 } and(lt(o, 168), lt(i, N)) { o := add(o, 3) } {
+                    let x := shr(232, mload(add(buf, o))) // b0 ‖ b1 ‖ b2
+                    let v := or(or(shl(16, and(x, 0x7f)), and(x, 0xff00)), shr(16, x))
+                    if lt(v, Q) {
+                        mstore(add(a, shl(5, i)), v)
+                        i := add(i, 1)
+                    }
+                }
+            }
+        }
+    }
+
+    /// NTT(t1_i · 2^13) from the public key (10-bit little-endian coefficients after ρ).
+    function _t1Hat(bytes calldata pk, uint256 i, uint256 a, uint256 z) private pure {
+        uint256 base;
+        assembly ("memory-safe") {
+            base := add(pk.offset, add(32, mul(i, 320)))
+        }
+        assembly ("memory-safe") {
+            for { let c := 0 } lt(c, N) { c := add(c, 1) } {
+                let bit := mul(c, 10)
+                let v := and(shr(and(bit, 7), _le4(calldataload(add(base, shr(3, bit))))), 0x3ff)
+                mstore(add(a, shl(5, c)), mulmod(v, 8192, Q))
+            }
+            function _le4(w) -> x {
+                x := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
+            }
+        }
+        PqNtt.ntt(a, N, Q, z);
+    }
+
+    /// z_j from the signature: γ1 − (zBits-bit little-endian value), stored mod q; false iff ‖z_j‖∞ ≥ γ1 − β.
+    function _decodeZ(Params memory P, bytes calldata enc, uint256 out) private pure returns (bool ok) {
+        uint256 g1 = P.gamma1;
+        uint256 bound = P.gamma1 - P.beta;
+        uint256 bits = P.zBits;
+        uint256 mask = (1 << bits) - 1;
+        ok = true;
+        assembly ("memory-safe") {
+            for { let c := 0 } lt(c, N) { c := add(c, 1) } {
+                let bit := mul(c, bits)
+                let w := calldataload(add(enc.offset, shr(3, bit)))
+                let x := or(or(byte(0, w), shl(8, byte(1, w))), or(shl(16, byte(2, w)), shl(24, byte(3, w))))
+                let v := and(shr(and(bit, 7), x), mask) // z = γ1 − v ∈ (−γ1, γ1]
+                let zz
+                switch gt(v, g1)
+                case 0 {
+                    zz := sub(g1, v)
+                    if iszero(lt(zz, bound)) { ok := 0 }
+                }
+                default {
+                    let m := sub(v, g1) // |z|
+                    if iszero(lt(m, bound)) { ok := 0 }
+                    zz := sub(Q, m)
+                }
+                mstore(add(out, shl(5, c)), zz)
+            }
+        }
+    }
+
+    /// HintBitUnpack (Algorithm 21): one 256-bit mask per row; false on a malformed hint.
+    function _hints(Params memory P, bytes calldata y) private pure returns (bool ok, uint256[] memory h) {
+        h = new uint256[](P.k);
+        uint256 omega = P.omega;
+        uint256 idx;
+        for (uint256 i; i < P.k; ++i) {
+            uint256 end = uint8(y[omega + i]);
+            if (end < idx || end > omega) return (false, h);
+            uint256 first = idx;
+            uint256 mask;
+            while (idx < end) {
+                uint256 pos = uint8(y[idx]);
+                if (idx > first && uint8(y[idx - 1]) >= pos) return (false, h);
+                mask |= 1 << pos;
+                ++idx;
+            }
+            h[i] = mask;
+        }
+        for (; idx < omega; ++idx) if (y[idx] != 0) return (false, h);
+        return (true, h);
+    }
+
+    /// SampleInBall(c~) (Algorithm 29) with SHAKE256 over the whole c~.
+    function _sampleInBall(Params memory P, bytes calldata ct) private pure returns (uint256 c) {
+        c = PqNtt.alloc(N);
+        uint256 seed = PqNtt.alloc(2);
+        assembly ("memory-safe") {
+            calldatacopy(seed, ct.offset, ct.length)
+        }
+        Shake.absorb(Shake.SHAKE256, seed, ct.length);
+        uint256 buf = PqNtt.alloc(6);
+        Shake.squeeze(Shake.SHAKE256, buf);
+        uint256 signs;
+        assembly ("memory-safe") {
+            let s := shr(192, mload(buf)) // 8 bytes, little-endian bit order
+            signs := or(or(or(byte(24, s), shl(8, byte(25, s))), or(shl(16, byte(26, s)), shl(24, byte(27, s)))),
+                or(or(shl(32, byte(28, s)), shl(40, byte(29, s))), or(shl(48, byte(30, s)), shl(56, byte(31, s)))))
+        }
+        uint256 pos = 8;
+        uint256 tau = P.tau;
+        for (uint256 i = N - tau; i < N; ++i) {
+            uint256 j;
+            while (true) {
+                if (pos == 136) {
+                    Shake.squeeze(Shake.SHAKE256, buf);
+                    pos = 0;
+                }
+                assembly ("memory-safe") {
+                    j := byte(0, mload(add(buf, pos)))
+                }
+                ++pos;
+                if (j <= i) break;
+            }
+            assembly ("memory-safe") {
+                let pj := add(c, shl(5, j))
+                mstore(add(c, shl(5, i)), mload(pj))
+                switch and(shr(sub(add(i, tau), N), signs), 1)
+                case 0 { mstore(pj, 1) }
+                default { mstore(pj, sub(Q, 1)) }
+            }
+        }
+    }
+
+    /// acc += a ∘ b (pointwise mod q).
+    function _mulAcc(uint256 acc, uint256 a, uint256 b) private pure {
+        assembly ("memory-safe") {
+            for { let i := 0 } lt(i, 8192) { i := add(i, 32) } {
+                let p := add(acc, i)
+                mstore(p, addmod(mload(p), mulmod(mload(add(a, i)), mload(add(b, i)), Q), Q))
+            }
+        }
+    }
+
+    /// acc −= a (mod q).
+    function _sub(uint256 acc, uint256 a) private pure {
+        assembly ("memory-safe") {
+            for { let i := 0 } lt(i, 8192) { i := add(i, 32) } {
+                let p := add(acc, i)
+                mstore(p, addmod(mload(p), sub(Q, mload(add(a, i))), Q))
+            }
+        }
+    }
+
+    /// UseHint (Algorithms 36, 40) on row `r` with hint mask `hm`, then SimpleBitPack(w1Bits) little-endian at `out`.
+    function _useHintEncode(Params memory P, uint256 r, uint256 hm, uint256 out) private pure {
+        uint256 g2 = P.gamma2;
+        uint256 m = (Q - 1) / (2 * g2);
+        uint256 bits = P.w1Bits;
+        assembly ("memory-safe") {
+            let twoG2 := shl(1, g2)
+            let accBits := 0
+            let accN := 0
+            let o := out
+            for { let c := 0 } lt(c, N) { c := add(c, 1) } {
+                let x := mload(add(r, shl(5, c)))
+                let r0p := mod(x, twoG2)
+                let diff := sub(x, r0p)
+                if gt(r0p, g2) { diff := add(diff, twoG2) }
+                let r1 := div(diff, twoG2)
+                if eq(diff, sub(Q, 1)) { r1 := 0 }
+                if and(shr(c, hm), 1) {
+                    switch and(gt(r0p, 0), iszero(gt(r0p, g2)))
+                    case 1 { r1 := mod(add(r1, 1), m) }
+                    default { r1 := mod(add(r1, sub(m, 1)), m) }
+                }
+                accBits := or(accBits, shl(accN, r1))
+                accN := add(accN, bits)
+                for {} iszero(lt(accN, 8)) {} {
+                    mstore8(o, and(accBits, 0xff))
+                    o := add(o, 1)
+                    accBits := shr(8, accBits)
+                    accN := sub(accN, 8)
+                }
+            }
+        }
+    }
+
+    /// Reads polynomial `off` (bytes) of the expanded key: 256 × u32 big-endian, each `< q`.
+    function _get(bytes calldata ek, uint256 off, uint256 a) private pure returns (bool ok) {
+        ok = true;
+        assembly ("memory-safe") {
+            let s := add(ek.offset, off)
+            for { let c := 0 } lt(c, N) { c := add(c, 1) } {
+                let v := shr(224, calldataload(add(s, shl(2, c))))
+                if iszero(lt(v, Q)) { ok := 0 }
+                mstore(add(a, shl(5, c)), v)
+            }
+        }
+    }
+
+    /// Writes polynomial `a` as 256 × u32 big-endian at `dst`; returns the next write position.
+    function _put(uint256 a, uint256 dst) private pure returns (uint256) {
+        assembly ("memory-safe") {
+            for { let c := 0 } lt(c, N) { c := add(c, 8) } {
+                let w := 0
+                for { let t := 0 } lt(t, 8) { t := add(t, 1) } {
+                    w := or(shl(32, w), mload(add(a, shl(5, add(c, t)))))
+                }
+                mstore(add(dst, shl(2, c)), w)
+            }
+        }
+        return dst + 1024;
+    }
+
+    function _copy(bytes calldata b) private pure returns (uint256 p) {
+        p = PqNtt.alloc((b.length + 31) / 32);
+        assembly ("memory-safe") {
+            calldatacopy(p, b.offset, b.length)
+        }
+    }
+}
+
+/// @title `mldsa44` / `mldsa65` UA verifier (accounts.md CTR-UA-23, kinds 0x0130 / 0x0131): FIPS 204 ML-DSA over
+///        `pq_msg` with the empty context, on the FIPS 204 public key (`keyData`). An EIP-8355 precompile is used when
+///        the constructor's probe of `candidate` passes (`pk ‖ sig ‖ pq_msg` ⇒ exactly the word 1, a flipped
+///        signature ⇒ exactly 0), else pure Solidity. **UNAUDITED.**
+contract UAMldsaVerifier is IUAKindVerifier {
+    uint16 public immutable KIND;
+    bytes32 public immutable KIND_TAG;
+    address public immutable PRECOMPILE; // 0 = pure Solidity
+
+    error UAMldsaKind(uint16 kind);
+
+    /// @param probeValid an input `pk ‖ sig ‖ msg` in the EIP-8355 layout that verifies; `probeInvalid` one that does not.
+    constructor(uint16 kind_, address candidate, bytes memory probeValid, bytes memory probeInvalid) {
+        if (kind_ != PqUA.MLDSA44 && kind_ != PqUA.MLDSA65) revert UAMldsaKind(kind_);
+        KIND = kind_;
+        KIND_TAG = PqUA.tag(kind_);
+        PRECOMPILE = PqUA.probe(candidate, probeValid, probeInvalid) ? candidate : address(0);
+    }
+
+    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
+        Shake.reserve(); // first allocation of the frame
+        MlDsa.Params memory P = KIND == PqUA.MLDSA44 ? MlDsa.params44() : MlDsa.params65();
+        if (keyData.length != P.pkLen || sig.length != P.sigLen) return false; // fixed split for the precompile too
+        bytes32 pq = PqUA.pqMessage(KIND_TAG, message);
+        if (PRECOMPILE != address(0)) return PqUA.callBool(PRECOMPILE, abi.encodePacked(keyData, sig, pq));
+        return MlDsa.verify(P, keyData, PqUA.emptyContext(pq), sig);
+    }
+
+    /// EIP-8051 expanded key of `pk` (FIPS 64-byte `tr`).
+    function expandedKey(bytes calldata pk) external view returns (bytes memory) {
+        Shake.reserve();
+        return MlDsa.expandKey(KIND == PqUA.MLDSA44 ? MlDsa.params44() : MlDsa.params65(), pk);
+    }
+}
diff --git a/smartcontracts/evm/test/ua/MlDsa.t.sol b/smartcontracts/evm/test/ua/MlDsa.t.sol
new file mode 100644
index 0000000..32b0d95
--- /dev/null
+++ b/smartcontracts/evm/test/ua/MlDsa.t.sol
@@ -0,0 +1,158 @@
+// SPDX-License-Identifier: Apache-2.0
+pragma solidity ^0.8.24;
+
+import {PqVectors} from "./PqVectors.sol";
+import {PqUA} from "../../src/ua/PqUA.sol";
+import {Shake} from "../../src/ua/Shake.sol";
+import {MlDsa, UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
+
+contract MlHarness {
+    function verify(uint256 level, bytes calldata pk, bytes calldata mprime, bytes calldata sig) external pure returns (bool) {
+        Shake.reserve();
+        return MlDsa.verify(level == 44 ? MlDsa.params44() : MlDsa.params65(), pk, mprime, sig);
+    }
+
+    function verifyExpanded(uint256 level, bytes calldata ek, bytes calldata mprime, bytes calldata sig)
+        external pure returns (bool)
+    {
+        Shake.reserve();
+        return MlDsa.verifyExpanded(level == 44 ? MlDsa.params44() : MlDsa.params65(), ek, mprime, sig);
+    }
+}
+
+/// An EIP-8355 precompile stand-in: `pk ‖ sig ‖ msg` ⇒ the 32-byte word 0 or 1, ML-DSA-44 or -65 by length.
+contract Eip8355Emulator {
+    fallback(bytes calldata input) external returns (bytes memory) {
+        Shake.reserve();
+        bool ok;
+        if (input.length >= 3732 && input.length < 5261) {
+            ok = MlDsa.verify(MlDsa.params44(), input[0:1312], abi.encodePacked(bytes2(0), input[3732:]), input[1312:3732]);
+        } else if (input.length >= 5261) {
+            ok = MlDsa.verify(MlDsa.params65(), input[0:1952], abi.encodePacked(bytes2(0), input[5261:]), input[1952:5261]);
+        }
+        return abi.encode(ok ? 1 : 0);
+    }
+}
+
+contract AlwaysOne {
+    fallback(bytes calldata) external returns (bytes memory) {
+        return abi.encode(uint256(1));
+    }
+}
+
+/// `mldsa44` / `mldsa65` (CTR-UA-23): ACVP ML-DSA sigVer (pure and internal), the EIP-8051 NIST KATs, the EIP-8355
+/// cases, the EIP-8051 expanded key, the precompile probe, the SCaaS UA vectors, malformed encodings.
+contract MlDsaTest is PqVectors {
+    function test_zetaTable_mldsa() public pure {
+        _zetas(MlDsa.ZETAS, 4, 256, 8380417, 1753);
+    }
+
+    function test_kat_mldsa44() public {
+        _uaVector("mldsa44", address(new UAMldsaVerifier(PqUA.MLDSA44, address(0), "", "")), PqUA.MLDSA44);
+    }
+
+    function test_kat_mldsa65() public {
+        _uaVector("mldsa65", address(new UAMldsaVerifier(PqUA.MLDSA65, address(0), "", "")), PqUA.MLDSA65);
+    }
+
+    /// The EIP-8051 expanded key: Solidity and clientkeys produce the same bytes, and it verifies the same signature.
+    function test_expandedKey() public {
+        string memory kat = _kat();
+        MlHarness h = new MlHarness();
+        string[2] memory names = ["mldsa44", "mldsa65"];
+        uint16[2] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65];
+        for (uint256 i; i < 2; ++i) {
+            uint256 level = i == 0 ? 44 : 65;
+            bytes memory ek = new UAMldsaVerifier(kinds[i], address(0), "", "").expandedKey(_k(kat, names[i], "pk"));
+            assertEq(ek, _k(kat, names[i], "expanded_key"), names[i]);
+            bytes memory mprime = abi.encodePacked(bytes2(0), _k(kat, names[i], "signed_message"));
+            bytes memory sig = _k(kat, names[i], "sig");
+            assertTrue(h.verifyExpanded(level, ek, mprime, sig));
+            sig[5] ^= 0x01;
+            assertFalse(h.verifyExpanded(level, ek, mprime, sig));
+            sig[5] ^= 0x01;
+            ek[3] = 0xff; // first Â coefficient ≥ q: refused, not reduced
+            assertFalse(h.verifyExpanded(level, ek, mprime, sig));
+        }
+    }
+
+    function test_acvp_mldsa() public {
+        vm.pauseGasMetering(); // 60 full verifications: correctness only
+        string memory ext = _ext();
+        MlHarness h = new MlHarness();
+        uint256 n = _cases(ext, "acvp_mldsa");
+        assertEq(n, 60);
+        for (uint256 i; i < n; ++i) {
+            string memory c = _case("acvp_mldsa", i);
+            uint256 level = keccak256(bytes(vm.parseJsonString(ext, string.concat(c, ".set")))) == keccak256("ML-DSA-44") ? 44 : 65;
+            bool got = h.verify(level, _b(ext, string.concat(c, ".pk")), _b(ext, string.concat(c, ".mprime")),
+                _b(ext, string.concat(c, ".sig")));
+            assertEq(got, vm.parseJsonBool(ext, string.concat(c, ".valid")), vm.parseJsonString(ext, string.concat(c, ".reason")));
+        }
+    }
+
+    function test_eip8051_nistKat() public {
+        vm.pauseGasMetering();
+        string memory ext = _ext();
+        MlHarness h = new MlHarness();
+        assertEq(_cases(ext, "eip8051_nist_kat"), 10);
+        for (uint256 i; i < 10; ++i) {
+            string memory c = _case("eip8051_nist_kat", i);
+            assertTrue(h.verify(44, _b(ext, string.concat(c, ".pk")), _b(ext, string.concat(c, ".mprime")), _b(ext, string.concat(c, ".sig"))));
+        }
+    }
+
+    function test_eip8355_cases() public {
+        vm.pauseGasMetering();
+        string memory ext = _ext();
+        MlHarness h = new MlHarness();
+        for (uint256 i; i < 2; ++i) { // cases 1 and 2; case 3 (too short to parse) runs in the probe test
+            string memory c = _case("eip8355", i);
+            bool got = h.verify(44, _b(ext, string.concat(c, ".pk")), _b(ext, string.concat(c, ".mprime")), _b(ext, string.concat(c, ".sig")));
+            assertEq(got, vm.parseJsonBool(ext, string.concat(c, ".valid")));
+        }
+    }
+
+    /// The precompile is used only on an exact EIP-8355 answer (valid ⇒ word 1, flipped ⇒ word 0), for both levels.
+    function test_probe_usesOnlyAnExactEip8355Answer() public {
+        vm.pauseGasMetering();
+        string memory kat = _kat();
+        string[2] memory names = ["mldsa44", "mldsa65"];
+        uint16[2] memory kinds = [PqUA.MLDSA44, PqUA.MLDSA65];
+        address pc = address(0x12);
+        for (uint256 i; i < 2; ++i) {
+            bytes memory valid = _k(kat, names[i], "eip8355_probe_valid");
+            bytes memory invalid = _k(kat, names[i], "eip8355_probe_invalid");
+            vm.etch(pc, ""); // no code: probe fails, pure Solidity
+            assertEq(new UAMldsaVerifier(kinds[i], pc, valid, invalid).PRECOMPILE(), address(0));
+            vm.etch(pc, address(new AlwaysOne()).code); // answers 1 to everything: refused
+            assertEq(new UAMldsaVerifier(kinds[i], pc, valid, invalid).PRECOMPILE(), address(0));
+            vm.etch(pc, address(new Eip8355Emulator()).code);
+            UAMldsaVerifier v = new UAMldsaVerifier(kinds[i], pc, valid, invalid);
+            assertEq(v.PRECOMPILE(), pc);
+            bytes32 uaMsg = bytes32(_k(kat, names[i], "ua_msg"));
+            assertTrue(v.verify(_k(kat, names[i], "pk"), uaMsg, _k(kat, names[i], "sig")));
+            assertFalse(v.verify(_k(kat, names[i], "pk"), uaMsg ^ bytes32(uint256(1)), _k(kat, names[i], "sig")));
+        }
+        (bool ok, bytes memory ret) = pc.staticcall(_b(_ext(), ".eip8355.cases[2].input")); // EIP-8355 case 3
+        assertTrue(ok);
+        assertEq(abi.decode(ret, (uint256)), 0);
+    }
+
+    function test_refusesOtherKinds() public {
+        vm.expectRevert(abi.encodeWithSelector(UAMldsaVerifier.UAMldsaKind.selector, PqUA.FNDSA512));
+        new UAMldsaVerifier(PqUA.FNDSA512, address(0), "", "");
+    }
+
+    function test_malformed_mldsa() public {
+        string memory kat = _kat();
+        UAMldsaVerifier v = new UAMldsaVerifier(PqUA.MLDSA44, address(0), "", "");
+        bytes memory pk = _k(kat, "mldsa44", "pk");
+        bytes memory sig = _k(kat, "mldsa44", "sig");
+        bytes32 m = bytes32(_k(kat, "mldsa44", "ua_msg"));
+        assertFalse(v.verify(_k(kat, "mldsa65", "pk"), m, sig)); // a 65 key on the 44 verifier
+        assertFalse(v.verify(pk, m, bytes.concat(sig, hex"00")));
+        sig[2420 - 4] = 0x51; // hint count of row 0 above ω = 80
+        assertFalse(v.verify(pk, m, sig));
+    }
+}
diff --git a/smartcontracts/evm/test/ua/PqGas.t.sol b/smartcontracts/evm/test/ua/PqGas.t.sol
index 9ac88f4..19673bd 100644
--- a/smartcontracts/evm/test/ua/PqGas.t.sol
+++ b/smartcontracts/evm/test/ua/PqGas.t.sol
@@ -5,6 +5,8 @@ import {Test, console2} from "forge-std/Test.sol";
 import {SlhDsaSha2128s, UASlhdsaVerifier} from "../../src/ua/SlhDsa.sol";
 import {Shake} from "../../src/ua/Shake.sol";
 import {UAFndsaVerifier} from "../../src/ua/FnDsa.sol";
+import {PqUA} from "../../src/ua/PqUA.sol";
+import {MlDsa, UAMldsaVerifier} from "../../src/ua/MlDsa.sol";
 
 /// SLH-DSA with every hypertree layer's WOTS+ message forced to 0: 510 chain steps per layer, the most work any input
 /// can force (a valid signature reaching it needs seven 2^-128 events). Same code as `verify` otherwise.
@@ -35,6 +37,13 @@ contract Permuter {
     }
 }
 
+contract MlDsaExpanded {
+    function verify(uint256 level, bytes calldata ek, bytes calldata mprime, bytes calldata sig) external pure returns (bool) {
+        Shake.reserve();
+        return MlDsa.verifyExpanded(level == 44 ? MlDsa.params44() : MlDsa.params65(), ek, mprime, sig);
+    }
+}
+
 /// T-GAS for the PQ kinds (accounts.md CTR-UA-23): execution gas of one `verify` call (the registry's capped
 /// `staticcall`), valid signature; SLH-DSA also at its worst case. `forge test --match-contract PqGasTest -vv` prints the
 /// numbers. Budget on EIP-7825 chains: `UA_VERIFY_BUDGET` = 12,000,000; an enabled kind on a public chain ≤ ~50 % =
@@ -84,4 +93,33 @@ contract PqGasTest is Test {
         assertLt(perm, 73_000);
         assertLt(fn, 2_500_000);
     }
+
+    function _expanded(string memory kat, string memory name, uint256 level) internal returns (uint256 used) {
+        MlDsaExpanded e = new MlDsaExpanded();
+        string memory k = string.concat(".kinds.", name);
+        bytes memory ek = vm.parseJsonBytes(kat, string.concat(k, ".expanded_key"));
+        bytes memory mprime = abi.encodePacked(bytes2(0), vm.parseJsonBytes(kat, string.concat(k, ".signed_message")));
+        bytes memory sig = vm.parseJsonBytes(kat, string.concat(k, ".sig"));
+        uint256 g = gasleft();
+        bool ok = e.verify(level, ek, mprime, sig);
+        used = g - gasleft();
+        require(ok, "expanded");
+    }
+
+    function test_gas_mldsa() public {
+        string memory kat = _kat();
+        uint256 c44 = _one(kat, "mldsa44", address(new UAMldsaVerifier(PqUA.MLDSA44, address(0), "", "")));
+        uint256 c65 = _one(kat, "mldsa65", address(new UAMldsaVerifier(PqUA.MLDSA65, address(0), "", "")));
+        uint256 e44 = _expanded(kat, "mldsa44", 44);
+        uint256 e65 = _expanded(kat, "mldsa65", 65);
+        console2.log("mldsa44 verify (valid, FIPS 204 key)", c44);
+        console2.log("mldsa65 verify (valid, FIPS 204 key)", c65);
+        console2.log("mldsa44 verify (valid, EIP-8051 expanded key)", e44);
+        console2.log("mldsa65 verify (valid, expanded key)", e65);
+        assertGt(c44, 6_000_000, "FIPS-key ML-DSA-44 over the public-chain bound: if this fails, revisit ruling P10");
+        assertLt(c44, 12_600_000);
+        assertLt(c65, 20_800_000);
+        assertLt(e44, 4_500_000);
+        assertLt(e65, 6_400_000);
+    }
 }
``````

### Task 5: Docs and TODO

The component docs take the built state and the measurements (net 0 lines on the over-budget pages); the research
note records the findings and keeps its questions open; TODO marks P6a.

**Files:** modify `docs/contracts/accounts.md` (kind table 0x0130–0x0133, CTR-UA-23, §1.9 verifier and enablement rows,
§1.15 gas rows and the cost paragraph, T-FUZZ), `docs/contracts/pq-zether.md` (§9.4 `UAMldsaVerifier`, the self-test
paragraph), `docs/clients/signers-clientkeys.md` ("PQ seeds"), `docs/research/pq-eips-vs-scaas.md` (findings under Q1, Q2,
Q3, Q4), `TODO.md` (row P6).

- [ ] **Step 1: Apply the diff below.**
- [ ] **Step 2: Check.** `python3 scripts/docs_check.py check` — 0 errors (the one warning, `token-wrappers.md` over
  budget, predates P6); `python3 scripts/docs_check.py facts check` — 0 misses (the old ML-DSA-65 cost "$36–240" stays
  quoted next to the measured one).
- [ ] **Step 3: Commit** `P6a T5: docs (PQ verifiers built, measured gas, EIP findings), TODO`.

``````diff
diff --git a/TODO.md b/TODO.md
index 473d964..9dbb471 100644
--- a/TODO.md
+++ b/TODO.md
@@ -18,7 +18,7 @@ phases P1–P5 (P0 = the docs, done); each phase ends with the size gate (CTR-TO
 | P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; `ZetherToken` to `legacy/p3/` (owner: backup, not delete) (done, merged `dc9d219`; P3b modes done) | MT-6 |
 | P4 | `MandateWallet`, `SmartKeyAccount` (rename: EVM, Solana, Soroban) on `MetaTxBase`; the typed-struct line to `legacy/p4/` (done, merged `ebacaac`) | MT-7 (+ rename in NM-*) |
 | P5 | Node, clientkeys, encoders for the new ABI; the v1 line to `legacy/p5/` (done; plan `docs/superpowers/plans/2026-10-11-p5-node-clients-new-abi.md`) | MT-8, MT-9 |
-| P6 | PQ Zether after P5 (owner 2026-10-11) and PQ signatures as compatible as possible with the Ethereum drafts, both directions (ML-DSA [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051) / [EIP-8355](https://eips.ethereum.org/EIPS/eip-8355): empty FIPS 204 context, `pq_msg = keccak256(TAG(kind) ‖ ua_msg)`, the EIP encodings incl. the expanded key; Falcon [EIP-8052](https://eips.ethereum.org/EIPS/eip-8052); `slhdsa128s` 0x0133 behind a gas gate; precompiles by probe at the EIP addresses, the 7622 addresses out of the EIP-1352 range; no hybrid kind, owner 2026-10-12; [CTR-UA-23](docs/contracts/accounts.md#CTR-UA-23), [pq-eips-vs-scaas.md](docs/research/pq-eips-vs-scaas.md) Q1–Q8). Roadmap `docs/superpowers/plans/2026-10-12-p6-roadmap.md`: **P6a** PQ signature verifiers on the EIP formats + clientkeys PQ signing (plan `docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md`); **P6b** E-S0 parameter spike; **P6c** UA registry gen 1 with the PQ kinds (UA F0 + F1 core + F9; owner: scope, ML-DSA stored-key form); **P6d** E-S1 `pqz-core` spike (kill criteria); **P6e** E-S2 relations; **P6f** E-S3 Nethermind precompiles on 7622 (owner-approved chain changes); **P6g** E-S4 contracts (`PqzToken` with CTR-PQZ-23/24); **P6h** E-S5/E-S6 clients and WASM; **P6i** E-S7 node; **P6j** E-S8 review; G-LIC any time (release gate) ([pq-zether.md](docs/contracts/pq-zether.md)) | UA PQ kinds, E-S* |
+| P6 | PQ Zether after P5 (owner 2026-10-11) and PQ signatures as compatible as possible with the Ethereum drafts, both directions (ML-DSA [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051) / [EIP-8355](https://eips.ethereum.org/EIPS/eip-8355): empty FIPS 204 context, `pq_msg = keccak256(TAG(kind) ‖ ua_msg)`, the EIP encodings incl. the expanded key; Falcon [EIP-8052](https://eips.ethereum.org/EIPS/eip-8052); `slhdsa128s` 0x0133 behind a gas gate; precompiles by probe at the EIP addresses, the 7622 addresses out of the EIP-1352 range; no hybrid kind, owner 2026-10-12; [CTR-UA-23](docs/contracts/accounts.md#CTR-UA-23), [pq-eips-vs-scaas.md](docs/research/pq-eips-vs-scaas.md) Q1–Q8). Roadmap `docs/superpowers/plans/2026-10-12-p6-roadmap.md`: **P6a** PQ signature verifiers on the EIP formats + clientkeys PQ signing (done: `UAMldsaVerifier`, `UAFndsaVerifier`, `UASlhdsaVerifier`, `src/pq.js`, vectors `smartcontracts/vectors/ua/`; SLH-DSA gate passed at 1.32 M worst case; plan `docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md`); **P6b** E-S0 parameter spike; **P6c** UA registry gen 1 with the PQ kinds (UA F0 + F1 core + F9; owner: scope, ML-DSA stored-key form); **P6d** E-S1 `pqz-core` spike (kill criteria); **P6e** E-S2 relations; **P6f** E-S3 Nethermind precompiles on 7622 (owner-approved chain changes); **P6g** E-S4 contracts (`PqzToken` with CTR-PQZ-23/24); **P6h** E-S5/E-S6 clients and WASM; **P6i** E-S7 node; **P6j** E-S8 review; G-LIC any time (release gate) ([pq-zether.md](docs/contracts/pq-zether.md)) | UA PQ kinds, E-S* |
 
 **P1 start checklist (owner decisions 2026-10-08):**
 - [x] Keep the old code for reference: git tag `ref/pre-token-tree` on the last commit before P1, and copy the v1/v2 token
diff --git a/docs/clients/signers-clientkeys.md b/docs/clients/signers-clientkeys.md
index 85e931e..65fd18d 100644
--- a/docs/clients/signers-clientkeys.md
+++ b/docs/clients/signers-clientkeys.md
@@ -587,7 +587,7 @@ offered; an app end-to-end test.
 | Identity UA for credentials | its own `<account>'` in the UA tree, never the paying account's | per kind |
 | `bls12381-minsig`, `schnorr-bls12381` | EIP-2333 `m/12381/0/<account>/<kindNo>` | BLS12-381 |
 | Zether conf key / viewing key | `m/254|12381/<coin>/<account>/7`, `…/8` ([CLI-SGN-10](#CLI-SGN-10)) | bn254 / BLS12-381 |
-| PQ seeds | `ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = kind_tag ‖ u32 account ‖ u32 i)` → FIPS 204 `KeyGen_internal(ξ)` / seeded FN-DSA keygen; `slhdsa128s` (SPECIFIED (P6)): the same HKDF with output length 48 → `SK.seed ‖ SK.prf ‖ PK.seed` (16 B each) → FIPS 205 `slh_keygen_internal`. `signUA` signs `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the empty FIPS 204/205 context ([CTR-UA-23](../contracts/accounts.md#CTR-UA-23), P6; transitional: ML-DSA over `ua_msg` with `ctx = kind_tag`) | ML-DSA, FN-DSA, SLH-DSA |
+| PQ seeds | `ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = kind_tag ‖ u32 account ‖ u32 i)` → FIPS 204 `KeyGen_internal(ξ)` (32 B) / Falcon-512 keygen from a 48-byte seed (implementation-specific: pinned to `@noble/post-quantum` 0.7.1 by the vectors); `slhdsa128s`: output length 48 → `SK.seed ‖ SK.prf ‖ PK.seed` (16 B each) → FIPS 205 `slh_keygen_internal`. `signUA(kind, sk, purposeTag, digest)` signs `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the empty FIPS 204/205 context (Falcon: `ua_msg`) ([CTR-UA-23](../contracts/accounts.md#CTR-UA-23)); BUILT (P6a): `src/pq.js` with the EIP-8051 expanded key `mldsaExpandedKey`, not in the portal bundle | ML-DSA, FN-DSA, SLH-DSA |
 | Passkeys | one credential per `rpId`; the same credential on several chains is the same kind (`webauthn-p256` or a family's native passkey) — allowed, the challenges are domain-separated digests | P-256 |
 
 In general form the tree is `m/7622'/0'/<account>'/<kind>'/<i>'`. `7622'` is the SCaaS BIP-43 purpose for UA trees (owner); the coin level is `0'` because a UA id is chain-independent
diff --git a/docs/contracts/accounts.md b/docs/contracts/accounts.md
index 9ee6785..c9b66f2 100644
--- a/docs/contracts/accounts.md
+++ b/docs/contracts/accounts.md
@@ -334,10 +334,10 @@ Derived kinds (registered; `d` = key data):
 | `0x0113` | `frost-bn254` | `Y (64) ‖ u16 t ‖ u16 n ‖ n × (t × C_ik (64) ‖ R_i (64) ‖ μ_i (32))`, 2 ≤ t ≤ n ≤ 16 | `bn254-g1` | DKG PoKs and `Y = Σ C_i0` **and** one FROST(bn254, keccak256) sig by `Y` | as 0x0104 (its H2 is the scaas Schnorr challenge), `Y` from `keyPtr` | EVM |
 | `0x0120` | `msig` | `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`, ids strictly increasing | — | none of its own; every member registered or native, kind ∈ MEMBER | inside the registry (members via their own kinds) | EVM → all |
 | `0x0121` | *reserved* (was `bls12381-multi`, cut) | — | — | — | — | — |
-| `0x0130` | `mldsa44` | `pk` (1312) | `mldsa44` | ML-DSA-44 sign(`pq_msg`, empty ctx), SPECIFIED (P6); transitional: sign(`ua_msg`, ctx = `kind_tag`) ([CTR-UA-23](#CTR-UA-23)) | precompile where probed, else pure Solidity | every EVM chain |
-| `0x0131` | `mldsa65` | `pk` (1952) | `mldsa65` | as 0x0130 | chain 7622 precompile `0x…0F10` ([CTR-PQZ-10](pq-zether.md#CTR-PQZ-10)), else Solidity | every EVM chain |
-| `0x0132` | `fndsa512` | `pk` (897) | `fndsa512` | FN-DSA-512 (Falcon), FIPS 206 draft encoding pinned by vectors | as 0x0130 | every EVM chain |
-| `0x0133` | `slhdsa128s` | `pk` (32) | `slhdsa128s` | SLH-DSA-SHA2-128s (FIPS 205) sign(`pq_msg`, empty ctx), sig 7,856 B; SPECIFIED (P6) | pure Solidity on SHA-256 `0x02` (no EIP proposes an SLH-DSA precompile), precompile only if probed | EVM; public chains only after the P6 gas gate ([CTR-UA-23](#CTR-UA-23)) |
+| `0x0130` | `mldsa44` | `pk` (1312) | `mldsa44` | ML-DSA-44 sign(`pq_msg`, empty ctx) ([CTR-UA-23](#CTR-UA-23)) | `UAMldsaVerifier` (BUILT, P6a): an EIP-8355 precompile where probed, else pure Solidity | every EVM chain where the measured cap fits |
+| `0x0131` | `mldsa65` | `pk` (1952) | `mldsa65` | as 0x0130 | as 0x0130; chain 7622: its `MLDSA65` precompile in the EIP-8355 layout ([CTR-PQZ-10](pq-zether.md#CTR-PQZ-10)) | as 0x0130 |
+| `0x0132` | `fndsa512` | `pk` (897: `0x09 ‖ h`) | `fndsa512` | Falcon-512 (specification v1.2, NIST third-round; EIP-8052 SHAKE256 hash-to-point) over `ua_msg`, padded sig 666 B | `UAFndsaVerifier` (BUILT, P6a), pure Solidity (EIP-8052 has no addresses) | every EVM chain |
+| `0x0133` | `slhdsa128s` | `pk` (32) | `slhdsa128s` | SLH-DSA-SHA2-128s (FIPS 205) sign(`pq_msg`, empty ctx), sig 7,856 B | `UASlhdsaVerifier` (BUILT, P6a), pure Solidity on SHA-256 `0x02` (no EIP proposes an SLH-DSA precompile) | EVM; the P6 gas gate passed ([CTR-UA-23](#CTR-UA-23)) |
 | `0x0140` | `zether-bn254` | `Y` (64) | `bn254-g1` | scaas Schnorr by `x` under the **Zether** Schnorr tag (`SCAAS-ZETHER-SCHNORR-V1`) on `ua_msg` | existing Zether Schnorr | EVM |
 | `0x0141` | `zether-bls12381` | `Y` (128) | `bls12381-g1` | as 0x0140 on BLS12-381 | existing | EVM (EIP-2537 chains) |
 | `0x0142` | `pqz-mlwe` ([CTR-PQZ-13](pq-zether.md#CTR-PQZ-13)) | `pk` (16 384) | `pqz-mlwe` | `R_REG` lattice proof over `uaMessage(0x0142, POP_TAG, popDigest(ua, authRef))` + the `authRef` co-sign | `UAPqzVerifier` → PQZ precompile `0x…0F01` op 3 | chain 7622 only ([CTR-PQZ-01](pq-zether.md#CTR-PQZ-01)); `authRef` PQ-only ([CTR-PQZ-12](pq-zether.md#CTR-PQZ-12)); `keyPtr` = SSTORE2(pk) |
@@ -429,7 +429,7 @@ Which kind for whom (guidance for apps and client systems):
 
 <a id="pq-kinds"></a>
 <a id="CTR-UA-23"></a>**CTR-UA-23** — **PQ signing kinds (`mldsa44`, `mldsa65`, `fndsa512`) and `ed25519` are enabled on
-every EVM chain** (owner). **Message (owner 2026-10-11, SPECIFIED (P6)):** ML-DSA and SLH-DSA kinds sign the 32-byte `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the **empty** FIPS 204 / FIPS 205 context (pure signing, not the pre-hash variants): EIP-8051 takes exactly a 32-byte message and EIP-8355 takes the raw message with an always-empty context, so a 32-byte digest whose preimage starts with the kind tag is the one form both verify unchanged (`kind_tag ‖ ua_msg` would not fit 8051); key data, `TAG(kind)` and UA ids do not change, the vectors change in P6. *Transitional:* the current spec and prototype sign `ua_msg` with `ctx = kind_tag`. Verification uses a native precompile where one is probed (chain 7622: `MLDSA65` at
+every EVM chain** (owner). **Message (owner 2026-10-11, SPECIFIED (P6)):** ML-DSA and SLH-DSA kinds sign the 32-byte `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the **empty** FIPS 204 / FIPS 205 context (pure signing, not the pre-hash variants): EIP-8051 takes exactly a 32-byte message and EIP-8355 takes the raw message with an always-empty context, so a 32-byte digest whose preimage starts with the kind tag is the one form both verify unchanged (`kind_tag ‖ ua_msg` would not fit 8051); key data, `TAG(kind)` and UA ids do not change. Verifiers BUILT (P6a, `smartcontracts/evm/src/ua/`; vectors `smartcontracts/vectors/ua/pq_kat.json`, `pq_external.json`); the registry is SPECIFIED. Verification uses a native precompile where one is probed (chain 7622: `MLDSA65` at
 `0x…0F10`, [CTR-PQZ-10](pq-zether.md#CTR-PQZ-10); any future EIP-8051/8052/8355 address by probe, never by assumption)
 and a **pure-Solidity verifier** everywhere else. Every check, the registration PoP included, completes **in one
 transaction** within the chain's `UA_VERIFY_BUDGET = min(12,000,000, ⌊0.7 × chain per-transaction gas cap⌋)` (EIP-7825
@@ -437,18 +437,18 @@ chains: 12 M ≈ 70 % of 16,777,216; Hedera, 15 M cap: 10.5 M), a constructor im
 
 **Each kind's verify cap is measured per chain** (worst-case accepting and rejecting input, test T-GAS) and set as a
 constructor immutable `verifyCap[kind]`, also published: e.g. `mldsa65` ≈ 20 k with the chain-7622 precompile, the
-measured Solidity worst case elsewhere. Estimates (measured by the PQ-kind stream): ML-DSA-65 1.2–8.1 M, ML-DSA-44
-lower, FN-DSA-512 0.6–2.5 M, ed25519 0.3–1.2 M. On public chains an enabled kind's measured cap must stay ≤ ~50 % of the
+measured Solidity worst case elsewhere. Measured (P6a, `test/ua/PqGas.t.sol`): ML-DSA-44 / -65 11.4 / 18.9 M on the FIPS 204 key, 4.1 / 5.8 M on a stored EIP-8051 expanded key (open: what the registry stores),
+FN-DSA-512 2.3 M, SLH-DSA 0.79 M (worst case 1.32 M); ed25519 0.3–1.2 M (estimate). On public chains an enabled kind's measured cap must stay ≤ ~50 % of the
 budget, so a later gas repricing cannot push it over after funds are held. **If a measured verifier exceeds that bound
 on a chain, the kind is disabled there (verifier address 0: not registrable), never "registrable but unusable"**: a
-registrable but unusable kind can *receive* and then never spend, locking funds. **`slhdsa128s`** (0x0133, SLH-DSA-SHA2-128s, FIPS 205; owner 2026-10-11, SPECIFIED (P6)) is the hash-based backup if lattice assumptions fall, in line with the Ethereum Foundation's hash-based direction: no EIP proposes an SLH-DSA precompile, so it verifies in pure Solidity on the SHA-256 precompile `0x02` unless a precompile is probed, and it is **enabled on public chains only after P6 measures its verification gas against the chain's per-transaction cap and `UA_VERIFY_BUDGET`** (the non-FIPS Keccak variant SPHINCS- was estimated at 94–276 k gas; the FIPS SHA2 variant is unmeasured).
+registrable but unusable kind can *receive* and then never spend, locking funds. **`slhdsa128s`** (0x0133, SLH-DSA-SHA2-128s, FIPS 205; owner 2026-10-11, SPECIFIED (P6)) is the hash-based backup if lattice assumptions fall, in line with the Ethereum Foundation's hash-based direction: no EIP proposes an SLH-DSA precompile, so it verifies in pure Solidity on the SHA-256 precompile `0x02` unless a precompile is probed, and it is **enabled on public chains only after P6 measures its verification gas against the chain's per-transaction cap and `UA_VERIFY_BUDGET`** — measured in P6a: 1.32 M at the worst case any input can force (510 WOTS+ steps on each of the 7 layers), 0.79 M for a valid signature, ≤ 13 % of every chain's budget, so the gate passes and enabling it is a registry deploy parameter.
 
 Multi-transaction verification with stored partial state and chunked verify are rejected (resumable state is a new replay/griefing surface and a second
-audit target for no gain while the estimates fit). Structures are bounded by the same caps (register step 4): a hybrid `{mldsa65, p256}` fits everywhere, but a quorum of two Solidity-verified PQ members (2 × up to 8.1 M) does not, so the
-`{mldsa65 ×3} t=2` treasury form is registrable only where an ML-DSA precompile exists (chain 7622). `fndsa512` freezes
-the FIPS 206 draft encoding in the vectors; a final FIPS 206 with a different encoding is a new kind version
+audit target for no gain while the estimates fit). Structures are bounded by the same caps (register step 4): a hybrid `{mldsa65, p256}` fits everywhere, but a quorum of two Solidity-verified PQ members (2 × 4–19 M) does not, so the
+`{mldsa65 ×3} t=2` treasury form is registrable only where an ML-DSA precompile exists (chain 7622). `fndsa512` is
+Falcon-512 v1.2 as EIP-8052 (no FIPS 206 draft is published), pinned by the vectors; a final FIPS 206 that differs is a new kind version
 (`…fndsa512.v2`), never a silent change. The earlier `PQ_COMMITMENT` scheme ("verify off chain") is retired. PQ checks
-cost real money on public chains (an ML-DSA-65 signature is 53–132 k gas of calldata alone, plus 1.2–8.1 M execution).
+cost real money on public chains (an ML-DSA-65 signature is 53–132 k gas of calldata alone, plus 5.8–18.9 M execution).
 
 ### 1.7 Function → accepted kinds
 
@@ -844,7 +844,7 @@ native   : ECDSA / 1271 over uaAuthDigest(ua, purposeTag, digest), classified by
 | `bls12381-minsig` | G1 sig (128) | `HashToCurve.hashToG1(ua_msg, DST)` with `DST_SIG = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_"`, PoP uses `…_POP_`; sig in subgroup, ≠ O |
 | `bls-bn254-minsig` | G1 sig (64) | `mapToG1("SCAAS-UA-BLS-BN254-SIG-V1" ‖ ua_msg)` (POP label for PoP); pairing `0x08` |
 | `msig` | `abi.encode(MemberSig[] sigs)`, `MemberSig{uint16 index; bytes keyData; bytes sig}` with strictly increasing `index`; the structure's key data is `auth.keyData` (not repeated) | for each: member `kind,id` from the structure; native ⇒ ECDSA/1271 over `uaAuthDigest(id, PURPOSE_MEMBER, member_digest)`; derived ⇒ `keccak(TAG(kind) ‖ keyData) == id` (stored kinds: `vk` from the member's `keyPtr`; no `kindOf` per member at verify: records are immutable and were checked at registration), verifier over `uaMessage(kind, PURPOSE_MEMBER, member_digest)`; `member_digest = keccak256(ua ‖ ua_msg)`; **stops at the threshold**: a `MemberSig` after Σ weight ≥ threshold ⇒ `UAUnauthorized` (keeps register step 4's bound sound) |
-| `mldsa*` / `fndsa512` / `slhdsa128s` | raw signature | precompile if probed, else Solidity verifier (`slhdsa128s`: on SHA-256 `0x02`), `pk` from `keyPtr` (EXTCODECOPY); ML-DSA and SLH-DSA verify `pq_msg` with the empty context ([CTR-UA-23](#CTR-UA-23), SPECIFIED (P6); transitional: ML-DSA context string = `kind_tag` over `ua_msg`) |
+| `mldsa*` / `fndsa512` / `slhdsa128s` | raw signature | ML-DSA: an EIP-8355 precompile if probed, else Solidity; FN-DSA, SLH-DSA (on SHA-256 `0x02`): Solidity; `pk` from `keyPtr` (EXTCODECOPY); ML-DSA and SLH-DSA verify `pq_msg` with the empty context, Falcon `ua_msg` ([CTR-UA-23](#CTR-UA-23); verifiers BUILT, P6a) |
 | `pqz-mlwe` | as [pq-zether.md](pq-zether.md) | proofs via the PQZ precompile; authorization via its PQ `authRef` |
 | `zether-*` (self, owner ops) | `R ‖ z` | Zether Schnorr with tag `SCAAS-ZETHER-SCHNORR-V1` over `ua_msg` — never the UA Schnorr tag, so a Zether key never produces a `schnorr-*` signature |
 
@@ -861,8 +861,8 @@ Per-chain enablement:
 | `ed25519` | every EVM chain (owner) | no precompile; Solidity verify incl. SHA-512 ≈ 0.3–1.2 M gas (estimate, to be measured) |
 | `bls12381-*`, `schnorr-bls12381`, `zether-bls12381` | chains where the `CurveCapability` probe passes (returndata compared) | EIP-2537 |
 | `bls-bn254-minsig` | private chains only | ~100-bit pairing security |
-| `mldsa44/65`, `fndsa512` | every EVM chain (owner); precompile where probed | Solidity ML-DSA-65 1.2–8.1 M, FN-DSA-512 0.6–2.5 M (estimates); measured cap ≤ ~50 % of the chain's `UA_VERIFY_BUDGET` on public chains, else disabled on that chain ([CTR-UA-23](#CTR-UA-23)) |
-| `slhdsa128s` | SPECIFIED (P6): public chains only after P6 measures it ([CTR-UA-23](#CTR-UA-23)) | pure Solidity on SHA-256 `0x02`; SPHINCS- (Keccak, non-FIPS) estimated 94–276 k, SLH-DSA-SHA2-128s unmeasured |
+| `mldsa44/65`, `fndsa512` | every EVM chain (owner); precompile where probed | Solidity (measured, P6a): ML-DSA-44 / -65 11.4 / 18.9 M (FIPS 204 key; 4.1 / 5.8 M on an expanded key), FN-DSA-512 2.3 M; measured cap ≤ ~50 % of the chain's `UA_VERIFY_BUDGET` on public chains, else disabled on that chain ([CTR-UA-23](#CTR-UA-23)) |
+| `slhdsa128s` | every EVM chain: the P6 gas gate passed ([CTR-UA-23](#CTR-UA-23)) | pure Solidity on SHA-256 `0x02`: 0.79 M valid, 1.32 M worst case (measured, P6a) |
 | `pqz-mlwe` | chain 7622 only | [CTR-PQZ-01](pq-zether.md#CTR-PQZ-01), [CTR-PQZ-10](pq-zether.md#CTR-PQZ-10) |
 
 The enabled set, each kind's measured `verifyCap` and the chain's `verifyBudget` are constructor arguments (verifier
@@ -1203,9 +1203,9 @@ measured worst case (T-GAS), published in the chain profile.
 | `bls12381-minsig` | 256 + 128 | ~120 k (measured on the private chain) | ~5 k | 200 k |
 | `msig` k-of-n | 4 + 36n + Σ member | Σ member verifies (≤ `c` members, stop at threshold) + ~2 k; stored-kind members + EXTCODECOPY | ~5 k | Σ of the `c` largest member caps ≤ `verifyBudget` |
 | `ed25519` | 32 + 64 | ~0.3–1.2 M (Solidity, SHA-512 dominates) | ~5 k | 1.5 M |
-| `mldsa44` | 2 420 sig | precompile (chain 7622) / ≤ ML-DSA-65 cost in Solidity | ~5 k + EXTCODECOPY ~3 k | measured; ≈ 20 k with a precompile |
-| `mldsa65` | 3 309 sig | 9 k-class precompile / 1.2–8.1 M Solidity | ~5 k + EXTCODECOPY ~3 k | measured: ≈ 20 k (chain 7622), Solidity worst case elsewhere (≤ 50 % of budget on public chains) |
-| `fndsa512` | ~666 sig | 0.6–2.5 M Solidity | ~5 k + EXTCODECOPY ~1.5 k | measured, as `mldsa65` |
+| `mldsa44` | 2 420 sig | EIP-8355-class precompile / 11.4 M Solidity (4.1 M expanded key) | ~5 k + EXTCODECOPY ~3 k | measured; ≈ 20 k with a precompile |
+| `mldsa65` | 3 309 sig | 9 k-class precompile / 18.9 M Solidity (5.8 M expanded key) | ~5 k + EXTCODECOPY ~3 k | measured: ≈ 20 k (chain 7622), Solidity worst case elsewhere (≤ 50 % of budget on public chains) |
+| `fndsa512` | 666 sig | 2.3 M Solidity (measured) | ~5 k + EXTCODECOPY ~1.5 k | measured, as `mldsa65` |
 | `zether-*` | — (proof path) | unchanged ([zether.md](zether.md#gas-measured)) | ~5 k (`kindOf` + `authRef`) | — |
 
 The `bls12381-minsig` figure is the measured BLS12-381 min-sig verification on the private chain with EIP-2537 live
@@ -1242,8 +1242,8 @@ Registration (execution gas, bn254 base):
 
 Calldata floor (EIP-7623): it binds when execution gas < 24 × non-zero bytes. With a precompile (execution small) a PQ
 check is floor-priced at 40 gas/byte: an ML-DSA-65 signature is ~132 k gas of calldata (~53 k at 16 gas/byte when a
-Solidity verifier makes execution dominate). With a Solidity verifier the 1.2–8.1 M execution dominates: on a public L1
-at 10 gwei and ETH $3 000 that is ≈ $36–240 per ML-DSA-65 check — enabled because the owner wants PQ everywhere, and
+Solidity verifier makes execution dominate). With a Solidity verifier the 5.8–18.9 M execution dominates: on a public L1
+at 10 gwei and ETH $3 000 that is ≈ $170–570 per ML-DSA-65 check (the 1.2–8.1 M estimate said $36–240) — enabled because the owner wants PQ everywhere, and
 shown to the user before they choose a PQ kind on such a chain. On rollups and low-fee chains it is cents; on
 private/PoA chains with zero gas price it is not money. EIP-7825 (16.78 M per transaction) bounds a single check, hence
 `UA_VERIFY_BUDGET` (min(12 M, 0.7 × chain cap)) and the structure bound.
@@ -1309,7 +1309,7 @@ EVM tests:
 | T-MEMBER | an `msig` with a `hedera-native` member registers in a `hederaNative` registry and is refused (`UAMemberUnknown`) in every other profile |
 | T-AUTH-4 | 63/64 starvation and out-of-gas inside every capped verifier `staticcall` ⇒ the check reverts, never passes; malformed/short returndata ⇒ revert |
 | T-FROST | RFC 9591 vectors pass `UAFrostSecp256k1Verifier`; the same signatures fail the BIP-340 verifier and vice versa |
-| T-FUZZ | **differential fuzzing** of the pure-Solidity ML-DSA-44/65, FN-DSA-512 and ed25519 (incl. SHA-512) verifiers against at least one independent implementation (e.g. the precompile's C core / `pqcrystals`, `ed25519-dalek` strict): accept/reject parity on mutated signatures, keys and messages; run before each generation is deployed (a permissive verifier is permanent, S15) |
+| T-FUZZ | **differential fuzzing** (deterministic part BUILT in P6a: mutation sets with noble's verdicts, `test/ua/PqVerifiers.t.sol`) of the pure-Solidity ML-DSA-44/65, FN-DSA-512, SLH-DSA and ed25519 (incl. SHA-512) verifiers against at least one independent implementation (e.g. the precompile's C core / `pqcrystals`, `ed25519-dalek` strict): accept/reject parity on mutated signatures, keys and messages; run before each generation is deployed (a permissive verifier is permanent, S15) |
 | T-ZET-1 | the Zether suite green with tagged UAs; `authRef` 0/native/derived; same-curve BLS refused; `zkCovered` rules |
 | T-V3-1 | v3 equivalences (`uaTransfer ≡ uaExecute`, …) as for the v2 named functions; the v2 address-typed path and the `ua*` path share `_uaNonce[pad(addr)]` |
 | T-V3-2 | invariants: `totalSupply == Σ balanceOf(native incl. UA_POOL)`, `balanceOf(UA_POOL) == Σ _uaBalance`, replaying `Transfer` logs equals `balanceOf` for every native holder; `UATransfer` emitted iff a side is derived |
diff --git a/docs/contracts/pq-zether.md b/docs/contracts/pq-zether.md
index 27a1575..0c06754 100644
--- a/docs/contracts/pq-zether.md
+++ b/docs/contracts/pq-zether.md
@@ -1166,7 +1166,7 @@ disks for that or prune ([NODE-OPS-15](../node/ops.md#NODE-OPS-15)).
 |---|---|---|
 | `PqzSafety` (library) | [CTR-PQZ-01](#CTR-PQZ-01) allowlist + self-test helper | |
 | `UAPqzVerifier` | UA `IUAKindVerifier` for `0x0142` | stateless; precompile address immutable |
-| `UAMldsaVerifier` | UA verifier for `mldsa44`/`mldsa65` on chain 7622 | stateless; used by the UA `UARegistry` |
+| `UAMldsaVerifier` | UA verifier for `mldsa44`/`mldsa65` (BUILT, P6a: EIP-8355 precompile by probe, else Solidity) | stateless; used by the UA `UARegistry` |
 | `ERC20MetaTx` (the one token base) | ERC20 + EIP712 + `IERC20MetaTx`, both structs, the address and UA paths, UA ledger | [CTR-MTX-07](metatx.md#CTR-MTX-07); `PqzToken --sizes` ≤ 24,576 B, else the `ua*` entry points move to a `fallback` decoder as MetaToken v3 |
 | `PqzToken` | shield, transfer, unshield, refresh, rollover, disclosure, meta-tx, `ITransferDisclosure`, `wrap`/`unwrap` | clone per token via `OpenFactory.createPqzToken` (flag-gated); immutable |
 | `PqzCt` (library) | `add`/`sub` on 64-bit lanes, `addTrivial(digits)` for the plain term, the `< q` check, `ctHash` | pure Solidity, no precompile |
@@ -1229,12 +1229,12 @@ split, never a silent acceptance (fail closed).
    gateway) with per-client rate limits and a concurrency cap on `eth_call`/`eth_estimateGas` (Nethermind's own JSON-RPC
    concurrency and gas-cap keys to be confirmed); public RPC is authenticated where the deployment allows it.
 
-<a id="self-test"></a>**Contract self-test.** Constructors of `UAPqzVerifier`, `UAMldsaVerifier` and
+<a id="self-test"></a>**Contract self-test.** The constructor of `UAPqzVerifier` and
 `PqzToken.initialize` call `OP_SELFTEST` and require the expected hash (a constant compiled into the contract; it folds
 in the precompile's own valid and invalid verify results). `UAPqzVerifier`'s constructor and `PqzToken.initialize`
 also take a valid `R_REG` vector (≈ 40 KB, too large to compile into code under EIP-170) as an argument, require
 `keccak256(vector) == SELFTEST_VECTOR_HASH`, require `OP_REGISTER` on it to return 1, then flip one proof bit in memory
-and require 0. `UAMldsaVerifier` checks `MLDSA65` on one valid and one invalid vector. Any mismatch ⇒ `SelfTestFailed`.
+and require 0. `UAMldsaVerifier` probes `MLDSA65` with one valid and one invalid vector and falls back to Solidity on a mismatch; the chain-7622 deploy requires the probe to pass. Any other mismatch ⇒ `SelfTestFailed`.
 This, not the allowlist alone, is what keeps PQZ off chains whose client is not ours.
 
 The chain profile, the private-chain runbook and the node's `pqz` profile flag
diff --git a/docs/research/pq-eips-vs-scaas.md b/docs/research/pq-eips-vs-scaas.md
index 279d92c..7801fdf 100644
--- a/docs/research/pq-eips-vs-scaas.md
+++ b/docs/research/pq-eips-vs-scaas.md
@@ -237,16 +237,40 @@ Kept open; none blocks the current contract phase (DEX, then Zether kinds) or th
   (and need a context-taking precompile, as chain 7622's `MLDSA65` is), or does a later kind version move the tag into
   the message with an empty context, so a standard precompile could serve it? Both are compatible with CTR-UA-23's
   "new verifier in a new generation" rule; nothing is built yet.
+- **Q1 finding (P6a, 2026-10-12): EIP-8051's μ.** The draft's pseudocode computes `μ = shake_256(tr + message)` over a
+  32-byte message with a 32-byte `tr` (key 20,512 B), i.e. `ML-DSA.Verify_internal` without the FIPS 204 prefix
+  `0x00 ‖ len(ctx) ‖ ctx`. Its own vectors disagree: all 100 records of `assets/eip-8051/mldsa_nist.rsp` (33-byte
+  messages, 2,560-byte secret keys, i.e. a 64-byte `tr`) verify as FIPS 204 **pure ML-DSA with the empty context** and
+  none verifies without the prefix (checked with `@noble/post-quantum` 0.7.1); the reference Solidity (ZKNox
+  `ETHDILITHIUM`, `ZKNOX_dilithium.sol`) also builds `M' = 0x00 ‖ 0x00 ‖ m` and reads a 64-byte `tr`, and stores
+  `NTT(t1·2^d)` where the text says `t1`. A precompile built from the text would reject every SCaaS (and every FIPS 204)
+  signature; SCaaS's probe (a valid and a flipped `pq_msg` vector, exact 32-byte answers) refuses such a precompile
+  rather than mis-verifying. P6a's expanded-key layout follows the reference implementation: `Â ‖ tr (64) ‖
+  NTT(t1·2^d)`, u32 big-endian, 20,544 B for ML-DSA-44. EIP-8355 has no such gap: empty context, FIPS 204 `M'`.
 - **Q2 EIP-8051 key format.** If 8051 (expanded 20 512-byte key, 32-byte message) rather than 8355 wins, the stored
   key per UA grows about tenfold and the message becomes a digest. Would SCaaS store the expanded key, or expand it per
   call?
+- **Q2 finding (P6a).** Measured pure-Solidity ML-DSA (`test/ua/PqGas.t.sol`): 11.4 M (ML-DSA-44) / 18.9 M (ML-DSA-65)
+  on the FIPS 204 key — `ExpandA` alone is ~80 / ~150 Keccak-f permutations at ~66 k gas each — and 4.1 M / 5.8 M on the
+  expanded key. Without a precompile, ML-DSA fits CTR-UA-23's ~50 % bound only if the registry stores the expanded key;
+  what that costs at registration (SSTORE2 of 20.5 / 36.9 KB, and proving the expansion on chain) is the P6c question.
 - **Q3 FN-DSA final.** FIPS 206 is still a draft (final expected late 2026 / early 2027 **[unverified]**). Does the
   final encoding match the frozen `fndsa512` vectors, and is EIP-8052's SHAKE256 hash-to-point exactly FN-DSA's? The
   Keccak-PRNG variant is not.
+- **Q3 finding (P6a).** No FIPS 206 draft is public yet (NIST slides 2025: "initial public draft soon"; an IETF LAMPS
+  draft of May 2026 still says "forthcoming"), so `fndsa512` is the NIST third-round Falcon-512 (v1.2) with EIP-8052's
+  SHAKE256 hash-to-point over a 32-byte message: verified against the NIST KATs published with EIP-8052 (pk and
+  compressed `s2` from `kat_FALCONCORE_512.rsp`, the salt from `kat_HASHTOPOINT_512.rsp`). EIP-8052's text has small
+  gaps: the precompile input splits the 666 bytes as salt 40 ‖ `s2` 626 while the padded format is header 1 ‖ salt 40 ‖
+  625; `FALCON_CORE` takes `h` in the NTT domain; it accepts `‖(s1, s2)‖² < ⌊β²⌋` where the reference code and noble
+  accept `≤`. Falcon keys from a seed are implementation-specific (noble's note), so SCaaS pins derivation to one
+  implementation by vectors.
 - **Q4 Hash-based kind.** **Decided (owner 2026-10-11):** kind `slhdsa128s` (0x0133, SLH-DSA-SHA2-128s), SPECIFIED (P6), public chains after a gas measurement ([CTR-UA-23](../contracts/accounts.md#CTR-UA-23)). Ethereum's base layer prefers hash-based (8288 leanSPHINCS, leanXMSS); SLH-DSA verifies in
   Solidity at ~0.6 M and SPHINCS- at ~0.1 M with no precompile, the only PQ family whose Solidity verifier comes near
   the 100 k / 400 k bounds of §4 (at the price of 4–8 KB signatures). Is an `slh-dsa` (or leanSPHINCS) UA kind worth reserving next to the lattice kinds? Stateful XMSS/WOTS keys
-  would need the leaf-state discipline of EIP-8310, which SCaaS clients do not have.
+  would need the leaf-state discipline of EIP-8310, which SCaaS clients do not have. *P6a:* SLH-DSA-SHA2-128s verifies in
+  Solidity on SHA-256 `0x02` for 0.79 M gas (valid) and at most 1.32 M (the worst case any input can force) — the gas
+  gate passes.
 - **Q5 Solidity cost basis.** Fireblocks' 1.23 M is **ML-DSA-44**, while `pq-zether.md` §3 and the CTR-UA-23
   estimates attribute it to ML-DSA-65; the ML-DSA-65 worst case is likely higher **[inference]**. The per-chain
   T-GAS measurement settles it before any cap is set.
``````

### Final

- [ ] **Whole branch.** From the worktree root after Task 5: `forge build` and `forge test` (911 passed, 10 skipped),
  size gate 0 errors, `FOUNDRY_PROFILE=private7622 forge build`, `npm test` in clientkeys (74 / 72 / 2), both vector
  hashes unchanged, `docs_check.py check` 0 errors, `facts check` 0 misses.
- [ ] **Review** against the Review Focus above; then merge to `main` (owner). Next: P6c (owner decisions in the
  roadmap §3) and P6b beside it.
