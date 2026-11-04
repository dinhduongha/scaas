> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# ML-DSA-87 on the EVM: verification gas, measured (2026-11-04)

The measurement behind [spec 2026-11-04-mldsa87](../superpowers/specs/2026-11-04-mldsa87.md) (owner 2026-11-04: add ML-DSA-87,
FIPS 204 NIST level V, as a UA kind; spec and measurement first). All figures are `UNAUDITED` research code, forge, not a chain.

## Method

- **Code.** `smartcontracts/evm/runs/2026-11-04-mldsa87-probe/MlDsa87.sol` is a copy of the built `MlDsa` library
  (`src/ua/MlDsa.sol`, main `4c72332d`) with two changes: `params87()` (k 8, l 7, η 2, τ 60, β 120, γ1 2^19,
  γ2 (q − 1)/32, ω 75, c̃ 64 B, pk 2,592 B, sig 4,627 B) and a 64-byte c̃ in `_sameCt` (the built code compares 32 or 48 B).
  Everything else is the built verifier: same NTT, SHAKE, ExpandA, hint, `z` and UseHint code. `Mldsa87Probe` mirrors
  `UAMldsaVerifier`'s pure-Solidity entries (`verify` over `pq_msg`, `verifyExpanded`, `expandedKeyPart`, `verifyCached`).
- **Vectors.** NIST ACVP ML-DSA sigVer (FIPS 204), `usnistgov/ACVP-Server` commit `975de31e`,
  `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`, SHA-256 `47cdd6314c7f…fba55437` — the same pinned file
  `clients/clientkeys/scripts/pq-external.mjs` imports for ML-DSA-44/65. The ML-DSA-87 groups kept are those the importer keeps:
  tgId 5 (pure, external interface, contexts 0–255 B) and tgId 12 (internal interface, no external μ): 30 cases, 6 valid,
  24 invalid (modified message, commitment, hint, `z`). preHash and external-μ groups are outside the kind (CTR-UA-23: pure
  signing). `extract.py` (run with `python3 -I`, SHA-256 checked before parsing) writes `acvp87.json`; `noble87.mjs` re-checks
  all 30 with `@noble/post-quantum` 0.7.1 (agrees) and makes one UA-shaped row `ua87.json`: a key from the SEP-0005 test
  mnemonic by `clientkeys`' PQ derivation under the proposed tag `scaas.ua.mldsa87.v1`, a deterministic signature over
  `pq_msg`, empty context, and three mutations.
- **Gas.** `Mldsa87Probe.t.sol` with the probe's own `foundry.toml` (extends the project's, adds read access to the probe
  directory): Foundry 1.8.5, solc 0.8.37, Amsterdam, `isolate = true`. Verify gas is the `staticcall`'s gas, as
  `test/ua/PqGas.t.sol` measures ML-DSA-44/65. The expanded-key cache runs through a harness with the registry's
  `cacheExpandedKey` body (id, stored-part check, `expandedKeyPart`, SSTORE2, pointer slot, event), one isolated transaction
  per part; at ML-DSA-65 it reads 10,115 / 10,265 regular gas below the registry's own `cacheExpandedKey` and the same state
  gas (calibration, `UARegistryPq.t.sol` `test_vectors_pq`). State gas is EIP-8037's as Foundry computes it at
  `foundry.toml`'s settings, the basis of accounts.md's registration table.

Reproduce: `cd smartcontracts/evm && FOUNDRY_SPARSE_MODE=true FOUNDRY_CONFIG=runs/2026-11-04-mldsa87-probe/foundry.toml
scripts/capped forge test -vv` (the `capped` path from the repo root). Evidence lines: `runs/2026-11-04-mldsa87-probe/summary.txt`.

## Results

Every ACVP case gives ACVP's verdict on both key forms; the UA row verifies on both, its three mutations are refused.

| Path (valid UA row, M' = 34 B) | ML-DSA-44 | ML-DSA-65 | **ML-DSA-87** |
|---|---|---|---|
| verify on the FIPS 204 key | 11,380,337 | 18,897,368 | **31,914,727** |
| verify on the expanded key (calldata) | 4,093,867 | 5,771,287 | **8,651,358** |
| `verifyCached` (SSTORE2 parts) | 4,119,323 | 5,815,139 | **8,643,140** |
| least working gas of `verifyCached`, cold pointers (± 1,000) | 4,180,577 | 5,902,586 | **8,763,152** |
| deployed cap without a precompile | 4,250,000 | 5,950,000 | — (≈ 8.8 M would be its cap) |

The 44 / 65 rows are re-measured in the same run (`PqGas.t.sol`); they match accounts.md CTR-UA-23 within 0.3 %.

**The message length matters.** μ = SHAKE256(tr ‖ M') costs about one Keccak permutation (~70 k gas in Solidity) per 136 B.
ACVP's valid messages are 2.8–7.3 KB, so their gas is higher than the UA row's: raw 33.3–35.7 M, expanded 9.97–12.38 M. The
UA kind always verifies a 34-byte M' (`0x00 ‖ 0x00 ‖ pq_msg`); the shortest ACVP message (1 B, tc 171, invalid at the last
check) costs 8,552,938 on the expanded key, 1.1 % below the UA row (SampleInBall and hint positions vary). Inputs refused at
decoding (a malformed hint, `z` out of range) cost 27–39 k.

**Expanded key.** `(k·l + k) · 1,024 + 64` = **65,600 B** (`Â` 57,344 ‖ `tr` 64 ‖ `NTT(t1·2^d)` 8,192), the layout of the
built cache (EIP-8051 itself covers ML-DSA-44 only, with a 32-byte `tr`). It does not fit one SSTORE2 blob (65,534 B at most,
`SSTORE2.write`), so it needs at least two parts; the probe keeps the built cache's EIP-170-sized parts, three of them:

| Part | Bytes | `expandedKeyPart` | `cacheExpandedKey` regular (registry, est. +10 k) | state gas (EIP-8037) |
|---|---|---|---|---|
| 0: `Â` rows 0–2 | 21,504 | 8,920,697 | 9,032,348 (≈ 9.04 M) | 33,184,170 |
| 1: `Â` rows 3–5 | 21,504 | 8,993,893 | 9,032,215 (≈ 9.04 M) | 33,184,170 |
| 2: rows 6–7 ‖ `tr` ‖ `t̂1` | 22,592 | 9,490,313 | 9,511,464 (≈ 9.52 M) | 34,848,810 |
| **Total** | 65,600 | | **27.6 M** | **101.2 M** |

(ML-DSA-65 for comparison: two parts, 6.48 M + 9.07 M regular, 23.8 M + 33.3 M state.) A part costs about 2.97 M regular gas per
row of `Â` (7 ExpandA polynomials) and the tail (`tr` and eight `t̂1` NTTs) about 3.5 M; two parts under the 64 KiB code
limit (rows 0–3, 28,672 B; rows 4–7 ‖ tail, 36,928 B) would cost ≈ 12.0 M and ≈ 15.5 M regular (estimate), under 2^24
with 1.3 M to spare on the second.

## What it means against the budget

- `UA_VERIFY_BUDGET` 12,000,000 (EIP-7825 chains) / 10,500,000 (Hedera). CTR-UA-23 enables a PQ kind on a chain only if its
  measured cap is **≤ 66 %** of the budget: 7,920,000 / 6,930,000.
- **FIPS 204 key:** 31.9 M — over the budget and over the 2^24 (16,777,216) per-transaction cap by itself. Never usable.
- **Expanded key:** least working 8,763,152, so a cap ≈ 8.8 M: **fits the budget** (73 % of 12 M, 84 % of 10.5 M) and a 2^24
  transaction (a registration's regular gas ≈ 8.8 M + the record's ≈ 0.2–0.4 M, estimate from the ML-DSA-44 row: 4,341,407 −
  4,117,867), **but exceeds the 66 % bound on both** (by 0.84 M / 1.83 M). By the rule as stated, pure-Solidity ML-DSA-87 is
  **disabled** wherever no ML-DSA-87 precompile exists. The cache's own transactions fit 2^24 by regular gas (9.0–9.5 M each);
  their 101 M state gas has to fit the block, not 2^24.
- **Precompile:** EIP-8355 prices ML-DSA-87 at 13,500 + 6 per message word (Draft). Through a `UAMldsaVerifier`-style wrapper
  the 65 path measured ≈ 236 k (`estimateGas`, with the transaction) on the SCaaS testnet's 68,000-gas precompile; an 87 path
  is the same shape with 1,958 more bytes, so a cap in the 0.2–0.3 M class (estimate; measured when built).

## Not measured here

Timing of the native verify (no calibration run: the owner's rule), the precompile path itself (no `0x…5caa0014` exists yet),
a worst case over adversarial inputs (T-GAS at build), the registry's own `register` and `requireAuthorized` at 0x0134 (not
built), and any family other than EVM.
