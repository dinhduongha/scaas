# T2 — Codex re-run of the on-chain review (plan Task 5f), after the 5g fixes

**Date:** 2026-10-20. **Reviewer:** Codex CLI 0.163.0 (one read-only task, thread `01a15606-7c6b-74e3-8083-142cc34c7960`;
owner-requested re-run of [T](T-codex-chain-aborted.md), which had stopped out of credits). **Target:** frozen worktree at
`fe2faf0` (the 5g fixes W-A…W-S merged): the Nethermind PQZ plugin and all EVM Solidity, brief
`scratchpad/code-review-2026-10-19b/brief-chain.md`. Codex's final report follows verbatim (progress lines removed), then
the controller's triage.

---

### CHAIN-01 — P2 — Zero ciphertext credits bypass the retained-base rollover fix

**Locations:** `smartcontracts/evm/src/pqz/PqzLib.sol:773`, `:776`, `:785`, `:580`; accepted relation at `docs/contracts/pq-zero-knowledge.md:789` and `pqz-core/pqzh/ligero/src/cs.rs:506`.

**Trigger:**

1. A funded victim prepares a debit with `acc = base`, `p = rolled = 0`, and empty inline credits.
2. A registered attacker makes zero-value transfers to the victim using `r = e1 = e2 = 0`. The resulting recipient ciphertext is entirely zero. These values satisfy the relation’s upper norm bounds; no positive-value or nonzero-randomness condition excludes them.
3. Anyone rolls those credits into the victim’s accumulator. Its bytes and hash stay unchanged, while `rolled` advances.
4. `_total` recognizes the hash as the **current** accumulator and never tries the retained base. One rolled zero credit makes the original empty inline array fail `InlineMismatch`. Seventeen credits, rolled in two calls, make the original `p` fail `InlineTooFar` even with replacement inline calldata.

**Impact:** An attacker can invalidate base-based debits that W-E intended to protect. Seventeen zero credits can force a different statement `p`, requiring another proof and authorization. The attack transfers no value to the victim and is particularly practical on the zero-gas-price test chain. No theft or accounting corruption identified.

**Confirmed or hypothesis:** Confirmed by source and the accepted relation; no proof or transaction was executed.

**Suggested fix:** When current and base hashes coincide, resolve the basis using the supplied `p` and inline credits instead of unconditionally selecting current state. Preserve both valid interpretations. Add regression cases for one and seventeen zero credits. Changes deployed token/library bytecode; no chainspec, gas-row or proof-format change is required.

### CHAIN-02 — P3 — First-activation tooling accepts historical activation times

**Locations:** `pqz-core/nethermind/chain/patch-chainspec.py:31`, `:43`; `pqz-core/nethermind/Nethermind.Pqz/PqzChainSpecEngineParameters.cs:47`. Compare `pqz-core/nethermind/chain/add-schedule.py:38`.

**Trigger:** For an existing chain without PQZ, supply a timestamp after genesis but before its current head, without `--testnet-reset`. The patcher writes it successfully; plugin validation rejects only timestamps **before genesis**.

For example, a historical transaction after that timestamp that called the previously empty PQZ address with limited gas can execute differently when replayed with the patched chainspec.

**Impact:** An operator error can retroactively change execution rules, causing replay failures or divergence during rollout. This is a latent tooling weakness, not evidence of a split in the reviewed chain.

**Confirmed or hypothesis:** Historical timestamps are accepted by source inspection. Divergence depends on deployment and affected transactions in that history.

**Suggested fix:** Apply the existing future-time guard to ordinary first activation; require the explicit reset path for genesis activation. This changes tooling only and prevents creation of an unsafe chainspec. No deployed bytecode, proof-vector or gas-row change.

### CHAIN-03 — P3 — Large-value fee calculations still overflow after W-S

**Locations:** `smartcontracts/evm/src/trade/TradeLib.sol:126`; `smartcontracts/evm/src/dex/SCaaSDex.sol:426`; `smartcontracts/evm/src/common/FeePolicy.sol:42`, `:45`.

**Trigger:** A valid full-fill order with `receiveFill = 2^250` and `fee = 10_000` passes the repaired 512-bit price comparison, but overflows `receiveFill * fee` in the fee-bound check. The mathematical fee fits in `uint256`.

Separately, `FeePolicy.compute(FIXED, 2^250, 0)` overflows while calculating its cap, and sufficiently large DEX fees overflow the relayer-share multiplication.

**Impact:** Otherwise valid high-supply token payments and orders revert. Reach is limited to extreme raw amounts; affected calls revert atomically.

**Confirmed or hypothesis:** Confirmed arithmetic paths; not executed.

**Suggested fix:** Use the existing `Math.mulDiv`, preserving each calculation’s floor or ceiling rounding. Changes linked library/contract bytecode; no chainspec, proof-vector or gas-row change.

### W-A–W-S verification

“Fixed” below means verified in source, not tested during this review.

| Item | Result |
|---|---|
| W-A | Fixed: direct storage-mode binding in `pqz/PqzLib.sol:217`, `:226`. |
| W-B | PQZ fixed: `pqz/PqzLib.sol:167`, `pqz/PqzSafety.sol:50`, `pqz/UAPqzVerifier.sol:39`. Zether remains creator-selected, explicitly retained at `docs/contracts/zether.md:1075`; the proposed twin fix did not land. |
| W-C | Documentation mitigation at `docs/contracts/accounts.md:1092`; wallet enforcement was not checked. |
| W-D | Regression test added at `Nethermind.Pqz.Test/SpecTests.cs:90`; assignment remains unchanged at `PqzChainSpecEngineParameters.cs:78`. The test documents why Nethermind supplies the genesis timestamp. Not rerun. |
| W-E | Partial: retained base implemented, but CHAIN-01 defeats it when hashes coincide. |
| W-F | Fixed: missing-row and duplicate checks at `chain/add-schedule.py:55`, `:59`. |
| W-G | Fixed in source: startup hash comparison at `SelfTest.cs:32`, build comparison at `build-image.sh:28`, clang pins at `Dockerfile:16`. |
| W-H | Recorded operational restriction at `chain/RUNBOOK.md:283`; process-exit behavior remains. |
| W-I | Runtime payload bounds and bn254 return-size checks repaired: `pqz/PqzLib.sol:270`, `:383`; `zether/ZetherCurves.sol:92`. Disclosure behavior is documented at `pqz/PqzLayer.sol:101`. The single-statement **view** still underflows on very short payloads at `pqz/PqzLib.sol:695`. |
| W-J | Recorded residual risk at `docs/contracts/accounts.md:1400`; raw-digest verification remains. |
| W-K | Recorded for both wallets at `docs/contracts/accounts.md:1727`; no account wrapping added. |
| W-L | Fixed: aligned period advancement at `wallet/MandateWallet.sol:126`. |
| W-M | Alternative fix: predecessor starvation is recognized and propagated at `ua/UARegistry.sol:674`. |
| W-N | Interface fixed at `ua/IUARegistry.sol:42`; dependency commit/checksum pins added at `scripts/evm_libs.sh:14`. |
| W-O | Alternative fix: token revert data is suppressed at `dex/SCaaSDex.sol:593`, `:610` and `dex/DexPuller.sol:25`. |
| W-P | Retained cancellation semantics at `metatx/ERC20MetaTx.sol:87`, `:339`; delayed cancellation can still advance a later nonce. |
| W-Q | Guards and wrap events repaired. Sweep behavior, same-token cycles and classification at market configuration remain documented choices: `docs/contracts/dex.md:497`, `dex/SCaaSDex.sol:156`, `:493`. |
| W-R | Fixed as proposed: `CryptographicException` becomes the zero word at `MlDsaPrecompile.cs:30`. |
| W-S | Price products fixed at `trade/TradeLib.sol:125`, `:138`. Dust rounding and chain allowlists remain deliberate. Fee arithmetic has CHAIN-03. |

Solidity paths in this table are under `smartcontracts/evm/src/`; plugin paths are under `pqz-core/nethermind/`.

### Checked and clean

These are source-review conclusions, subject to the findings and retained risks above.

- **Plugin:** schedule lookup, row discrimination—including op-7 legs/auditor shape—input limits, pinned P/Invoke spans, exact library loading, startup refusal and node-fault exit. References: `pqz-core/nethermind/Nethermind.Pqz/PqzChainSpecEngineParameters.cs:141`, `PqzPrecompile.cs:46`, `Native.cs:22`, `PqzPlugin.cs:42`.
- **ML-DSA:** fixed key/signature split, pure-message verification, output encoding and linear message gas calculation: `pqz-core/nethermind/Nethermind.Pqz/MlDsaPrecompile.cs:19`.
- **Image and fault hooks:** digest-pinned base images, default Rust verifier build, committed native-library pin and separate fault-hook crate: `pqz-core/nethermind/Dockerfile:8`, `:33`; `fault-hooks/Cargo.toml:13`.
- **`pqz/`:** statement fields derive from contract state/configuration; key pointers, counter, recipients, fees and envelope binding enter the statement. Pending hashes are checked, debits update before payout, and precompile results require exactly the word one. References: `PqzLib.sol:412`, `:805`, `:828`, `:889`; `UnderlyingPqzToken.sol:60`.
- **`zether/`:** statement/state correspondence, transfer-mode tags, counter checks, range-proof linkage, subgroup-checking MSM paths and precompile return lengths. References: `ZetherLib.sol:435`, `:535`, `:562`; `ZetherVerifier.sol:109`, `:365`; `ZetherCurves.sol:214`.
- **`ua/`:** immutable records, registration PoP/authRef consent, stored-key authorization, distinct multisig indexes, generation routing and authenticated expanded-key cache construction. References: `UARegistry.sol:331`, `:510`, `:581`; `UAKinds.sol:431`; `MlDsa.sol:491`.
- **`account/`, `wallet/`:** atomic factory initialization, guardian delay, last-key protection, owner/delegate separation, mandate epochs and spending limits: `SmartKeyAccount.sol:88`, `:173`, `:254`; `SmartKeyAccountFactory.sol:35`; `MandateWallet.sol:115`.
- **`metatx/`, `common/`:** salted domains, shared nonce lanes, allowlisted self-call tickets, bounded signature calls, UA-pool accounting and receiver-fee authorization: `MetaTxBase.sol:161`, `:213`; `ERC20MetaTx.sol:278`, `:469`; `MetaTokenBase.sol:337`; `SigCheck.sol:57`.
- **Wrapper value paths:** measured inbound receipts, tracked reserves, exact sender-side payout deltas and shielded collateral included in rate execution: `metatx/UnderlyingLib.sol:155`, `:261`, `:373`; `pqz/UnderlyingPqzToken.sol:99`.
- **`factory/`:** creator-scoped CREATE2 salts, atomic initialization, registrar-only catalogue changes and separation of unregistered provenance: `OpenFactory.sol:54`, `:194`, `:236`, `:240`.
- **`dex/`, `trade/`:** order domains, cancellation/fill accounting, puller isolation, settlement atomicity, bounded failure reasons, exchange floors and conservation: `SCaaSDex.sol:223`, `:270`, `:393`, `:493`, `:549`; `TradeLib.sol:83`.
- **`hedera/`:** bounded HIP-632 calls and fail-closed HTS queries/association: `HederaAccountAuth.sol:22`; `HederaLib.sol:33`.

### Not checked

No edits, builds, tests, deployments, containers or chain calls were performed. Findings were not dynamically reproduced. Native proof-core internals, vendored libraries, deployed binaries/configuration and client-side mitigations were excluded; cryptographic constants and unrolled hash rounds were not independently rederived.

The tree remained clean. This source review does not establish production readiness.

---

## Triage (controller)

No new P0 / P1. CHAIN-01's location verified (`PqzLib.sol` `_total`, the W-E base branch).

| # | Finding | Verdict | Disposition |
|---|---|---|---|
| CHAIN-01 | Zero-value transfers with `r = e1 = e2 = 0` give an all-zero recipient ciphertext that passes the relation's norm bounds; rolling such credits leaves `acc`'s hash unchanged while `rolled` advances, so `_total` takes the current branch and a base-based debit (W-E) can be forced to re-prove (17 credits) | P2, confirmed in source; no value moves | Obsoleted by plan Task 5h (W-E's base removed, `ROLL_AGE` instead); **carry-over to 5h:** refuse an operation whose shared `u` is all zero (the spec already claims "no rollover carries an all-zero `u`", pq-zero-knowledge.md §7.6 — false today), or require `r ≠ 0` in the relation at the parameter step |
| CHAIN-02 | `patch-chainspec.py` accepts a first activation after genesis but in the past (only pre-genesis is refused); `add-schedule.py` already has the future-time guard | P3 tooling | **Fixed** in `88c8083` (branch `rev2-small-fixes`): `patch-chainspec.py` refuses a first timestamp less than 5 minutes ahead; at genesis only with `--testnet-reset`, which takes exactly the genesis timestamp; self-check `--check`; plugin unchanged |
| CHAIN-03 | Fee products still overflow for raw amounts near 2^256 after W-S (`TradeLib.sol:126`, `SCaaSDex.sol:426`, `FeePolicy.sol:42/45`) | P3 | **Fixed** in `4fae6ab` (branch `rev2-small-fixes`): `Math.mulDiv` in the four places, same rounding; tests at 2^250 (`smartcontracts/evm/runs/2026-10-20-small-fixes.txt`); every token +201–221 B (size baseline ratcheted) |
