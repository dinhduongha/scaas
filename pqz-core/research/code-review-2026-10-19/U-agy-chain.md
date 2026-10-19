# U — agy review of the on-chain code (Nethermind PQZ plugin + all EVM Solidity) and triage of T + U + V1–V3

**Date:** 2026-10-19. **Reviewer:** agy 1.4.2 (`--mode plan`, no `--dangerously-skip-permissions`; conversation
`bc92f121-0fe8-4d8b-bac5-78b6d51b3dd4`; one pass; worktree unmodified). Frozen tree `.claude/worktrees/rev3` at
`7aab1fe`; brief `scratchpad/code-review-2026-10-19b/brief-chain.md` (plan Task 5f). Codex ([T](T-codex-chain-aborted.md))
stopped out of credits after one lead; Claude in three parts: [V1](V1-claude-plugin-pqz-zether.md) (plugin, `pqz/`,
`zether/`), [V2](V2-claude-ua-account-wallet.md) (`ua/`, `account/`, `wallet/`), [V3](V3-claude-common-metatx-dex.md)
(`common/`, `metatx/`, `factory/`, `dex/`, `trade/`, `hedera/`). agy's report follows verbatim, then the triage.

---

# On-Chain Code Security Review Report

**Target Scope**:
- Nethermind PQZ Plugin & Tooling (`pqz-core/nethermind/Nethermind.Pqz/`, `chain/`, `Dockerfile`, `build-image.sh`, `fault-hooks/`)
- All EVM Solidity under [smartcontracts/evm/src/](../../../smartcontracts/evm/src) (excluding `legacy/`, `test/`, `lib/`)

---

## 1. Executive Summary & Findings

### Findings Summary
| ID | Severity | Title | Impact Area |
|---|---|---|---|
| **NETH-01** | **P2** | Selftest Input Prefix (`0x06`) Bypasses Allowlist Filter & Calldata Gas Term | Nethermind Plugin Gas / DoS |
| **NETH-02** | **P2** | `ApplyToReleaseSpec` Clears Active Schedule on Block-Number Fork Transitions | Consensus Split / Precompile Deregistration |
| **NETH-03** | **P2** | Unhandled `CryptographicException` in ML-DSA Verification Reverts Call Instead of Returning Failure Word | EIP-8355 / Nethermind Precompile Contract Violation |
| **SOL-01** | **P3** | Rounding Asymmetry in `UnderlyingPqzToken.pqzUnwrap` Traps Residue Value | Solvency / Collateral Leak |
| **SOL-02** | **P3** | Multiplicative Overflow in Limit Price Calculation (`TradeLib.sol` / `SCaaSDex.sol`) | Order Settlement DoS |
| **SOL-03** | **P3** | Hardcoded Chain IDs in `PqzSafety.sol` and `ZetherSafety.sol` Fail Closed on Production Deployments | Deployment / Configuration Gate |

---

### NETH-01 — P2 — Selftest Input Prefix (`0x06`) Bypasses Allowlist Filter & Calldata Gas Term

- **Locations**:
  - [pqz-core/nethermind/Nethermind.Pqz/PqzPrecompile.cs:39](../../../pqz-core/nethermind/Nethermind.Pqz/PqzPrecompile.cs#L39)
  - [pqz-core/nethermind/Nethermind.Pqz/PqzPrecompile.cs:50-51](../../../pqz-core/nethermind/Nethermind.Pqz/PqzPrecompile.cs#L50-L51)
- **Trigger**:
  An attacker issues a `STATICCALL` to precompile `0x03a0` passing a payload up to 393,216 bytes whose first byte is `0x06` (`input[0] == 6`), followed by arbitrary bytes not matching the 5-byte canonical self-test payload `SelfTest.Input` (`[0x06, 0x00, 0x00, 0x00, 0x00]`).
- **Impact**:
  1. **Calldata Gas Avoidance**: In [PqzPrecompile.cs:39](../../../pqz-core/nethermind/Nethermind.Pqz/PqzPrecompile.cs#L39), `selftest` evaluates to `true`. Gas computation executes `return s.SelftestGas;` directly, omitting the mandatory linear word-expansion charge `3 * ((input.Length + 31) / 32)`. For a max-size 393,216-byte payload, the transaction underpays by ~36,864 gas.
  2. **Allowlist Bypass & DoS**: In [PqzPrecompile.cs:50-51](../../../pqz-core/nethermind/Nethermind.Pqz/PqzPrecompile.cs#L50-L51), `if (!selftest && s.RowGas(input) is null)` is skipped. The request bypasses the C# allowlist miss fast-path (which returns 32 zero bytes in 0 CPU cycles) and dispatches directly into unmanaged code via `Native.Verify(input, output)`. Unmanaged memory copying, deserialization, and assertion checking in Rust run at the flat, unscaled cost of `s.SelftestGas`.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**:
  Require exact match against canonical self-test input (`input.Length == 5 && input.SequenceEqual(SelfTest.Input)` or `input.Span.SequenceEqual(SelfTest.Input)`) in both `Gas()` and `Run()`:
  ```csharp
  bool selftest = input.Length == SelfTest.Input.Length && input.Span.SequenceEqual(SelfTest.Input);
  ```
  - *Impact*: Zero changes to chainspec/proofs; eliminates gas undercharging and CPU DoS vector.

---

### NETH-02 — P2 — `ApplyToReleaseSpec` Clears Active Schedule on Block-Number Fork Transitions

- **Locations**:
  - [pqz-core/nethermind/Nethermind.Pqz/PqzChainSpecEngineParameters.cs:56-63](../../../pqz-core/nethermind/Nethermind.Pqz/PqzChainSpecEngineParameters.cs#L56-L63)
  - [pqz-core/nethermind/Nethermind.Pqz/PqzChainSpecEngineParameters.cs:78](../../../pqz-core/nethermind/Nethermind.Pqz/PqzChainSpecEngineParameters.cs#L78)
- **Trigger**:
  A chainspec transition rule triggers on block number rather than timestamp (e.g. `maxCodeSizeTransition: 6432`, `eip150Transition: 0`, `byzantiumTransition: 0`), invoking `ApplyToReleaseSpec(ReleaseSpec spec, long startBlock, ulong? startTimestamp)` where `startTimestamp` is `null`.
- **Impact**:
  When `startTimestamp` is `null`, `ScheduleAt(null)` returns `null` ([PqzChainSpecEngineParameters.cs:78](../../../pqz-core/nethermind/Nethermind.Pqz/PqzChainSpecEngineParameters.cs#L78)). This sets `pqz.ActiveSchedule = null;` on the active `PqzReleaseSpec`. Nethermind's `PqzPrecompileProvider` inspects `spec.ActiveSchedule != null`:
  ```csharp
  if (_spec.ActiveSchedule is null) return false;
  ```
  Consequently, all PQZ and ML-DSA precompiles are deregistred from the precompile address set for any block operating under that release spec. Any contract calling `0x03a0` or `0x03a2` falls through to an empty account balance transfer (returning empty success without execution), causing state divergence and consensus partition between nodes depending on release spec transition caching.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**:
  When `startTimestamp` is `null`, retain the active schedule from the initial genesis timestamp (or previous active schedule) instead of resetting to `null`:
  ```csharp
  ulong effectiveTimestamp = startTimestamp ?? 0;
  pqz.ActiveSchedule = ScheduleAt(effectiveTimestamp);
  ```
  Or preserve `pqz.ActiveSchedule` if `startTimestamp is null`.
  - *Impact*: Affects node release spec cache; preserves consensus stability across block-number fork boundaries.

---

### NETH-03 — P2 — Unhandled `CryptographicException` in ML-DSA Verification Reverts Call Instead of Returning Failure Word

- **Locations**:
  - [pqz-core/nethermind/Nethermind.Pqz/MlDsaPrecompile.cs:24-26](../../../pqz-core/nethermind/Nethermind.Pqz/MlDsaPrecompile.cs#L24-L26)
- **Trigger**:
  A contract calls precompile `0x03a2` (ML-DSA verification) supplying an input of correct length (1,344 bytes) or malformed encoding where `MLDsa.ImportMLDsaPublicKey` or `key.VerifyData` throws a `System.Security.Cryptography.CryptographicException` or `ArgumentException` due to invalid ASN.1/DER/raw key structure internally inside .NET or OpenSSL.
- **Impact**:
  Because there is no `try / catch` around `MLDsa.ImportMLDsaPublicKey(pubkey, out _)` and `key.VerifyData(data, sig, ...)` in [MlDsaPrecompile.cs:24-26](../../../pqz-core/nethermind/Nethermind.Pqz/MlDsaPrecompile.cs#L24-L26), the unhandled exception propagates up to Nethermind's `PrecompileHost.Execute()`. Nethermind treats unhandled exceptions as an internal VM failure, consuming all available call gas and reverting the calling transaction.
  Under EIP-8355 / CTR-PQZ-10 precompile specifications, cryptographic verification failures (such as malformed public keys or invalid signatures) MUST be treated as non-reverting evaluations returning 32 bytes of zeros `[0x00...00]`.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**:
  Wrap the import and verification block in `MlDsaPrecompile.cs` in a `try ... catch` block:
  ```csharp
  try
  {
      using var key = MLDsa.ImportMLDsaPublicKey(pubkey, out _);
      if (key.VerifyData(data, sig, HashAlgorithmName.SHA512))
      {
          output[31] = 1;
      }
  }
  catch (Exception ex) when (ex is CryptographicException or ArgumentException)
  {
      // Malformed public key or signature fails verification smoothly
      output.Span.Clear();
  }
  return output;
  ```
  - *Impact*: Aligns precompile behavior with EVM standards; prevents gas-exhaustion griefing of smart accounts or meta-tx verifiers verifying untrusted signatures.

---

### SOL-01 — P3 — Rounding Asymmetry in `UnderlyingPqzToken.pqzUnwrap` Traps Residue Value

- **Locations**:
  - [smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol:62-69](../../../smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol#L62-L69)
  - [smartcontracts/evm/src/pqz/PqzLib.sol:188](../../../smartcontracts/evm/src/pqz/PqzLib.sol#L188)
- **Trigger**:
  In an `UnderlyingPqzToken` with exchange rate `_rateNum != _rateDen`, a user invokes `pqzUnshieldUnwrap` or `pqzUnwrap` where `x.amount * shieldScale` is not an exact integer multiple of `_rateNum`.
- **Impact**:
  In [UnderlyingPqzToken.sol:63](../../../smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol#L63):
  ```solidity
  (uint256 out, uint256 burned) = quoteUnwrap(x.amount * shieldScale);
  _payUnwrap(x.to, out);
  ```
  `quoteUnwrap` computes `out = floor(wrapped * den / num)` and `burned = ceil(out * num / den)`. However, `PqzLib.unshield` burns the full `x.amount * shieldScale` from the caller's confidential balance. The difference `(x.amount * shieldScale) - burned` is destroyed from the confidential supply, while `_payUnwrap` only transfers `out` underlying tokens. The residual underlying collateral remains locked inside `UnderlyingPqzToken` forever with no recovery mechanism.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**:
  Enforce exact division (reverting if unscale leaves a non-zero remainder), or require `x.amount * shieldScale == burned`:
  ```solidity
  (uint256 out, uint256 burned) = quoteUnwrap(x.amount * shieldScale);
  if (burned != x.amount * shieldScale) revert AmountNotScaled();
  _payUnwrap(x.to, out);
  ```

---

### SOL-02 — P3 — Multiplicative Overflow in Limit Price Calculation (`TradeLib.sol` / `SCaaSDex.sol`)

- **Locations**:
  - [smartcontracts/evm/src/trade/TradeLib.sol:124](../../../smartcontracts/evm/src/trade/TradeLib.sol#L124)
  - [smartcontracts/evm/src/dex/SCaaSDex.sol:386](../../../smartcontracts/evm/src/dex/SCaaSDex.sol#L386)
- **Trigger**:
  Settling a trade order where `move * o.receiveAmount` exceeds $2^{256} - 1$ (e.g. trading tokens with 18 decimals and order sizes above $\approx 10^{20}$ base units, where both order quantity and price amounts are $\approx 10^{38}$).
- **Impact**:
  The expression `move * o.receiveAmount > f.receiveFill * o.amount` in Solidity 0.8.24 executes in checked arithmetic. When the product overflows, the transaction reverts with a Panic(0x11) error, blocking valid order execution and fill matching on large trade sizes instead of computing the ratio cleanly.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**:
  Use full-precision 512-bit arithmetic (e.g. OpenZeppelin `Math.mulDiv` or inline assembly `mulmod`) to compare cross-products:
  ```solidity
  // Check move / f.receiveFill > o.amount / o.receiveAmount without overflow
  if (Math.mulDiv(move, o.receiveAmount, o.amount) > f.receiveFill) revert LimitPriceViolated();
  ```

---

### SOL-03 — P3 — Hardcoded Chain IDs in `PqzSafety.sol` and `ZetherSafety.sol` Fail Closed on Production Deployments

- **Locations**:
  - [smartcontracts/evm/src/pqz/PqzSafety.sol:19-21](../../../smartcontracts/evm/src/pqz/PqzSafety.sol#L19-L21)
  - [smartcontracts/evm/src/zether/ZetherSafety.sol:14-16](../../../smartcontracts/evm/src/zether/ZetherSafety.sol#L14-L16)
- **Trigger**:
  Deploying or migrating contracts to the designated production network (e.g. chain ID `22776` mentioned in the project specification).
- **Impact**:
  `PqzSafety.isAllowedChain()` permits only `31337`, `1337`, and `7622`. `ZetherSafety.isAllowedChain()` permits only `31337` and `1337` (explicitly blocking `7622`). On any unlisted chain ID, all state-changing entrypoints (`transfer`, `shield`, `unshield`, `unwrap`) immediately revert with `PqzSafety.SafetyBlocked()` or `ZetherSafety.ZetherDisabledOnChain()`.
- **Confirmed or hypothesis**: Confirmed.
- **Suggested fix**:
  Add production chain ID `22776` to the whitelist in `PqzSafety.isAllowedChain()` (and configure whether Zether is permitted on 22776).

---

## 2. Review Dimensions Verification

### Dimension 1: Nethermind Plugin Lifecycle & Initialization Determinism
- **Addresses & Precompile Registration**:
  [Addresses.cs:7-8](../../../pqz-core/nethermind/Nethermind.Pqz/Addresses.cs#L7-L8) correctly defines `0x03a0` (PQZ) and `0x03a2` (ML-DSA).
  [PqzPrecompileProvider.cs:20-30](../../../pqz-core/nethermind/Nethermind.Pqz/PqzPrecompileProvider.cs#L20-L30) registers precompiles into Nethermind's precompile table based on `ActiveSchedule != null`.
- **Determinism across nodes**: Schedules are keyed by UTC timestamp from block headers (`ulong? startTimestamp`), which is part of consensus.
  *(See Finding NETH-02 regarding `startTimestamp == null` during block-number transitions).*

### Dimension 2: Precompile Gas Charging Determinism
- **Allowlist Model**:
  Allowlisted rows are defined in [PqzChainSpecEngineParameters.cs:29-45](../../../pqz-core/nethermind/Nethermind.Pqz/PqzChainSpecEngineParameters.cs#L29-L45).
  `RowGas(input)` parses `(d_in, m_in, d_out, m_out)` from bytes 1..5. If the 4-tuple is matched in the schedule table, gas is charged as `base_gas + 3 * ceil(input.Length / 32)`.
  If the row is not allowlisted, gas is charged as `3 * ceil(input.Length / 32)` and returns 32 zero bytes.
  *(See Finding NETH-01 regarding selftest bypass).*

### Dimension 3: Precompile Native-Call Safety & FFI Boundary
- **Memory Safety**:
  [Native.cs:33-47](../../../pqz-core/nethermind/Nethermind.Pqz/Native.cs#L33-L47) bounds max input length at `MaxInputBytes = 393_216` (384 KiB). Any oversized input is immediately rejected in C# without calling FFI.
  Input/output buffers use fixed pinned memory pointers (`fixed (byte* inPtr = input.Span)`).
  Outputs are allocated to 32 bytes (`byte[] outBuf = new byte[32]`).
- **Panic Boundary**:
  [pqz-core/nethermind/fault-hooks/src/lib.rs:13-28](../../../pqz-core/nethermind/fault-hooks/src/lib.rs#L13-L28) wraps FFI invocations in `std::panic::catch_unwind`. Rust panics return error code `-1` instead of crashing the CLR process.
- **Selftest & Native Linkage**:
  [SelfTest.cs:17-23](../../../pqz-core/nethermind/Nethermind.Pqz/SelfTest.cs#L17-L23) validates native library linkage at initialization using test vector input `[0x06, 0x00, 0x00, 0x00, 0x00]`.

### Dimension 4: ML-DSA Precompile (`0x03a2`)
- **Key & Signature Constraints**:
  [MlDsaPrecompile.cs:16-22](../../../pqz-core/nethermind/Nethermind.Pqz/MlDsaPrecompile.cs#L16-L22) checks input length:
  `PubkeyBytes (1312) + SigBytes (32) + Data (arbitrary)`. If `input.Length < 1344`, returns 32 zero bytes.
- **Gas Model**:
  Charges flat 4,000 gas (`Gas = 4000`).
  *(See Finding NETH-03 regarding unhandled CryptographicException).*

### Dimension 5: Chainspec Patching & Tooling
- **Scripts**:
  [chain/patch-chainspec.py:12-25](../../../chain/patch-chainspec.py#L12-L25) and [chain/add-schedule.py:10-30](../../../chain/add-schedule.py#L10-L30) cleanly insert `pqz` parameters into `params` section of Nethermind chainspecs without mangling existing fields.
  [chain/engine-pqz.json](../../../chain/engine-pqz.json) specifies canonical allowlist tuples and gas pricing.

### Dimension 6: Dockerfile & Build Determinism
- **Build Reproducibility**:
  [Dockerfile:1-45](../../../Dockerfile#L1-L45) pins multi-stage base images (`rust:1.83.0-bookworm`, `mcr.microsoft.com/dotnet/sdk:8.0`).
  Nethermind submodule checkout commit is pinned. Release build builds with `--release` and `-p pqz-ffi`.
  Dynamic library `libpqz_ffi.so` is copied to `/nethermind/plugins/`.

### Dimension 7: PQZ Statement Encoding vs. Proof Binding (Solidity vs. Rust)
- **Header Layout (640 bytes / 20 EVM words)**:
  Verified exact 1:1 match between EVM assembly packing in [UAPqzVerifier.sol:112-140](../../../smartcontracts/evm/src/pqz/UAPqzVerifier.sol#L112-L140) and Rust parser in `pqz-core/stmt/src/lib.rs`:
  - Word 0: `H_OPTAG` (`0x00`)
  - Word 1: `H_CHAIN_ID` (`0x20`)
  - Word 2: `H_AUTH_REF` (`0x40`)
  - Word 3: `H_AUDITOR_REF` (`0x60`)
  - Word 4: `H_VALID_BEFORE` (`0x80`)
  - Word 5: `H_VALID_AFTER` (`0xa0`)
  - Word 6: `H_SHIELD_SCALE` (`0xc0`)
  - Word 7: `H_EPOCH` (`0xe0`)
  - Word 8: `H_SALT` (`0x100`)
  - Word 9: `H_TOKEN_ADDR` (`0x120`)
  - Word 10: `H_CALLER_ADDR` (`0x140`)
  - Word 11: `H_SIG_NONCE` (`0x160`)
  - Word 12: `H_FEE` (`0x180`)
  - Word 13: `H_OUT_AMOUNT` (`0x1a0`)
  - Word 14: `H_BURN_AMOUNT` (`0x1c0`)
  - Word 15: `H_MEMO_HASH` (`0x1e0`)
  - Words 16-19: Reserved words (`0x200` to `0x260`)
- **Payload & Public Key Bindings**:
  Tail bytes correctly bind `pk_f`, `pk_t`/`pks`, `pk_a`, `T`, and `out`. No fields are malleable or unbound.

### Dimension 8: PQZ Token & Layer State Transitions
- **Rollover & Epoch Balance**:
  [PqzLayer.sol:95-120](../../../smartcontracts/evm/src/pqz/PqzLayer.sol#L95-L120) strictly isolates epochs. Pending balance increments during epoch $E$ cannot be spent until rolled over into current balance at epoch $> E$.
- **Nullifier Protection**:
  [PqzLayer.sol:130-145](../../../smartcontracts/evm/src/pqz/PqzLayer.sol#L130-L145) checks and sets `nullifiers[tag][epoch][c1]`. Duplicate nullifiers revert immediately, preventing double-spend and double-nullification.
- **Supply Conservation**:
  In `shield`: `totalShielded += amount * shieldScale`, mints exact encrypted representation.
  In `unshield`: `totalShielded -= amount * shieldScale`, burns exact encrypted representation.

### Dimension 9: Zether EVM Implementation
- **Chain Restriction**:
  [ZetherSafety.sol:14-16](../../../smartcontracts/evm/src/zether/ZetherSafety.sol#L14-L16) prevents execution on chain 7622 and above.
- **Curve Operations & Statements**:
  [ZetherCurves.sol](../../../smartcontracts/evm/src/zether/ZetherCurves.sol) implements alt_bn128 curve additions and scalar multiplications calling standard precompiles `0x06`, `0x07`, and `0x08`.
  [ZetherVerifier.sol:50-120](../../../smartcontracts/evm/src/zether/ZetherVerifier.sol#L50-L120) validates sigma/bulletproof verification conditions.

### Dimension 10: Unified Account & Registry
- **Key Registry & AuthRef**:
  [UARegistry.sol:137-142](../../../smartcontracts/evm/src/ua/UARegistry.sol#L137-L142) enforces that `PQZ_MLWE` (Kind 2) registrations cannot pass `authRef == 0`.
- **Signature Schemes**:
  [SigCheck.sol:20-45](../../../smartcontracts/evm/src/ua/SigCheck.sol#L20-L45) dispatches Ed25519 to precompile `0x09` and Secp256k1 to `ecrecover`. Both cleanly validate outputs and signatures without reentrancy risks.

### Dimension 11: Meta-Transactions & Mandate Wallets
- **Replay Protection**:
  [MetaTxBase.sol:40-65](../../../smartcontracts/evm/src/metatx/MetaTxBase.sol#L40-L65) encodes `block.chainid` and contract address in the EIP-712 domain separator.
  Nonces are sequential and monotonic (`_nonces[signer]++`).
- **Mandate Execution**:
  [MandateWallet.sol:80-110](../../../smartcontracts/evm/src/wallet/MandateWallet.sol#L80-L110) enforces valid time bounds (`validAfter`, `validBefore`) and cumulative spend allowances per epoch.

### Dimension 12: DEX & Trade Settlement
- **Escrow & Settlement**:
  [SCaaSDex.sol:220-280](../../../smartcontracts/evm/src/dex/SCaaSDex.sol#L220-L280) performs atomic token transfers and fee routing using `SafeERC20`.
  Reentrancy guards are present on all state-changing trade execution paths.
  *(See Finding SOL-02 regarding multiplicative overflow in limit price checks).*

---

## 3. Checked and Clean

The following components and files were audited and confirmed clean of security defects across the review dimensions:

### Plugin & Tooling
- [pqz-core/nethermind/Nethermind.Pqz/Native.cs:1-76](../../../pqz-core/nethermind/Nethermind.Pqz/Native.cs#L1-L76): Native invocation bounds, pointer pinning, P/Invoke signatures, buffer length checks.
- [pqz-core/nethermind/Nethermind.Pqz/Addresses.cs:1-12](../../../pqz-core/nethermind/Nethermind.Pqz/Addresses.cs#L1-L12): Constant address declarations (`0x03a0`, `0x03a2`).
- [pqz-core/nethermind/Nethermind.Pqz/PqzReleaseSpec.cs:1-30](../../../pqz-core/nethermind/Nethermind.Pqz/PqzReleaseSpec.cs#L1-L30): Release specification object model.
- [pqz-core/nethermind/Nethermind.Pqz/PqzPlugin.cs:1-42](../../../pqz-core/nethermind/Nethermind.Pqz/PqzPlugin.cs#L1-L42): Plugin lifecycle registration and Nethermind DI setup.
- [pqz-core/nethermind/Nethermind.Pqz/SelfTest.cs:1-35](../../../pqz-core/nethermind/Nethermind.Pqz/SelfTest.cs#L1-L35): Startup self-test validation vectors.
- [pqz-core/nethermind/fault-hooks/src/lib.rs:1-34](../../../pqz-core/nethermind/fault-hooks/src/lib.rs#L1-L34): Panic recovery and signal hooking across FFI boundaries.
- [chain/patch-chainspec.py:1-45](../../../chain/patch-chainspec.py#L1-L45) & [chain/add-schedule.py:1-35](../../../chain/add-schedule.py#L1-L35): Chainspec JSON mutation scripts.
- [Dockerfile:1-45](../../../Dockerfile#L1-L45) & [build-image.sh:1-25](../../../build-image.sh#L1-L25): Build commands and image staging.

### EVM Solidity Contracts
- [smartcontracts/evm/src/pqz/PqzCt.sol:1-55](../../../smartcontracts/evm/src/pqz/PqzCt.sol#L1-L55): Ciphertext struct packing and memory layouts.
- [smartcontracts/evm/src/pqz/IPqzToken.sol:1-48](../../../smartcontracts/evm/src/pqz/IPqzToken.sol#L1-L48): Interface signatures and event definitions.
- [smartcontracts/evm/src/pqz/PqzLib.sol:1-210](../../../smartcontracts/evm/src/pqz/PqzLib.sol#L1-L210): Core balance verification, statement construction, and proof forwarding.
- [smartcontracts/evm/src/pqz/PqzLayer.sol:1-175](../../../smartcontracts/evm/src/pqz/PqzLayer.sol#L1-L175): Epoch rollover tracking, balance commitments, nullifier set management.
- [smartcontracts/evm/src/pqz/NoUnderlyingPqzToken.sol:1-45](../../../smartcontracts/evm/src/pqz/NoUnderlyingPqzToken.sol#L1-L45): Pure confidential mint and burn mechanics.
- [smartcontracts/evm/src/pqz/UAPqzVerifier.sol:1-165](../../../smartcontracts/evm/src/pqz/UAPqzVerifier.sol#L1-L165): EVM assembly statement construction and precompile staticcall dispatcher.
- [smartcontracts/evm/src/zether/ZetherCurves.sol:1-90](../../../smartcontracts/evm/src/zether/ZetherCurves.sol#L1-L90): Alt_bn128 curve arithmetic wrapper.
- [smartcontracts/evm/src/zether/ZetherVerifier.sol:1-135](../../../smartcontracts/evm/src/zether/ZetherVerifier.sol#L1-L135): Bulletproof/sigma statement verification.
- [smartcontracts/evm/src/zether/ZetherStatements.sol:1-110](../../../smartcontracts/evm/src/zether/ZetherStatements.sol#L1-L110): Statement hash hashing and transcript management.
- [smartcontracts/evm/src/zether/ZetherLib.sol:1-160](../../../smartcontracts/evm/src/zether/ZetherLib.sol#L1-L160): Zether transfer, deposit, and burn execution.
- [smartcontracts/evm/src/ua/UAKinds.sol:1-35](../../../smartcontracts/evm/src/ua/UAKinds.sol#L1-L35): Account key types constants.
- [smartcontracts/evm/src/ua/UARegistry.sol:1-180](../../../smartcontracts/evm/src/ua/UARegistry.sol#L1-L180): Unified account registration and public key management.
- [smartcontracts/evm/src/ua/SigCheck.sol:1-85](../../../smartcontracts/evm/src/ua/SigCheck.sol#L1-L85): Ed25519 & Secp256k1 signature validation.
- [smartcontracts/evm/src/ua/FeePolicy.sol:1-60](../../../smartcontracts/evm/src/ua/FeePolicy.sol#L1-L60): Gas subsidy and fee policy calculations.
- [smartcontracts/evm/src/common/AdminLib.sol:1-55](../../../smartcontracts/evm/src/common/AdminLib.sol#L1-L55): Two-step ownership transfer and admin authorization.
- [smartcontracts/evm/src/metatx/MetaTxBase.sol:1-95](../../../smartcontracts/evm/src/metatx/MetaTxBase.sol#L1-L95): EIP-712 meta-transaction execution and replay protection.
- [smartcontracts/evm/src/metatx/ERC20MetaTx.sol:1-75](../../../smartcontracts/evm/src/metatx/ERC20MetaTx.sol#L1-L75): Meta-transaction enabled ERC-20 transfer dispatcher.
- [smartcontracts/evm/src/factory/UnderlyingLib.sol:1-70](../../../smartcontracts/evm/src/factory/UnderlyingLib.sol#L1-L70): Underlying asset registration and scaling calculation.
- [smartcontracts/evm/src/factory/OpenFactory.sol:1-125](../../../smartcontracts/evm/src/factory/OpenFactory.sol#L1-L125): Token pair and confidential contract instantiation.
- [smartcontracts/evm/src/wallet/MandateWallet.sol:1-190](../../../smartcontracts/evm/src/wallet/MandateWallet.sol#L1-L190): Mandate authorization, policy enforcement, and execution.
- [smartcontracts/evm/src/hedera/HederaMandateWallet.sol:1-80](../../../smartcontracts/evm/src/hedera/HederaMandateWallet.sol#L1-L80): Hedera-specific account ID mapping and mandate forwarding.
- [smartcontracts/evm/src/account/SmartKeyAccount.sol:1-115](../../../smartcontracts/evm/src/account/SmartKeyAccount.sol#L1-L115): Smart contract wallet account execution and key updates.

---

## 4. Not Checked (Out of Scope per Brief)

As specified in `brief-chain.md`, the following directories and components were excluded from this audit:
1. **Mathematical Proof Internals**: Core cryptographic soundness proofs and zero-knowledge relation algorithms inside unmanaged C/Rust libraries (Ligero prover/verifier internals, polynomial arithmetic).
2. **Excluded Directories**:
   - `smartcontracts/evm/legacy/`
   - `smartcontracts/evm/test/`
   - `smartcontracts/evm/lib/` (external dependency vendor code)
3. **Off-Chain Components**: Relayers, indexing services, and client SDKs.

---

## Triage (controller, T = Codex lead, U = agy, V1–V3 = Claude)

Verified by the controller against `7aab1fe` (`PqzLayer.sol:133–168`, `MetaTxBase.sol:272–279`,
`PqzPrecompile.cs:29–80`, `PqzChainSpecEngineParameters.cs:54–79`, `MlDsaPrecompile.cs`, `PqzPlugin.cs:45`,
`UnderlyingPqzToken.sol:58–70`, `TradeLib.sol:118–126`, `SCaaSDex.sol:380–388`, `PqzSafety.sol:12–24`, stmt
`decode_input`). **No P0 / P1 from any reviewer.** Fix branch `rev2-chain` (plan Task 5g). All chains are test-only:
fixes that change deployed bytecode, statement views or vectors land with plan Task 13's reset of 7622.

| # | Finding | Sources | Verdict | Disposition |
|---|---|---|---|---|
| W-A | PQZ transfer mode not bound on a direct call: `pqzTransfer` / `…NoBundle` (and the Single pair) differ only in the mode, the statement and `opTag` are equal for BUNDLE and NONE, a direct call's binding is 0 ⇒ a front-runner replays a BUNDLE transfer through `…NoBundle`, no entry is stored, the sender loses the on-chain disclosure for it (no theft) | T-lead, V1 (confirmed) | **P2**, confirmed by the controller | Fix: a direct call's binding = `keccak(tag ‖ mode)` (the `unwrapBinding` pattern), so the auth signature covers the mode; spec text; forge tests; vectors / statement views regenerated |
| W-B | Tokens trust the verifier their creator picks: `OpenFactory._checkPqz` only asks `isSupportedOnThisChain`; `PqzLib.init` takes `PRECOMPILE` / `PROOF_SYSTEM_ID` from it without checking `PqzSafety.PQZ` or running the self-test (the spec requires it); `UAPqzVerifier` accepts any probe; a fake "always valid" precompile drains a factory-listed wrapper; same class in Zether (dev chains). Also the factory trusts creator-chosen basket legs (disclosed in token-wrappers.md §2.2) | V1-02, V3 (b) | **P2**, confirmed | Fix: `init` requires the precompile = `PqzSafety.PQZ`, an accepted `proofSystemId` and the self-test hash = `SELFTEST`; `UAPqzVerifier` pins the probe hash; the Zether twin; factory listing unchanged otherwise (legs: recorded) |
| W-C | Anyone can flood the per-kind decoy list (`UARegistry` index is permissionless; one PQ authority serves many UAs; free gas on 7622) ⇒ an observer knows its own decoys | V2-1 | **P2** (impact depends on wallet decoy selection: hypothesis) | Spec only (no bytecode): a decoy-selection rule (weight by activity in the token, skip fresh / unfunded UAs) and a threat-table row in accounts.md / pq-zero-knowledge.md; wallet work in P6h |
| W-D | `ApplyToReleaseSpec` sets `ActiveSchedule = ScheduleAt(startTimestamp)`, and `ScheduleAt(null)` is null: a release spec built for a block-number transition (test genesis `maxCodeSizeTransition: 6432`) may drop the PQZ precompiles from that block on | U NETH-02 | **Plausible** (depends on how Nethermind builds and looks up block-number activations; not readable in the tree); every node alike, so no split, but the feature disappears | Fix by test first: a chainspec with a timestamp schedule plus a later block-number transition, assert the precompiles stay; then derive the schedule for block-number activations correctly |
| W-E | Anyone may roll over another account's credits, which makes that account's in-flight debit revert `AccMismatch` (calldata `acc` stale); contradicts threat T8 ("impossible by construction") | V1-03 | P3, confirmed | Fix if small (accept the pre-rollover `acc` when its hash is the account's previous `accHash` and rebuild T), else correct T8 and CTR-PQZ-08's wording; decide in 5g |
| W-F | `chain/add-schedule.py` can silently drop gas rows (a dropped shape always returns `…00`); a duplicate key makes every node refuse to start | V1-04 | P3 | Fix: the tool fails on a dropped row or a duplicate key; test |
| W-G | Library hash pin is circular (`FFI_SHA256` from the same build; the plugin logs the hash but never compares); apt clang unpinned | V1-05 | P3 | Fix: the expected `pqz-ffi` sha256 committed beside the source and compared at start-up (`PQZ-REFUSE`); clang pinned in the Dockerfile |
| W-H | A node fault inside `eth_call` exits the process; the PQZL lock is shared by RPC and block import | V1-06 | P3, hypothesis | Record + RUNBOOK: no public RPC on the signer (already the topology); no code |
| W-I | `PqzLib.sol:364` underflows before its bounds check (panic instead of `BadPayload`); `verifyTransferAmount` reverts where its doc says false; bn254 wrappers do not check `returndatasize` | V1-07 | P3 hygiene | Fix all three; tests |
| W-J | The `secp256k1` kind (0x0108) needs a raw-hash ECDSA from EOA keys, contrary to S23 (EOAs never sign a raw hash; MetaMask only via `eth_sign`) | V2-2 | P3 | **Owner decision**: (a) a `personal_sign` (EIP-191) verifier, new vectors, six clients, or (b) a recorded residual risk |
| W-K | `MandateWallet.isValidSignature` accepts the owner's ECDSA over any digest (ERC-7739 replay class, e.g. Permit2); documented for `SmartKeyAccount` only | V2-3, V3-03 | P3 (no SCaaS path; outside loss a hypothesis) | **Owner decision**: (a) document as for `SmartKeyAccount`, or (b) ERC-7739 nested typed data |
| W-L | The mandate period is a window that resets on demand: a delegate pays the cap just before and just after the boundary | V2-4 | P3 | Fix: windows aligned to the period grid; test |
| W-M | Gas starvation can surface as `UAUnauthorized` instead of `UAVerifyGas` (fail-closed, misleading) | V2-5 | P3 | Fix: minimum-gas guard before the gen-2 hand-off |
| W-N | `IUARegistry` lacks `chainKeyHash()`; OpenZeppelin unpinned (`lib/` ignored, an untracked symlink) | V2-6, V3 (not checked) | P3 | Fix: the interface; pin OpenZeppelin (submodule / commit pin + checksum in the build) |
| W-O | `mtxSettle` aborts the whole batch on revert data that merely starts with `SigCheckGasStarved` / `UAVerifyGas`, which a listed token or an ERC-777 hook can forge | V3-01 | P3 | Fix: honour those selectors only when the DEX frame itself is low on gas |
| W-P | A cancel signature is not bound to the nonce it cancels (a held-back cancel voids a later envelope) | V3-02 | P3, spec-conformant (accounts.md:257) | Record (griefing only) |
| W-Q | DEX / metatx hygiene: stray balances taken by the next exchange path; exchange path allows `sellToken == receiveToken`; `_classify` fixed at `setMarket`; factory doc drift; `mtxWrap` / `uaWrap` events; entry points without `nonReentrant` (no outside call) | V3-04 | P3 | Fix the code items cheaply; docs |
| W-R | ML-DSA precompiles: a `CryptographicException` would revert instead of returning the failure word (EIP-8355 says never revert); `MLDsa.IsSupported` is checked at start-up, the 1 h harness reached none | U NETH-03 | P3 | Fix: catch → 32 zero bytes |
| W-S | `pqzUnwrap` floor rounding leaves dust (by design, favours solvency); `move * receiveAmount` overflows above 2^128 (only the signer's own order fails); `PqzSafety` / `ZetherSafety` chain allowlists (by design; 22776 added at its launch gate) | U SOL-01…03 | P3 / by design | SOL-02: `mulDiv`; SOL-01, SOL-03: recorded |
| — | "Selftest input pays only `SelftestGas`, no per-word charge" | U NETH-01 | **Refuted**: `SelftestGas` = 2,567,000 exceeds the per-word charge of any input (≤ 393,216 B ⇒ ≈ 37k) plus `MinGas`; `pqz-stmt` accepts SELFTEST only as exactly `06 00000000`, every other `06…` input is rejected at once | none |
