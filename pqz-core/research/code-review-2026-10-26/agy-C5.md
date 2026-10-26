# Independent Security Review: Unit C5 (Meta-Transactions, Relay, Token Base, and Factory)

**Repository:** SCaaS EVM Smart Contracts (`smartcontracts/evm/src/`)  
**Commit:** `64549aa4` (frozen detached worktree)  
**Review Type:** Static Code Review & Security Audit (Read-Only)  
**Unit:** C5 — Meta-transactions, relay, token base, and factory  

---

## 1. Executive Summary

This independent security review evaluated the architecture, implementation, and invariant guarantees of Unit C5 in the SCaaS EVM smart contracts. The scope encompasses the core meta-transaction dispatch engine (`MetaTxBase`), the token abstraction layer (`ERC20MetaTx`, `MetaTokenBase`, `NoUnderlyingToken`, `UnderlyingToken`, `UnderlyingLib`), token administration (`AdminLib`), the factory deployment pipeline (`OpenFactory`, `IFactoryToken`), and common cryptographic and utility libraries (`MetaTxLib`, `FeePolicy`, `SaltedEIP712`, `SSTORE2`).

The review verified compliance with all owner rulings and architectural constraints:
- **Relayability:** Every state-changing `mtx*` call is relayable; signatures bind all executable parameters; `fee = 0` is valid.
- **Envelope Integrity:** Strict EIP-712 typed hashing with chain UID salt and clone contract domain separation prevents cross-chain, cross-token, and cross-type replay.
- **Reentrancy & Execution Control:** A custom transient-storage reentrancy guard (`_GUARD`, `_TICKET`) ensures exactly one self-call per ticket, guarantees atomicity across batch calls, and bubbles inner reverts without swallowing errors.
- **Value Conservation:** Fee-on-transfer underlyings are measured upon wrapping; unwrap operations verify exact token balance outflow; allowances are restricted strictly to smart contracts.
- **Factory Security:** Library code hashes are pinned and verified at deployment; releases and environments are append-only and immutable; deterministic clones are atomically initialized in the same call as deployment.

**Results:** No critical (P0), high (P1), or medium (P2) vulnerabilities were identified in the reviewed scope. Three low-severity / code hygiene items (P3) were noted (C5-1, C5-2, C5-3).

---

## 2. Review Scope & Specifications

### 2.1 File Inventory
| Component | Files Under Review |
| :--- | :--- |
| **Meta-Tx Base & Tokens** | `smartcontracts/evm/src/metatx/MetaTxBase.sol`<br>`smartcontracts/evm/src/metatx/ERC20MetaTx.sol`<br>`smartcontracts/evm/src/metatx/MetaTokenBase.sol`<br>`smartcontracts/evm/src/metatx/NoUnderlyingToken.sol`<br>`smartcontracts/evm/src/metatx/UnderlyingToken.sol`<br>`smartcontracts/evm/src/metatx/UnderlyingLib.sol`<br>`smartcontracts/evm/src/metatx/AdminLib.sol`<br>`smartcontracts/evm/src/metatx/IMetaTx.sol`<br>`smartcontracts/evm/src/metatx/IERC20MetaTx.sol`<br>`smartcontracts/evm/src/metatx/IERC20Payment.sol`<br>`smartcontracts/evm/src/metatx/IMetaTokenV2.sol`<br>`smartcontracts/evm/src/metatx/ITokenAdmin.sol`<br>`smartcontracts/evm/src/metatx/IUnderlyingToken.sol`<br>`smartcontracts/evm/src/metatx/IUALedger.sol` |
| **Factory** | `smartcontracts/evm/src/factory/OpenFactory.sol`<br>`smartcontracts/evm/src/factory/IFactoryToken.sol`<br>`smartcontracts/evm/src/factory/IOpenFactory.sol` |
| **Common Libraries** | `smartcontracts/evm/src/common/MetaTxLib.sol`<br>`smartcontracts/evm/src/common/FeePolicy.sol`<br>`smartcontracts/evm/src/common/SaltedEIP712.sol`<br>`smartcontracts/evm/src/common/SSTORE2.sol` |

### 2.2 Normative Documents & Standards
- `docs/contracts/metatx.md` (CTR-MTX-01 through CTR-MTX-28)
- `docs/contracts/token-wrappers.md` (CTR-TOK-01 through CTR-TOK-26)
- `docs/decisions.md` (CTR-MTX-*, CTR-TOK-*, NET-EVM-*)
- `pqz-core/research/code-review-2026-10-19/` (prior review baseline: T, U, V1, V2, V3, T2)
- `pqz-core/research/code-review-2026-10-25/` (precompile requirements)

---

## 3. Findings

```
┌────────────────────────────────────────────────────────────────────────┐
│ Severity Distribution:                                                 │
│ P0 (Critical): 0   | P1 (High): 0   | P2 (Medium): 0   | P3 (Low): 3  │
└────────────────────────────────────────────────────────────────────────┘
```

---

### Finding C5-1: Transient storage slot `_BINDING` is not cleared upon exiting `_selfCall` and conditionally written only when non-zero

- **Severity:** P3 (Low / Latent Risk / Defense-in-Depth)
- **Location:** `smartcontracts/evm/src/metatx/MetaTxBase.sol:216`, `220-221`
- **Related References:** `smartcontracts/evm/src/metatx/MetaTxBase.sol:268-273`

#### Claim
In `MetaTxBase._selfCall`, the transient storage slot `_BINDING` is updated only if `binding != bytes32(0)`. When the self-call completes, `_TICKET` and `_SENDER` are cleared to 0, but `_BINDING` is not cleared. Consequently, if a transaction executes multiple envelopes in sequence (such as inside `mtxBatch` or `uaBatch`), an item that produces a non-zero binding followed by an item that produces a zero binding (`bytes32(0)`) leaves the prior envelope's binding lingering in the `_BINDING` slot. If a subsequent function reads `_ticketBinding()`, it could observe stale binding data.

#### Evidence
`MetaTxBase.sol:213-225`:
```solidity
    function _selfCall(bytes32 subject, bytes memory data, bytes32 binding) internal returns (bytes memory ret) {
        _tstore(_SENDER, uint256(subject));
        _tstore(_TICKET, 1);
        if (binding != bytes32(0)) _tstore(_BINDING, uint256(binding));
        bool ok;
        (ok, ret) = address(this).call(data);
        bool guarded = _tload(_TICKET) == 2;    // the target was `nonReentrant` and consumed the ticket
        _tstore(_TICKET, 0);
        _tstore(_SENDER, 0);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
        if (!guarded) revert Reentrancy();      // fail closed: an allowlisted function must be `nonReentrant`
    }
```
The developer comments at `MetaTxBase.sol:268-270` explicitly document this fragile coupling:
```solidity
    /// Step 5 writes it only when non-zero, which is safe only while an override is never 0 or always 0: one
    /// that returns 0 for some envelopes would let that `mtxBatch` item read the previous item's binding, so
    /// such an override needs step 5 to write the slot unconditionally.
```
In the current code, confidential tokens (`ZetherLayer`, `PqzLayer`) compute bindings via a `keccak256` digest that is never zero for any input, and PQZ ops disable batching (`_batchable = false`). However, relying on child contracts to never return zero is unnecessary and creates latent vulnerability for future selectors or token kinds.

#### Suggested Fix
Unconditionally write and clear `_BINDING` in `MetaTxBase._selfCall`:
```solidity
    function _selfCall(bytes32 subject, bytes memory data, bytes32 binding) internal returns (bytes memory ret) {
        _tstore(_SENDER, uint256(subject));
        _tstore(_TICKET, 1);
        _tstore(_BINDING, uint256(binding)); // Unconditional write
        bool ok;
        (ok, ret) = address(this).call(data);
        bool guarded = _tload(_TICKET) == 2;
        _tstore(_TICKET, 0);
        _tstore(_SENDER, 0);
        _tstore(_BINDING, 0);                 // Explicit cleanup
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
        if (!guarded) revert Reentrancy();
    }
```

---

### Finding C5-2: Unused / Dead function `FeePolicy.requireConfidentialSafe`

- **Severity:** P3 (Code Hygiene / Dead Code)
- **Location:** `smartcontracts/evm/src/common/FeePolicy.sol:73-75`

#### Claim
`FeePolicy.requireConfidentialSafe` is declared in `FeePolicy.sol` and referenced in library docstrings, but is never invoked anywhere across the entire smart contract codebase.

#### Evidence
`FeePolicy.sol:73-75`:
```solidity
    function requireConfidentialSafe(FeeMode mode) internal pure {
        if (mode == FeeMode.PERCENT) revert PercentFeeForbiddenOnConfidential();
    }
```
Grepping all Solidity sources in `smartcontracts/evm/src/` shows that `requireConfidentialSafe` appears only at its definition (`FeePolicy.sol:73`) and in comments (`FeePolicy.sol:16`). 

The prohibition against percentage fees on confidential operations is instead enforced directly in `MetaTxBase._checkCall` (`MetaTxBase.sol:199-201`):
```solidity
    if (r.feeClass == FEE_CLASS_ABSOLUTE && MetaTxLib.feeModeOf(mode) == FeeMode.PERCENT) {
        revert MtxFeeClass(sel, mode);
    }
```
All confidential entry points in `ZetherLayer` and `PqzLayer` are registered with `FEE_CLASS_ABSOLUTE`. While the invariant is enforced, `requireConfidentialSafe` remains redundant dead code.

#### Suggested Fix
Either remove `requireConfidentialSafe` from `FeePolicy.sol`, or call it as an explicit assert in confidential token entry points for additional defense-in-depth.

---

### Finding C5-3: Production deployment caveat disclaimer in `SSTORE2.sol`

- **Severity:** P3 (Documentation & Readiness)
- **Location:** `smartcontracts/evm/src/common/SSTORE2.sol:6`

#### Claim
`SSTORE2.sol` retains a prominent warning comment: `/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.**`.

#### Evidence
`SSTORE2.sol:5-7`:
```solidity
/// @title Bytes stored once as contract code (SSTORE2): runtime = `0x00` (STOP) ‖ data, so the data contract cannot
///        be called into anything; read back with EXTCODECOPY (accounts.md CTR-UA-17 `keyPtr`).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
library SSTORE2 {
```
`SSTORE2` is an essential building block used across the production token system:
1. `UARegistry.sol:310, 425, 438` (storing Universal Account public keys and ML-DSA expanded key parts).
2. `PqzCore.sol:316, 481, 543` (persisting confidential ciphertexts in contract state per owner rulings).

The implementation of `SSTORE2` was reviewed and verified sound (prepends `0x00` STOP opcode, enforces lengths, uses `EXTCODECOPY` memory-safely). Retaining the disclaimer creates uncertainty regarding deployment readiness.

#### Suggested Fix
Formally update the library header docstring upon completion of this audit round to reflect reviewed status.

---

## 4. Checked and Sound (Invariants Verified)

Every core security invariant was analyzed with verifiable evidence from code:

| Invariant | Status | Verification Evidence |
| :--- | :--- | :--- |
| **Envelope Signing (`mtxExecute`)** | Sound | Signature covers `(from, keccak256(data), batch, nonce, validUntil, mode, relayer, fee, feeRecipient)` in EIP-712 domain binding `(name, version="1", chainId, verifyingContract=address(this), salt=CHAIN_UID)` (`MetaTxBase.sol:150-156`, `MetaTxLib.sol:97-102`, `SaltedEIP712.sol:68`). |
| **Envelope Signing (`uaExecute`)** | Sound | Signature over `UAMetaTransaction` struct digest verified via `UARegistry.requireAuthorized` under `PURPOSE_METATX` for derived UAs, or native ECDSA/ERC-1271/7702 (`ERC20MetaTx.sol:357-359, 448-456`, `MetaTxLib.sol:190-196`). |
| **2D Nonce & Replay Protection** | Sound | Nonces are partitioned per lane (`mapping(bytes32 => mapping(uint256 => uint256)) nonce`), strictly sequential (`expected != nonce` reverts `MetaTxBadNonce`), incremented at step 4 (`_useNonce`), and reverted atomically if execution fails (`MetaTxBase.sol:161-183`). |
| **Nonce Cancellation Semantics** | Sound | Direct or relayed `cancelNonce` increments lane nonce (`MetaTxBase.sol:130-133`); derived UA `uaCancelNonce` validates `PURPOSE_METATX_CANCEL` and marks digest spent in `cancelUsed` (`ERC20MetaTx.sol:340-350`). |
| **Relayable Selectors & `MtxRule`** | Sound | Allowlist declared via `mtxSelectors()` with pinned static lengths (`staticLen != 0 && data.length != staticLen` reverts `MtxDataShape`) or dynamic bounds; unlisted selectors revert `MtxSelectorNotAllowed` (`MetaTxBase.sol:191-206`). |
| **Fee Classes & 1% Cap** | Sound | `FEE_CLASS_ABSOLUTE` rejects `FeeMode.PERCENT` (`MtxFeeClass`); `FEE_CLASS_AMOUNT` enforces 1% hard cap (`MAX_FEE_PPM = 10_000`) calculated via `Math.mulDiv` preventing overflow (`MetaTxBase.sol:199-205`, `FeePolicy.sol:40-52`). |
| **Fee Payment Non-Redirection** | Sound | Bound `feeRecipient` is hashed into EIP-712 struct when `MODE_RESTRICT_FEE_RECIPIENT` is set; cannot equal payee `to` (`FeeRecipientIsPayee`), contract itself (`TransferToSelf`), `UA_POOL`, or `SHIELD_POOL` (`ERC20MetaTx.sol:212-226, 242-252`). |
| **Receiver-Pays Integrity** | Sound | `mtxPayReceiverFee` & `uaPayReceiverFee` require payee co-signed `ReceiverFee` over payer's payment digest, enforced on single-use lane `payLane(entryRef)` at nonce 0, fee $\le$ payment value (`MetaTokenBase.sol:317-361`). |
| **Griefing Resistance & Gas Rules** | Sound | ERC-1271 callers verify `gasleft() >= cap * 64 / 63 + GAS_MARGIN` reverting `SigCheckGasStarved` if starved; inner call reverts bubble raw return data; relayer cannot collect fee on failed execution (`SigCheck.sol:62-64`, `MetaTxBase.sol:218-222`). |
| **Reentrancy & Ticket Lifecycle** | Sound | Transient storage `_GUARD` and `_TICKET` admit exactly one self-call under ticket=1, consume ticket=2, require allowlisted functions to have `nonReentrant`, and clear slots upon return (`MetaTxBase.sol:57-67, 213-224`). |
| **Allowance Lockdown (CTR-TOK-01)** | Sound | `approve` and `transferFrom` require both caller and spender to be contracts (`CallerNotContract`, `SpenderNotContract`); EOAs (including EIP-7702 delegated EOAs) cannot approve; never allowlisted (`ERC20MetaTx.sol:257-271`, `SigCheck.sol:26-34`). |
| **Wrapping: Fee-on-Transfer In** | Sound | `UnderlyingLib._pull` measures actual balance increase (`balanceOf(this) - before`), pricing and minting only measured delta; reverts `ReserveShortfall` if balance $<$ reserve (`UnderlyingLib.sol:156-172`). |
| **Unwrapping: Transfer Fees Out** | Sound | `UnderlyingLib.payOut` burns wrapped tokens first (CEI), executes `SafeERC20.safeTransfer`, and verifies exact outflow (`sent == out`), reverting `UnderlyingTransferMismatch` if token takes fee (`UnderlyingLib.sol:259-272`). |
| **Guardian & Rate Admin Roles** | Sound | `disableWrap` is permanently one-way (no re-enable); rate changes require timelock (`rateDelay` 2-30 days, step $\le$ 10%), rateAdmin must be contract, and `executeRate` enforces collateral solvency (`UnderlyingLib.sol:311-404`). |
| **Factory Immutability & Access** | Sound | Only immutable `registrar` can publish envs or deploy implementations; release versions and env versions cannot be overwritten; notice period enforced; deprecation irreversible (`OpenFactory.sol:71-125, 261-276`). |
| **Library Code Hash Pinning** | Sound | `deployImplementation` iterates `env.libs` and verifies each runtime `codehash` matches `env.libCodeHashes` before executing CREATE2 (`OpenFactory.sol:286-289`). |
| **Clone Determinism & Init** | Sound | `createToken` executes EIP-1167 clone with salt scoped by `msg.sender` (`keccak256(creator, salt)`), calls `initialize` in same transaction; implementation constructor permanently locks itself (`OpenFactory.sol:330-349`, `MetaTokenBase.sol:56-82`). |
| **Storage Layout Pins (ERC-7201)** | Sound | Formulas for `scaas.token`, `scaas.metatx`, `scaas.ua.ledger`, and `scaas.underlying` mathematically verified to match hardcoded constants (`AdminLib.sol:65`, `MetaTxBase.sol:50`, `ERC20MetaTx.sol:42`, `UnderlyingLib.sol:64`). |
| **SSTORE2 Bytecode Storage** | Sound | Runtime bytecode prepended with STOP (`0x00`), preventing accidental or malicious calls; `read` retrieves data via `EXTCODECOPY` starting at offset 1; handles empty data safely (`SSTORE2.sol:11-29`). |

---

## 5. Not Covered

To maintain precise audit boundaries, the following components were designated out-of-scope for Unit C5:
1. **Precompile & Proof Systems:** The `PQZ` precompile at `0x...5caa0f01` and its underlying zero-knowledge proof cryptography (MSIS/MLWE, LNP22, LaZer, Ligero) were reviewed under Units R0–R4.
2. **BLS12-381 / Zether Verifiers:** The off-chain and on-chain verification math for classical Zether (`IZetherVerifier`, `ZetherVerifier.sol`, `ZetherCurves.sol`).
3. **Specific UA Signature Verifiers:** The internal cryptographic implementations of individual PQ and classical verifiers in `smartcontracts/evm/src/ua/verifiers/` (e.g., `MlDsa.sol`, `SlhDsa.sol`, `Musig2`, `Frost`, `WebAuthn`).
4. **DEX Order Settlement Engine:** Matching algorithms, price cross calculations, and liquidity pool interactions in `SCaaSDex.sol` and `TradeLib.sol` beyond the direct token meta-tx entry points (`mtxTrade`, `uaTrade`, `mtxCancelOrder`, `mtxInvalidateNonces`).
5. **Off-Chain Infrastructure:** Relayer nodes (`scaas-node`), RPC proxy configurations, and client SDK implementations.

---

## 6. Execution Plan & Recommendations

1. **Address Finding C5-1:** Update `MetaTxBase._selfCall` to write `_tstore(_BINDING, uint256(binding))` unconditionally and clear `_tstore(_BINDING, 0)` upon return.
2. **Address Finding C5-2:** Clean up unused `FeePolicy.requireConfidentialSafe` or connect it to confidential token entry points.
3. **Address Finding C5-3:** Remove the development notice from `SSTORE2.sol` in coordination with release preparation.
4. **Approve Review Artifact:** Please review the findings and sign off on this report.
