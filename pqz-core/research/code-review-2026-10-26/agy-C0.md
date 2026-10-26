# Independent Security Review: Unit C0 — Cryptographic Design of the Contract Layer

**Target:** SCaaS EVM Smart Contracts (`smartcontracts/evm/src/`)  
**Commit:** `64549aa4` (detached worktree)  
**Profile:** Solidity `^0.8.20` / `0.8.24`, Foundry 1.8.5, Amsterdam profile  
**Scope Unit:** **C0 — Cryptographic Design of the Contract Layer**  
**Committed Parameter Set:** `n2304-kmax4096` (`smartcontracts/evm/src/pqz/PqzSet.sol`)

---

## 1. Executive Summary

This security review evaluates the cryptographic design and contract layer bindings of the confidential token protocols (post-quantum PQZ and classical Zether on BLS12-381), the Universal Account (UA) registry, and the meta-transaction relay interfaces. 

The review verified compliance against the four owner rulings:
1. **Ciphertexts stay in contract state** — ciphertexts are stored in full via SSTORE2 op blobs or storage slots, never solely hashed.
2. **Every state-changing `mtx*` call is relayable** — all state-changing entry points are exposed in `mtxSelectors()` with explicit binding validation.
3. **Chain limits & gas model independence** — contracts avoid chain-specific block gas limits and accommodate EIP-7825 ($2^{24}$ gas limit), EIP-7976 calldata floor (64 gas/byte), and EIP-8037 state gas.
4. **`fee = 0` is valid** — zero fee transfers and shields are supported without underflow or division-by-zero reverts.

No P0 (loss of funds, unauthorized forgery, or complete privacy break) vulnerabilities were found. Five findings are reported: one P1 regarding transaction inclusion limits under EIP-7976 / EIP-7825 for parameter set `n2304-kmax4096`, two P2 design/specification inconsistencies, and two P3 defense-in-depth issues.

---

## 2. Findings

### [C0-1] P1: Parameter Set `n2304-kmax4096` Debit Proofs Exceed EIP-7976 Calldata Floor Cap Under EIP-7825

- **Location:** [`smartcontracts/evm/src/pqz/PqzCore.sol:212`](smartcontracts/evm/src/pqz/PqzCore.sol#L212), [`docs/research/pqzh-calldata-cap.md:1-120`](docs/research/pqzh-calldata-cap.md#L1-L120), [`smartcontracts/evm/src/pqz/PqzSet.sol:1-100`](smartcontracts/evm/src/pqz/PqzSet.sol#L1-L100)
- **Claim:** On chains deploying EIP-7976 (calldata floor of 64 gas per byte) alongside EIP-7825 (transaction gas limit capped at $2^{24} = 16,777,216$ gas), confidential debit operations (`mtxConfidentialTransfer`, `confidentialTransfer`, `confidentialTransferMulti`) for the committed parameter set `n2304-kmax4096` cannot be included in any transaction because their calldata requirement exceeds the maximum transaction calldata capacity of 261,909 bytes.
- **Evidence:**
  Under EIP-7976 and EIP-7825:
  $$\text{Calldata Floor Cap} = \left\lfloor \frac{2^{24}}{64} \right\rfloor = 261,909 \text{ bytes}$$
  In [`docs/research/pqzh-calldata-cap.md`](docs/research/pqzh-calldata-cap.md):
  > "For parameter set `n2304-kmax4096`, the debit proof size alone exceeds 270 KB. The total transaction calldata (`header + proof + ciphertext legs + authSig`) exceeds 278,000 bytes. At 64 gas/byte, the calldata cost alone is $278,000 \times 64 = 17,792,000 > 16,777,216$ gas."
  
  Because the transaction gas requirement strictly exceeds the EIP-7825 transaction limit of $2^{24}$, transactions submitted on EIP-7976-compliant chains are rejected by consensus prior to execution.
- **Suggested Fix:**
  Adopt **Proposal (A)** from [`docs/research/pqzh-calldata-cap.md`](docs/research/pqzh-calldata-cap.md): deploy contracts targeting on-chain debits with parameter set `n2048-kmax1024` (whose debit proofs remain within the 261,909-byte ceiling), and reserve parameter sets `n2304-kmax4096` and above for account registration, disclosure verification, or off-chain aggregation where debits are batched off-chain or executed on chains with higher per-transaction gas ceilings. This preserves all four owner rules without introducing the multi-transaction state complexity of chunking (Proposal B) or the untrusted setup of KZG (Proposal D).

---

### [C0-2] P2: Incomplete Creator-Chosen Verifier Validation in Classical Zether (`ZetherLib.sol`)

- **Location:** [`smartcontracts/evm/src/zether/ZetherLib.sol:170-176`](smartcontracts/evm/src/zether/ZetherLib.sol#L170-L176), [`smartcontracts/evm/src/zether/ZetherLayer.sol:62-67`](smartcontracts/evm/src/zether/ZetherLayer.sol#L62-L67), [`docs/contracts/zether.md:1075`](docs/contracts/zether.md#L1075)
- **Claim:** In the 2026-10-19 review (finding W-B), PQZ resolved the creator-chosen verifier attack by hardcoding [`PqzSafety.requirePqz(s.pqz, s.psid)`](smartcontracts/evm/src/pqz/PqzSafety.sol#L20-L40) and verifying `selfTest() == SELF_TEST_HASH`. Classical Zether in [`ZetherLib.sol`](smartcontracts/evm/src/zether/ZetherLib.sol#L170) does not pin the verifier contract address or verify a bytecode hash, leaving an incomplete twin fix.
- **Evidence:**
  In [`ZetherLib.sol:170-176`](smartcontracts/evm/src/zether/ZetherLib.sol#L170-L176):
  ```solidity
  if (v.isSupportedOnThisChain() != 1) revert UnsupportedPrecompile(address(v));
  s.verifier = v;
  ```
  And in [`ZetherLayer.sol:62-67`](smartcontracts/evm/src/zether/ZetherLayer.sol#L62-L67):
  ```solidity
  if (t.proofSystemId() != b.proofSystemId()) revert ProofSystemMismatch();
  ```
  The deployer passes arbitrary contract addresses for `v` and `b`. Any contract returning `1` for `isSupportedOnThisChain()` and `verifyTransfer()` can be installed. While [`ZetherSafety.requireDevChain()`](smartcontracts/evm/src/zether/ZetherSafety.sol#L14-L16) prevents production deployment on chain IDs other than 31337 and 1337, the missing verifier address pinning or codehash verification leaves an architectural loophole documented as an unclosed twin in `docs/contracts/zether.md:1075`.
- **Suggested Fix:**
  Add verifier pinning in [`ZetherSafety.sol`](smartcontracts/evm/src/zether/ZetherSafety.sol) or [`ZetherLib.sol`](smartcontracts/evm/src/zether/ZetherLib.sol#L170) asserting that `address(v)` matches an immutable known verifier deployment or that `address(v).codehash` matches the canonical compiled `ZetherVerifier` bytecode hash.

---

### [C0-3] P2: Contradictory NatSpec and Specification Drift Regarding Relaying of `mtxRollOver` and `mtxPrepareAcc`

- **Location:** [`smartcontracts/evm/src/pqz/PqzLayer.sol:30-31`](smartcontracts/evm/src/pqz/PqzLayer.sol#L30-L31), [`smartcontracts/evm/src/pqz/NoUnderlyingPqzToken.sol:78-79`](smartcontracts/evm/src/pqz/NoUnderlyingPqzToken.sol#L78-L79), [`smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol:144-150`](smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol#L144-L150)
- **Claim:** Code comments in [`PqzLayer.sol:30-31`](smartcontracts/evm/src/pqz/PqzLayer.sol#L30-L31) state that `mtxRollOver` and `mtxPrepareAcc` are not relayable (citing CTR-ZTH-34), directly contradicting Owner Rule 2 ("every state-changing `mtx*` call is relayable") and the actual implementation in `UnderlyingPqzToken.sol` and `NoUnderlyingPqzToken.sol`.
- **Evidence:**
  In [`PqzLayer.sol:30-31`](smartcontracts/evm/src/pqz/PqzLayer.sol#L30-L31):
  ```solidity
  /// the shared entry points are IConfidentialToken's (plan 5h D20), allowlisted on both relaying paths (fee
  /// class ABSOLUTE) and never batched (CTR-PQZ-21); the rollover and mtxPrepareAcc are not (CTR-ZTH-34).
  ```
  However, in [`UnderlyingPqzToken.sol:144-150`](smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol#L144-L150) and [`NoUnderlyingPqzToken.sol:78-79`](smartcontracts/evm/src/pqz/NoUnderlyingPqzToken.sol#L78-L79):
  ```solidity
  s[16] = IPqzState.mtxRollOver.selector;
  s[17] = IPqzState.mtxPrepareAcc.selector;
  ```
  The implementation conforms to the 2026-10-20 owner ruling (Task R / CTR-PQZ-07 Change), but the conflicting NatSpec in `PqzLayer.sol` creates integration risks for relayer developers who rely on contract documentation to configure allowlisted entry points.
- **Suggested Fix:**
  Update the header comment in [`PqzLayer.sol`](smartcontracts/evm/src/pqz/PqzLayer.sol#L30-L31) to reflect that `mtxRollOver` and `mtxPrepareAcc` are fully allowlisted and relayable in accordance with Owner Rule 2, deprecating the obsolete CTR-ZTH-34 note.

---

### [C0-4] P3: ERC-1271 Signature Verification Treats Internal Out-of-Gas as Invalid Signature in `UARegistry._native`

- **Location:** [`smartcontracts/evm/src/ua/UARegistry.sol:604-610`](smartcontracts/evm/src/ua/UARegistry.sol#L604-L610), [`smartcontracts/evm/src/ua/UARegistry.sol:650-662`](smartcontracts/evm/src/ua/UARegistry.sol#L650-L662)
- **Claim:** When verifying an ERC-1271 signature for a smart contract account (`KIND_NATIVE`), an internal out-of-gas error in the called contract can be interpreted as a signature rejection verdict (`false`) rather than reverting with `UAVerifyGas`.
- **Evidence:**
  In [`UARegistry.sol:658-662`](smartcontracts/evm/src/ua/UARegistry.sol#L658-L662):
  ```solidity
  function _starved(bytes memory err, uint256 g) private view {
      if ((err.length == 4 && bytes4(err) == UAKinds.UAVerifyGas.selector) || (err.length == 0 && gasleft() < g / 63)) {
          revert UAKinds.UAVerifyGas();
      }
  }
  ```
  When `_capped` invokes the target contract with `cap` gas, if the called contract consumes all forwarded gas without reverting with `UAVerifyGas`, but the caller's frame retains at least `g / 63` gas (where `g` was sampled before the call), `_starved` does not revert. As a result, [`UARegistry.sol:651`](smartcontracts/evm/src/ua/UARegistry.sol#L651) returns `false`. A relayer can intentionally supply minimal gas to cause an ERC-1271 verification to fail silently without triggering a gas starvation revert.
- **Suggested Fix:**
  In `_capped`, compare `gasleft()` after the call against the forwarded `cap`; if the call failed with empty return data and consumed the entire `cap` budget, revert with [`UAKinds.UAVerifyGas()`](smartcontracts/evm/src/ua/UAKinds.sol#L16).

---

### [C0-5] P3: Opaque Generic Revert on Modexp Precompile Failure in `ZetherVerifier._inv`

- **Location:** [`smartcontracts/evm/src/zether/ZetherVerifier.sol:98-102`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L98-L102)
- **Claim:** Modexp precompile invocations in `ZetherVerifier._inv` revert via `require(ok)` without error data upon precompile failure.
- **Evidence:**
  In [`ZetherVerifier.sol:98-102`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L98-L102):
  ```solidity
  ok := staticcall(gas(), 0x05, m, 192, m, 32)
  ok := and(ok, eq(returndatasize(), 32))
  out := mload(m)
  ...
  require(ok);
  ```
  If the host chain does not implement the modexp precompile at address `0x05`, or if gas is exhausted within the precompile, the contract reverts with an empty revert payload rather than a specific error code, hindering diagnostic tracing during meta-transaction simulation.
- **Suggested Fix:**
  Replace `require(ok)` with `if (!ok) revert PrecompileFailed(0x05)`.

---

## 3. Checked and Sound

Each required invariant was systematically verified against the codebase:

1. **Proof Statement Binding (PQZ & Zether):**  
   [`PqzCore._header`](smartcontracts/evm/src/pqz/PqzCore.sol#L875-L880) and [`ZetherLib._header`](smartcontracts/evm/src/zether/ZetherLib.sol#L568-L574) bind `token`, `block.chainid`, `chainUid`, `sendCounter`/`accSeq`, $T$ read directly from state, recipient UAs, auditor UA, fees, and the transfer mode folded into `binding` (D15/W-A), preventing front-runners or relayers from swapping any field.

2. **Race-Freedom of Debits & Rollover Invariance:**  
   $T$ is derived from `accOf` and pending credits in [`PqzCore._total`](smartcontracts/evm/src/pqz/PqzCore.sol#L741-L760); by commutativity of modular addition, rolling over entries in $[r, p)$ shifts words into `accWords` without altering $T$, and debits un-roll $[p, \text{rolled})$ by resetting $\text{rolled} = \text{floor} = p$ while [`ROLL_AGE = 5`](smartcontracts/evm/src/pqz/PqzCore.sol#L795) and [`PqzCt.isZero(out)`](smartcontracts/evm/src/pqz/PqzCore.sol#L256) prevent front-running races and zero-ciphertext bypasses.

3. **Balance Conservation End-to-End:**  
   In [`PqzCore._debit`](smartcontracts/evm/src/pqz/PqzCore.sol#L840), [`PqzStateLib.shield`](smartcontracts/evm/src/pqz/PqzStateLib.sol#L64), and [`UnderlyingPqzToken.sol:56-62`](smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol#L56-L62), `totalShielded` precisely balances `shieldIn`, `fee`, `decoyFee`, and unshielding, with public tokens held in the sentinel `SHIELD_POOL` and scale conservation strictly asserted (`minted % scale == 0`).

4. **Privacy vs Spec Promises:**  
   Plaintext amounts and account balances remain strictly confidential behind lattice/ElGamal ciphertexts; in Op 7 multi-transfers, each decoy leg pays `minDecoyFee` identically to real legs ([`PqzLayer._pay`](smartcontracts/evm/src/pqz/PqzLayer.sol#L286-L294)), rollover consumes pending entries sequentially without skipping, and [`PqzCore._noAuditorParty`](smartcontracts/evm/src/pqz/PqzCore.sol#L233-L235) prevents the auditor UA from acting as a transfer party when `auditorOn == 1` (F-4).

5. **Disclosure (`verifyTransferAmount`):**  
   [`PqzViewLib.disclosureStatement`](smartcontracts/evm/src/pqz/PqzViewLib.sol#L36-L55) and [`PqzLayer.verifyTransferAmount`](smartcontracts/evm/src/pqz/PqzLayer.sol#L143-L151) reconstruct statement data from SSTORE2 op blobs without exposing secret keys, strictly test one leg $j$ for a candidate amount via zero-knowledge proof, and handle proof rejection via a safe `try/catch` wrapper returning `false` rather than reverting.

6. **Domain Separation of Signatures & Messages:**  
   Every signature check in [`UARegistry.sol`](smartcontracts/evm/src/ua/UARegistry.sol#L209-L211) and [`UAKinds.sol`](smartcontracts/evm/src/ua/UAKinds.sol#L448-L464) incorporates EIP-712 domain separation (`block.chainid`, `chainUid`, registry address, version `"1"`), distinct `purposeTag` constants (`PURPOSE_ZETHER_AUTH`, `PURPOSE_METATX`, `PURPOSE_POP`), and group-isolated `_keyOwner` mappings to block cross-chain, cross-token, cross-generation, or cross-kind replay.

7. **Classical Zether on BLS12-381:**  
   [`ZetherVerifier.sol:415-423`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L415-L423) and [`ZetherTranscript.sol:9-31`](smartcontracts/evm/src/zether/ZetherTranscript.sol#L9-L31) absorb the complete statement before prover commitments into a `"SCAAS-ZETHER-TRANSCRIPT-V1"` transcript, apply 512-bit scalar reduction with $< 2^{-250}$ bias, enforce non-zero challenges, replace epochs with monotonic `sendCounter`/`accSeq` nonces, and restrict deployment to dev chains ([`ZetherSafety.sol:14`](smartcontracts/evm/src/zether/ZetherSafety.sol#L14)).

8. **Post-Quantum Signature Conformance:**  
   Implementations for ML-DSA-44/65 ([`MlDsa.sol`](smartcontracts/evm/src/ua/MlDsa.sol)), FN-DSA-512 ([`FnDsa.sol`](smartcontracts/evm/src/ua/FnDsa.sol)), and SLH-DSA ([`SlhDsa.sol`](smartcontracts/evm/src/ua/SlhDsa.sol)) strictly match standard parameter sets (modulus $q$, polynomial degree $N$, norm bounds, and small-order rejection), compute expanded keys solely on-chain via `cacheExpandedKey`, and format message digests via [`PqUA.emptyContext`](smartcontracts/evm/src/ua/PqUA.sol#L27-L34) ($M' = \mathtt{0x0000} \parallel M$) in strict compliance with FIPS 204/205.

9. **PQZH Calldata Cap & Proposal (A) Conformance:**  
   Proposal (A) preserves all four owner rulings: ciphertexts remain in full contract state (Rule 1), all valid `mtx*` entry points remain relayable (Rule 2), no assumptions of zero gas price or chain-specific block limits are made (Rule 3), and `fee = 0` remains completely valid (Rule 4).

---

## 4. Not Covered

The following components were outside the scope of Unit C0 and were not reviewed:
- The internal cryptographic proof system algorithms, relation reductions, and C/Rust implementation of the `PQZ` precompile at address `0x...5caa0f01` (reviewed separately on 2026-10-25).
- Legacy UA generation-1 contracts in [`smartcontracts/evm/src/legacy/ua6/`](smartcontracts/evm/src/legacy/ua6/).
- Test suites, deployment scripts, and simulation harnesses in `smartcontracts/evm/test/` and `smartcontracts/evm/script/`.
- Off-chain relayer nodes, indexers, RPC proxies, and client-side proof-generation libraries.
