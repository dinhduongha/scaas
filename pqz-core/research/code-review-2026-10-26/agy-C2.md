# Independent Security Review Report: Unit C2 — PQZ Confidential Token (Code)

**Repository:** `scaas` (frozen detached checkout at commit `64549aa4`)  
**Scope:** `smartcontracts/evm/src/pqz/` (all files), [`IConfidentialToken.sol`](smartcontracts/evm/src/confidential/IConfidentialToken.sol), [`PqzSet.sol`](smartcontracts/evm/src/pqz/PqzSet.sol), and the four generated parameter sets (`n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`, `n2816-kmax65536`).  
**Audit Constraints:** Strictly read-only analysis without compilation, test execution, or modification of state.

---

## Findings

### `C2-1`: Arithmetic Underflow in Single Transfer Statement View (Incomplete Fix of W-I)
- **Severity:** P3
- **File & Line:** [`PqzViewLib.sol:29`](smartcontracts/evm/src/pqz/PqzViewLib.sol#L29)
- **Claim:** Calling [`statementOf(1, e, payload)`](smartcontracts/evm/src/pqz/PqzViewLib.sol#L21-L36) with `payload.length < PqzCore.T_OUT` (208 bytes) causes an uncaught arithmetic underflow reverting with `Panic(0x11)` instead of cleanly reverting with [`IPqzToken.BadPayload(payload.length)`](smartcontracts/evm/src/pqz/IPqzToken.sol#L50).
- **Evidence:**
  In [`PqzViewLib.sol:28-32`](smartcontracts/evm/src/pqz/PqzViewLib.sol#L28-L32):
  ```solidity
  } else if (op == 1) {
      uint256 l = payload.length - PqzCore.T_OUT;
      e.mode = l == PqzCore.OUT_ON + PqzCore.MEMO || l == PqzCore.OUT_OFF + PqzCore.MEMO ? ZetherTypes.TransferMode.HASH : PqzCore._defaultMode();
      (, buf) = PqzCore.prepareTransfer(e, payload, payload[0:0], 0);
  }
  ```
  `payload.length - PqzCore.T_OUT` executes prior to calling [`PqzCore.prepareTransfer`](smartcontracts/evm/src/pqz/PqzCore.sol#L202-L210), which contains the canonical guard `if (len < T_OUT + memo) revert IPqzToken.BadPayload(len);`. By contrast, `op == 7` safely guards this in [`PqzCore.multiHasMemo`](smartcontracts/evm/src/pqz/PqzCore.sol#L388-L395) with `if (payload.length < M_OUT) return false;`, and `op == 2` safely guards it in [`PqzCore.prepareBurn`](smartcontracts/evm/src/pqz/PqzCore.sol#L556) with `if (payload.length != B_OUT + PqzCt.CT) revert IPqzToken.BadPayload(payload.length);`.
  In previous audit round T2 (`pqz-core/research/code-review-2026-10-19/T2-codex-chain.md` line 70), finding W-I noted: *"The single-statement view still underflows on very short payloads at `pqz/PqzLib.sol:695`."* When `PqzLib` was split across four delegatecall libraries (`PqzTransferLib`, `PqzBurnLib`, `PqzStateLib`, `PqzViewLib`), line 29 of `PqzViewLib.sol` remained unpatched.
- **Suggested Fix:**
  Add an explicit length check before subtraction in [`PqzViewLib.sol:29`](smartcontracts/evm/src/pqz/PqzViewLib.sol#L29):
  ```solidity
  } else if (op == 1) {
      if (payload.length < PqzCore.T_OUT) revert IPqzToken.BadPayload(payload.length);
      uint256 l = payload.length - PqzCore.T_OUT;
  ```

---

## Checked and Sound

1. **Statement bytes:** Statement buffers constructed across op 1 ([`_transferBuffer`](smartcontracts/evm/src/pqz/PqzCore.sol#L248-L267)), op 2 ([`_burnBuffer`](smartcontracts/evm/src/pqz/PqzCore.sol#L578-L594)), op 3 (UA registration statement via [`UAPqzVerifier.sol:60-70`](smartcontracts/evm/src/pqz/UAPqzVerifier.sol#L60-L70)), ops 4–5 ([`disclosureBuffer`](smartcontracts/evm/src/pqz/PqzCore.sol#L606-L639)), and op 7 ([`_multiBuffer`](smartcontracts/evm/src/pqz/PqzCore.sol#L444-L483) with $S_{\text{AUD}}$ auditor copy partitioning) match the byte layout, tag word offsets, and scalar alignments defined in `pqz-stmt` byte-for-byte across all four generated parameter sets (`n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`, `n2816-kmax65536`).
2. **Precompile calls:** Precompile invocation in [`PqzCore._verifyPrecompile`](smartcontracts/evm/src/pqz/PqzCore.sol#L508-L529) passes exact `gasBound`, targets immutable precompile address `0x...5caa0f01`, prefixes the exact 5-byte header (`0x50515a00` ‖ `op`), checks `success`, and strictly enforces `returndatasize == 32 && mload(out) == 1`.
3. **State transitions & anti-desync/griefing:** Invariants $cleared \le floor \le rolled \le pendingCount$ are strictly preserved in [`PqzCore._total`](smartcontracts/evm/src/pqz/PqzCore.sol#L697-L737) and [`PqzStateLib.sol`](smartcontracts/evm/src/pqz/PqzStateLib.sol); `accHint` hash verification prevents forged or stale accumulator states; split halves (`PREP0` / `PREP1`) prevent partial materialization desync; `ROLL_AGE = 5` blocks blocks frontrunning; strictly monotonic `sendCounter` prevents replay.
4. **P46 packing / unpacking & lane bounds:** Across all four parameter configurations (`PACK_BITS` 42, 46, 50, 54), the maximum unreduced accumulator lane bound $(ROLL\_MAX + 1) \cdot q < 2^{64}$ holds with $\ge 42$ carry guard bits in each 64-bit word, preventing arithmetic overflow across adjacent coefficient limbs during unreduced additions in [`PqzCt.sol:62-110`](smartcontracts/evm/src/pqz/PqzCt.sol#L62-L110).
5. **Ciphertext persistence & wallet recovery:** Full ciphertexts remain permanently accessible on-chain via SSTORE2 pointer references stored in [`entryPtr`](smartcontracts/evm/src/pqz/PqzCore.sol#L361) and packed `accWords` in contract storage; full wallet balance recovery is supported via [`pqzAccount`](smartcontracts/evm/src/pqz/PqzViewLib.sol), [`pqzAcc`](smartcontracts/evm/src/pqz/PqzViewLib.sol), [`pqzPendingCt`](smartcontracts/evm/src/pqz/PqzViewLib.sol), and [`pqzEntryBlob`](smartcontracts/evm/src/pqz/PqzViewLib.sol).
6. **Shield pool accounting & value conservation:** Value conservation strictly holds: in [`NoUnderlyingPqzToken.sol:41-47`](smartcontracts/evm/src/pqz/NoUnderlyingPqzToken.sol#L41-L47) and [`UnderlyingPqzToken.sol:45-51`](smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol#L45-L51), `_poolMove` adjusts `SHIELD_POOL` by exactly $\Delta = shieldIn - (txFee + M \cdot decoyFee)$ for transfers and $shieldIn - (amount + fee)$ for burns, matching `totalShielded` adjustments in `PqzCore._debit` and `_settleBurn`, while enforcing $d \ge minDecoyFee$.
7. **Auditor modes & AuditorAsParty:** [`PqzCore._parseTransfer`](smartcontracts/evm/src/pqz/PqzCore.sol#L282-L283) and [`PqzCore._parseMulti`](smartcontracts/evm/src/pqz/PqzCore.sol#L417-L418) enforce contract-level `auditorMode` (`NONE` rejects auditor copies; `FULL` requires auditor copies); [`PqzCore._noAuditorParty`](smartcontracts/evm/src/pqz/PqzCore.sol#L233-L235) and [`_legs`](smartcontracts/evm/src/pqz/PqzCore.sol#L438) prevent mask cancellation attacks by forbidding `auditorUA` from acting as either sender or recipient leg.
8. **Disclosure views:** [`PqzCore.disclosureBuffer`](smartcontracts/evm/src/pqz/PqzCore.sol#L606-L639) cleanly slices leg commitments $u_{g(j)}$ and $v_j$ (or $v_{a,j}$) from immutable SSTORE2 bundle data and binds window parameter $w = j \pmod{S_{\text{AUD}}}$ for auditor disclosures without exposing witness or secret noise data.
9. **ROLL_MAX gas bounds:** Relayed transactions via [`PqzLayer.mtxExecute`](smartcontracts/evm/src/pqz/PqzLayer.sol#L77-L100) and [`PqzLayer.uaExecute`](smartcontracts/evm/src/pqz/PqzLayer.sol#L125-L148) constrain rollover loops to $ROLL\_MAX \in \{32, 64, 80, 96\}$, guaranteeing total transaction gas remains below $0.75 \cdot 2^{24} = 12,582,912$ gas on customer chains enforcing EIP-7825 limits.
10. **Reentrancy & external calls:** All mutating external functions in [`PqzLayer.sol`](smartcontracts/evm/src/pqz/PqzLayer.sol) enforce the `nonReentrant` modifier; in [`UnderlyingPqzToken.sol:62-72`](smartcontracts/evm/src/pqz/UnderlyingPqzToken.sol#L62-L72), state updates strictly precede `UnderlyingLib.payOutTo` and ERC-20 `safeTransfer` calls.
11. **Access control & initialization:** Storage initialization in [`PqzCore.initializeStorage`](smartcontracts/evm/src/pqz/PqzCore.sol#L742-L771) is restricted to `factory`, checks precompile address probe and self-test verification, writes immutable configuration parameters, and prevents re-initialization.
12. **Relayability of mtx* calls:** Every state-changing entry point ([`mtxTransfer`](smartcontracts/evm/src/pqz/PqzLayer.sol#L84), [`mtxTransferMulti`](smartcontracts/evm/src/pqz/PqzLayer.sol#L86), [`mtxBurn`](smartcontracts/evm/src/pqz/PqzLayer.sol#L88), [`mtxRefresh`](smartcontracts/evm/src/pqz/PqzLayer.sol#L90), [`mtxPrepareAccHalf`](smartcontracts/evm/src/pqz/PqzLayer.sol#L92), [`mtxMaterializeAcc`](smartcontracts/evm/src/pqz/PqzLayer.sol#L94), [`mtxRollover`](smartcontracts/evm/src/pqz/PqzLayer.sol#L96)) is callable through both `mtxExecute` and `uaExecute` relay dispatchers, correctly handles $fee = 0$, and enforces no minimum gas price.

---

## Not Covered

- **PQZ Precompile Implementation & Cryptographic Proof Verification:** Out of scope by review definition; precompile binary logic and polynomial arithmetic at `0x...5caa0f01` were reviewed separately in the 2026-10-25 precompile audit round.
- **Classical Zether Contracts:** Contracts residing under `smartcontracts/evm/src/zether/` (BLS12-381 scalar / point arithmetic and $\Sigma$-protocols).
- **Universal Account (UA) Registry Internals:** Verifier and registry contracts under `smartcontracts/evm/src/ua/` (Falcon, Dilithium, and secp256k1 signature verification engines).
- **Tooling, Off-chain Provers & Build Infrastructure:** Rust proof generator engines in `pqz-core/`, deployment scripts, and Foundry testing harnesses (due to strictly read-only audit constraints).
