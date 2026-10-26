# Security Review Report: Unit C1 — On-Chain Cryptographic Verifier Code

**Target Commit:** `64549aa4`  
**Scope:** `smartcontracts/evm/src/ua/MlDsa.sol`, `FnDsa.sol`, `SlhDsa.sol`, `Shake.sol`, `PqNtt.sol`, `PqUA.sol`; `smartcontracts/evm/src/common/Bls12381.sol`, `HashToCurve.sol`, `Ed25519.sol`, `Sha512.sol`, `CurveSigs.sol`, `SigCheck.sol`, `WebAuthnClientData.sol`, `MultiSig.sol`; and the Zether verifier math under `smartcontracts/evm/src/zether/`.  
**Review Mode:** Strictly read-only analysis against standard specifications (FIPS 202, FIPS 204, FIPS 205, FIPS 206 draft, RFC 8032, RFC 9380, EIP-2537, EIP-7951 / RIP-7212).

---

## Findings

### C1-1: P256Precompile bypasses low-$s$ check and public key validation during pure Solidity fallback
- **Severity:** P2
- **File & Lines:** [`smartcontracts/evm/src/ua/verifiers/P256Precompile.sol:30-35`](smartcontracts/evm/src/ua/verifiers/P256Precompile.sol#L30-L35)
- **Claim:** When deployed on EVM chains where the `0x100` (`P256VERIFY`) precompile is not present, `_p256Verify` delegates immediately to OpenZeppelin's `P256.verifySolidity`, bypassing the low-$s$ non-malleability constraint ($s \le N/2$) and public key validation (`isValidPublicKey`).
- **Evidence:**
  In [`P256Precompile.sol:30-35`](smartcontracts/evm/src/ua/verifiers/P256Precompile.sol#L30-L35):
  ```solidity
  function _p256Verify(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) internal view returns (bool) {
      if (!PRECOMPILE) return P256.verifySolidity(h, r, s, x, y);
      if (uint256(r) == 0 || uint256(r) >= P256.N || uint256(s) == 0 || uint256(s) > _HALF_N) return false;
      if (!P256.isValidPublicKey(x, y)) return false;
      return _call(h, r, s, x, y);
  }
  ```
  If `PRECOMPILE` is `false` (determined at deployment if `0x100` is missing or fails the probe vector), line 31 returns the output of `P256.verifySolidity(h, r, s, x, y)`. Lines 32–33 are never executed. 
  OpenZeppelin's `P256.verifySolidity` only verifies standard ECDSA ($0 < r < N$, $0 < s < N$) and does not enforce $s \le N/2$. As a result, an attacker can submit malleable signatures $(r, N - s)$ which pass verification on chains without precompile `0x100`, violating the contract's contract-level invariant documented in [`WebAuthnP256Verifier.sol:11-12`](smartcontracts/evm/src/ua/verifiers/WebAuthnP256Verifier.sol#L11-L12) ("low-s P-256 over sha256(...)") and producing inconsistent signature validity across different EVM environments.
- **Suggested Fix:**
  Execute range, low-$s$, and public key validity checks *before* evaluating the `!PRECOMPILE` branch:
  ```solidity
  function _p256Verify(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) internal view returns (bool) {
      if (uint256(r) == 0 || uint256(r) >= P256.N || uint256(s) == 0 || uint256(s) > _HALF_N) return false;
      if (!P256.isValidPublicKey(x, y)) return false;
      if (!PRECOMPILE) return P256.verifySolidity(h, r, s, x, y);
      return _call(h, r, s, x, y);
  }
  ```

---

### C1-2: WebAuthnClientData allows unclosed or unvalidated trailing JSON suffixes
- **Severity:** P3
- **File & Lines:** [`smartcontracts/evm/src/common/WebAuthnClientData.sol:30-35`](smartcontracts/evm/src/common/WebAuthnClientData.sol#L30-L35)
- **Claim:** When `clientDataJSON` contains `,"crossOrigin":false` followed by a comma `,`, `WebAuthnClientData.parse` returns `true` without verifying that the remainder of the payload is closed with `}`.
- **Evidence:**
  In [`WebAuthnClientData.sol:30-35`](smartcontracts/evm/src/common/WebAuthnClientData.sol#L30-L35):
  ```solidity
  bytes memory crossFalse = ',"crossOrigin":false';
  uint256 after_ = end + 1 + crossFalse.length;
  if (after_ >= n || hashSlice(cd, end + 1, crossFalse.length) != keccak256(crossFalse)) return (false, 0, 0);
  if (cd[after_] == "}") return (after_ + 1 == n, originStart, originLen);
  return (cd[after_] == ",", originStart, originLen);
  ```
  If `cd[after_] == ","`, the function returns `(true, originStart, originLen)`. It fails to check if the character at `n - 1` is `}` or whether any bytes follow. A truncated payload ending abruptly with `,` (e.g., `{"type":"webauthn.get","challenge":"...","origin":"...","crossOrigin":false,`) or payloads with unclosed/malformed trailing data will be judged valid.
- **Suggested Fix:**
  Ensure that when `cd[after_] == ","`, the payload is at least terminated with `}` at `cd[n - 1]`, and enforce that no unexpected keys or formatting can bypass parsing bounds:
  ```solidity
  if (cd[after_] == "}") return (after_ + 1 == n, originStart, originLen);
  if (cd[after_] == ",") return (cd[n - 1] == "}", originStart, originLen);
  return (false, 0, 0);
  ```

---

### C1-3: BLS12-381 `verifyMinSig` accepts identity points for both signature and public key
- **Severity:** P3
- **File & Lines:** [`smartcontracts/evm/src/common/Bls12381.sol:123-134`](smartcontracts/evm/src/common/Bls12381.sol#L123-L134)
- **Claim:** Direct invocation of `Bls12381.verifyMinSig` does not reject identity points ($\mathcal{O}_{G1}$ or $\mathcal{O}_{G2}$). If both signature and public key are encoded as zero bytes (the identity element in EIP-2537), the pairing equation evaluates to $1 = 1$, returning `true` for arbitrary messages.
- **Evidence:**
  In [`Bls12381.sol:123-134`](smartcontracts/evm/src/common/Bls12381.sol#L123-L134):
  ```solidity
  function verifyMinSig(
      bytes memory negG2Generator,
      bytes memory hashedMsgG1,
      bytes memory pubkeyG2,
      bytes memory sigG1
  ) internal view returns (bool) {
      if (sigG1.length != G1_BYTES) revert BadLength(sigG1.length, G1_BYTES);
      if (hashedMsgG1.length != G1_BYTES) revert BadLength(hashedMsgG1.length, G1_BYTES);
      if (pubkeyG2.length != G2_BYTES) revert BadLength(pubkeyG2.length, G2_BYTES);
      if (negG2Generator.length != G2_BYTES) revert BadLength(negG2Generator.length, G2_BYTES);
      return pairingCheck(bytes.concat(sigG1, negG2Generator, hashedMsgG1, pubkeyG2));
  }
  ```
  In EIP-2537, point at infinity $\mathcal{O}$ is encoded as all zeros. If `sigG1 == bytes128(0)` and `pubkeyG2 == bytes256(0)`, the precompile checks:
  $$e(\mathcal{O}, -G_2) \cdot e(H(m), \mathcal{O}) = 1 \cdot 1 = 1$$
  which evaluates to `true` for any `hashedMsgG1`. While the higher-level wrapper [`CurveSigs.bls12381`](smartcontracts/evm/src/common/CurveSigs.sol#L62-L65) rejects zero signatures via `_isZero(sig)`, the `Bls12381` library function does not enforce non-identity points on `sigG1` or `pubkeyG2`.
- **Suggested Fix:**
  Add explicit identity guards within `Bls12381.verifyMinSig` before performing the pairing check:
  ```solidity
  if (_isZero(sigG1) || _isZero(pubkeyG2)) return false;
  ```

---

## Checked and Sound

The following critical cryptographic invariants were audited and confirmed mathematically and behaviorally sound:

1. **ML-DSA (FIPS 204):** [`MlDsa.sol:137-216`](smartcontracts/evm/src/ua/MlDsa.sol#L137-L216) strictly checks infinity norm bound $\|z\|_\infty < \gamma_1 - \beta$ (`_decodeZ`), enforces canonical hint counts $\le \omega$ with strictly ascending indices (`_hints`), rejects non-zero padding bits, and computes $w_1$ via standard `_useHintEncode`.
2. **FN-DSA / Falcon-512 (FIPS 206 draft):** [`FnDsa.sol:78-124`](smartcontracts/evm/src/ua/FnDsa.sol#L78-L124) rejects negative zero (`-0`) encodings, checks $|s_2| \le 2047$, verifies zero padding via `_zeroTail`, rejects unreduced candidates $t \ge 61445$ in `_hashToPoint`, and enforces the squared $\ell_2$-norm bound $\|s_1\|^2 + \|s_2\|^2 \le 34,034,726$.
3. **SLH-DSA (FIPS 205):** [`SlhDsa.sol:41-89`](smartcontracts/evm/src/ua/SlhDsa.sol#L41-L89) correctly formats 22-byte ADRSc structures, computes WOTS+ chains step-by-step, unpacks FORS tree indices correctly, and checks staticcall success and return size.
4. **FIPS 202 SHAKE128 / SHAKE256:** [`Shake.sol:173-195`](smartcontracts/evm/src/ua/Shake.sol#L173-L195) correctly applies domain separator `0x1f` and pad10*1 `0x80` (yielding `0x9f` upon byte boundary alignment), unrolls Keccak-f[1600], and protects memory layout by halting with `ShakeMemory` if free memory pointer $\ne 0x80$.
5. **Polynomial NTT & Modular Arithmetic:** [`PqNtt.sol:34-83`](smartcontracts/evm/src/ua/PqNtt.sol#L34-L83) accurately implements FIPS 204 Algorithms 41 & 42, prevents underflows in INTT via bias `big := shl(220, q)`, and computes exact inverses via Fermat's Little Theorem ($n^{q-2} \pmod q$).
6. **Ed25519 (RFC 8032):** [`Ed25519.sol:44-93`](smartcontracts/evm/src/common/Ed25519.sol#L44-L93) enforces canonical scalar range $S < L$, coordinate range $y < 2^{255}-19$, explicitly rejects all 8 small-order points (`smallOrderY`), reduces SHA-512 outputs mod $L$ bitwise, and validates point equality.
7. **FIPS 180-4 SHA-512:** [`Sha512.sol:18-80`](smartcontracts/evm/src/common/Sha512.sol#L18-L80) correctly computes multi-block 128-byte block expansion and big-endian 128-bit bit length padding across calldata inputs.
8. **RFC 9380 Hash-to-Curve:** [`HashToCurve.sol:20-65`](smartcontracts/evm/src/common/HashToCurve.sol#L20-L65) correctly implements `expandMessageXmd` with SHA-256, uniform reduction mod $P$ using the `0x05` MODEXP precompile, and complete SSWU map-to-curve for BLS12-381 G1.
9. **EIP-2537 Precompile Integration:** [`Bls12381.sol:70-108`](smartcontracts/evm/src/common/Bls12381.sol#L70-L108) correctly maps precompile addresses (`0x0b` to `0x11`), enforces 64-byte field element encodings, verifies return size (`0x20`) and return value (`== 1`), and verifies G2 subgroup membership via scalar multiplication (`requireInG2Subgroup`).
10. **MultiSig Quorum & Anti-Replay:** [`MultiSig.sol:38-60`](smartcontracts/evm/src/common/MultiSig.sol#L38-L60) enforces non-zero thresholds $\le \text{owners.length}$, validates strictly ascending signer addresses (`rec > last`), and prevents duplicate or zero-address signer bypasses.
11. **ERC-1271 & EIP-7702 Delegation:** [`SigCheck.sol:26-70`](smartcontracts/evm/src/common/SigCheck.sol#L26-L70) detects EIP-7702 delegation designation code (`0xef0100`), enforces low-$s$ ECDSA recovery, and guards against relayer gas starvation via the EIP-150 $64/63$ gas margin check.
12. **Zether Sigma Protocols & Bulletproofs Math:** [`ZetherVerifier.sol:60-450`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L60-L450) and [`ZetherTranscript.sol:20-80`](smartcontracts/evm/src/zether/ZetherTranscript.sol#L20-L80) strictly enforce Bulletproofs vector folding reductions, distinct transcript domain separators for relations E1–E8, and scalar reductions modulo curve order $r$.

---

## Not Covered

The following components and areas were outside the scope of Unit C1 and were not analyzed:
- The native C++ / Rust implementation of the PQZ precompile at `0x...5caa0f01` (reviewed separately under `pqz-core/research/code-review-2026-10-25/`).
- Off-chain witness generation, proving pipelines, and client-side key generation routines.
- State-transition logic, fee collection, and balance accounting in `ZetherToken.sol`, `ZetherPool.sol`, and PQZ contract state.
- Meta-transaction relay infrastructure, gas sponsorship policies, and account registration workflows in `UARegistry.sol`.
- Deprecated legacy UA-6 contracts under `legacy/ua6/` (e.g., `zether-bn254`).
