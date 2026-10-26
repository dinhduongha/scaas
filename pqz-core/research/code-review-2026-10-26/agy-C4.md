# Independent Security Review Report: Unit C4 — Universal Account Registry, Accounts, and Wallets

- **Target Repository:** SCaaS (commit [`64549aa4`](file://.claude/worktrees/review-2026-10-26))
- **Review Unit:** C4 — Universal Account (UA) registry, accounts, and wallets
- **Compiler Target:** Solidity `^0.8.24`, Foundry 1.8.5, Amsterdam EVM profile
- **Mode:** Strictly read-only security audit

---

## 1. Executive Summary & Review Scope

Unit C4 comprises the identity registry, smart accounts, mandate delegation wallets, and Hedera account authentication adapters:
- **Registry & Kinds:** [`UARegistry.sol`](smartcontracts/evm/src/ua/UARegistry.sol), [`IUARegistry.sol`](smartcontracts/evm/src/ua/IUARegistry.sol), [`UAKinds.sol`](smartcontracts/evm/src/ua/UAKinds.sol), [`IUAVerifier.sol`](smartcontracts/evm/src/ua/IUAVerifier.sol), [`UAPqzVerifier.sol`](smartcontracts/evm/src/ua/UAPqzVerifier.sol), [`PairingVerifiers.sol`](smartcontracts/evm/src/ua/PairingVerifiers.sol), [`Secp256k1Verifier.sol`](smartcontracts/evm/src/ua/Secp256k1Verifier.sol), [`WebAuthnP256Verifier.sol`](smartcontracts/evm/src/ua/WebAuthnP256Verifier.sol).
- **UA Libraries:** [`Shake.sol`](smartcontracts/evm/src/ua/Shake.sol), [`PqUA.sol`](smartcontracts/evm/src/ua/PqUA.sol), [`PqNtt.sol`](smartcontracts/evm/src/ua/PqNtt.sol), [`MlDsa.sol`](smartcontracts/evm/src/ua/MlDsa.sol), [`SlhDsa.sol`](smartcontracts/evm/src/ua/SlhDsa.sol), [`FnDsa.sol`](smartcontracts/evm/src/ua/FnDsa.sol).
- **Accounts & Wallets:** [`SmartKeyAccount.sol`](smartcontracts/evm/src/account/SmartKeyAccount.sol), [`SmartKeyAccountFactory.sol`](smartcontracts/evm/src/account/SmartKeyAccountFactory.sol), [`MandateWallet.sol`](smartcontracts/evm/src/wallet/MandateWallet.sol), [`WebAuthnClientData.sol`](smartcontracts/evm/src/wallet/WebAuthnClientData.sol), [`SigCheck.sol`](smartcontracts/evm/src/common/SigCheck.sol), [`SaltedEIP712.sol`](smartcontracts/evm/src/metatx/SaltedEIP712.sol), [`MetaTxBase.sol`](smartcontracts/evm/src/metatx/MetaTxBase.sol), [`SSTORE2.sol`](smartcontracts/evm/src/storage/SSTORE2.sol).
- **Hedera Auth Adapters:** [`HederaAccountAuth.sol`](smartcontracts/evm/src/hedera/HederaAccountAuth.sol), [`HederaLib.sol`](smartcontracts/evm/src/hedera/HederaLib.sol), [`HederaMandateWallet.sol`](smartcontracts/evm/src/hedera/HederaMandateWallet.sol).

**Audit Conclusion:**
**Zero P0, P1, or P2 vulnerabilities were identified.** The codebase exhibits exceptional architectural rigor, strictly enforcing domain separation, monotonic state transitions, fail-closed authentication logic, replay immunity, and zero-squatting key possession checks. One P3 informational observation is noted for Hedera native account integrations.

---

## 2. Status of Previous Findings (2026-10-19 Round)

| Previous ID | Summary | Commit / Reference | Status | Verification Detail |
| :--- | :--- | :--- | :--- | :--- |
| **V2-1** | Decoy list flooding / S30 | `accounts.md` (CTR-UA-29, S30) | **Sound (By Design)** | Resolved per specification: wallet decoy selection is governed by client-side sampling policy weighted by on-chain activity; PQZ keys are dual-listed under dedicated kind `0x0142` in [`UARegistry.sol:346`](smartcontracts/evm/src/ua/UARegistry.sol#L346). |
| **V2-2** | `secp256k1` raw ECDSA vs Layer 4 / S23 | `accounts.md` (Row S23) | **Sound (Accepted Risk)** | Formalized as an accepted residual design limitation per owner ruling 2026-10-19, scheduled for revision during the post-P6 `personal_sign` overhaul. |
| **V2-3** | `MandateWallet` ERC-1271 raw digest vs ERC-7739 | `accounts.md` (§ lines 1744–1747) | **Sound (Accepted Risk)** | Confirmed by owner ruling 2026-10-19: nested ERC-7739 wrapping is intentionally omitted to prevent gas blowup; wallet verifies direct digests under strict nonces. |
| **V2-4** | `MandateWallet` period window boundary burst | Commit [`a59168c5`](smartcontracts/evm/src/wallet/MandateWallet.sol#L126-L130) | **Fixed & Verified** | [`MandateWallet.sol:128`](smartcontracts/evm/src/wallet/MandateWallet.sol#L128) now locks period boundaries to a fixed temporal grid from inception (`md.periodStart += uint64((now - periodStart) / periodSeconds * periodSeconds)`), strictly bounding cross-boundary bursts to $\le 2 \times \text{maxPerPeriod}$. |
| **V2-5** | Gen 1 out-of-gas classified as `UAUnauthorized` | Commit [`17c72d62`](smartcontracts/evm/src/ua/UARegistry.sol#L535-L540) | **Fixed & Verified** | [`UARegistry.sol:535-540`](smartcontracts/evm/src/ua/UARegistry.sol#L535-L540) introduces `_starved(err, g)` which checks `err.length == 0 && gasleft() < g / 63`, correctly bubbling up `UAVerifyGas` rather than masking an OOG error as unauthorized. |
| **V2-6** | `IUARegistry.chainKeyHash` missing & unpinned forge libs | Commit [`a94c9ffd`](smartcontracts/evm/src/ua/IUARegistry.sol#L45) | **Fixed & Verified** | `chainKeyHash` was added to [`IUARegistry.sol:45`](smartcontracts/evm/src/ua/IUARegistry.sol#L45); Foundry external libraries are pinned by exact git commit hash and sha256 checksum in `scripts/evm_libs.sh`. |

---

## 3. Findings

### C4-1 (P3): Hedera Native ED25519 Accounts Require Non-Static Frames for Meta-Transaction Authorization

- **File & Lines:** [`smartcontracts/evm/src/hedera/HederaMandateWallet.sol:25-31`](smartcontracts/evm/src/hedera/HederaMandateWallet.sol#L25-L31), [`smartcontracts/evm/src/hedera/HederaAccountAuth.sol:12-15`](smartcontracts/evm/src/hedera/HederaAccountAuth.sol#L12-L15)
- **Claim:** Native Hedera ED25519 accounts (64-byte signatures) cannot be verified via static ERC-1271 calls (`isValidSignature`) and can only authenticate through non-static meta-transaction entry points.
- **Evidence:**
  Hedera system contract `IHederaAccountService` at `0x16a` executes HIP-632 `isAuthorizedRaw`. Because the Java implementation in Hedera node (`IsAuthorizedRawCall.java`) does not enable `allowsStaticFrame()`, calling `0x16a` within a `STATICCALL` frame immediately halts and reverts.
  [`HederaAccountAuth.sol:12-14`](smartcontracts/evm/src/hedera/HederaAccountAuth.sol#L12-L14):
  ```solidity
  /// Phải gọi bằng CALL, không STATICCALL: `IsAuthorizedRawCall` không cài `allowsStaticFrame()` (mặc định
  /// false) nên system contract HALT trong frame tĩnh (`AbstractNativeSystemContract`).
  ```
  In [`HederaMandateWallet.sol:25-30`](smartcontracts/evm/src/hedera/HederaMandateWallet.sol#L25-L30), `_requireValidSignature` uses `HederaAccountAuth.asView()` which casts `isAuthorizedRaw` (a regular `CALL`) to a view function pointer via inline assembly. This functions correctly when called from non-static state-changing meta-transaction entry points (such as `mtxExecuteAsOwnerRaw`, `mtxPayUnderMandate`, or `mtxRevoke`). However, if an external caller invokes standard ERC-1271 [`isValidSignature`](smartcontracts/evm/src/account/SmartKeyAccount.sol#L104) via `STATICCALL` with a 64-byte ED25519 signature from a native account, HIP-632 reverts, causing `ok = false`, and the wallet safely fails closed (reverting or returning invalid).
- **Suggested Fix:** The current implementation correctly fails closed and documents this behavior in contract docstrings. External client SDK documentation and wallet integration manuals should explicitly emphasize that native ED25519 Hedera owners must interact via `mtxExecuteAsOwnerRaw` rather than standard static ERC-1271 off-chain verification.

---

## 4. Checked and Sound

Every invariant specified in the audit scope was systematically analyzed and verified sound against the codebase:

1. **Registration & Proof of Possession Binding:**
   - *Evidence:* [`UARegistry.sol:386-429`](smartcontracts/evm/src/ua/UARegistry.sol#L386-L429) computes `popDigest` committing to `(chainKeyHash, CHAIN_UID, address(this), ua, pqzKeyHash)`; [`_pop`](smartcontracts/evm/src/ua/UARegistry.sol#L405) verifies the signature over `uaMessage(kind, POP, popDigest)`, ensuring single keys are proven via their verifier and `msig` verifies member signatures; `keyOwner[kh]` reverts with `UAKeyInUse` if already claimed; `_pqzPop` validates `R_REG` proof over `popDigest(ua, h)`; and kind `0x0142` reverts `UAKindNotDerived` if attempted as a standalone UA.
2. **Generations & Predecessor Lookup Separation:**
   - *Evidence:* [`UARegistry.sol:145`](smartcontracts/evm/src/ua/UARegistry.sol#L145) enforces `_groupInPredecessor`, preventing Generation 2 from registering any group active in Generation 1; all query entry points (`recordOf`, `keyOf`, `kindOf`, `keyOwner`, `uaCount`, `uaAt`, `uaPage`, `uaIndex`, and `_authorized`) fall through to `predecessor` strictly when `_records[ua].kind == 0` or `!_listedHere(kind)`.
3. **Cross-Purpose and Cross-Chain Replay Immunity:**
   - *Evidence:* [`UARegistry.sol:209-211`](smartcontracts/evm/src/ua/UARegistry.sol#L209-L211) binds native authorizations to `uaAuthDigest` using typed struct `UAAuth(ua, purposeTag, digest)` under an EIP-712 domain salted with immutable `CHAIN_UID` and dynamic `block.chainid`; [`UAKinds.sol:184-188`](smartcontracts/evm/src/ua/UAKinds.sol#L184-L188) enforces domain tagging with `MSG_TAG`, `tag(kind)`, and distinct purpose tags (`TRANSFER`, `WITHDRAW`, `ROLLOVER`, `SIGNING`, `POP`), preventing cross-purpose and cross-chain message collisions.
4. **Expanded-Key Cache Integrity:**
   - *Evidence:* [`UARegistry.sol:291-318`](smartcontracts/evm/src/ua/UARegistry.sol#L291-L318) computes `expandedKeyPart` deterministically on-chain from the supplied `pk` using `UAMldsaVerifier`, writes to immutable SSTORE2 pointers indexed under `uaOf(kind, pk)`, strictly enforces `part` bounds, rejects verifiers that use precompiles (`UAKeyCache`), and enforces write-once immutability (`if (_ekPtr[ua][part] != address(0)) return ua`).
5. **Per-Kind Monotonic Lists & Decoy Pagination:**
   - *Evidence:* [`UARegistry.sol:340-349`](smartcontracts/evm/src/ua/UARegistry.sol#L340-L349) monotonically appends new IDs to `_list[kind]` during `_record`; [`uaPage`](smartcontracts/evm/src/ua/UARegistry.sol#L261-L272) cleanly clips pagination slices to the active list length; and PQZ keys are dual-listed under both their parent signing kind and `0x0142` (`PQZ_MLWE`) for client decoy discovery.
6. **SmartKeyAccount, MandateWallet, & Hedera Authentication:**
   - *Evidence:* [`SmartKeyAccount.sol:112-120`](smartcontracts/evm/src/account/SmartKeyAccount.sol#L112-L120) enforces lane 0 nonces, 400k clone gas limits, and a 2-day recovery delay cancelable by active keys; [`MandateWallet.sol:115-137`](smartcontracts/evm/src/wallet/MandateWallet.sol#L115-L137) enforces fixed-grid period rollovers, per-payment caps, single-use `entryRef` replay tracking, and epoch-invalidated revocations; and [`HederaMandateWallet.sol:25-30`](smartcontracts/evm/src/hedera/HederaMandateWallet.sol#L25-L30) cleanly routes 64-byte Ed25519 signatures through HIP-632 system contract `0x16a`.
7. **Access Control & Reentrancy Protections:**
   - *Evidence:* [`SmartKeyAccount.sol:76-79`](smartcontracts/evm/src/account/SmartKeyAccount.sol#L76-L79) restricts account management functions to `onlySelf` via self-executed meta-transactions; [`MandateWallet.sol:60-63`](smartcontracts/evm/src/wallet/MandateWallet.sol#L60-L63) strictly restricts configuration and ad-hoc executions to `onlyOwner`; and all meta-transaction entry points enforce OpenZeppelin `nonReentrant` guards and atomic nonce/ticket consumption.

---

## 5. Not Covered

The following components were explicitly outside the scope of this Unit C4 audit:
- The internal cryptographic proof systems and C++/Rust implementation of the `PQZ` precompile at `0x...5caa0f01` (audited separately in the 2026-10-25 review).
- The confidential token contract state transitions (`PqzToken.sol`, `ZetherToken.sol`, and related contracts under `smartcontracts/evm/src/pqz/` and `zether/`).
- Automated market maker / DEX swap contracts and token factory contracts outside the UA/account/wallet scope.
- Off-chain relayer infrastructure, indexing subgraphs, and client-side signing SDKs.
- Formal verification, gas benchmark measurements, or live compilation tests (in compliance with the strictly read-only audit mandate).
