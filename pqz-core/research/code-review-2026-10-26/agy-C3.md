# Independent Security Review: Unit C3 — Zether Token on BLS12-381 (Code)

**Repository:** `scaas` (public detached worktree at commit `64549aa4`)  
**Scope:**
- `smartcontracts/evm/src/zether/` (all 14 files): [`ZetherSafety.sol`](smartcontracts/evm/src/zether/ZetherSafety.sol), [`ZetherTypes.sol`](smartcontracts/evm/src/zether/ZetherTypes.sol), [`IZetherVerifier.sol`](smartcontracts/evm/src/zether/IZetherVerifier.sol), [`ITransferDisclosure.sol`](smartcontracts/evm/src/zether/ITransferDisclosure.sol), [`IZetherToken.sol`](smartcontracts/evm/src/zether/IZetherToken.sol), [`ZetherCurves.sol`](smartcontracts/evm/src/zether/ZetherCurves.sol), [`ZetherTranscript.sol`](smartcontracts/evm/src/zether/ZetherTranscript.sol), [`ZetherStatements.sol`](smartcontracts/evm/src/zether/ZetherStatements.sol), [`ZetherVerifier.sol`](smartcontracts/evm/src/zether/ZetherVerifier.sol), [`ZetherLib.sol`](smartcontracts/evm/src/zether/ZetherLib.sol), [`ZetherLayer.sol`](smartcontracts/evm/src/zether/ZetherLayer.sol), [`NoUnderlyingZetherToken.sol`](smartcontracts/evm/src/zether/NoUnderlyingZetherToken.sol), [`UnderlyingZetherToken.sol`](smartcontracts/evm/src/zether/UnderlyingZetherToken.sol), [`ZetherDisclosure.sol`](smartcontracts/evm/src/zether/ZetherDisclosure.sol)
- `smartcontracts/evm/src/common/` (2 files): [`Bls12381.sol`](smartcontracts/evm/src/common/Bls12381.sol), [`HashToCurve.sol`](smartcontracts/evm/src/common/HashToCurve.sol)
- **Specifications & Decisions:** [`docs/contracts/zether.md`](docs/contracts/zether.md), [`docs/decisions.md`](docs/decisions.md) (CTR-ZTH-01 through CTR-ZTH-51).

---

## Findings

### C3-1: Multi-Recipient Ceiling Discrepancy with EIP-7825 Transaction Gas Cap
- **Severity:** P3 (Informational / Gas Limit Boundary)
- **File & Lines:** [`smartcontracts/evm/src/zether/ZetherLib.sol#L144`](smartcontracts/evm/src/zether/ZetherLib.sol#L144), [`smartcontracts/evm/src/zether/ZetherLib.sol#L464-L465`](smartcontracts/evm/src/zether/ZetherLib.sol#L464-L465)
- **Claim:** [`ZetherLib`](smartcontracts/evm/src/zether/ZetherLib.sol) enforces `MAX_RECIPIENTS = 16`, but on EVM chains enforcing EIP-7825 ($2^{24} = 16,777,216$ gas limit per transaction), transactions with $M \ge 8$ in `BUNDLE` mode (or $M \ge 9$ in `Compact`/`NONE` mode) exceed the maximum transaction gas ceiling and will revert out of gas at the EVM transaction boundary.
- **Evidence:**
  In [`ZetherLib.sol`](smartcontracts/evm/src/zether/ZetherLib.sol#L144):
  ```solidity
  uint256 private constant MAX_RECIPIENTS = 16;
  ```
  And in [`ZetherLib.sol#L464-L465`](smartcontracts/evm/src/zether/ZetherLib.sol#L464-L465):
  ```solidity
  uint256 m = uint256(bytes32(payload[80:112]));
  if (m == 0 || m > MAX_RECIPIENTS) revert IZetherToken.BadRecipientCount(m);
  ```
  However, specification [`docs/contracts/zether.md#L1408-L1409`](docs/contracts/zether.md#L1408-L1409) and [`docs/contracts/zether.md#L1435-L1445`](docs/contracts/zether.md#L1435-L1445) documents that for BLS12-381 `BUNDLE` transfers, $M = 8$ uses $18,499,048$ gas (auditor on) or $17,529,613$ gas (auditor off), requiring a transaction gas limit $> 18.5\text{M}$, well above $2^{24}$. While the off-chain `zether-prover` client clamps $M$ via `gas_limits` and refuses proofs exceeding $2^{24} - 167,772$, contracts compiled with `MAX_RECIPIENTS = 16` allow proof verification calldata up to $M = 16$ which can never execute on chains under EIP-7825 rules.
- **Suggested Fix:** Add a NatSpec notice on [`MAX_RECIPIENTS`](smartcontracts/evm/src/zether/ZetherLib.sol#L144) explaining that the constant represents the statement format maximum, but effective maximums on EIP-7825 networks are $M \le 6$ (relayed BUNDLE), $M \le 7$ (relayed Compact/NONE), and $M \le 8$ (direct Compact/NONE without auditor).

---

## Checked and Sound

1. **Protocol Equations & Transcript Binding:**
   The verifier [`ZetherVerifierBase`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L350-L596) checks all equations (E1–E8 in [`_sigmaTransfer`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L443-L486), E1–E8 with per-leg E3/E6/E7 in [`_sigmaTransferMulti`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L490-L567), and E1, E5, E8 in [`_sigmaBurn`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L575-L595)) without missing terms; Bulletproofs BP-1 and BP-2 range proofs are evaluated over the sequentially running Fiat-Shamir transcript ([`ZetherVerifier.sol#L397-L399`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L397-L399)); the 480-byte header absorbs `opTag`, `psid`, `chainId`, `chainUid`, `token`, `tag`, `binding`, `sendCounter`, `accSeq`, `fee`, `beneficiary`, `amount`, `recipient`, `salt`, and `memoHash` ([`ZetherLib.sol#L570-L574`](smartcontracts/evm/src/zether/ZetherLib.sol#L570-L574)); BLS12-381 subgroup membership is strictly validated on every point via `0x0c` G1MSM with returndatasize validation ([`ZetherCurves.sol#L235-L239`](smartcontracts/evm/src/zether/ZetherCurves.sol#L235-L239)).

2. **Ring / Decoy Handling:**
   Multi-recipient transfers validate recipient bounds $M \in [1, 16]$ ([`ZetherLib.sol#L465`](smartcontracts/evm/src/zether/ZetherLib.sol#L465)), enforce pairwise distinctness and reject self-transfers ([`ZetherLib.sol#L606-L607`](smartcontracts/evm/src/zether/ZetherLib.sol#L606-L607)), require active UA registration as `KIND_ZETHER_BLS12381` ([`ZetherLib.sol#L608`](smartcontracts/evm/src/zether/ZetherLib.sol#L608)), and the verifier independently rejects identity/self points via `_isZero(yt) || keccak256(yt) == l.yf` ([`ZetherVerifier.sol#L556`](smartcontracts/evm/src/zether/ZetherVerifier.sol#L556)).

3. **Epochs & Pending Rollover Protection:**
   Debits strictly check `provedAccSeq == a.accSeq` and `provedSend == a.sendCounter` before incrementing `sendCounter` ([`ZetherLib.sol#L613-L617`](smartcontracts/evm/src/zether/ZetherLib.sol#L613-L617), [`#L663`](smartcontracts/evm/src/zether/ZetherLib.sol#L663)); incoming credits affect only `pendC`, `pendD`, and `pendingSeq` ([`ZetherLib.sol#L678-L680`](smartcontracts/evm/src/zether/ZetherLib.sol#L678-L680)); [`_rollOver`](smartcontracts/evm/src/zether/ZetherLib.sol#L684-L695) is a silent no-op if no new credit arrived; `OWNER_ONLY` mode rejects public rollovers ([`ZetherLib.sol#L347`](smartcontracts/evm/src/zether/ZetherLib.sol#L347)); and [`rollOverSigned`](smartcontracts/evm/src/zether/ZetherLib.sol#L362-L381) requires an authorized UA Schnorr signature over `(TAG_ROLLOVER, chainid, chainUid, token, ua, accSeq, expectedPendingSeq, validUntilBlock)`, preventing griefing, locks, or replay.

4. **Value Conservation:**
   Value moves between public balances and confidential balances strictly through `SHIELD_POOL` ([`ZetherLayer.sol#L127-L132`](smartcontracts/evm/src/zether/ZetherLayer.sol#L127-L132), [`#L176-L178`](smartcontracts/evm/src/zether/ZetherLayer.sol#L176-L178); [`UnderlyingZetherToken.sol#L57-L64`](smartcontracts/evm/src/zether/UnderlyingZetherToken.sol#L57-L64), [`#L93-L96`](smartcontracts/evm/src/zether/UnderlyingZetherToken.sol#L93-L96)); `balanceOf(SHIELD_POOL) == totalShielded * shieldScale` is maintained, and fees are subtracted from `totalShielded` and disbursed in public units from `SHIELD_POOL` ([`ZetherLib.sol#L657-L659`](smartcontracts/evm/src/zether/ZetherLib.sol#L657-L659), [`ZetherLayer.sol#L247-L251`](smartcontracts/evm/src/zether/ZetherLayer.sol#L247-L251)).

5. **Ciphertext Storage in Contract State:**
   ElGamal account balances (`accC`, `accD`, `pendC`, `pendD`) are stored as full 128-byte G1 points in storage slot `_STORAGE` via [`Account`](smartcontracts/evm/src/zether/ZetherLib.sol#L44-L52) and never hashed; transfer records are persisted in contract storage as complete bundles in `BUNDLE` mode ([`ZetherLib.sol#L710`](smartcontracts/evm/src/zether/ZetherLib.sol#L710)) or committed via hash with memo in `HASH` mode ([`ZetherLib.sol#L712-L714`](smartcontracts/evm/src/zether/ZetherLib.sol#L712-L714)).

6. **Relayability & Transfer Mode Binding:**
   All 10 state-changing `mtx*` selectors are explicitly registered in [`mtxSelectors`](smartcontracts/evm/src/zether/NoUnderlyingZetherToken.sol#L58-L77), [`UnderlyingZetherToken.sol#L143-L170`](smartcontracts/evm/src/zether/UnderlyingZetherToken.sol#L143-L170), and [`_mtxRule`](smartcontracts/evm/src/zether/ZetherLayer.sol#L280-L287) with `FEE_CLASS_ABSOLUTE` (allowing `fee = 0`); the transfer mode (`HASH`, `BUNDLE`, `NONE`) is directly bound into `opTag` (`OP_MULTI_HASH`, `OP_MULTI_BUNDLE`, `OP_MULTI_NONE` in [`ZetherLib.sol#L585-L587`](smartcontracts/evm/src/zether/ZetherLib.sol#L585-L587)), preventing any relayer front-running or mode-stripping.

7. **Reentrancy and Access Control:**
   Every external state-changing method across [`ZetherLayer.sol`](smartcontracts/evm/src/zether/ZetherLayer.sol#L127-L208), [`NoUnderlyingZetherToken.sol`](smartcontracts/evm/src/zether/NoUnderlyingZetherToken.sol), and [`UnderlyingZetherToken.sol`](smartcontracts/evm/src/zether/UnderlyingZetherToken.sol#L57-L107) enforces `nonReentrant`; unshield-unwrap enforces Checks-Effects-Interactions by deducting state and burning from `SHIELD_POOL` prior to calling [`UnderlyingLib.payOutTo`](smartcontracts/evm/src/zether/UnderlyingZetherToken.sol#L93-L97); spending authority is strictly derived from the zero-knowledge proof of the private key ([`ZetherLib.sol#L644-L653`](smartcontracts/evm/src/zether/ZetherLib.sol#L644-L653)).

8. **Curve & Precompile Wrapping Safety:**
   [`Bls12381.sol`](smartcontracts/evm/src/common/Bls12381.sol) and [`HashToCurve.sol`](smartcontracts/evm/src/common/HashToCurve.sol) validate returndatasize on all calls to EIP-2537 precompiles (`0x0b`–`0x12`) and MODEXP (`0x05`), preventing truncated return values from being silently accepted as identity/zero elements.

9. **Dev Chain Gate Enforcement:**
   [`ZetherSafety.requireDevChain()`](smartcontracts/evm/src/zether/ZetherSafety.sol#L13-L16) is evaluated in [`ZetherLib.init`](smartcontracts/evm/src/zether/ZetherLib.sol#L167), preventing contract deployment or initialization on production chains outside chain IDs `31337` and `1337`.

---

## Not Covered

The following components were explicitly outside the scope of Unit C3 and were not audited:
1. The PQZ C/Rust cryptographic precompile at address `0x...5caa0f01` and its lattice proof system.
2. The Rust prover implementation (`clients/zether-prover/**`, `zether-cli`).
3. Universal Account registry signature verifiers outside BLS12-381 (e.g., Dilithium, Falcon, SPHINCS+, Secp256k1 FROST/MuSig2, Ed25519, Bip340).
4. Legacy bn254 Zether contracts under `smartcontracts/evm/legacy/`.
5. SCaaS DEX and Orderbook contracts (`smartcontracts/evm/src/dex/`).
6. Core Nethermind client plugins and RPC daemon implementations.
