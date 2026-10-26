Reviewed frozen commit `64549aa4f95f52618edbb6d55ac9c90dc6abf5fb`. **One confirmed finding: P0 amount-privacy failure in audited Zether multi-recipient transfers.** No additional signature-forgery finding was established by static inspection.

## C1-1 — P0 — Shared auditor mask exposes amount differences and defeats zero-value decoys

**Locations:** `smartcontracts/evm/src/zether/ZetherVerifier.sol:538–566`, especially lines 546 and 562; `smartcontracts/evm/src/zether/ZetherLib.sol:577–594`, `:699–735`; `docs/contracts/zether.md:540–568`.

**Claim:** Every audited leg encrypts its amount under the same auditor key with the same randomness. Anyone reading the transaction can cancel that encryption mask, test amount differences, and identify equal-value legs. With zero-value decoys, this exposes the real recipient and permits amount recovery by candidate testing.

**Evidence:** `_sigmaLegs` assigns one response to every leg:

```solidity
l.zs = z[1];
```

Each `_sigmaLeg` then checks the auditor relation using that shared response:

```solidity
_z4(
    [l.g, l.ya, _lp(x, j, 2), _pf(x, 8 + 4 * j)],
    [zv, l.zs, l.nc, r1]
)
```

This implements the documented relation:

```text
C_aud_j = [v_j]G + [s]Y_a
```

Consequently, for any two legs:

```text
C_aud_i − C_aud_j = [v_i − v_j]G
```

The observer needs neither the auditor’s secret key nor a forged proof.

A concrete honest transfer demonstrates the failure:

1. Send amounts `(0, 0, 100)` to three distinct registered recipients with auditing enabled and any nonzero randomness `s`.
2. The two decoy auditor ciphertexts are identical: both equal `[s]Y_a`.
3. The remaining ciphertext differs from either decoy by `[100]G`.
4. An observer recognizes the equal decoy pair and tests the candidate amount `100` with one base multiplication and comparison. Transfers `(0,0,100)` and `(0,0,200)` are publicly distinguishable.

More generally, a recipient who knows its own amount obtains the common mask as `C_aud_i − [v_i]G`, exposing every other amount as a bounded discrete logarithm. Equality and candidate tests do not require solving a general curve discrete logarithm.

This is reachable through ordinary valid proofs. `ZetherLib._multiStatement` supplies one auditor key, and the ciphertexts are present in calldata regardless of storage mode. The contract also stores or emits the records where configured.

**Prior-review status:** This is absent from T/U/V1/V2/V3/T2’s findings. The PQZ R0-1 fix does not repair this separate classical Zether relation. The documented acceptance that voluntarily disclosing `s` opens all legs does not address disclosure to observers who never receive `s`.

**Suggested fix:** Give each auditor leg independent encryption randomness and bind its encryption of the same `v_j` into the proof. Update the corresponding auditor ephemeral points, statements, disclosure equations, prover, proof-system identifier and vectors together. A temporary containment is to reject audited transfers with more than one leg until the corrected relation exists.

Severity follows the requested P0 definition for amount-privacy breaks. The existing development-chain gate limits current deployment exposure.

## Checked and sound

These are source-review conclusions, not executed conformance results.

- **ML-DSA ranges and canonical encoding:** `MlDsa.sol:125–148`, `:263–312` enforce exact signature length, strict `‖z‖∞ < γ1−β`, bounded monotonic hint counts, strictly increasing indices and zero unused hint bytes.
- **Falcon decoding and norm:** `FnDsa.sol:25–57`, `:85–149` enforce headers, exact padded lengths, public coefficients below `q`, `|s2_i|≤2047`, rejection of negative zero, zero trailing bits and the squared-norm bound. The decoding structure agrees with the [Falcon reference codec](https://falcon-sign.info/impl/codec.c.html).
- **SLH-DSA reconstruction:** `SlhDsa.sol:29–51`, `:64–152` use the expected digest partition, compressed addresses, FORS indices, WOTS checksum and hypertree authentication paths for SHA2-128s. Address/hash layouts match [FIPS 205 §11.2.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).
- **Ed25519 canonicality and low-order handling:** `Ed25519.sol:34–74` requires `S<L`, canonical `y`, rejects small-order points, validates public-key decompression and compares the reconstructed `R` encoding exactly. It uses the cofactorless equation permitted by [RFC 8032 §5.1.7](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.7); this is not a separate prime-subgroup-membership test.
- **Hash/XOF boundaries and memory:** `Shake.sol:173–238` handles full-rate blocks and terminal padding separately; its callers provide space for whole-block output writes. `Sha512.sol:13–35` correctly separates the padding block at 111/112-byte boundaries and clears dirty padding memory. No exploitable memory overwrite was identified in the scoped paths.
- **NTT/modular arithmetic:** `PqNtt.sol:34–81` uses modular products, the matching inverse butterfly and final `n⁻¹` scaling. Lazy intermediate bounds remain below 256 bits for the two callers; these routines do not use Montgomery or Barrett representations.
- **EIP-2537 encoding and results:** `Bls12381.sol:74–108` and `ZetherCurves.sol:207–238` check call success and exact return lengths. Verification MSM/pairing paths supply subgroup checks as required by [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537#subgroup-checks).
- **Hash-to-curve:** `HashToCurve.sol:49–124` binds output length and DST in XMD, reduces both field elements and adds the cofactor-cleared maps, consistently with [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html).
- **Message/context binding:** `PqUA.sol:30–42` implements the documented UA/PQ tags and empty-context formatting. `UARegistry.sol:300–311` derives cached expanded keys itself under the public-key-derived UA identifier.
- **Zether proof equations:** Apart from C1-1’s privacy failure, the sigma balance/value equations, Bulletproof linkage, scalar bounds and transcript ordering in `ZetherVerifier.sol` showed no additional defect.
- **WebAuthn parsing:** `WebAuthnClientData.sol:19–34` binds the exact type/challenge prefix and bounds every hashed slice. Origin policy remains the caller’s responsibility; the comma suffix deliberately permits additional signed fields.
- **MultiSig and signature dispatch:** `MultiSig.sol:44–57` checks threshold bounds and strictly increasing recovered owners. `SigCheck.sol:53–69` checks recovery errors and requires an exact ERC-1271 answer through a capped call.

## Not covered

- No builds, compilation, tests, benchmarks, timing, deployments or chain calls were performed. No files were intentionally changed.
- Native precompile/proof-system internals, complete registry/token/factory/relay behavior, and off-chain provers or wallets were outside this unit.
- Test harnesses and selected vector material were read; the complete vector corpus was not individually inspected or executed.
- Cryptographic constant tables were inspected but not independently recomputed. Exhaustive reference-verdict parity and compiler-generated assembly behavior remain unverified.

Historical ciphertexts affected by C1-1 remain readable after a prospective fix.