# C1 — Claude UltraCode review (64549aa4)

Scope: on-chain cryptographic verifier code. This covers `smartcontracts/evm/src/ua/{MlDsa,FnDsa,SlhDsa,Shake,PqNtt,PqUA}.sol`, `smartcontracts/evm/src/common/{Bls12381,HashToCurve,Ed25519,Sha512,CurveSigs,SigCheck,WebAuthnClientData,MultiSig}.sol` and the Zether verifier math under `smartcontracts/evm/src/zether/`. The review was read-only: nothing was built, run or timed. Between fe2faf0 and HEAD, none of the PQ verifier files or the common hash / curve libraries changed; the only commits are in `zether/` and in FeePolicy / MetaTxLib. The depth below is therefore new work, not a repeat of the V2 spot-checks.

## Findings

| id | severity | file:line | claim | evidence | fix |
|---|---|---|---|---|---|
| C1-1 | P3 (informational: a precondition missing from the docs; no in-repo impact). Votes: 2 × P3, 1 × refuted as a doc nit | `smartcontracts/evm/src/zether/ZetherVerifier.sol:170-199` (verifyRange), `:184`, `:229-231` (BP-1 V term); `smartcontracts/evm/src/zether/IZetherVerifier.sol:82-83` | `ZetherInnerProductBase.verifyRange(st, V, proof)` is a public `external view` range-proof verifier, and it never absorbs `V`. It is sound only when the caller's `st` already binds `V`. Neither the interface nor the implementation natspec says so. | The only absorbs are `"bp.AS"` (`:184`: `abi.encodePacked(uint32(b.n), _slice(pr, 0, 2 * b.p))`), `"bp.T"`, `"bp.t"` and `"ipa.LR"`. `V` is used only in BP-1, `[t̂−δ]G + [τ_x]Hb − [z²]V − [x]T1 − [x²]T2 = O`, after y, z, x, w and u_j are all fixed. BP-1 is linear in V, z ≠ 0 is enforced, and BP-2 does not involve V. With an unbound `st` (for example `T.init()`), a forgery works in four steps: (1) pick any a_L, a_R that are not bits and post A, S; (2) take y, z and post T1, T2; (3) take x, then compute an honest l, r, t̂, τ_x, μ and IPA, so BP-2 holds; (4) set `V = z⁻²([t̂−δ]G + [τ_x]Hb − [x]T1 − [x²]T2)`. BP-1 then holds and the call returns true for an out-of-range value. This is the weak Fiat-Shamir ("Frozen Heart") pattern. **In the repo it is sound:** the sole caller is `_range` (`:397-399`). Every V it passes is a point inside `proof[0:sigmaLen]`, which `_ctx` absorbs as `"sigma.commit"` before `"sigma.c"` (`:420-422`). For transfer that is `_pf(0)` and `_pf(1)` with sigmaLen 10p; for multi, `_pf(6+4j)` and `_pf(0)` with (6+4m)p; for burn, `_pf(0)` with 4p. The docs imply the binding only for the combined protocol (docs/contracts/zether.md:241-243, §9 :470 "same transcript, right after c"). They say nothing about standalone use of the external `verifyRange`. `IZetherVerifier.sol:82` says only "One range proof (n = 64) of V on the running transcript st". The constructor calls `ZetherSafety.requireDevChain()`, so the code deploys on dev chains only. | Cheapest: add a natspec precondition to `IZetherInnerProductVerifier.verifyRange` and `ZetherInnerProductBase.verifyRange`: "`st` must already bind `V`; standalone use with an unbound `st` is unsound." Alternative: absorb `st = T.absorb(st, "bp.V", V)` before `"bp.AS"`. That is a transcript change, so the prover, ZetherStatements and the KATs must change with it. |

## Refuted

| claim | reason |
|---|---|
| The precompile probe accepts any contract as the EIP-8355 "precompile" (PqUA.sol:46-59, MlDsa.sol:460-468, :475), so a proxy or metamorphic candidate becomes a permanent universal-accept oracle | `candidate` is a constructor argument chosen by the deployer. That same trusted deployer picks the verifier addresses in the immutable registry kind config (UARegistry.sol:97-113, DeployBase.sol:218-231), so it could install an accept-all verifier directly. The probe guards against an honest mistake on a given chain (an empty or wrong precompile), not against a malicious deployer. Nothing is reachable today: DeployBase passes `address(0)`, and e2e.py only passes 7622's native precompile, which has no code. A `code.length == 0` check would be optional defense in depth only. |

## Checked and sound

**1. Each verifier accepts exactly the valid signatures of its standard**
- ML-DSA-44/65 (MlDsa.sol):
  - Params `:36-42` match FIPS 204 Table 1: k, l, τ, β, γ1, γ2 = (q−1)/88 and (q−1)/32, ω, ctLen 32/48, zBits 18/20, w1Bits 6/4, pk 1312/1952, sig 2420/3309 = 32+2304+84 and 48+3200+61. The signature length is checked exactly (`:125`).
  - `_decodeZ` (`:263-290`): z = γ1 − v over (−γ1, γ1], with exactly one encoding per z. It rejects ‖z‖∞ ≥ γ1 − β on both signs.
  - `_hints` (`:293-313`) is exactly HintBitUnpack (Alg. 21): `end < idx` or `end > ω` rejected, strictly increasing positions within a row, zero tail. Hints are canonical, so there is no malleability.
  - `_sampleInBall` (`:316-354`): SHAKE256 over the whole c̃ (final FIPS 204, not the draft's 32 bytes), 8 sign bytes little-endian, rejection j ≤ i, refill at 136.
  - ExpandA (`:219-241`): seed ρ‖s‖r with s = column and r = row. CoeffFromThreeBytes masks b2 & 0x7f.
  - Decompose/UseHint (`:377-408`): the r⁺ − r0 = q−1 corner gives r1 = 0 and r0 ≤ 0, so the hint goes to m−1 as FIPS does. w1Encode is 6/4 bits LE.
  - tr = H(pk,64), μ = H(tr‖M',64), c̃ compared on 32 or 48 bytes (`:152-174`, `:206-214`).
  - `_t1Hat`: 10-bit LE × 2^13.
- ML-DSA expanded-key path:
  - `_get` rejects coefficients ≥ q (`:411-421`).
  - `verifyCached` checks the part count, each part's length and the total (`:510-526`).
  - The registry feeds only SSTORE2 pointers it wrote itself from an authenticated pk via `expandedKeyPart` (UARegistry.sol:300-313, 445-452, 541-547).
  - Parts are 20,544 / 15,360 / 21,568 B, all under EIP-170.
- Falcon-512 (FnDsa.sol):
  - Headers and lengths: 0x09 / 0x39, PK 897, SIG 666 = 1+40+625. The pk is 14-bit BE with each coefficient < q.
  - comp_decode (`:100-151`) matches the reference: sign, 7 low bits, unary high part, m ≤ 2047, −0 refused, byte availability checked before every read. `_zeroTail` requires the unused bits and the padding to be zero.
  - HashToPoint (`:61-83`): 16-bit BE draws < 61445, then mod q.
  - s1 is centred at 6144. Two's-complement squares are exact. The bound is ≤ 34,034,726, the reference l2bound[9]; the deviation from the EIP-8052 text '<' is documented at `:10`.
- SLH-DSA-SHA2-128s (SlhDsa.sol):
  - H_msg = MGF1-SHA-256(R‖seed‖SHA-256(R‖seed‖root‖M'),30), split md 21 B / idx_tree mod 2^54 / idx_leaf mod 2^9 (`:35-39`).
  - FORS indices are base_2b big-endian 12-bit, tree index i·2^12+idx (`:71-106`).
  - WOTS checksum: shifted by 4, 3 nibbles, chain j = v..14 (`:118-135`).
  - ADRSc layout: layer(1)‖tree(8)‖type(1)‖3 words, right-aligned at buf+54.
  - Hypertree update order is correct (`:44-50`). Sig length is 7856.
- Ed25519 (Ed25519.sol), against RFC 8032 and dalek verify_strict:
  - S < L (`:36`); y < p for A and R.
  - The small-order y set {0, 1, p−1, ±Y8} is refused; Y8 was recomputed and has order 8.
  - x = 0 with the sign bit set is refused.
  - k = SHA-512(R‖A‖M) LE mod L.
  - R is compared as an encoding, so a non-canonical or off-curve R is refused.
- Schnorr (CurveSigs.sol:28-48):
  - z < r, e ≠ 0, R ≠ O, Y ≠ O, checked by one MSM `[z]G − R − [e]Y`.
  - bn254 points are checked canonical and on the curve in Solidity (cofactor 1). BLS12-381 points are subgroup-checked by G1MSM.
- BLS min-sig on both curves: sig ≠ O is refused, so pk = O cannot verify. The bn254 G2 generator is in EIP-197 order. The pairing output must be exactly 32 bytes and equal 1.
- BIP-340 / FROST / MuSig2 ecrecover identities and fail-closed corners are correct. secp256k1: low-s, v ∈ {27, 28}, r and s ≠ 0.
- SigCheck: OZ 5.2 `tryRecover` (65 bytes, low-s, never address 0). EIP-7702 designators are handled. ERC-1271 has a gas cap with the 63/64 guard, requires returndatasize 32 and compares the magic exactly (SigCheck.sol:26-70).
- Test vectors are present:
  - ML-DSA: ACVP sigVer (60 cases), EIP-8051/8355 cases, malformed hint / z / hint-count tests.
  - Falcon: NIST KATs as padded signatures, plus −0, unused-bit and padding mutants.
  - SLH-DSA: KAT and 28 ACVP cases.
  - Ed25519: RFC 8032 and dalek-parity fuzz.
  - SHA-512: FIPS cases and block boundaries.
  - RFC 9380: K.1 vectors.

**2. Hash / XOF correct for every length; assembly memory safety**
- Keccak-f[1600] (Shake.sol):
  - All 24 iota constants (`:30-53`), all 25 ρ offsets and π destinations (`:73-97`) were checked lane by lane against FIPS 202.
  - θ D[x] = C[x−1] ^ rot1(C[x+1]) (`:66-70`); χ keeps lanes at 64 bits.
  - An offline transliteration matches hashlib for lengths 0, 1, 135, 136, 137, 167, 168 and 300.
- SHAKE padding: 0x1F … 0x80, giving 0x9F when len = rate−1; a full-rate input gets a separate pad block.
- Shake memory map: lanes [0x80, 0x3a0), temporaries to 0x6c0, round constants to 0x9c0, PAD to 0xaa0 = END. There is no overlap.
- Shake guards:
  - `reserve()` requires the free pointer to be 0x80, and foundry.toml has `via_ir = false`.
  - `absorb` re-checks that guard.
  - Every external PQ entry point calls `reserve()` first.
- Squeeze overruns (160/192 B) land in alloc(6) = 192 B buffers. In `expandKeyRows`, the tr overrun lands in the t̂1 region, which is written afterwards (MlDsa.sol:97-105). Sponge states are never interleaved.
- SHA-512 (Sha512.sol):
  - All 80 K constants and the IVs were recomputed.
  - All 64 schedule tuples (t−2, t−7, t−15, t−16) with σ0/σ1 use shr 71/70 on x·(2^64+1).
  - The a..h role renaming over all 80 rounds was verified by script.
  - Padding end = 128·⌊(len+144)/128⌋ = ⌈(len+17)/128⌉·128.
- RFC 9380 expand_message_xmd (HashToCurve.sol:49-78): Z_pad 64, l_i_b_str 2-byte BE, 0x00, DST_prime = DST‖len, the b_i strxor chain, ell ≤ 255, DST ≤ 255. hash_to_field (L = 64) reduces via MODEXP and checks the output length.
- ZetherTranscript framing is injective: `st‖0x00‖u8 len‖label‖u32 len‖data` for absorb and `st‖0x01‖u8 len‖label` for challenge. The 33-byte hashToScalar seeds (`‖0x02` / `‖0x03`) cannot collide with the ≥ 34-byte transcript inputs.

**3. NTT / modular arithmetic**
- Zeta tables, recomputed for every entry:
  - `MlDsa.ZETAS` = 1753^brv8(k) mod 8380417 (all 256).
  - `Falcon512.ZETAS` = 10302^brv9(k) mod 12289 (all 512); 10302 = 11^12 and 10302^512 = −1.
- PqNtt (`:34-83`) follows FIPS 204 Alg. 41/42:
  - The lazy forward bound (1+log n)q feeds only mulmod / addmod / reduce.
  - intt adds q<<220, which stays above every intermediate, so t − u never underflows.
  - n⁻¹ is computed by Fermat.
- Ed25519 constants: D, 2D, √−1, L and 2^256 mod L were recomputed, and all 45 jB table words match. The dbl-2008-hwcd / add-2008-hwcd-3 formulas are correct. Every unreduced operand is < 2p and feeds only mulmod.
- Zether: amounts ≤ maxShielded ≤ 2^54, fee < 2^64 (ZetherLib.sol:513-552), at most 16 recipients. The balance sum therefore stays far below r and cannot wrap mod r.

**4. EIP-2537 calls: encoding, return checks, gas**
- Addresses 0x0b–0x11 follow the final EIP numbering.
- Every call (Bls12381.sol, HashToCurve.sol, ZetherCurves.sol, plus bn254 0x05–0x07) checks success and the exact output length.
- Subgroup checks come through G1MSM / G2MSM / PAIRING_CHECK; `isValid` uses an MSM with k = 1.
- `NEG_G2_GENERATOR` = (x, p − y) of G2, recomputed.
- `G1Bls12381.neg` borrows correctly across the two words; a non-canonical y fails closed at the next precompile.
- UASafeVerifier caps gas and turns reverts into false (PairingVerifiers.sol:43-51).
- Gas is bounded. Per-kind caps sit under the 2^24 per-transaction cap. The uncached ML-DSA-65 cost (about 18.9 M) is documented at accounts.md:1094. No loop can be lengthened by a third party.

**5. No out-of-bounds assembly reads or writes on adversarial lengths**
- Every calldata bit read stays inside its polynomial; the over-reads are masked.
- SLH-DSA hash inputs are 102 / 118 / 310 / 646 B, inside 160 / 704 B buffers.
- Every Zether `_slice` / `_copy` / `_word` offset lies within proof or statement lengths that are checked first. Lengths: transfer 42p+512, burn 20p+256, multi (6+4m)p + ….
- SSTORE2 init code `61 LLLL 80 600c 6000 39 6000 f3` is 12 bytes, and reads skip the STOP byte.
- `WebAuthnP256Verifier._bytesAt` bounds offset and length with no overflow.

**6. Message encoding (context strings, domain tags)**
- ML-DSA and SLH-DSA sign M' = 0x00‖0x00‖keccak256(TAG(kind)‖ua_msg); Falcon signs ua_msg. This matches PqUA.sol:36-43, accounts.md CTR-UA-23 and clients/clientkeys/src/pq.js:47-81.
- PoP is separated from authorization by `PURPOSE_POP` (UAKinds.sol:44), which differs from all ten other purpose tags. Every `requireAuthorized` caller passes a constant non-POP purpose (ERC20MetaTx.sol:146/160/171/347/359/386, ZetherLib.sol:641, PqzCore.sol:817). So `verifyPop == verify` cannot turn a PoP into an authorization.
- `GEN_DST` (ZetherVerifier.sol:643) differs from `DST_SIG` / `DST_POP` (PairingVerifiers.sol:85-86) and from the FROST DSTs.
- The 130 NUMS messages (h/0, U/0, G/0..63, H/0..63) are distinct.
- The blob layout h = 0, U = 1, G = 2..65, H = 66..129 matches every reader. Σ and the BPs use the same h (`generatorStore` copied from innerProduct).
- Zether statement binding: the whole statement is absorbed before c. The token builds a header holding op, psid, chainid, chainUid, token, tag, binding, sendCounter, accSeq, fee, beneficiary, amount, recipient, salt and memoHash (ZetherLib.sol:567-575). A proof therefore does not replay across tokens or chains.
- Zether math:
  - Every Σ commitment, including V_v / V_b / V_vj, is absorbed before c. The only gap is the standalone-use precondition in C1-1.
  - All scalars are < r and all challenges are ≠ 0.
  - δ(y,z), BP-1 and BP-2 (with s_i⁻¹ = s_{n−1−i}) match Bulletproofs.
  - E1–E8 are consistent for single, multi and burn.
  - Y_f ≠ Y_t, D_out ≠ O. With the auditor off, C_aud = A_aud = O is forced.
- ZetherDisclosure Chaum-Pedersen: e binds tag, chainid, chainUid, token, entryRef, index, amount, kind, A1 and A2. amount < 2^64, z < r, e ≠ 0. The statement points are fixed by on-chain state.
- Inner-product trust: ZetherLayer.sol:46-60 pins `ip == t.innerProduct() == b.innerProduct()` from the registrar's Env.deps. This is the same trust root as the verifiers themselves.

**7. WebAuthn client-data parsing cannot be confused**
- The prefix is fixed: type `webauthn.get` and a base64url challenge without padding.
- The origin runs up to the first `"`. After it comes exactly `}` at the end, or `,"crossOrigin":false` followed by `}` or `,`. `crossOrigin:true`, reordering and whitespace all fail closed.
- Every index is bounds-checked before `hashSlice`.
- rpIdHash and the UP+UV flags are required. Low-s is enforced on both P-256 paths (P256Precompile.sol:30-35 and OZ verifySolidity).

**8. MultiSig threshold and duplicate-signer checks**
- `requireQuorum` (MultiSig.sol:38-60) requires 1 ≤ threshold ≤ owners.
- Recovered signers must be strictly increasing, so there are no duplicates and no address(0). OZ recover refuses high s.
- Membership is a binary search; an unsorted owners array can only cause false negatives.
- The library has no callers in src/.

## Not covered

- The `PQZ` precompile and its proof systems (out of scope; reviewed separately).
- The PQZ contracts under `src/pqz/`, apart from the PoP purpose call site PqzCore.sol:817.
- `ua/verifiers/*` beyond the BIP-340 / FROST / MuSig2 identities, PairingVerifiers and the P-256 / secp256k1 checks named above.
- No KAT, fuzz, gas or timing run (read-only review). Test-vector coverage was judged by reading the test sources, and the reference computations were done offline.
- All critic gaps were closed in the gap round: inner-product trust, the NUMS generator derivation and blob layout, ZetherTranscript framing and continuity, statement-to-context binding, and PoP vs authorization separation. Results are under items 3–6 above.