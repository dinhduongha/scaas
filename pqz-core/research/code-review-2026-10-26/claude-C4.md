# C4 — Claude UltraCode review (64549aa4)

Unit: Universal Account registry, accounts and wallets (code). The review was read-only at commit 64549aa4. Committed parameter set: n2304-kmax4096.

Two findings survived refutation, both P3. No P0, P1 or P2 issue was found.

## Findings

| id | severity | file:line | claim | evidence | fix |
|---|---|---|---|---|---|
| C4-C1 | P3 (3/3 votes) | `docs/contracts/accounts.md:365`, `:1492`; also `docs/contracts/pq-zero-knowledge.md:74`, `:1760` | The spec still gives the old PQZ key size (16,384 B) and the old `R_REG` verify cap (3,000,000) for scheme `0x0142`. The cap is a constructor argument (`UARegistry.sol:154-157`, `verifier \| cap << 160`, used at `:424`). A deployer who takes 3 M from accounts.md gets a registry that refuses every PQZ key registration. This fails closed and puts no funds at risk. The revert may be `UAVerifyGas` or `UAPoP`, depending on the path (`:623-633`). | accounts.md:365: "`pk` (`PqzCt.PK`; 16,384 now) … `UAPqzVerifier` → PQZ precompile `0x…0F01` op 3 (cap 3,000,000 on the SCaaS testnet)". accounts.md:1492: "SSTORE2 16 KB". `PqzSet.sol:30` has `PK = 18_432`, and `PqzCt.PK` is `PqzSet.PK` (`PqzCt.sol:24`). `script/pqz/e2e.py:53` has `CAP_PQZ = 4_500_000`. Its comment at `:49-52` says 3,000,000 "refused every PQZ key registration" (PQZL 3.62–3.67 M) and that PQZH needs ≥ 5.1 M. `decisions.md:3569` item (5) and `pq-zero-knowledge.md:2035-2036` agree with that. pq-zero-knowledge.md:447 already gives the per-set values 16,384 / 18,432 / 20,480 / 22,528. | In accounts.md:365 and :1492, give `PqzSet.PK` per set (16,384 / 18,432 / 20,480 / 22,528 B). Change the testnet cap to 4,500,000 (PQZL), with a note that a PQZH registry needs ≥ 5.1 M. Correct the 16,384 B figures at pq-zero-knowledge.md:74 and :1760. |
| C4-C2 | P3 (2 confirm, 1 refute as test-coverage / NatSpec only) | `smartcontracts/evm/src/ua/UARegistry.sol:79-87` (`MSIG_MEMBER_GAS` NatSpec), `:464-501` (`_checkMembers`), `:562-586` (`_msig`); `smartcontracts/evm/test/ua/UAGas.t.sol:66-72`, `:111-117`, `:240-263` (`_bigSig`); `smartcontracts/evm/test/ua/UARegistryPq.t.sol:379-389`, `:426-448` | `MSIG_MEMBER_GAS` (35,000 per member) was calibrated only with classical signatures of at most 512 B. The msig structure bound has never been measured with PQ members, whose signatures run to 666 / 2,420 / 3,309 / 7,856 B (fndsa512 / mldsa44 / mldsa65 / slhdsa128s). Each member signature is copied into registry-frame memory three times: `abi.decode(auth,(bytes,bytes))` at `:522`, `abi.decode(blob,(MemberSig[]))` at `:567`, and `abi.encodeWithSelector` in `_verifierCall` at `:619`. Memory expansion is quadratic, so its cost grows with signature size and member count, while the bound stays flat. The NatSpec at `:85-86` says msigs registered exactly at `verifyBudget` authorize within it. That claim is broader than the test that backs it. | `_bigSig` reads only `vectors/ua/signatures.json`, asserting `rows == 22 + 91`. That file's derived kinds are 256–264 and 321 only, and its largest signature is 512 B (webauthn-p256). The PQ msig budget tests have c = 2: three mldsa65 members with t = 2 and mock signatures (`:379-389`), and {mldsa65, clone} (`:426-448`). No test has c ≥ 8 large PQ signatures. Worst case: 8 × slhdsa128s (cap 1.4 M) + 1 clone, t = 9. Its bound is 11,930,873 ≤ 12 M, so it registers. The memory added by about 5.9–6.5 k words is estimated at about 104–125 k gas. Estimates of the bound's slack range from about 109 k to about 170 k (holds are checked before each call, not consumed). So the margin is probably positive, but it has not been measured. If the bound were exceeded, the result is a clean `UAVerifyGas` revert, never a false verdict. No consumer pins `verifyBudget` (ERC20MetaTx.sol:347/450, PqzCore.sol:817 and ZetherLib.sol:641 forward the remaining gas), and the 2^24 transaction cap leaves about 4.7 M of headroom. | Add synthetic or real PQ signature rows (up to 7,856 B) to the `_bigSig` source. Add an at-budget case to `test_T_GAS_msigAtBudget` with c ≥ 8 slhdsa128s members at real signature size, each capped call burning its cap. If that case fails, add a signature-size term per PQ member kind in `_checkMembers` or raise `MSIG_MEMBER_GAS`. Correct the NatSpec at UARegistry.sol:85-86 and UAGas.t.sol:111-117 to name the signature sizes the measurement covers. |

## Refuted

| claim | reason refuted |
|---|---|
| Registering a PQZ holder (mldsa65, no ML-DSA precompile, PQZH `R_REG`) exceeds the EIP-7825 2^24 limit | Under EIP-8037, SSTORE2 writes are state gas, which the 2^24 regular cap does not count (`pqz-core/params/sets/README.md:116-129`). The path is measured in `runs/2026-10-26-t8d2b-gas-n2304-kmax4096.txt:77-78`: regular gas is 14.84 M, the EIP-7976 floor. Adding the Solidity ML-DSA PoP (+5.83 M) gives 14.26–15.27 M, which is still within each set's floor and under 2^24. One doc nit remains: the `register` row at pq-zero-knowledge.md:2176 still says "16 KB pk". |
| A PQ-eligible msig that passes the structure bound cannot register its PQZ key under EIP-7825, because the bound ignores `R_REG` | `0x0142` is enabled only on the e2e registry (`e2e.py:519-522`), where ML-DSA uses the precompile at a 200 k cap. There the worst case is 16 × 235 k ≈ 3.8 M, so a registration is about 10.5 M. DeployBase never enables `0x0142`. The finding also sums caps as if they were gas actually spent. |
| A PQZ-holder msig passes the bound, then every PQZ debit fails, so its funds are locked (P1) | Same configuration premise. DeployBase has no `PQZ_MLWE` (`DeployBase.sol:185`, `:224-231`), so `_pqzAttr` reverts `UAKindDisabled`. On the e2e registry, the largest msig fits beside the largest op. Reserving debit gas for holders in `_checkMembers` is at most a P3 hardening. |
| On a Hedera registry, an msig whose threshold needs a hedera-native member can never sign, so funds are locked | A long-zero contract account can pass the ERC-1271 branch. The limitation is documented (`UARegistry.sol:73-74`, `accounts.md:325`, `HederaAccountAuth.sol:11-13`). The owner can only lock their own funds this way, as with any keyless member; nobody else can trigger it. One doc inconsistency remains: accounts.md:1042 says "via HIP-632". |
| UAMldsaVerifier fixes the precompile at deploy time with no fallback, so moving the precompile locks ML-DSA UAs for good | The only deploy path passes `address(0)` (`DeployBase.sol:225-228`). A precompile-backed verifier exists only in the 7622 e2e script, on a test chain that may be reset. The probe-once behaviour is specified (`accounts.md:458`, `:849`). Removing or moving a precompile is a breaking hard fork; BLS and PQZ depend on their precompiles in the same way. |
| (duplicate of the previous row) A precompile change permanently locks ML-DSA UAs | Not reachable at this commit (`PRECOMPILE == 0` in every deployment). The design is the same intentional probe-into-immutable pattern used elsewhere (`P256Precompile.sol:20-27`). At most a P3 design note for P6g. |
| C4-7: the admin-free `UARegistry` does not check the verifier's `KIND` against `c.kind` | The deployer is already fully trusted: they could pass a verifier that always returns true, or set a wrong cap. Only UAMldsaVerifier exposes `KIND`, and DeployBase wires every kind correctly. Every mis-wiring that was traced fails closed. This is a hygiene note, not a defect. |

## Checked and sound

- **PoP bound to UA id, kind, chain and registry (CTR-UA-07).**
  - `popDigest = keccak(abi.encode(PURPOSE_POP, chainKeyHash, chainUid, registry, ua, pqzKeyHash))` (`UAKinds.sol:220-224`). `chainKeyHash` comes from `block.chainid` in the constructor (`UARegistry.sol:171`).
  - The PoP is signed over `uaMessage(kind, POP, popDigest(ua,h))` (`:449`), and `ua = keccak(TAG(kind) ‖ keyData)` (`UAKinds.sol:185-188`).
  - `register` never reads `msg.sender`, and every record field comes from validated `keyData` or signed data (`:333-351`). A front-runner can only submit the identical record or get a revert.
  - Every check is a view or staticcall before any write, so a failure leaves no partial state.
  - The `popDigest` encoding matches `clients/ua-rs` and `ua-py`.
- **No squatting of ids or keys.**
  - A native-space id is refused (`:366`). `kindOf` is checked in both generations (`:367`).
  - A PQ-eligible msig always needs an m-of-n PoP, even with no PQZ key (`:444-446`).
  - A classical-dominant msig takes an empty PoP and cannot hold a PQZ key (`:396-398`).
  - `0x0142` cannot be registered as a kind: `_requireDerived` reverts `UAKindNotDerived` (`UAKinds.sol:149-151`, `:250`).
- **PQZ key attribute (`R_REG`) bound to the UA.**
  - `R_REG` runs over `uaMessage(0x0142, POP, popDigest(ua,h))` (`:420-428`), and the holder's own PoP covers the same h (`:446`, `:449`). The key can therefore be neither stripped nor swapped.
  - Precompile input: `u8(3) ‖ be32(STMT_REGISTER) ‖ opTag ‖ psid ‖ message ‖ pk ‖ proof`, with `STMT_REGISTER = 96 + PK` (`UAPqzVerifier.sol:65-75`, `PqzSet.sol:30`, `:42`). This matches pq-zero-knowledge.md:838 and :1749.
  - The verifier requires exactly `PK` bytes and `PqzCt.isCanonical` (`UAPqzVerifier.sol:51-53`), and accepts only exactly 32 bytes equal to 1.
  - Holder rule: mldsa44, mldsa65, fndsa512 or a PQ-eligible msig. `_pqEligible` counts the weight outside `0x0130-0x0133` (`:396-415`). `pqzPop` must be empty exactly when `pqzKey` is (`:391-402`).
  - The key is kept in full in SSTORE2 (`:425`). `PK + 1` is at most 22,529 B, under EIP-170, and the token re-checks the pointer's code length (`PqzCore.sol:861-865`).
- **keyOwner uniqueness.**
  - `_claim` and `_pqzAttr` check `keyOwner` in this generation and in gen 1 (`:281-284`, `:372-380`, `:399-401`). Each is written once (`:347-350`, `:425-426`).
  - keyHash groups: x-only for secp256k1 and P-256, MuSig2 and FROST via their prefix, full point or key otherwise, and `pqz-mlwe` separate (`UAKinds.sol:165-207`).
  - The gen-2 constructor refuses any kind, `0x0142` included, whose group gen 1 enables (`:155`, `:706-716`).
  - Canonical encodings are enforced: ed25519, BLS via MSM, bn254 G2 via pairing, FN-DSA with no spare bits, sorted msig ids (`UAKinds.sol:304-464`).
- **Generations and the kind-0 fall-through cannot be confused.**
  - `_authorized` hands a kind-0 record to gen 1, and gen 1, with predecessor 0, returns false (`:520-521`, `:645`).
  - In `_derived`, a stored kind needs `r.kind == kind` locally (`:541-542`). A non-stored kind needs `uaOf == id` (`:550`). A member of a kind gen 2 does not enable is handed to gen 1 with empty keyData (`:554`).
  - `recordOf`, `keyOf`, `kindOf`, `keyOwner` and `uaIndex` forward only on kind 0 (`:213-284`).
  - The gen-2 constructor checks the predecessor's generation, `chainUid` and `hederaNative` (`:143-147`).
  - `_starved` (the V2-5 / W-M fix, `:658-662`) is complete. It re-raises gen 1's `UAVerifyGas`, and an empty revert with `gasleft < g/63`. Any other revert stays a verdict.
- **uaAuthDigest, purposes and the EIP-712 domain.**
  - SaltedEIP712 domain: name, version = generation, live chainid, registry, salt = chainUid. It is rebuilt when chainid or address changes (`SaltedEIP712.sol:58-69`, `UARegistry.sol:139`).
  - `ua_msg = keccak(MSG_TAG ‖ TAG(kind) ‖ purpose ‖ digest)` (`UAKinds.sol:209-211`).
  - The msig member digest binds the structure UA under `PURPOSE_MEMBER` (`:568`, `:580-581`).
  - Every consumer passes a fixed purpose (ERC20MetaTx.sol:146/160/171/347/359/386, MetaTokenBase.sol:357, PqzCore.sol:817, ZetherLib.sol:641). None uses `POP` or `MEMBER`. Zether Schnorr has its own tag (`PairingVerifiers.sol:111-125`).
- **Native-id verification (CTR-UA-24).**
  - Empty code or a 7702 designator gets ECDSA via OZ `tryRecover` over `uaAuthDigest` (low-s, no `address(0)`). Other code gets ERC-1271, capped at 50 k, or 400 k for the exact SmartKeyAccount clone codehash (`:172-176`, `:591-611`).
  - A pass needs exactly 32 bytes equal to the left-aligned selector.
  - `_capped` (`:625-636`) holds `cap + cap/63 + 5 k` before the call and writes only to scratch memory.
- **The expanded-key cache cannot be poisoned.**
  - Only `expandedKeyPart(pk, part)` from the kind's verifier is stored, under `uaOf(kind, pk)`, after `pk` is validated. Each part is written once, and the cache is refused for precompile verifiers (`:300-313`).
  - `_expanded` returns pointers only when the cache is complete (`:316-323`). Only the registry's own pointers reach `verifyCached`, which checks the part count, each part length and the total (`MlDsa.sol:505-526`).
  - Part sizes (20,544 / 15,360 / 21,568 B) fit EIP-170.
- **msig structure and verification.**
  - Layout: count 1–16, exact length, ids strictly increasing, weights > 0, native kind iff native-space id, `0 < threshold <= total` (`UAKinds.sol:438-453`).
  - `kindOf(member) == kind` is checked at registration (`:476`). `MEMBER` excludes msig, Zether and `0x0142`.
  - `_msig` needs strictly increasing indexes below the count, stops at the threshold, and needs empty keyData for native members (`:572-585`).
  - Apart from C4-C2, the bound's choice of c (the lightest weights), the c largest caps and one hold is sound.
- **Per-kind lists.** `_list` appends once per registration, and holders are also added to the `0x0142` list (`:230-235`, `:427`). `_listedHere` forwards a kind this generation does not enable (`:239-241`). `uaPage` clips at the end (`:254-263`). Decoy flooding is the known W-C.
- **SmartKeyAccount and its factory.**
  - The implementation is locked in its constructor. `initialize` is factory-only, runs once, and runs in the same transaction as the clone. The salt is (firstKey, guardian) (`SmartKeyAccount.sol:82-97`, `SmartKeyAccountFactory.sol:27-41`).
  - Key management is `onlySelf` behind the MetaTxBase ticket, and `execute` cannot re-enter (`MetaTxBase.sol:57-67`).
  - The account can never reach zero keys (LastKey), and rotate adds before it removes. A removed key slot becomes NONE, which verifies false.
  - The Merkle leaf is double-hashed.
  - WebAuthn checks rpIdHash, UP and UV, the strict clientDataJSON with its origin hash, and low-s P-256.
  - Recovery only adds a key, after 2 days, and can be cancelled.
  - `_mtxRule` static lengths 164 / 36 / 196 / 36 / 4 match the ABI.
- **MandateWallet.**
  - `payUnderMandate` checks the delegate, epoch, expiry, payee, both caps and the grid-aligned period (the W-L fix, `:126-130`), and allows each `entryRef` once.
  - State is written before `payWithFee`, under `nonReentrant`, and a false return reverts `PayFailed` (`:115-137`).
  - The epoch bumps on every `setMandate` and revoke (`:86`, `:238`), and the delegate's revoke is bound to the epoch.
  - Named builders derive the lanes. `from = wallet` is refused.
  - Static lengths 164 / 68 / 196 / 100 / 36 match the ABI.
  - The ECDSA-only ERC-1271 is the known W-K.
- **Hedera.**
  - HIP-632 is used only for 64-byte signatures from accounts without code. The CALL is capped at 100 k, and only exactly 32 bytes equal to 1 passes, so it fails closed (`HederaMandateWallet.sol:25-31`, `HederaAccountAuth.sol:23-27`).
  - `HederaLib.checkAndAssociate` bounds-checks the fee-array offsets and refuses any custom fee (`HederaLib.sol:33-48`).
- **PQ crypto glue (gap round).**
  - **Shake.sol** Keccak-f[1600]:
    - All 24 RC values, theta, all 25 rho/pi moves and chi rows match FIPS 202.
    - Rates are 168 / 136. Padding is 0x1F / 0x80, giving 0x9F when len = rate−1.
    - Lanes are little-endian via `_bswap`, and caller buffers cover the squeeze overrun.
    - The `reserve()` memory map does not overlap and is the first allocation at every entry; `via_ir = false`.
  - **PqNtt.sol**: `ntt` / `intt` follow FIPS 204 Alg. 41 / 42, with n⁻¹ applied via Fermat.
  - **Zeta tables**, recomputed: Falcon `10302^brv9(k) mod 12289` and ML-DSA `1753^brv8(k) mod 8380417` match exactly.
  - **FnDsa.sol**:
    - `_decompress` matches the reference `comp_decode`.
    - `_zeroTail` requires the padding to be zero.
    - `_hashToPoint` keeps draws `t < 61445`.
    - `BOUND = 34,034,726` with `<=`, as the NatSpec documents.
  - **SlhDsa.sol**:
    - The H_msg digest split is right.
    - ADRSc layout, FORS / WOTS / XMSS addressing and checksum nibbles are right.
    - The signature offsets total 7,856 B, and the final root compare is correct.
  - **MlDsa.sol**:
    - The parameters match FIPS 204.
    - Decoding is correct for ExpandA, t1, z, HintBitUnpack and SampleInBall.
    - UseHint handles the q−1 edge, and the 32 / 48-byte c~ compare is right.
  - **Message convention**: ML-DSA and SLH-DSA sign `pq_msg = keccak(TAG ‖ ua_msg)` with the empty context. FN-DSA signs `ua_msg`.
  - **Precompile probe**: exact lengths, answer 1 / 0.
  - **Deploy wiring**: DeployBase puts each verifier in its own slot. A mis-slotted PQ verifier fails closed.
- **Previous round.** The fixes are present: V2-4 / W-L (grid), V2-5 / W-M (`_starved`) and V2-6 / W-N (`chainKeyHash` in `IUARegistry.sol:45`). W-C, W-J and W-K are owner decisions and documented. Nothing has come back.

## Not covered

- The internals of the curve verifiers under `ua/verifiers/` (CurveSigs, PairingVerifiers beyond their domain tags, WebAuthnP256Verifier). These are outside this unit's crypto-glue scope.
- How the PQZ precompile binds `message` inside `R_REG`. The precompile is out of scope.
- Consumer digests (PqzCore / ZetherLib / ERC20MetaTx / DEX) beyond their purpose tags and statement headers.
- MetaTxBase's ticket and lane mechanics were read only where accounts and wallets use them.
- No gas was measured: the review was read-only. Still unmeasured are an at-budget PQ msig with c ≥ 8 large signatures (C4-C2) and whether the provisional `MSIG_MEMBER_GAS` and PQ caps are correct.