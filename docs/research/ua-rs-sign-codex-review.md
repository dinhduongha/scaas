> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Codex security review of the revised `ua-rs-sign` spec, 2026-11-05 (kept verbatim; requested by the owner after the Fable counter-review).

# Security review: ua-rs-sign

Reviewed branch `ua-rs-sign`, HEAD `ba3b7578a9bc59c3134fb48e10e343fca7a67e08`, 2026-11-05. **UNAUDITED.** This is a source-and-standards review of a SPECIFIED design, not an assertion that its proposed implementation already exists. No builds, tests, generators, installs, benchmarks or mutations were run; this report is the only file written. Findings are additional to Fable, except where an applied fix remains incomplete, identified below. Severity describes the consequence of implementing the text as written.

12 findings: 3 high, 8 medium, 1 low. No critical finding established.

## 1. High — The proposed scalar blinding is erased by the pinned curve implementation

**Spec:** §3, §12; spec lines 115–119, 606–611. Incomplete application of Fable's smaller scalar-blinding note.

**Problem:** `k + rho*r` cannot be represented as an arkworks scalar field element without becoming `k` again. More subtly, passing an unreduced wide integer to the usual **projective** `mul_bigint` is also insufficient here: both pinned G1 curve configurations convert its limbs back to `ScalarField` before GLV multiplication. Thus even an implementation that carefully avoids field arithmetic while constructing the blinded integer can remove the entire mitigation at the multiplication boundary. The remaining multiplication depends on the original signing secret/nonce, despite the spec claiming blinding narrows that exposure.

**Concrete fix:** Specify the exact secret-multiplication path. It must preserve the unreduced integer through multiplication, bypassing the reducing GLV override; preferably use a constant-time secret-scalar implementation. If retaining blinding as a partial mitigation, specify the blinding width and zeroization, and explicitly retain the side-channel residual. Add a structural/instrumented check that different blinders reach the multiplication loop as different integers; public-point equality alone cannot detect removal of blinding. Apply this to long-lived secret and nonce multiplications, including the relevant facade/group paths.

**Evidence:** `clients/ua-rs/src/verify.rs:218` demonstrates the existing scalar-multiplication idiom; `clients/zether-prover/src/keys.rs:116` uses it for key construction. In local pinned crate sources, `ark-ec 0.5.0`, `src/models/short_weierstrass/group.rs:282` dispatches `mul_bigint` to the curve configuration; `ark-bn254 0.5.0`, `src/curves/g1.rs:43–48`, and `ark-bls12-381 0.5.0`, `src/curves/g1.rs:57–59`, both call `ScalarField::from_sign_and_limbs` before GLV. The generic double-and-add path is itself variable time (`ark-ec 0.5.0`, `src/scalar_mul/mod.rs:48–57`), so bypassing GLV is not a constant-time proof.

## 2. High — Wallet locking does not specify revocation or destruction of outstanding key handles

**Spec:** §8.2, §9.1–§9.2, §15; spec lines 323–326, 374–376, 411–412, 454–455, 714–715. Incomplete F-46 fix after introducing cached key handles.

**Problem:** `ua_key`, `native_key` and `kem_key` return owned types without a borrow lifetime, and §15 says the handles hold the derived keys. `Wallet::lock()` nevertheless promises to drop **every** secret. There is no rule tying those allocations to locking or wallet destruction. A straightforward implementation leaves an earlier handle able to sign or decapsulate after locking. Alternatively, freeing their backing storage during lock/free leaves dangling handles. `Send + Sync` and concurrent C calls make this a synchronization issue as well as an ownership issue. Calling UAF/double-free undefined does not answer whether freeing the wallet invalidates a separately owned, otherwise valid key handle.

**Concrete fix:** Define one wallet-owned secret store and revocation generation; derived handles reference that store and check the generation under the same lock used by signing/decapsulation. Lock waits for in-flight operations, wipes the secrets, and makes existing handles return `WalletLocked`/`KeyRevoked`; unlock must not silently reactivate old handles. Specify wallet-free behavior and require caller synchronization against freeing the *same* C handle during use. Include native, KEM, Zether/PQZ and group-session secrets. Check derive → lock → sign/decapsulate refusal, wallet-free with retained child handles, and concurrent lock/sign behavior.

**Evidence:** The incompatible lifetime and custody promises are in the cited spec lines. The current C ABI has no handles (`clients/ua-c/include/scaas_ua.h:6–12`); its thread-safety statement cannot establish the new handles' lifetime semantics. Rust signatures at spec lines 374–376 do not prevent a key from outliving or coexisting with a mutable lock of its wallet.

## 3. High — Container authentication trusts a sender identity supplied by the container itself

**Spec:** §6.3, §8.4; spec lines 266–279, 352–355. Incomplete F-07/F-43 fix.

**Problem:** The opener verifies `sender.sig` against the registry key for `sender.ua`, but both come from the untrusted container. No independently expected sender is an input to verification/import. An attacker with any registered signing UA can seal attacker-chosen recovery material to the victim's public recovery KEM key, set `sender.ua` to the attacker's UA and provide a completely valid signature. All stated checks pass. A restore/link flow that treats this as the user's authenticated backup can install an attacker-known wallet. Binding the self-asserted sender in AAD prevents editing that field; it does not establish that this is the sender the user intended.

**Concrete fix:** Give the container-verification/import operation an independently trusted `expected_sender_ua` (or a locally approved sender set), expected purpose, and expected recipient descriptor. Refuse mismatch before importing any material. Define where each caller obtains the trust anchor: existing wallet identity for restore, or an independently authenticated pairing identity for linking. Registry key resolution must authenticate the key-to-UA relationship. Add a refusal case with an otherwise valid container signed by a different registered UA. Do not treat the embedded manifest as the trust anchor.

**Evidence:** The container schema and entire stated opener check are at spec lines 274–279. `clients/ua-rs/src/lib.rs:307–320` provides the derived-key-to-UA binding needed for verification but cannot establish an expected identity. [RFC 9180 §5.1.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.3) distinguishes key authentication from binding an application identity; the application still needs an independently selected peer.

## 4. Medium — SCaaS canonicalization changes arbitrary EIP-712 messages

**Spec:** §5.3–§5.4, §9.4; spec lines 167–184, 504. Incomplete F-22 fix at the general-wallet boundary.

**Problem:** Field-name matching applies SCaaS mode semantics recursively to every struct containing `mode`, `relayer`, and `feeRecipient`. `sign_typed_any` is also a general EVM wallet interface. An unrelated contract can have those names with different semantics. For example, an unrelated `Order(uint32 mode,address relayer,address feeRecipient,uint256 amount)` with `mode=0` and nonzero addresses is silently signed with zero addresses. This either fails at its verifier or authorizes a different order if the changed value is submitted. The explicit opt-in to arbitrary typed data does not authorize rewriting it. The reference's helper matching these fields is only reached through its known-operation builder; the generic reference hasher does not do this.

**Concrete fix:** Keep generic EIP-712 hashing and `sign_typed_any` faithful to the supplied values. Apply canon in checked SCaaS record builders only, using their authenticated schema/operation context; recursion there remains appropriate for nested SCaaS records. Make clear-signing devices see exactly the final value hashed. Add an unrelated-domain/struct example with these three field names and assert its standard EIP-712 digest remains unchanged.

**Evidence:** `clients/clientkeys/src/evm.js:377–385` defines the heuristic, but `evm.js:439` invokes it from the operation builder; `evm.js:54–60` hashes supplied typed values without canon. `smartcontracts/evm/src/common/MetaTxLib.sol:92–100` supplies specific SCaaS semantics. [EIP-712, Definition of encodeData](https://eips.ethereum.org/EIPS/eip-712#definition-of-encodedata) encodes member values, not semantics inferred from field names.

## 5. Medium — KEM derivation does not define how a key handle proves ownership by the supplied wallet

**Spec:** §6.1, §9.1–§9.2; spec lines 210–219, 376, 430.

**Problem:** The KEM seed uses the wallet seed and the handle's UA, while the API takes those as separate objects. The text calls this the wallet's “own” handle but specifies only a KEM-holder kind check. With a valid holder handle from wallet A passed to wallet B, an implementation can derive a different `(ek, pk_X)` for the same `(ua, version)`. The result defeats the stated one-key-per-version construction and can cause durable loss of decryptability when the wrong key is recorded/backed up. Two handles being valid and of the correct kind is insufficient.

**Concrete fix:** Tie derived handles to an unforgeable wallet-instance identity and check it in `kem_key`, or derive the KEM key through the UA handle's owning secret store without accepting a second wallet. Specify that cross-wallet handles are refused even when both wallets are unlocked. The self-test cache must follow the actual key/store identity, not just `(ua, version)`. Check the two-wallet substitution explicitly.

**Evidence:** Formula and checks at spec lines 210–219; the Rust and C calls independently accept the wallet and UA handle at lines 376 and 430. `clients/ua-rs/src/lib.rs:307–320` binds a UA to its public signing key, not to any BIP-39 seed supplied separately.

## 6. Medium — Indexed derivation silently aliases keys on the EIP-2333 UA paths

**Spec:** §3–§4, §8.3, §9.1, §11; spec lines 93–94, 135, 344–345, 374, 575.

**Problem:** The Schnorr/BLS EIP-2333 paths terminate at `<kindNo>` and contain no `index`, although `ua_key(kind, account, index)`, the manifest, discovery, and vectors model an index for every kind. At fixed seed/account/kind, indices 0 and 1 therefore produce the same secret and UA. A caller can believe it created independent identities while reusing one key; gap-limit discovery for these kinds also repeatedly yields the same candidate. Byte-equality against a generator using the same omission will not detect this.

**Concrete fix:** Preserve the currently specified paths and refuse `index != 0` for these kinds, record that constraint in the manifest/discovery API, and test the refusal. If multiple indices are required, change the normative derivation rule explicitly before adding an index child and regenerating the vectors; do not silently change the pinned path in Rust alone. Specify the bn254 MuSig2 participant path separately, rather than implying the secp256k1 participant path applies to both curves.

**Evidence:** `docs/clients/signers-clientkeys.md:703–705` repeats the index-free paths; this is a spec/API mismatch, not a claim Rust has diverged from that rule. `clients/zether-prover/src/keys.rs:78–85` shows that EIP-2333 path derivation consumes only explicitly supplied child indices. [ERC-2333, derive_child_SK](https://eips.ethereum.org/EIPS/eip-2333#derive_child_sk) likewise takes the child index explicitly.

## 7. Medium — The WebAuthn assertion builder cannot perform its promised challenge check

**Spec:** §5.6, §9.1; spec lines 197–200, 396–397. Incomplete F-28 fix.

**Problem:** `webauthn_assertion(auth_data, client_data_json, r, s)` receives neither the expected `ua_msg` nor a request/session carrying it. It cannot compare the returned challenge to the requested operation. Reading a challenge from the untrusted JSON and checking its encoding is not that comparison. Separately, generic JSON acceptance permits layouts that the current chain-compatible verifier rejects, such as reordered fields or `crossOrigin:true`. That is a signer/verifier mismatch, even with a cryptographically valid assertion.

**Concrete fix:** Add `expected_challenge: &[u8;32]` (or a bound request object) to the builder and matching bindings. Check it with the existing chain-compatible client-data acceptance rule, validate scalar ranges before low-s normalization, and preserve the original signed JSON bytes. For phase-2 signing, verify the complete assertion against the selected key and request before return, as §9.4 promises. Check wrong challenge and JSON accepted by a generic parser but rejected by the existing verifier.

**Evidence:** `clients/clientkeys/src/metaop.js:43–50` retains the digest while requesting and checking the assertion. `clients/ua-rs/src/verify.rs:118–147` and `clients/clientkeys/src/ua-verify.js:30–42` implement the stricter wire acceptance. The current JS DER conversion checks `0 < r,s < n` before normalizing (`clients/clientkeys/src/webauthn.js:77–95`).

## 8. Medium — The fixed SignRequest interface discards BLS SIG/POP domain selection

**Spec:** §3, §9.4; spec lines 94, 497–514. Incomplete F-45 interface fix.

**Problem:** `UaMsg {kind, ua_msg}` carries only an already hashed UA message. The BLS kinds require an additional choice of SIG versus POP hash-to-curve domain. That choice is not recoverable from `ua_msg`. An implementation of the common `Signer::sign_request` cannot correctly produce both ordinary BLS signatures and registration PoPs using this request alone. Always choosing one domain fails the other verifier. External-result verification also needs the same choice to verify what was requested. Group registration operations likewise should not be conflated with an ordinary single-message signature.

**Concrete fix:** Carry a validated, internal signature-role discriminator in `SignRequest` (ordinary authorization versus the exact PoP operation), selected by the record builder, and use it for signing and post-verification. Do not let the external signer select it. Pin BLS ordinary and PoP cases through the common trait, including a negative case with the correct message but wrong DST.

**Evidence:** `clients/ua-rs/src/verify.rs:25–40` exposes the separate `pop` argument; `verify.rs:254` and `verify.rs:277` select different domains. `clients/ua-rs/src/ua8.rs:854–857` deliberately invokes the PoP verifier. JS independently selects these labels in `clients/clientkeys/src/ua-verify.js:109` and `ua-verify.js:117`. Neither `UaMsg` at spec line 503 nor `KeyRef` carries that role.

## 9. Medium — Locking the Wallet allocation does not lock its separately allocated secret buffers

**Spec:** §8.2; spec lines 323–337. Incomplete F-46 fix.

**Problem:** `mlock`/`VirtualLock` and `MADV_DONTDUMP` cover address ranges, not an object's ownership graph. Applying them to the `Wallet` allocation does not cover derived-key handle allocations, vector backing buffers, boxed crate keys, or buffers relocated when a collection grows. The proposed `Zeroizing<Vec<u8>>` Falcon storage is one explicit example. Those secrets remain swappable/dumpable even when locking the Wallet itself succeeds. Best-effort failure handling does not cure locking the wrong pages.

**Concrete fix:** Allocate long-lived secrets in stable storage, apply memory protection to each actual secret-bearing allocation, and track/unprotect/wipe it on release. State exactly which temporary/stack/library buffers remain outside that coverage; do not claim graph-wide protection from locking only the outer object. Avoid a process-global `PR_SET_DUMPABLE` side effect from a reusable library unless explicitly requested by the host. Validate range coverage of a derived-key buffer, not just successful locking of the Wallet header.

**Evidence:** Spec line 326 names only the Wallet allocation; line 333 explicitly specifies a separate `Vec` for Falcon; lines 411–412 introduce separately allocated handles. [Linux mlock(2), Description](https://man7.org/linux/man-pages/man2/mlock.2.html) defines protection over the pages intersecting the supplied address and size, not reachable allocations.

## 10. Medium — The fixed 32-byte vault payload conflicts with supported mnemonic imports

**Spec:** §4, §8.1, §8.4; spec lines 127–130, 299–303, 354–355. Incomplete F-18 fix.

**Problem:** Import accepts 12–24-word BIP-39 mnemonics, but the vault label `seed` is specified as “the 32-byte BIP-39 entropy.” Valid 12/15/18/21-word imports have 16/20/24/28 bytes of entropy. Enforcing 32 bytes prevents such wallets from surviving vault/backup round trips; padding or generating replacement entropy changes the mnemonic and every derived signing/KEM key. Correct generation of new 24-word wallets does not resolve imports.

**Concrete fix:** Preserve the exact original entropy length in Wallet, vault and backup payloads; permit precisely 16/20/24/28/32 bytes for the seed payload. Keep new generation at 32 bytes. Refuse any other decrypted payload length before wallet construction and require the seed label in the wallet-opening path. Round-trip an imported 12-word wallet through vault and sealed backup, comparing mnemonic, public signing key and KEM key before/after.

**Evidence:** `clients/clientkeys/src/seed.js:47–55` accepts all valid BIP-39 lengths and converts the actual entropy back to the mnemonic. `clients/clientkeys/src/vault.js:66–70` encrypts the supplied bytes without imposing 32 bytes. [BIP-39, Generating the mnemonic](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039.mediawiki) defines the five entropy lengths and corresponding word counts.

## 11. Medium — Signed containers have no specified replay/rollback acceptance policy

**Spec:** §6.3, §8.4; spec lines 274–279, 352–355.

**Problem:** A valid signature and AEAD tag authenticate `created`; neither makes it fresh. There is no check on that timestamp, consumed-link state, or backup generation. Replaying a previously valid container passes every specified check. If import replaces current state, this can restore stale imported keys/FROST shares, resurrect removed random KEM keys, or reapply an old link payload. The short-code hash binds one code but does not establish one-time consumption. Fresh encapsulation on seal also does not make open single-use. This concern is about state-changing restore/link acceptance, not repeated decryption of an archival backup.

**Concrete fix:** State that raw `open` offers no replay protection. Require link callers to bind a fresh local pairing session/ephemeral recipient, enforce its lifetime, consume it atomically on successful installation, and refuse subsequent installation. Require backup restore to compare the selected wallet identity and generation/current state or obtain explicit rollback confirmation before replacement. Keep these state rules in the caller if appropriate, but name them as required container-consumer obligations. Test replay after successful installation and import of an older valid backup over newer state.

**Evidence:** The complete signed AAD at spec lines 275–278 includes only `created` as freshness-related data and defines no acceptance check. The manifest at lines 341–343 has creation times but no monotonic backup generation. [RFC 9180 §9.7.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.3) explicitly limits HPKE replay protection; a stateless one-shot seal does not acquire stronger protection from its AEAD.

## 12. Low — The rotation note incorrectly calls PIN rewrapping DEK rotation

**Spec:** §8.1, §15; spec lines 310–311, 719–721. Incorrect F-50 note.

**Problem:** §15 says the vault DEK rotates through `rewrap_pin`; §8.1 correctly says it keeps the DEK. An attacker who previously learned the DEK can still decrypt future data encrypted with that same DEK after a PIN change. The rotation note can therefore lead a custody/recovery UI to claim revocation that did not happen. Merely retaining an old encrypted backup is a separate, unavoidable recovery exposure and is not the defect here.

**Concrete fix:** Correct §15 to say PIN rewrapping rotates the passphrase envelope/KEK and does not revoke a compromised DEK. If recovery from DEK compromise is required, explicitly reseal data under a fresh DEK and rebuild every PIN/PRF envelope; do not rename rewrapping as rotation.

**Evidence:** `clients/clientkeys/src/vault.js:84–94` replaces only the PIN envelope while preserving `data` and PRF. The contradictory spec statements are at lines 310–311 and 720.

## Checked and found sound at design level

- **KEM construction and checks:** The 1,601-byte public key and 1,568-byte ML-KEM-1024 ciphertext sizes, modulus check, distinct input-length failures, all-zero X25519 rejection on both sides, and preservation of ML-KEM implicit rejection agree with [FIPS 203 §§7.2–7.3 and Algorithms 16–18](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) and [RFC 7748 §§5–6.1](https://www.rfc-editor.org/rfc/rfc7748.txt). The combiner's fixed-length concatenation and inclusion of both X25519 public inputs follow the [X-Wing draft §§5.3 and 6](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-09.html#section-5.3) pattern. Omitting `ct_M` is not independently a defect; this is a custom ML-KEM-1024 construction, not a claim of X-Wing conformance or a new security proof. The no-KEM-for-msig rule is explicit; per-member expansion does not provide threshold confidentiality and is an accepted design choice.
- **Seal cryptographic framing:** Fixed component lengths make the v1 wire split unambiguous; strict rejection of non-1 version/scheme avoids a current downgrade path. The literal `scaas/seal/v1` label separates the format version; scheme, length-delimited purpose and whole-recipient-key hash bind the other KDF context. Independent internal OS randomness for each encapsulation supports one encryption per derived key with nonce zero, conditional on functioning entropy and no vector-mode production API. Caller AAD is authenticated; empty plaintext, the 1 MiB cap and lack of length hiding are explicit. HKDF output bounds agree with [RFC 5869 §2.3](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3). This does not resolve findings 3 or 11.
- **Signature bytes and nonces:** RFC-6979/no-extra-entropy ECDSA, low-s and recovery conventions are pinned; [RFC 6979 §3.2](https://www.rfc-editor.org/rfc/rfc6979.html#section-3.2) and [BIP-340 Default Signing](https://bips.dev/340/#default-signing) support the selected deterministic/auxiliary-randomness modes. The new Schnorr nonce's fixed-width secret, public-key binding, fresh aux, zero refusal and explicit 512-bit reduction avoid the prior ambiguous 256-bit reduction rule (`clients/ua-rs/src/verify.rs:198–218`, `clients/clientkeys/src/ua-verify.js:70–71`). This is source agreement, not an independent cryptanalysis or side-channel assurance.
- **PQ signing and derivation:** `pq.js:58–82` and `pq.rs:13–46` agree on ASCII kind tags in HKDF and the ML-DSA/SLH-DSA empty-context `M'`, with Falcon signing `ua_msg` directly. Hedged ML-DSA's 32-byte randomizer and SLH-DSA's deterministic/randomized choice match [FIPS 204 Algorithms 2 and 7](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) and [FIPS 205 Algorithms 19 and 22](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf). Falcon seeded-keygen equivalence is correctly left as a T0 decision; no claim it already matches was accepted.
- **Domains, policy and structures:** UA kind/purpose/message separation agrees with `clients/ua-rs/src/lib.rs:288–305` and `clients/clientkeys/src/pq.js:25–56`. The new seal purpose is off-chain and requires no claim of on-chain acceptance. Checked `Expect` variants port the reference's rebuild-and-compare gate (`evm.js:661–680`, `913–962`); callers must supply independently confirmed expectations. Portable records versus registry-bound UAAuth are distinguished. Nested member digests and two-level minimality match `ua8.rs:319–348`, `1030–1063` and the existing `portable.json`/`nested.json` vector shapes. Ordinary and PoP BLS domains exist in the current verifier; finding 8 concerns carrying that distinction into signing.
- **EVM transaction framing:** An explicit enum of types 0–3, internal RLP and required chain ID prevents type-4 construction on that entry point; legacy replay protection matches [EIP-155 Specification](https://eips.ethereum.org/EIPS/eip-155#specification), and signing blob transaction fields without a sidecar matches [EIP-4844 Blob transaction](https://eips.ethereum.org/EIPS/eip-4844#blob-transaction). The raw-digest opt-in remains a trusted-caller escape hatch: opaque hashes cannot cryptographically prove that their preimage is not a type-4 authorization. The type-4 exclusion is sound for `sign_transaction`, not an enforceable guarantee about hostile callers of the raw API.
- **Vault and ABI safeguards:** Scrypt allow-list before work, NFKC, label AADs, entropy rather than the 64-byte seed, v2 refusal and explicit PRF handling are appropriate and match the intended v1 reference format (`vault.js:14–16`, `47–62`, `106–121`); the reference still lacks the bounds fix and the spec acknowledges it. Caller-buffer zeroization, thread-local errors without argument echoes, unwind containment with explicit abort-build limitations, and treating C double-free/UAF as caller UB are stated. Those rules do not establish child-handle revocation, protected allocation coverage, or phase-2 callback lifetime safety; the latter remains implementation review work. Facade input construction correctly avoids forwarding secret-bearing JSON, and PQZ raw leaf export is explicitly fenced. No proof-system assessment was performed.
