# UA identity libraries

The Universal Account identity layer ([accounts.md](../contracts/accounts.md) §1.3–§1.6) — kind table, ids, keyHash,
purpose tags, `ua_msg`, the portable registration digests (UA-8), the registry's `UAAuth` digest, member digests, canonical ids, the closed kind sets
and key-data validation — is implemented once on chain and in five client libraries, with bindings for C, C++, QML and Dart and a pure-Dart port. All of them must reproduce
`smartcontracts/vectors/ua/kinds.json`, `structures.json` and (UA-8) `portable.json`. UNAUDITED: no library is published as a package before an
audit.

| Library | Path | Runs in | Curve code | Test |
|---|---|---|---|---|
| Solidity `UAKinds` | `smartcontracts/evm/src/ua/UAKinds.sol` | the registry and tokens (on chain) | EIP-2537 MSM, the bn254 pairing precompile, modular arithmetic | `forge test --match-path test/ua/UAKinds.t.sol` |
| JS `ua.js` | `clients/clientkeys/src/ua.js` | browsers, the app, wallets | `@noble/curves` 2.4.0 | `npm test` in `clients/clientkeys` |
| Rust `scaas-ua` | `clients/ua-rs` | Rust services and the C, C++, QML and Dart bindings; planned for the node and zether-prover | `k256`, `p256`, `curve25519-dalek`, arkworks 0.5 | `cargo test` in `clients/ua-rs` |
| Python `scaas_ua` | `clients/ua-py` | client systems (ERP) | integers, `py_ecc` 6.0.0 | `python3 -m unittest -v tests.test_vectors` in `clients/ua-py` |
| Go `ua` | `clients/ua-go` | client systems | `gnark-crypto` v0.16.0, `filippo.io/edwards25519`, `math/big` | `go test ./...` in `clients/ua-go` |
| C# `Scaas.Ua` | `clients/ua-cs` | client systems (.NET) | `System.Numerics.BigInteger`, BouncyCastle (keccak) | `dotnet test` in `Scaas.Ua.Tests` |
| C++ `scaas::ua` | `clients/ua-cxx` | C++17 code without Qt (`#include "scaas_ua.hpp"`, CMake target `ScaasUa::scaas_ua`) | `scaas-ua` via `cxx` 1.0.202 | `ctest` in `clients/ua-cxx/build` |
| C `scaas_ua.h` | `clients/ua-c` | any language with a C FFI: C, Swift, Kotlin/JNI, Go cgo, Python ctypes, Zig, C# (`#include "scaas_ua.h"`, `libscaas_ua_c.a` / `.so`) | `scaas-ua`, header by cbindgen 0.28.0 | `cargo test` (header drift), the C smoke test and `python3 -m unittest -v tests.test_vectors` in `clients/ua-c`, after `cargo build` (the suite loads `target/debug/libscaas_ua_c.so`; override with `SCAAS_UA_C_LIB`) |
| QML `Scaas.Ua` / `UaKinds` | `clients/ua-qt` | Qt 6 QML apps (singleton `UaKinds`, defined in Rust with CXX-Qt 0.10.0) | `scaas-ua` | `QT_QPA_PLATFORM=offscreen ctest` in `clients/ua-qt/build` |
| Dart `scaas_ua_frb` | `clients/ua-dart-frb` | Dart / Flutter on Linux today (flutter_rust_bridge 2.13.0); Android, iOS, desktop, web planned | `scaas-ua` | `dart test` in `clients/ua-dart-frb`, after `cargo build --manifest-path rust/Cargo.toml` (the test loads `rust/target/debug/libscaas_ua_frb.so`; override with `SCAAS_UA_LIB`) |
| Dart `scaas_ua` | `clients/ua-dart` | every Dart target incl. the web (pure Dart, no native code) | `BigInt`, in-package Keccak | `dart test` (and `-p node`) in `clients/ua-dart` |

**Directories.** Every UA client library lives in `clients/ua-<lang>`. Bindings over the Rust crate (`ua-rs`): `ua-c`,
`ua-cxx`, `ua-qt`, `ua-dart-frb`; independent ports with their own curve code: `ua-py`, `ua-go`, `ua-cs`, `ua-dart`. Package names
did not change with the 2026-10-12 directory rename (`scaas-ua` crate, `scaas::ua`, `Scaas.Ua`, `scaas_ua`, `scaas_ua_frb`).

**Vectors.** `node scripts/ua-vectors.mjs` in `clients/clientkeys` writes both files from `ua.js` on deterministic keys;
every valid row is accepted and every invalid row refused before it is written, and a clientkeys test regenerates them
byte for byte. The Rust crate's curve code is independent of noble: a row is accepted only when both agree. The other four
read the same files. Never edit them by hand.

**One API.** Each library has the same functions in its own case (`uaOf` / `ua_of` / `UAOf`): the table and closed sets
(`kindInfo`, `isNativeKind`, `isZetherKind`, `isSigningKind`, `isMemberKind(kind, hederaNative)`; JS names shown, the set predicates drop `Kind` elsewhere: `is_native` / `IsNative`), tags (`TAG`, `GROUP`,
`MSG_TAG`, `purposeTag`), ids (`uaOf`, `deriveUA`, `nativeId`, `inNativeSpace`, `canonicalId`), `keyHashOf`,
`validateKeyData`, digests (`uaMessage`, `chainKeyHash`, `uaAuthDomainSeparator`, `uaAuthDigest`,
`memberDigest`) and `encodeMsig`. UA-6 adds the PQZ key attribute ([accounts.md](../contracts/accounts.md) CTR-UA-16): `isPqzHolder(kind)` (`mldsa44`, `mldsa65`, `fndsa512`, and `mldsa87`, `fndsa1024` since owner 2026-11-04) and `msigPqzEligible` (an `msig` whose non-PQ weight is below the threshold; PQ weight is kinds `0x0130`–`0x0135`). `mldsa87` (0x0134, [CTR-UA-39](../contracts/accounts.md#CTR-UA-39)): every library's kind table, key length 2,592 and group, BUILT on branch `mldsa87`; `ua-rs` (feature `pq`, `ml-dsa`'s `MlDsa87`) verifies it, the vectors (`kinds.json`, `structures.json`, `pq_kat.json`, `pq_external.json`, `pq_signatures.json`) carry its rows. `fndsa1024`
(0x0135, [CTR-UA-40](../contracts/accounts.md#CTR-UA-40)) the same way: every library's kind table, key length 1,793 with the header `0x0A`
and every `h_i < q` checked, group, holder; `ua-rs` (feature `pq`, `pqcrypto-falcon`'s `falconpadded1024`) verifies it; the vectors carry its
rows and `pq_external.json` the NIST round-3 Falcon-1024 KATs (`falcon1024_kat`). BUILT on branch `mldsa87`.

**UA-8: portable registrations** ([accounts.md](../contracts/accounts.md) CTR-UA-07, CTR-UA-31, CTR-UA-32, plan `superpowers/plans/2026-10-30-ua8-portable-registrations.md`, tasks A1–A10). The chain-bound `popDigest` is **removed from the live API** of clientkeys, ua-py, ua-go, ua-cs, ua-dart and the four Rust wrappers (ua-c, ua-cxx, ua-dart-frb, ua-qt); their old files are in each package's `legacy/ua8/` (the Rust-wrapper copies there build only against `ref/pre-ua8`). ua-rs and zether-prover keep the old functions public in source under a `_v1` name (`pop_digest_v1`, `holder_pop_message_v1`, `pqz_reg_message_v1`, `zether_pop_v1`) for the legacy vectors, with no `legacy/ua8/` source copy. `chainKeyHash` / `chain_key_hash` stays in every library: `keccak256("evm:" ‖ decimal chainId)`, the mesh `chain_key` that the registry's `chainKeyHash()` view returns (it is not part of the `UAAuth` domain, which is `(name, version = generation, chainId, registry, salt = chainUid)`). New in every library unless noted (language case: `portableRecordDigest` / `portable_record_digest` / `PortableRecordDigest`); the records are typed EIP-712 structs since `typed-signing` (domain `("SCaaS UA Portable", "1")`, CTR-UA-07): `portableDomainSeparator` (the Rust side `PORTABLE_DOMAIN_SEPARATOR`), the portable domain and type constants, `kemRecordHash` (`hashStruct(UAKemRecord)`; no key = the zero record), `portableRecordDigest(ua, kind, pqzKeyHash, kemRecordHash)`, `registrationDigest(ua, kind, pqzKeyHash, kemRecordHash, pqzPopHash)`, `kemRecordDigest(ua, version, kemPk)` (`setKemKey`: version 0 refused) and `kemRecordMessage`, the PQZ key record (`pqzKeyDigest(ua, pqzKeyHash)`, `pqzKeyRecordDigest(ua, pqzKeyHash, pqzPopHash)`, `pqzKeyRecordMessage` with its write-once `alreadySet`), `holderPopMessage(kind, {ua, keyData, pqzKey, pqzPop | pqzPopHash, kemPk})` (what a holder signs to register: the hashes, both digests and the `uaMessage(kind, PURPOSE_POP_V2, registrationDigest)` message, the KEM key always version 0; an `msig` also returns the `memberDigest` its derived members sign), `pqzRegMessage` (the message `R_REG` proves over: `uaMessage(0x0142, PURPOSE_POP_V2, portableRecordDigest)`; the registering kind comes first, clientkeys takes `{ua, kind, pqzKey, kemPk}`), `isPortablePurpose` (`pop` v2, `kem` and `pqz-key`: a code-less or EIP-7702-designator native `msig` member signs the record's typed digest itself for these), the versioned `purposeTag(p, version)` (`pop` v2), `PURPOSES` += `kem`, `pqz-key`, and the scheme table with the four PQZ key lengths (clientkeys, ua-rs, ua-py, ua-go, ua-cs, ua-dart; the Rust wrappers do not expose the lengths). clientkeys adds the wallet JSON `portableTypedData` ([CLI-SGN-41](signers-clientkeys.md#CLI-SGN-41)). The raw digests, `personalSignDigest` and the two record tags are in each package's `legacy/typed-signing/`. Errors added everywhere: `UAKemHolder`, `UAKemVersion`, `UAKemKeyLength`, `UAKemScheme`, `UAPqzPopHash`, `UAPqzKeySet`. A zero-length proof hash means "absent", a hash of another length is `UAPqzPopHash`, and so is `keccak256("")`. **Client rules:** one PQZ key per UA, ever (per PQZ parameter set: a copied unproven key of another set's length may be replaced by `setPqzKey`, owner ruling R-cross-set; read the current key with `pqzKeyOf`); a registration to copy to another chain is rebuilt from `registrationOf` (or the logs) and sent unchanged.

**Registry arguments (`typed-signing`, [CTR-UA-36](../contracts/accounts.md#CTR-UA-36)).** Every library builds the explicit call of a registration: entry choice (`register`, `registerMsig`, `registerWebAuthn`, `registerMuSig2`, `registerFrost`), `UAAttrs` with `KemKey`, the KEM hash commit plus the `setKemKey(ua, 0, kem, UASig())` fill when the calldata is over `REGISTER_CALLDATA_LIMIT` (261,909 B) or forced, the `setKemKey` / `setPqzKey` arguments, and the ABI calldata length (arithmetic, no ABI encoder). A malformed KEM key is refused before a form is chosen (`kemKeyOf` runs the record check), and a `setKemKey` builder refuses no key. **Client rule (owner 2026-11-01):** a front-runner can land the commit form of a full `register`, so after `register`, or on `UAAlreadyRegistered`, read `registrationOf`; when `attrs.kemPkHash != 0` and `kemKeyAt(ua, 0)` is empty, send `setKemKey(ua, 0, key, UASig())` ([CTR-UA-32](../contracts/accounts.md#CTR-UA-32)); clientkeys `kemRepair` and ua-rs `kem_repair` return that call or null from the read values, the other libraries build it with their `setKemKey` builder. clientkeys `registrationArgs` is the reference ([CLI-SGN-41](signers-clientkeys.md#CLI-SGN-41)); `scaas_ua::ua8::registration_args` in ua-rs; `registration_args` in ua-py and `registrationArgs` in ua-dart (named JSON maps), `RegistrationArgs` in ua-go and ua-cs (typed structs / records that marshal to the same JSON). The four wrappers take JSON in and out, one shim in ua-rs (feature `json`), because a nested typed struct over a C ABI is not thin: `scaas_ua_registration_args`, `scaas_ua_set_kem_key_args`, `scaas_ua_set_pqz_key_args` in ua-c, `registrationArgs` / `setKemKeyArgs` / `setPqzKeyArgs` in ua-cxx, ua-qt and ua-dart-frb, the object shapes of `portable.json`'s `args`. Bad JSON, a field of the wrong type or bad hex is `UAArgument`; the UA errors pass through.

Language notes: Dart's KEM version is a `BigInt` (2^64 − 1 does not fit an `int`); ua-dart-frb's package entry point refuses a version below 0 or at or above 2^64 (`UAKemVersion`) before the bridge, which would otherwise wrap it to 64 bits; ua-qt's numbers (chain id, KEM version) are JS numbers, exact up to 2^53, and a larger or fractional value is `UAArgument`; ua-qt exposes `holderPopMessage(kind, ua, keyData, pqzKey, pqzPop, kemPk)` (+ `holderPopMessageH` for a hash-only proof, `purposeTagV(purpose, version)`) and returns JSON. **ua-c ABI version 5** (1 → 2: the proof-hash argument takes `(ptr, len)`, len 0 = absent, len ≠ 32 = `UAPqzPopHash`; 2 → 3: the typed digests, `scaas_ua_portable_domain_separator`, `scaas_ua_kem_record_hash`, `scaas_ua_portable_record_digest`, the `kem_record_tag`, `pqz_key_record_tag`, `portable_pop_digest` and `personal_sign_digest` exports gone; then `scaas_ua_registration_args`, `scaas_ua_set_kem_key_args`, `scaas_ua_set_pqz_key_args`): statuses **12–17** (`UAKemHolder`, `UAKemVersion`, `UAKemKeyLength`, `UAPqzPopHash`, `UAPqzKeySet`, `UAKemScheme`), structs `ScaasUaHolderPop` and `ScaasUaPqzKeyRecord` (225 bytes, align 1), `scaas_ua_purpose_tag_v`; ua-cxx and ua-dart-frb follow through the Rust wrapper. Tests in every package read `portable.json` (27 registrations, 15 KEM records, 16 PQZ key records, 68 negatives; `mldsa87` and `fndsa1024` with `fndsa512`'s rows each: a KEM register key, KEM records v1-v3, PQZ key records at the four sets) and pin two known answers as literals: `chainKeyHash(1099511627783)` = `keccak256("evm:1099511627783")` = `0x6e45d591…`, and the KEM record digest at version 2^64 − 1 `0xa0063a84…38f07` (ua-qt pins it at 2^53 = `0x04a0150e…990482`, the largest version a QML number carries exactly). Errors carry one code everywhere: `UAKeyData`, `UAIdInNativeSpace`, `UAKindUnknown`,
`UAKindNotDerived`, `UAKindNotNative`, `UAIdFormat`, `UAPurposeUnknown`. The Solidity library has the on-chain subset.

**Nested `msig` (`msig-nested`, [CTR-UA-38](../contracts/accounts.md#CTR-UA-38)).** Key data alone does not show an `msig` member's PQ eligibility, so
`msigPqzEligible`, `holderPopMessage` and `pqzKeyRecordMessage` refuse a record that needs it `UAMemberUnknown`. ua-rs has the `_with` forms with an
`inner` lookup (`msig_pqz_eligible_with`, `ua8::holder_pop_message_with`, `ua8::pqz_key_record_message_with`); the four wrappers take `inner` in
the form the JSON calls take it, `{id: keyData}` as JSON text, no callback across the ABI: `scaas_ua_msig_pqz_eligible_with`,
`scaas_ua_holder_pop_message_with`, `scaas_ua_pqz_key_record_message_with` in ua-c (NULL = none; additive, `SCAAS_UA_ABI_VERSION` stays 5), and
`msigPqzEligibleWith`, `holderPopMessageWith`, `pqzKeyRecordMessageWith` in ua-cxx, ua-qt and ua-dart-frb ("" = none). An `inner` over 65,536 bytes,
with more than 16 entries or key data over 580 bytes is `UAArgument` (ua-rs `json::inner_json`); with `inner`, `UAMemberUnknown` means a member
missing from it or an entry that holds an `msig` (a third level). `scaas_ua_replayed_member_sig` / `replayedMemberSig` turn the bytes of a slot's
`UAMemberSig` event (they hash to `memberSigHashOf(ua, index)`, owner 2026-11-03) into the slot JSON `{index, members: [{index, sig}], sig}` a copy sends to `acceptMembership` (CTR-UA-37), `UAUnauthorized`
(ua-c `SCAAS_UA_ERR_UNAUTHORIZED` = 20, new) for bytes that are not that slot's. Tests: `nested.json`'s `msig-nested-pq`, its eligibility rows,
nested PQZ key records and every `memberships` row in each wrapper (`test_nested_inner`, `nested_inner`, `nested inner`). ua-cxx, ua-qt and
ua-dart-frb export `keccak256(data)` (ua-rs `keccak256`; ua-qt hex in and out, `UAArgument` on bad hex), and their `member_sig_hashes`,
`test_member_sig_hashes`, `member sig hashes` tests check every `msig` registration row's `memberSigHashes` in `portable.json` and `nested.json`
(keccak256 of the slot's `sig`, or of an `msig` member's `abi.encode(InnerSig[])`, encoded in the test) and every `memberships` row's
`storedHash` = keccak256(`stored`). BUILT.

**Metatx hashes (metatx split T18).** The Rust crate and QML also carry the three hashes a wallet needs for
[CTR-MTX-26](../contracts/metatx.md#CTR-MTX-26) / [CTR-MTX-27](../contracts/metatx.md#CTR-MTX-27):
`meta_pay_id(salt, meta)` (`keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`), `pay_lane(p)` (`keccak256("scaas.pay.lane"
‖ p)`, 32 bytes) and `relay_ref(chain_id, target, call_data)` (the EVM router's `ref`; other families' forms differ, see
[CLI-SGN-39](signers-clientkeys.md#CLI-SGN-39)); QML `UaKinds.metaPayId(saltHex, metaHex)`, `payLane(hex)`,
`relayRef(chainId, targetHex, callDataHex)` (chain id exact to 2^53). Vectors: `smartcontracts/vectors/metatx/paymeta.json`
and `relayref.json` (written by forge); the JS twins are in `clientkeys` `evm.js`. The C, C++ and Dart bindings and the
independent ports do not carry them yet.

**Bindings.** C: the caller owns every buffer and nothing is freed; a fixed-size argument points to 32 bytes (20 for
`registry20`), a variable output takes `(out, size_t *out_len)` and returns `SCAAS_UA_ERR_BUFFER` with the size needed
in `*out_len` when it is too small (strings NUL-terminated, the NUL counted); every fallible call returns an `int32_t`
`ScaasUaStatus` whose `scaas_ua_status_name` is the code above, or `UAArgument` (a NULL pointer, a table index out of
range), `UABuffer` or `UAInternal`, and sets the per-thread `scaas_ua_last_error()` detail (`""` after a success);
`keyHashOf` of a structure kind and an unknown group return `*present = false`, not an error; non-UTF-8 text maps as in
C++; every function is thread-safe; `scaas_ua_abi_version()` guards the layout.
C++: `std::vector<uint8_t>` in and out, `std::optional` for `keyHashOf`, errors as `scaas::ua::Error` with
`code()` and `reason()`; a wrong-length digest, id or registry is reported as `UAKeyData: length`, and non-UTF-8 text maps
to `UAPurposeUnknown` (purpose), `UAIdFormat` (canonical id) or "unknown" (`std::nullopt`, groups). QML: byte values as
`"0x…"` hex strings, `kindInfo` as a JSON string, `encodeMsig` from a JSON array; a failing call returns `""` / `false` and
sets `UaKinds.lastError` (readable from QML) to the code (cleared by the next call; undecodable key data is `UAKeyData`,
other undecodable arguments, wrong lengths included, `UAArgument`); `keyHashOf` of a structure kind returns `""` with an
empty `lastError` (not an error); chain ids are exact to 2^53; a kind outside 0..0xFFFF is `UAArgument`, but QML numbers
beyond int32 wrap (ToInt32) before they reach the binding, so range-check them in QML. FRB Dart: `Uint8List`, `U8Array32` /
`U8Array20` for fixed sizes (a wrong length throws `AssertionError` with asserts on and a `PanicException` with asserts
off, not a coded error), `UAError` with `code` and `reason` (the label after `UAKeyData: `, as in C++ and pure Dart);
integers are `int` (i64) so nothing wraps: a kind outside 0..0xFFFF is `UAKindUnknown`, a negative chain id or an
out-of-range generation, threshold or weight is `UAArgument`. Pure Dart: `Uint8List` or hex strings, `UAError`; chain ids
are exact to 2^53 when compiled to JavaScript. No Rust panic crosses a binding.

**Test overrides.** Each suite finds the vectors at `smartcontracts/vectors/ua` by default: the cxx and Qt suites take the
CMake cache variables `-DSCAAS_UA_VECTORS_DIR` and `-DUA_VECTORS_DIR`, FRB Dart the environment variable
`SCAAS_UA_VECTORS` (and `SCAAS_UA_LIB` for the native library), the C ctypes suite `SCAAS_UA_VECTORS` (and
`SCAAS_UA_C_LIB`), pure Dart `UA_VECTORS`.

**Kinds and schemes (UA-6).** The kind `0x0140` is gone and `0x0142` `pqz-mlwe` is a **scheme**, not a kind: it keeps its
tag, keyHash group and key-data length (16,384 B) in a separate schemes table (`SCHEMES`), `kindInfo` / `deriveUA` / `uaOf`
refuse to derive an id from it (`UAKindNotDerived`), and `keyHashOf(0x0142, pk)` still works. The Zether kind `0x0141`
(`zether-bls12381`) is in SIGNING (and in ZETHER, the closed set `{0x0141}`); `zether-bn254` is a legacy line
(`smartcontracts/evm/legacy/ua6/`).

**Definitions this layer fixes** (controller rulings, pending the owner): `GROUP(g) = keccak256("scaas.ua.group." ‖ g ‖
".v1")` and `keyHash = keccak256(GROUP(g) ‖ canonical pubkey)` (secp256k1 `x`, P-256 `x`, the full point or key otherwise;
`x(Q)` / `x(Y)` and `Q` / `Y` for MuSig2 / FROST); `slhdsa128s` is in SIGNING and MEMBER; an `msig` has 1–16 members,
every weight ≥ 1, native members with ids in the native space and derived members outside it.

**What validation checks.** Lengths; P-256 and secp256k1 on the curve with coordinates `< p` and compressed prefix
`02`/`03`; ed25519 canonical (`y < p`, no negative zero), not small order; bn254 G1 on the curve, not the identity; bn254 G2
(EIP-197, imaginary part first) and BLS12-381 G1/G2 (EIP-2537, 16 zero bytes of padding, `c0` first) on the curve and in
the prime-order subgroup; MuSig2 / FROST layouts of valid points with sorted members and scalars below the order; `msig`
layout and member rules; FN-DSA header and coefficients `< 12289`; ML-DSA, SLH-DSA and `pqz-mlwe` by length. Precompile calls (EIP-2537 G1MSM / G2MSM, the bn254 pairing) are capped at 2× their EIP price; a gas
shortage reverts `UAVerifyGas`, never `UAKeyData`; on a chain that prices those precompiles above 2× the EIP price, valid keys fail with `UAVerifyGas` (check the prices before enabling the kinds). Registration status, KeyAgg, the FROST DKG check, PoP and the structure gas bound are the registry's.

**Not here.** Signing (`UAKey`, the per-kind signers), PoP signatures and group vectors, the registry contract, the UA ledger.
Not built yet: the FRB layer as a Flutter plugin and its Android, iOS and web builds (the web build needs nightly Rust, wasm-bindgen-cli and COOP/COEP headers; whether `scaas-ua` compiles to wasm is open), and Qt packaging for Windows and macOS.
