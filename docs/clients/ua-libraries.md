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
`memberDigest`) and `encodeMsig`. UA-6 adds the PQZ key attribute ([accounts.md](../contracts/accounts.md) CTR-UA-16): `isPqzHolder(kind)` (`mldsa44`, `mldsa65`, `fndsa512`) and `msigPqzEligible` (an `msig` whose non-PQ weight is below the threshold).

**UA-8: portable registrations** ([accounts.md](../contracts/accounts.md) CTR-UA-07, CTR-UA-31, CTR-UA-32, plan `superpowers/plans/2026-10-30-ua8-portable-registrations.md`, tasks A1–A10). The chain-bound `popDigest` is **removed from the live API** of clientkeys, ua-py, ua-go, ua-cs, ua-dart and the four Rust wrappers (ua-c, ua-cxx, ua-dart-frb, ua-qt); their old files are in each package's `legacy/ua8/` (the Rust-wrapper copies there build only against `ref/pre-ua8`). ua-rs and zether-prover keep the old functions public in source under a `_v1` name (`pop_digest_v1`, `holder_pop_message_v1`, `pqz_reg_message_v1`, `zether_pop_v1`) for the legacy vectors, with no `legacy/ua8/` source copy. `chainKeyHash` / `chain_key_hash` stays in every library: `keccak256("evm:" ‖ decimal chainId)`, the mesh `chain_key` that the registry's `chainKeyHash()` view returns (it is not part of the `UAAuth` domain, which is `(name, version = generation, chainId, registry, salt = chainUid)`). New in every library unless noted (language case: `portablePopDigest` / `portable_pop_digest` / `PortablePopDigest`): `portablePopDigest(ua, pqzKeyHash, kemRecordHash)`, `registrationDigest(portable, pqzPopHash)`, `kemRecordDigest(ua, version, kemPk)` and `kemRecordMessage`, the PQZ key record (`pqzKeyDigest`, `pqzKeyRecordDigest`, `pqzKeyRecordMessage` with its write-once `alreadySet`), `holderPopMessage(kind, {ua, keyData, pqzKey, pqzPop | pqzPopHash, kemVersion, kemPk})` (what a holder signs to register: the hashes, both digests and the `uaMessage(kind, PURPOSE_POP_V2, registrationDigest)` message; an `msig` also returns the `memberDigest` its members sign), `pqzRegMessage(ua, pqzKey, kem)` (the message `R_REG` proves over: `uaMessage(0x0142, PURPOSE_POP_V2, portablePopDigest)`), `personalSignDigest` and `isPortablePurpose` (the EIP-191 digest a code-less native `msig` member signs, for `pop` v2, `kem` and `pqz-key` only), the versioned `purposeTag(p, version)` (`pop` v2), the tags `KEM_RECORD_TAG` and `PQZ_KEY_RECORD_TAG`, `PURPOSES` += `kem`, `pqz-key`, and the scheme table with the four PQZ key lengths (clientkeys, ua-rs, ua-py, ua-go, ua-cs, ua-dart; the Rust wrappers do not expose the lengths). Errors added everywhere: `UAKemHolder`, `UAKemVersion`, `UAKemKeyLength`, `UAPqzPopHash`, `UAPqzKeySet`. A zero-length proof hash means "absent", a hash of another length is `UAPqzPopHash`, and so is `keccak256("")`. **Client rules:** one PQZ key per UA, ever; a registration to copy to another chain is rebuilt from `registrationOf` (or the logs) and sent unchanged. Language notes: Dart's KEM version is a `BigInt` (2^64 − 1 does not fit an `int`); ua-dart-frb's package entry point refuses a version below 0 or at or above 2^64 (`UAKemVersion`) before the bridge, which would otherwise wrap it to 64 bits; ua-qt's numbers (chain id, KEM version) are JS numbers, exact up to 2^53, and a larger or fractional value is `UAArgument`; ua-qt exposes `holderPopMessage(kind, ua, keyData, pqzKey, pqzPop, kemVersion, kemPk)` (+ `holderPopMessageH` for a hash-only proof, `purposeTagV(purpose, version)`) and returns JSON; ua-cs writes the `personal_sign` prefix byte as `\u0019` (a C# `\x19E` would be one wide character), the Rust wrappers take it from ua-rs's byte string `b"\x19Ethereum…"`. **ua-c ABI version 2** (was 1; the signature break): the proof-hash argument takes `(ptr, len)` (len 0 = absent, len ≠ 32 = `UAPqzPopHash`), new statuses **12–16** (`UAKemHolder`, `UAKemVersion`, `UAKemKeyLength`, `UAPqzPopHash`, `UAPqzKeySet`), structs `ScaasUaHolderPop` and `ScaasUaPqzKeyRecord` (225 bytes, align 1), `scaas_ua_purpose_tag_v`, `scaas_ua_kem_record_tag`, `scaas_ua_pqz_key_record_tag`; ua-cxx and ua-dart-frb follow through the Rust wrapper. Tests in every package read `portable.json` (25 registrations, 9 KEM records, 8 PQZ key records, 63 negatives of which 7 are signature-level) and pin three known answers as literals: the `personal_sign` digest of the `msig-pq-native` member digest `0x606d9a70…` → `0xe5d24987…`, `chainKeyHash(1099511627783)` = `keccak256("evm:1099511627783")` = `0x6e45d591…7ce950`, and the KEM record digest at version 2^64 − 1 `0xdea39530…7dd31` (ua-qt pins it at 2^53 = `0xff3acbe0…0348b`, the largest version a QML number carries exactly; the version word is computed by the ua-rs function it calls). Errors carry one code everywhere: `UAKeyData`, `UAIdInNativeSpace`, `UAKindUnknown`,
`UAKindNotDerived`, `UAKindNotNative`, `UAIdFormat`, `UAPurposeUnknown`. The Solidity library has the on-chain subset.

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
