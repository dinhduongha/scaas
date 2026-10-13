# UA identity libraries

The Universal Account identity layer ([accounts.md](../contracts/accounts.md) §1.3–§1.6) — kind table, ids, keyHash,
purpose tags, `ua_msg`, `popDigest`, the registry's `UAAuth` digest, member digests, canonical ids, the closed kind sets
and key-data validation — is implemented once on chain and in five client libraries, with bindings for C, C++, QML and Dart and a pure-Dart port. All of them must reproduce
`smartcontracts/vectors/ua/kinds.json` and `structures.json`. UNAUDITED: no library is published as a package before an
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
`validateKeyData`, digests (`uaMessage`, `chainKeyHash`, `popDigest`, `uaAuthDomainSeparator`, `uaAuthDigest`,
`memberDigest`) and `encodeMsig`. Errors carry one code everywhere: `UAKeyData`, `UAIdInNativeSpace`, `UAKindUnknown`,
`UAKindNotDerived`, `UAKindNotNative`, `UAIdFormat`, `UAPurposeUnknown`. The Solidity library has the on-chain subset.

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
