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
| Dart `scaas_ua_frb` | `clients/ua-dart-frb` | Dart / Flutter on Linux today (flutter_rust_bridge 2.13.0); Android, iOS, desktop planned; not the web: wallet secrets are Rust-owned `SecretBytes` written and read in place through `dart:ffi`, never through the bridge's codec (owner 2026-11-06) | `scaas-ua` | `dart test` in `clients/ua-dart-frb`, after `cargo build --manifest-path rust/Cargo.toml` (the test loads `rust/target/debug/libscaas_ua_frb.so`; override with `SCAAS_UA_LIB`) |
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
and every `h_i < q` checked, group, holder; `ua-rs` (feature `pq`, PQClean `falcon-padded-1024`, vendored since ua-rs-sign T3b) verifies it; the vectors carry its
rows and `pq_external.json` the NIST round-3 Falcon-1024 KATs (`falcon1024_kat`). BUILT on branch `mldsa87`.

**Id display** (ua-mtx-merge spec §6, MD-9; BUILT on branch `ua-mtx-merge`, task T13). How a client shows a `bytes32` id before the
user signs: `idDisplay(id, kind)` (`id_display` / `IDDisplay` / `IdDisplay`; ua-c `scaas_ua_id_display`) takes `0x` + 64 hex
digits. An id with the top 96 bits zero (the native space, [CTR-UA-03](../contracts/accounts.md#CTR-UA-03)) is shown as its
EIP-55 address, as the contract reads it, whatever `kind` says; any other id is derived and shown only as
`urn:scaas:ua:v1:<kind name>:<hex32>` ([NET-ALL-21](../networks/README.md#NET-ALL-21)) under `kind`, the id's kind from its
registry record (0 = none known: `UAKindUnknown`, a native kind `UAKindNotDerived`, never an address). A malformed id is
`UAIdFormat`. clientkeys (`ua.js`) and ua-rs return the kind with the text (`{kind: "native", address}` /
`{kind: "derived", urn}`, `IdDisplay::Native` / `Derived`); the wrappers and the ports return the text, an address or a URN.
`smartcontracts/vectors/ua/id_display.json` (`node scripts/id-display-vectors.mjs` in `clients/clientkeys`) pins every library.

**UA-8: portable registrations** ([accounts.md](../contracts/accounts.md) CTR-UA-07, CTR-UA-31, CTR-UA-32, plan `superpowers/plans/2026-10-30-ua8-portable-registrations.md`, tasks A1–A10). The chain-bound `popDigest` is **removed from the live API** of clientkeys, ua-py, ua-go, ua-cs, ua-dart and the four Rust wrappers (ua-c, ua-cxx, ua-dart-frb, ua-qt); their old files are in each package's `legacy/ua8/` (the Rust-wrapper copies there build only against `ref/pre-ua8`). ua-rs and zether-prover keep the old functions public in source under a `_v1` name (`pop_digest_v1`, `holder_pop_message_v1`, `pqz_reg_message_v1`, `zether_pop_v1`) for the legacy vectors, with no `legacy/ua8/` source copy. `chainKeyHash` / `chain_key_hash` stays in every library: `keccak256("evm:" ‖ decimal chainId)`, the mesh `chain_key` that the registry's `chainKeyHash()` view returns (it is not part of the `UAAuth` domain, which is `(name, version = generation, chainId, registry, salt = chainUid)`). New in every library unless noted (language case: `portableRecordDigest` / `portable_record_digest` / `PortableRecordDigest`); the records are typed EIP-712 structs since `typed-signing` (domain `("SCaaS UA Portable", "1")`, CTR-UA-07): `portableDomainSeparator` (the Rust side `PORTABLE_DOMAIN_SEPARATOR`), the portable domain and type constants, `kemRecordHash` (`hashStruct(UAKemRecord)`; no key = the zero record), `portableRecordDigest(ua, kind, pqzKeyHash, kemRecordHash)`, `registrationDigest(ua, kind, pqzKeyHash, kemRecordHash, pqzPopHash)`, `kemRecordDigest(ua, version, kemPk)` (`setKemKey`: version 0 refused) and `kemRecordMessage`, the PQZ key record (`pqzKeyDigest(ua, pqzKeyHash)`, `pqzKeyRecordDigest(ua, pqzKeyHash, pqzPopHash)`, `pqzKeyRecordMessage` with its write-once `alreadySet`), `holderPopMessage(kind, {ua, keyData, pqzKey, pqzPop | pqzPopHash, kemPk})` (what a holder signs to register: the hashes, both digests and the `uaMessage(kind, PURPOSE_POP_V2, registrationDigest)` message, the KEM key always version 0; an `msig` also returns the `memberDigest` its derived members sign), `pqzRegMessage` (the message `R_REG` proves over: `uaMessage(0x0142, PURPOSE_POP_V2, portableRecordDigest)`; the registering kind comes first, clientkeys takes `{ua, kind, pqzKey, kemPk}`), `isPortablePurpose` (`pop` v2, `kem` and `pqz-key`: a code-less or EIP-7702-designator native `msig` member signs the record's typed digest itself for these), the versioned `purposeTag(p, version)` (`pop` v2), `PURPOSES` += `kem`, `pqz-key`, and the scheme table with the four PQZ key lengths (clientkeys, ua-rs, ua-py, ua-go, ua-cs, ua-dart; the Rust wrappers do not expose the lengths). clientkeys adds the wallet JSON `portableTypedData` ([CLI-SGN-41](signers-clientkeys.md#CLI-SGN-41)). The raw digests, `personalSignDigest` and the two record tags are in each package's `legacy/typed-signing/`. Errors added everywhere: `UAKemHolder`, `UAKemVersion`, `UAKemKeyLength`, `UAKemScheme`, `UAPqzPopHash`, `UAPqzKeySet`. A zero-length proof hash means "absent", a hash of another length is `UAPqzPopHash`, and so is `keccak256("")`. **Client rules:** one PQZ key per UA, ever (per PQZ parameter set: a copied unproven key of another set's length may be replaced by `setPqzKey`, owner ruling R-cross-set; read the current key with `pqzKeyOf`); a registration to copy to another chain is rebuilt from `registrationOf` (or the logs) and sent unchanged.

**Registry arguments (`typed-signing`, [CTR-UA-36](../contracts/accounts.md#CTR-UA-36)).** Every library builds the explicit call of a registration: entry choice (`register`, `registerMsig`, `registerWebAuthn`, `registerMuSig2`, `registerFrost`), `UAAttrs` with `KemKey`, the KEM hash commit plus the `setKemKey(ua, 0, kem, UASig())` fill when the calldata is over `REGISTER_CALLDATA_LIMIT` (261,909 B) or forced, the `setKemKey` / `setPqzKey` arguments, and the ABI calldata length (arithmetic, no ABI encoder). A malformed KEM key is refused before a form is chosen (`kemKeyOf` runs the record check), and a `setKemKey` builder refuses no key. **Client rule (owner 2026-11-01):** a front-runner can land the commit form of a full `register`, so after `register`, or on `UAAlreadyRegistered`, read `registrationOf`; when `attrs.kemPkHash != 0` and `kemKeyAt(ua, 0)` is empty, send `setKemKey(ua, 0, key, UASig())` ([CTR-UA-32](../contracts/accounts.md#CTR-UA-32)); clientkeys `kemRepair` and ua-rs `kem_repair` return that call or null from the read values, the other libraries build it with their `setKemKey` builder. clientkeys `registrationArgs` is the reference ([CLI-SGN-41](signers-clientkeys.md#CLI-SGN-41)); `scaas_ua::ua8::registration_args` in ua-rs; `registration_args` in ua-py and `registrationArgs` in ua-dart (named JSON maps), `RegistrationArgs` in ua-go and ua-cs (typed structs / records that marshal to the same JSON). The four wrappers take JSON in and out, one shim in ua-rs (feature `json`), because a nested typed struct over a C ABI is not thin: `scaas_ua_registration_args`, `scaas_ua_set_kem_key_args`, `scaas_ua_set_pqz_key_args` in ua-c, `registrationArgs` / `setKemKeyArgs` / `setPqzKeyArgs` in ua-cxx, ua-qt and ua-dart-frb, the object shapes of `portable.json`'s `args`. Bad JSON, a field of the wrong type or bad hex is `UAArgument`; the UA errors pass through.

Language notes: Dart's KEM version is a `BigInt` (2^64 − 1 does not fit an `int`); ua-dart-frb's package entry point refuses a version below 0 or at or above 2^64 (`UAKemVersion`) before the bridge, which would otherwise wrap it to 64 bits; ua-qt's numbers (chain id, KEM version) are JS numbers, exact up to 2^53, and a larger or fractional value is `UAArgument`; ua-qt exposes `holderPopMessage(kind, ua, keyData, pqzKey, pqzPop, kemPk)` (+ `holderPopMessageH` for a hash-only proof, `purposeTagV(purpose, version)`) and returns JSON. **ua-c ABI version 5, the identity surface** (the wallet surface is ABI 6, [CLI-UAL-05](#CLI-UAL-05); 1 → 2: the proof-hash argument takes `(ptr, len)`, len 0 = absent, len ≠ 32 = `UAPqzPopHash`; 2 → 3: the typed digests, `scaas_ua_portable_domain_separator`, `scaas_ua_kem_record_hash`, `scaas_ua_portable_record_digest`, the `kem_record_tag`, `pqz_key_record_tag`, `portable_pop_digest` and `personal_sign_digest` exports gone; then `scaas_ua_registration_args`, `scaas_ua_set_kem_key_args`, `scaas_ua_set_pqz_key_args`): statuses **12–17** (`UAKemHolder`, `UAKemVersion`, `UAKemKeyLength`, `UAPqzPopHash`, `UAPqzKeySet`, `UAKemScheme`), structs `ScaasUaHolderPop` and `ScaasUaPqzKeyRecord` (225 bytes, align 1), `scaas_ua_purpose_tag_v`; ua-cxx and ua-dart-frb follow through the Rust wrapper. Tests in every package read `portable.json` (27 registrations, 15 KEM records, 16 PQZ key records, 68 negatives; `mldsa87` and `fndsa1024` with `fndsa512`'s rows each: a KEM register key, KEM records v1-v3, PQZ key records at the four sets) and pin two known answers as literals: `chainKeyHash(1099511627783)` = `keccak256("evm:1099511627783")` = `0x6e45d591…`, and the KEM record digest at version 2^64 − 1 `0xa0063a84…38f07` (ua-qt pins it at 2^53 = `0x04a0150e…990482`, the largest version a QML number carries exactly). Errors carry one code everywhere: `UAKeyData`, `UAIdInNativeSpace`, `UAKindUnknown`,
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

**Bindings (the identity calls; the wallet surface: [below](#the-wallet-surface-of-ua-rs-built)).** C: the caller owns every buffer and nothing is freed; a fixed-size argument points to 32 bytes (20 for
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

## The wallet surface of `ua-rs`: BUILT

Built on branch `ua-rs-sign` (plan tasks T0 to T18, each commit in the
[register](../decisions.md#39-clients--ua-libraries)). No contract, node or signed-record byte format changed. Design and the
review mapping: the [signer spec](../superpowers/specs/2026-11-05-ua-rs-sign.md). UNAUDITED: reviewed by AI (Fable, Codex,
Claude), no external audit.

| Area | Module (`clients/ua-rs/src/`) | Calls |
|---|---|---|
| Wallet and keys | `wallet/mod.rs`, `derive.rs`, `store.rs` | `Wallet::{generate, from_mnemonic, open_vault, seal_vault, lock, unlock, manifest, memory_protection, ua_key, native_key}`; derivation as [signers-clientkeys §9](signers-clientkeys.md#9-derivation-and-role-keys) |
| Single-key signing | `sign.rs`, `pqsign.rs`, `pairing.rs`, `signer.rs` | `UaKey::{sign_ua, sign_member}`, `NativeKey::{sign_typed, sign_transaction, sign_key_proof, sign_digest}`, the `Signer` trait |
| `UASig` and groups | `uasig.rs`, `pairing.rs` | `ua_sig`, `msig_sig`, `membership_sig` (`msig` sets minimal at both levels, `UAPoP` otherwise); MuSig2 and FROST sessions, a secret nonce used once |
| EIP-712, policy, transactions | `eip712.rs`, `policy.rs`, `tx.rs` | `TypedData`, `scaas_typed_data`, `pqz_verdict_typed_data` (the `PqzVerdict` a PQZ verifier UA signs under `pqz-verdict`, group 3f), `Expect`; `EvmTx` types 0 to 3 (`alloy-rlp`; type 4 has no variant, chain id 0 refused) |
| WebAuthn | `webauthn.rs` | `webauthn_challenge`, `webauthn_assertion` |
| Factory addresses | `factory.rs` | `create3_salt`, `create3_address`: a creation's chain-neutral CREATE3 address (chain-neutral spec §4, `vectors/factory/create3_kat.json`), shown before a router create op |
| KEM, seal, containers | `kem.rs`, `seal.rs`, `aead.rs` | `UaKey::kem_key`, `kem_encaps`, `KemKeyPair`, `seal`, `open_container`, `LinkSession`, `from_link`; AEAD, HKDF, HMAC ([§9.1](signers-clientkeys.md#91-the-ua-kem-key-seal-and-containers)) |
| Vault, manifest, backup | `vault.rs`, `manifest.rs` | clientkeys vault v1 byte for byte, `discover_candidates`, `import_native_key`, `imported_ua_key` (an imported key's own derived kind, [CLI-SGN-29](signers-clientkeys.md#CLI-SGN-29)), `SeedBackup`, `backup_seal`, `link_seal`, `restore_backup`, label vaults |
| Facades | `facade/zether.rs`, `pqz.rs`, `pqz_pack.rs`, `pqz_backup.rs`, `decoys.rs` | `ZetherKey`, `PqzKey`, each one JSON `call` ([below](#confidential-token-facades-no-decryption-oracle)); `pqz_set`, `export_pqz_leaf_raw` |
| Bounded readers | `wallet/bounded.rs` | [CLI-UAL-03](#CLI-UAL-03) |

**Features** (`clients/ua-rs/Cargo.toml`). `--no-default-features` keeps the verify-only identity layer, a CI cell of its own.

| Feature | Gives | Default |
|---|---|---|
| `wallet` | `pq`, `signers`, `json` and everything in the table above but the facades | yes |
| `zether` | `wallet` and the Zether facade (`zether-prover`, BLS12-381 only) | yes |
| `pqz` | `wallet` and the PQZ facade (`pqz-ffi` with `prove`; the Rust PQZL backend, PQZH where the set has it) | yes |
| `pqz-set-<set>` | exactly one with `pqz` (a const assert): `n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`, `n2816-kmax65536`; a wallet serving two sets ships two builds; another set is `PqzSetMismatch` | `n2304-kmax4096` |
| `mlock` | arena protection ([CLI-UAL-10](#CLI-UAL-10)); compiled out off Unix | yes (owner 2026-11-06) |
| `pq`, `signers`, `json` | the identity layer's own: PQ verifiers, group signers, JSON shims | through `wallet` |
| `vectors` | test-only entry points; never in a production artifact ([CLI-UAL-25](#CLI-UAL-25)) | no |

**C ABI 6** (`clients/ua-c`, `include/scaas_ua.h` by cbindgen; the v5 header is kept at `legacy/ua-rs-sign/scaas_ua.v5.h`).
Every v5 declaration is unchanged. New: the opaque handles `ScaasUaWallet`, `ScaasUaKey` (UA or native), `ScaasUaKemKey`,
`ScaasUaLinkSession`, `ScaasUaSeedBackup`, `ScaasUaZetherKey`, `ScaasUaPqzKey`; a call per row of the table above;
`scaas_ua_zether_call` and `scaas_ua_pqz_call` for the facades' JSON; statuses 21 to 42 (`SealOpen`, `SealVersion`, `KemCheck`,
`Aead`, `VaultOpen`, `VaultParams`, `VaultVersion`, `RawDigestRefused`, `PolicyRefused`, `ExternalSignature`, `WalletLocked`,
`KeyRevoked`, `ContainerSender`, `ContainerReplay`, `BackupRollback`, `WebAuthnAssertion`, `KindUnavailable`, `WalletMismatch`,
`Rng`, `PqzSetMismatch`, then group 3g's `PqzKeyVersion` 41 and `KeyInUse` 42, appended). `scaas_ua_features()` returns the build's bits: 0 `wallet`, 1 `pq`, 2 `falcon`, 3 `zether`, 4 `pqz`,
5 to 8 the four sets, 9 `external` (clear in this round), 10 `mlock`, 11 `vectors` (a binding refuses it). A size query of a
proving call runs it again and a proof's length varies, so callers use `SCAAS_UA_PQZ_OUT_MAX` (1,052,672 B) as the buffer.

**Bindings of the wallet surface.** Each checks the ABI version and the features at load and refuses a mismatch. Identity calls
stay as above: `ua-py`, `ua-go`, `ua-cs` and `ua-dart` keep their own ports as the independent cross-check.

| Binding | Reaches `ua-rs` by | Handles and load check | Secrets |
|---|---|---|---|
| `ua-c` | the C ABI; `vectors` does not compile | caller frees each handle once; `scaas_ua_abi_version`, `scaas_ua_features` | caller memory, the caller zeroizes |
| `ua-cxx` | a second `cxx` bridge over the Rust API | move-only classes, `scaas::ua::load()`, `UAAbiMismatch` | `Secret`, zeroized in Rust before the call returns |
| `ua-qt` | singleton `UaWallet` over `ua-cxx` | QML holds an id, never a handle | public data, seal to a public key, sign by id; no decaps, open, raw digest, typed `Any` or export in QML; wraps neither facade |
| `ua-dart-frb` | `flutter_rust_bridge`, a hand Dart facade `lib/src/wallet.dart` | opaque handles, `UAAbiMismatch` | Rust-owned `SecretBytes`, never the bridge's codec ([CLI-UAL-05](#CLI-UAL-05)); no web build |
| `ua-py` | `scaas_ua.wallet`, ctypes over `libscaas_ua_c` | one class per handle, close waits for calls in flight | bytes-like in (a `str` is refused), `bytearray` out, `wipe()` |
| `ua-go` | subpackage `clients/ua-go/wallet`, cgo (the identity port stays cgo-free) | `Close` under a write lock, a finalizer | `[]byte`, `Wipe`; each call on a locked OS thread |
| `ua-cs` | `Scaas.Ua/Wallet.cs`, P/Invoke with `SafeHandle` | `IDisposable`, freed once | pinned arrays, `CryptographicOperations.ZeroMemory` |
| `ua-dart` | identity only, no signing | — | — |

Stated gaps: no binding wraps the C calls of the PQZ seed backup ([CLI-SGN-47](signers-clientkeys.md#CLI-SGN-47): `scaas_ua_pqz_seed_backup`, `scaas_ua_pqz_share_reseal`, `scaas_ua_wallet_pqz_reconstruct`,
`scaas_ua_pqz_seed_backup_warning`, `scaas_ua_wallet_pqz_held_key`), and none marshals an external signer's callback (each passes NULL
and expects `KindUnavailable`). The wasm-bindgen browser binding is PLANNED (next, after the size and device numbers).

**Targets.** CI (`.github/workflows/ci.yml`; its header lists the commands): `ua-rs` runs ten cells, each with clippy and tests;
`ua-rs-targets` compiles for the other targets; `ua-deps` runs `cargo tree --locked`, `cargo deny`, `cargo audit`;
`test-features` runs [CLI-UAL-25](#CLI-UAL-25)'s check. The jobs have not yet run on GitHub (no push on this branch).

| Target | Core | Zether, PQZ | Status |
|---|---|---|---|
| x86-64 Linux | every cell | every cell (PQZ at two sets) | built and tested locally, every binding's suite |
| `wasm32-unknown-unknown` | compiles; Falcon `KindUnavailable` (its C is skipped); `mlock` compiled out; `getrandom`'s JS backend per generation | compiles | nine cells built locally; nothing runs through a browser binding yet |
| `aarch64-linux-android` | compiles (NDK clang, API 24) | compile cells | `ua-c`'s cells built for the size ratchet, `ua-rs`'s verify-only cell locally, its other cells CI's first run; no device run |
| `aarch64-apple-ios` | CI compile only | CI compile only | not built here (no Xcode) |

Sizes per target and cell, and the timing still to come: [CLI-UAL-43](#CLI-UAL-43).

<a id="CLI-UAL-01"></a>**CLI-UAL-01** — **`ua-rs` is the only signer, and a secret leaves it only through a named export.**
Every client signs through `scaas-ua`: a client core or wallet module over it never signs on its own, and apps reach it through
the bindings above. It derives every key exactly as clientkeys, signs for every kind, holds the UA KEM key, seals and opens,
wraps AEAD, HKDF and HMAC from RustCrypto crates (never its own AES), and keeps the vault, the manifest and backups. clientkeys
stays the JS reference and writes every vector row first. The only exits of a secret: `seal_vault` and `seal_label_vault`
(encrypted), `SeedBackup` (shown once, three-word check, `take()` forgets), `backup_seal` and `link_seal` (sealed containers), and
`export_pqz_leaf_raw` with the marker `AllowSecretExport`, the one call that returns a secret in the clear. `decaps` returns `ss`, a
per-encapsulation secret ([CLI-SGN-43](signers-clientkeys.md#CLI-SGN-43)). Key types are neither `Clone` nor `Debug`-printing and
have no accessor for secret bytes (compile-fail doc tests). BUILT.

<a id="CLI-UAL-02"></a>**CLI-UAL-02** — **No release signature takes randomness.** Every randomized call (ML-DSA `rnd`, SLH-DSA
`opt_rand`, Falcon, BIP-340 and scaas Schnorr `aux`, the KEM's `m` and `e`, PQZ `rnd32`, link codes) draws from the OS RNG inside
`ua-rs`; deterministic entry points exist only under `vectors`, and a compile-fail doc test shows a release build has none. BUILT.

<a id="CLI-UAL-03"></a>**CLI-UAL-03** — **Every outside input is bounded by length and depth before it allocates or recurses.**
Over a cap: `Argument`, nothing parsed. A fuzz target per decoder (`clients/ua-rs/fuzz/`: `build.sh`, `run.sh <target> <seconds>`,
`seeds.py`; stable Rust, clang sanitizers). `fuzz_caps` reads the over-cap inputs in `regress/` in the `vectors` CI cell; the
campaigns stay local. BUILT.

| Input | Cap | Fuzz target |
|---|---|---|
| typed data JSON | 64 KiB, depth 8, 32 struct types, 64 fields each, type references acyclic and 8 deep, arrays 1,024 | `typed_data` |
| `Expect`, transaction JSON | 16 KiB, depth 4 | `expect`, `tx` |
| vault JSON | 2 MiB, depth 2; the scrypt bounds of [CLI-SGN-21](signers-clientkeys.md#CLI-SGN-21) | `vault` |
| manifest JSON; backup and link payload | 1 MiB, depth 3; payload depth 4 | `manifest` |
| `Sealed`; container JSON | `pt` ≤ 1 MiB, fixed field lengths; 4 MiB, depth 7, `sender.auth` two levels, lists of 16 | `sealed`, `container` |
| `ContainerExpect`, accepted JSON | 16 KiB, depth 4; an approved set of 64 UAs, indices `u16` | `container_expect`, `accepted` |
| members JSON | 512 KiB, depth 4, 64 UAs (owner 2026-11-06) | `members` |
| `UASig` request JSON | 64 KiB, depth 6, 16 slots | `uasig` |
| `kemPk` | exactly 1,601 B | `kem_pk` |
| mnemonic text | 1 KiB, 24 words | `mnemonic` |
| Zether command JSON | 1 MiB, depth 8 | `zether_cmd` |
| PQZ command JSON | 4 MiB, depth 8 (16 pending 8-leg audited blobs, `acc` and the key in hex reach about 2.3 MiB at `n2816-kmax65536`) | `pqz_cmd` |
| balance-cache box; `pickDecoys` | 2 MiB, depth 1; 4 MiB, depth 2 | through the two above |

<a id="CLI-UAL-04"></a>**CLI-UAL-04** — **Errors carry no input and no panic crosses the ABI.** `Display` of an error and
`scaas_ua_last_error` never echo an argument (not a BIP-39 word, a vault label's plaintext or a typed-data value); `ua-rs` has no
`log` or `tracing`; bindings print no argument on an error path; a test runs secret inputs through the error paths. `catch_unwind` does nothing on
`wasm32-unknown-unknown` or under `panic = "abort"`, so `clippy::{unwrap_used, expect_used, panic, indexing_slicing}` are denied in
`ua-rs`'s wallet and facades, `scaas-ct` and `ua-c`; every C export also runs in one `catch_unwind` (`SCAAS_UA_ERR_INTERNAL`) and the shared
library keeps `panic = "unwind"`. BUILT.

<a id="CLI-UAL-05"></a>**CLI-UAL-05** — **Header rules of ABI 6: handles, and whose memory holds a secret.** `_free(NULL)` is a
no-op; the caller frees each handle it received exactly once; use after free, a double free of one handle, or freeing a handle
while a call on it runs is undefined; `_free` zeroizes; a handle may be used from any thread concurrently; the last-error detail
stays per thread. A child handle refers to its wallet's secret store, not into the wallet handle, so freeing the wallet before
its children is defined ([CLI-UAL-09](#CLI-UAL-09)). Exactly one of `vault_passphrase` and `prf32` is non-NULL (both: PRF first,
as clientkeys); `bip39_passphrase` NULL means empty. A call that changes state or reveals once checks its capacity before it
runs. The mnemonic, both passphrases, `ss32`, an opened plaintext and the exported PQZ leaf sit in **caller** memory: the header
says the caller zeroizes them and each binding does. `ua-dart-frb` passes no secret through flutter_rust_bridge's codec, whose transfer
buffers are freed unzeroed: every secret in or out is a Rust-owned `SecretBytes` (whole 16 KiB page-aligned blocks, never moved,
`mlock` and no-dump best effort, zeroed on dispose) that Dart writes and reads in place through `dart:ffi`; `SecretBytes.take`
zeroes the source, so the package has no web build (owner 2026-11-06). Residual: a caller's copies, and a Dart `String` from a
text field, stay the caller's. BUILT.

<a id="CLI-UAL-06"></a>**CLI-UAL-06** — **A facade adds key custody and the ABI, no cryptography, and no request field can carry a
key.** Every proof, transcript, statement and encryption stays in `zether-prover` and `pqz-core`; verifiers, the precompile, the
self-test and the PQZL C core are not exposed. `Wallet::zether_key` and `Wallet::pqz_key` give `ZetherKey` and `PqzKey`, separate
handles under separate features: the Zether `x` and the PQZ `seed32` sit in the wallet's arena under the store guard, PQZ's `s` and
`e` are rebuilt per call and wiped. `call` reads a bounded request, keeps an allow-list of fields per command and a shape per
nested object, and hands the key itself to the prover: `key`, `revealSecret` and `includeWitness` cannot arrive by request.
`pqz_set()` names the build's set; a token's `proofSystemId` of another set is `PqzSetMismatch` before anything is parsed. BUILT.

<a id="CLI-UAL-07"></a>**CLI-UAL-07** — **The external-key interface is fixed and tested; device implementations are phase 2.**
Every signing path goes through `trait Signer { key_ref, sign_request }`; `UaKey` and `NativeKey` implement it, the `UASig`, typed,
transaction, key-proof and raw-digest builders take `&dyn Signer` (`sign_typed_by`, `sign_transaction_by`, `sign_key_proof_by`,
`sign_digest_by`). `SignRequest` has no public constructor. `ua-rs` normalises a device's answer (low-s, `v`) and verifies it
against the `KeyRef` under the request's role before returning it, else `ExternalSignature`. A test `TestExternalKey` (under
`vectors`) runs the `sign.json` rows through the interface. BUILT. The C header declares `ScaasUaExternalSigner` and
`scaas_ua_external_key_new`, which returns `KIND_UNAVAILABLE` in every build with the feature bit `external` clear. Secure Enclave,
StrongBox, Android Keystore, Ledger and passkey implementations: PLANNED; an external key has no KEM key.

<a id="CLI-UAL-08"></a>**CLI-UAL-08** — **Every multiplication by a secret on an arkworks curve goes through
`scaas_ct::secret_mul`.** A blinded scalar cannot be an arkworks field element (it reduces back), G1's GLV path reduces it again,
and the unreduced paths skip leading zeros and branch per bit. So `clients/scaas-ct` (a small crate `ua-rs` and `zether-prover` share,
owner 2026-11-05) forms `k' = k + ρ·r` as a 384-bit integer (`ρ` 128 bits from the OS RNG), runs a Montgomery ladder of exactly 384
iterations with a masked swap, and wipes `ρ`, `k'` and the swap state. Covered: the public keys of `0x0104`–`0x0107` and `0x0112`, the
scaas Schnorr nonce point, the BLS signature, the MuSig2-bn254 nonces, FROST-BN254 through an element newtype, and in zether-prover
every `x` times a supplied point and the proofs' nonces over `x` on supplied points. `mul_bigint` and friends are refused by
`clippy.toml`; a structural test under `vectors` shows, per path, one point, two integers, each `≥ r` and `≡ k`, 384 iterations.
Residual: arkworks field arithmetic, point-addition cases, the scalar arithmetic of a signature, Zether's fixed-base `[x]G`, `[k]G` and
per-transfer secrets (a leak of those reveals that transfer's amounts, never `x`). Blinding narrows; it does not make them constant time. BUILT.

<a id="CLI-UAL-09"></a>**CLI-UAL-09** — **One secret store per wallet; `lock()` revokes every handle for good.** The store is a
read-write lock over `{generation, arena}`, shared by `Arc`. Every handle (`UaKey`, `NativeKey`, a derived `KemKeyPair`, a group
session, `ZetherKey`, `PqzKey`) holds the `Arc`, its generation and its slot, and no secret bytes. Every secret operation takes the
read lock, refuses `KeyRevoked` when the generation is old, and runs under the guard. `lock()` takes the write lock (so it waits for
calls in flight), wipes the arena and raises the generation. `unlock` reopens the vault into a new arena at the raised generation and
never revives an old handle; a vault of another wallet is `WalletMismatch`. A wallet call that needs secrets while locked is
`WalletLocked`; the public manifest stays. Freeing the wallet is `lock()` plus the release of its reference: a child returns
`KeyRevoked` until its own `_free`. An imported or rebuilt key is listed after `unlock` and held only once its label vault is opened
(`backup_seal` refuses until then). An ephemeral `KemKeyPair` and a `LinkSession` have a store of their own. BUILT.

<a id="CLI-UAL-10"></a>**CLI-UAL-10** — **Memory protection covers the arena, not the object graph.** The arena is page-aligned 16 KiB
chunks that never move or grow, each `mlock`ed and `MADV_DONTDUMP` (Linux, Android) at allocation, wiped, unmarked and unlocked at
release. Every long-lived secret lives in it as bytes: the entropy, the seed, each handle's key bytes, imported keys, group secret
nonces, the Zether `x`, the PQZ `seed32`. Best effort: a failed lock is reported by `Wallet::memory_protection()` (`{chunks, locked,
no_dump}`) and never fails the wallet. **Outside, stated:** a crate's key type rebuilt for one operation and its temporaries, the
scrypt work buffer (128 MiB at `N = 2^17`, the crate offers no caller buffer), caller buffers, Windows (no `VirtualLock`, reports 0),
a kernel page that does not divide 16 KiB (nothing locked), everything on wasm32. `ua-rs` never sets `PR_SET_DUMPABLE`; a host app
may. BUILT.

<a id="CLI-UAL-11"></a>**CLI-UAL-11** — **A container's sender is expected, never self-declared.** A valid signature proves only that some
registered UA sealed it, so the one opening call is `open_container(kem_key, container, expect, members, accepted)` and no call
opens without a `ContainerExpect {purpose, sender (a UA or an approved set), recipient}`. Before any decapsulation, each a refusal
with nothing imported: the purpose; the recipient, which is the opening key's own; `sender.ua` expected; `sender.auth.keyData`
derives `sender.ua` (an `msig`, or exactly one single-key kind: the container names no kind, the opener tries the derived kinds
that may sign, each under its own tag); `sender.auth` verifies over the rebuilt `aad` and wire form. An `msig` sender: no signature of
its own, the minimal set at both levels, its signers accepted at both levels through the caller's `accepted(id, index)` (a missing
lookup refuses, [CTR-UA-37](../contracts/accounts.md#CTR-UA-37)). A mismatch, or a signer not accepted: `ContainerSender`; a bad signature,
the wrong `UASig` form or a bad tag: `SealOpen`. **Trust anchors.** Restore: the wallet's identity UA, known before the container
is read (the UA a backup holder approved, kept in its manifest as `backup_senders`, or the account the user confirms); after
decryption the payload's entropy must derive `sender.ua`, else `ContainerSender`. Link: the UA the user confirms on the new device
from the old device's screen, never from the container. BUILT, clientkeys and `ua-rs`.

<a id="CLI-UAL-12"></a>**CLI-UAL-12** — **`open` gives no replay protection; link and restore carry their own.** Link:
`LinkSession::new()` makes the ephemeral key, an 8-digit short code from the OS RNG and a window; `created` outside session start +
10 minutes is `ContainerReplay`; `from_link` takes the session by value and consumes it, so a second install cannot be expressed (C:
the handle stays allocated, later calls `KEY_REVOKED`; a malformed JSON does not consume it). The short code's hash is in the link
`aad`. Restore: the payload's `generation` (raised by each `backup_seal`; a link raises none) lower than the recorded one over a wallet
already held is `BackupRollback`, unless the caller passes the marker `AllowRollback` (JS `allowRollback: true`; C its own name,
`scaas_ua_wallet_restore_backup_rollback`) after the user confirmed; an equal generation installs nothing. Reading an old backup is
not refused; installing it over newer state is. BUILT, clientkeys and `ua-rs`.

<a id="CLI-UAL-13"></a>**CLI-UAL-13** — **The EIP-712 hasher is faithful; the canonical step belongs to checked SCaaS records.** The
generic hasher hashes the values supplied and never rewrites a field. `scaas_typed_data` (the SCaaS builders) writes an unbound
`relayer` / `feeRecipient` as zero, recursively, within a SCaaS domain and operation only. `sign_typed` with a checked `Expect` (one variant per
clientkeys check: `Payment`, `ReceiverFee`, `PayMeta`, `Op`, `Call`, `OwnerCall`, `Cancel`, `TradeOrder`, `WrapOrder`) **refuses** a
non-zero unbound field (`PolicyRefused`), so what the user confirmed is what is hashed (owner 2026-11-05). `Expect::Any(AllowAnyTypedData)`, with its
own C name `scaas_ua_sign_typed_any`, signs the standard digest of the values as supplied. An unrelated domain's struct with the
same field names is untouched. Since the merge of `ua-mtx-merge` `aa898cf6` (T20b) the op table and the checks follow its merged-entry rows (`typed/typed_ops.json`, 80 structs; 83 since `4f6d8605`, with the router's `UACreateToken`, `UACreateDex`, `UACreateInstance`; 86 since
`7558a364`, with 3f's `UAPqzSetVerifier`, `UAPqzCancelVerifier`, `UAPqzRevokeVerifier`, [CLI-UAL-59](../decisions.md#CLI-UAL-59)): a payment, a receiver fee, a SCaaS sell token's order, a wrap order and their cancels are the `UA` structs between 32-byte ids, `PayMeta` is v2 (`{salt, payNo, schema, body}`), the PQZ debits name `keyVersion` and the PQZ `UARollOver` is its own row (`UAPqzRollOver`). BUILT.

<a id="CLI-UAL-14"></a>**CLI-UAL-14** — **The KEM key comes through the UA key's own store.** `UaKey::kem_key(version)` has no wallet
argument, so a handle cannot be combined with another wallet's seed and two wallets cannot make a second `(ek, pk_X)` for one
`(ua, version)`. It refuses a kind that is not a KEM holder (`KemHolder`) and a revoked handle (`KeyRevoked`). The FIPS 203 §7.3
self-test of a derived key runs once per store per `(ua, version)`, its record in the store. BUILT.

<a id="CLI-UAL-15"></a>**CLI-UAL-15** — **EIP-2333 UA kinds have index 0 only.** Their paths have no index level (`0x0104`–`0x0107`,
`0x0112`), so `index ≠ 0` is `Argument` and two indices can never alias one key; the manifest records 0, `discover_candidates`
returns index 0 alone, and several keys of such a kind come from several `account` values. `account`, `index` and `coinType` are
`< 2^31` for every kind. BUILT, clientkeys and `ua-rs`.

<a id="CLI-UAL-16"></a>**CLI-UAL-16** — **A WebAuthn assertion is built against the challenge the caller asked for, and verified before it
is returned.** `webauthn_assertion(key_data, expected_challenge, authData, clientDataJSON, r, s)`, in order: `0 < r, s < n`; `s` to
low-s; `clientDataJSON` kept as the exact signed bytes, UTF-8, accepted only by the chains' rule (`client_data_ok`) against
`expected_challenge`, never the JSON's own; the whole encoding through `verify(0x0100, …)`. Any failure: `WebAuthnAssertion`, nothing
returned. BUILT, clientkeys and `ua-rs`.

<a id="CLI-UAL-17"></a>**CLI-UAL-17** — **The signature role is set inside `ua-rs`.** `SigRole::{Authorization, Pop}` picks the BLS domain
(SIG or POP) and every kind's post-verification: `sign_ua` maps a portable purpose (`pop` v2, `kem`, `pqz-key`) to `Pop` and every
other to `Authorization`, as the registry's `_sigOk`; `sign_member` is always `Authorization`. No public call takes a role; an
external signer reads it. BUILT.

<a id="CLI-UAL-18"></a>**CLI-UAL-18** — **A `seed` vault holds the BIP-39 entropy at its own length.** Exactly 16, 20, 24, 28 or 32 bytes
(12 to 24 words; a new wallet 32), never the 64-byte seed, never padded. Another length is `VaultOpen` before a `Wallet` is built;
`open_vault` needs the label `seed` (`Argument`). The BIP-39 passphrase is never stored: it is asked at every unlock. The format is
clientkeys vault v1 ([CLI-SGN-02](signers-clientkeys.md#CLI-SGN-02)) byte for byte, both ways; vault v2 and its tombstone are
`VaultVersion` by name. BUILT.

<a id="CLI-UAL-19"></a>**CLI-UAL-19** — **`rewrap_pin` is not a DEK rotation.** It replaces the passphrase envelope and keeps the DEK, so it
revokes nothing from someone who learnt the DEK. Recovery from a DEK compromise is `seal_vault` anew: a fresh DEK, every envelope rebuilt. A
wallet UI does not call a PIN change a key rotation. BUILT.

<a id="CLI-UAL-43"></a>**CLI-UAL-43** — **A size ratchet per target and feature cell; timing only on an idle machine or on real
devices.** `clients/ua-c/size-baseline.json` (34 cells) and `clients/ua-c/sizes.py` (`measure`, `check`, `selftest`; gate step `ua-sizes`):
stripped release `libscaas_ua_c` per target and feature cell, the bindings' own artifacts and the wasm32 modules; `pqzh` per set recorded,
not checked. A cell fails on growth past 1 %, on a cell missing from the baseline, on a failed build or when nothing was measured; the
baseline moves only by hand, with its old → new figure and a reason in the commit. The 1 % departs from MD-12's plain text (any growth):
another host's C compiler and checkout path move the bytes with no change of code. Default `libscaas_ua_c` cdylib: x86-64 5,685,272 B,
aarch64-android 4,972,880 B, wasm32 5,362,876 B; the table per cell is in the run record `clients/ua-rs/runs/2026-11-07-ua-rs-sign-t17.md`.
BUILT for x86-64, aarch64-android and wasm32; aarch64-ios is not measured (no Xcode on the measuring host).
**Reference timing** on a desktop through `clients/ua-rs/examples/ua_bench.rs` (release, default features, no test feature, the public API:
PQZ `R_TX` prove with PQZL and PQZH, scrypt at `N = 2^17` opening a seed vault, Falcon-1024 and SLH-DSA keygen per handle; p50 and p95):
pending, run alone once the machine is idle (owner 2026-11-07); a desktop reference, not CTR-PQZ-18's proof.
**Device timing:** pending, the owner has no devices yet (2026-11-07): PQZ `R_TX` prove and heap peak on Android and iOS against
[CTR-PQZ-18](../contracts/pq-zero-knowledge.md#CTR-PQZ-18) (≤ 15 s, ≤ 128 MiB), wasm32 scrypt at `N = 2^17` on a phone browser, Falcon-1024
and SLH-DSA keygen per handle. No figure is quoted without its device and commit; until then CTR-PQZ-18 is unmeasured on a device.

**Notes, not rules.** No key rotation exists for a UA's signing key: a UA id is the hash of its key, so "rotation" is a new UA or an
`msig` membership move; KEM keys rotate by version, FROST by a new DKG. Consumer recovery beyond the phrase (SLIP-39 shares, a
threshold of recovery UAs) is later work; `backup_seal` to an organisation UA and `msig` cover institutional recovery.
Reproducible builds are for the apps' own stores (`--locked`, `SOURCE_DATE_EPOCH`, `cargo auditable`); no binary goes to GitHub.
`no_std` is not needed: no listed target asks for it.

## Confidential-token facades: no decryption oracle

[ARCH-POS-13](../decisions.md#ARCH-POS-13) (owner 2026-11-06: no part of SCaaS decrypts, opens or test-decrypts a ciphertext
chosen by anyone other than the key holder and lets that party learn anything about the result) splits one duty
in two: the library makes a bare ciphertext impossible to hand over, and the layer that reads the chain guarantees the words
it hands over are real chain state. Design, findings and the owner's decisions: the
[no-decryption-oracle spec](../superpowers/specs/2026-11-06-no-decryption-oracle.md). Zether and PQZ are separate modules,
handles and features; each rule names the one it is about or says both. UNAUDITED.

***Library duties (`ua-rs` facades and every binding): BUILT*** (ua-rs-sign T15c, T15c2, T15e, T14b,
T15g, T15i, T15l):

1. <a id="CLI-UAL-20"></a>**CLI-UAL-20 — No bare ciphertext in a production artifact (both).** No release command takes a ciphertext, a statement, `T`, `p` or a
   parsed state field. The raw forms (table below) and their request types compile only under the test feature `vectors`;
   zether-prover's raw commands and its decrypt and opening helpers are `pub` only under its feature `hazmat`.
2. <a id="CLI-UAL-21"></a>**CLI-UAL-21 — Location and raw words (both).** A decrypting command takes a named location (`chainUid`, `token`, `block`, `psid`, the
   reader's `ua`; an old entry by its sender's `fromUA` and `sendCounter`, `entryRef` recomputed as the contract derives it)
   and the raw storage words the reading layer read at that block, each in a named field. The facade alone parses them by the
   pinned storage layout (`scaas.pqz`, `scaas.zether` in `smartcontracts/evm/test/v2/layout/namespaces.json`, compared through
   the forge state rows), checks them, rebuilds every ciphertext exactly as the contract does, and only then uses the key.
   PQZ: `p` is chosen by the facade (the inline window and `K_MAX`), the pending words are exactly `[rolled, p)`, a TRIVIAL
   entry is `vOff == 0`, the materialised `acc` is `not()` of its slots and must hash to `accHash`, and the stored form is
   unpacked by `facade::pqz_pack`. Zether: `family` names the layout parser (EVM only; another family is refused until its
   parser exists), the account slots are those of the reader's own `acct[UA(Y)]`.
3. <a id="CLI-UAL-22"></a>**CLI-UAL-22 — Leg and role bound to the handle (both).** Before the key is used: the handle's key equals the registered key the words
   carry (PQZ: the registry's `pqzKey[ua][v]` record of the key version read, `proven`, its SSTORE2 code; Zether: the leg's `Y_t` or the token's auditor
   key); the selected leg's owner is the reader; an auditor read needs the token's auditor mode not NONE and an auditor copy
   on that leg. These checks stop a careless caller; they never make words authentic.
4. <a id="CLI-UAL-23"></a>**CLI-UAL-23 — One refusal before the key (both).** Every refusal before the key is used is `Argument` (C: `SCAAS_UA_ERR_ARGUMENT`)
   with no detail; PQZ's `psid` of another set is `PqzSetMismatch` (a fact of the build, compared before anything is parsed).
   After the key only `KeyRevoked` (the wallet locked or freed), `Aead` (the standalone balance-cache box calls
   `open_balance_cache`) and these refusals, **all `Argument`**, each to the caller only (T15l, Fable P3-8): PQZ, digits that
   are not a balance (a decryption above `u64`); a debit's balance below amount and fee; an opened memo that does not name
   the entry's legs (`auditorOn` and the leg UAs, compared in constant time); `proveDiscloseSender`'s leg that is not the
   sender's re-derivation (another key as the leg owner's, another sender's entry); Zether, `DecryptBound` (the balance above
   the BSGS bound), a `cacheBox` that does not open under the key or holds no entry for the UA and token, a debit below its
   amount; and a prover refusal on either.
5. <a id="CLI-UAL-24"></a>**CLI-UAL-24 — A Zether balance hint is the sealed box (Zether).** `checkBalance` and a debit's hint take the holder's own sealed
   balance-cache box `{iv, ct}` (`cacheBox`, a balance above the device's BSGS bound), never a number (T15l, Fable P3-1): the
   facade opens it under the handle's key, uses its entry `<UA>:<token>` only at the words' `accSeq` (a stale entry: BSGS of
   the rebuilt `acc`) and checks it against the rebuilt `acc` (`[b]G == C − [x]D`). Every multiplication of the key `x` by a
   supplied point runs through `scaas_ct::secret_mul`; the per-transfer secrets stay on arkworks (a leak reveals that
   transfer's amounts, never `x`).
6. <a id="CLI-UAL-25"></a>**CLI-UAL-25 — No test feature in a production artifact (both).** `scaas_ua::VECTORS` and the feature bit `SCAAS_UA_FEATURE_VECTORS`
   (`1 << 11`): `ua-c` does not compile with it, every binding refuses to load a library that has it, and a `vectors` build
   makes key handles only after a test-only marker. `scripts/check_test_features.py` (CI and the gates) fails when a manifest
   enables `vectors` or `hazmat` of `scaas-ua`, `zether-prover` or `pqz-ffi`, or `vectors` of `scaas-ct`, outside
   `[dev-dependencies]` or a test-only crate, or when `cargo tree -e features` of `ua-c` (the library `ua-py`, `ua-go` and
   `ua-cs` load), `ua-cxx`, `ua-qt`, `ua-dart-frb`'s crate, `zether-prover` (`zether-read-balance`), `scaas-node`,
   `pqz-core/ffi/wasm` or `ua-rs` itself (`pqz-read`) shows one, transitive defaults included; each check has a positive control. The name `hazmat` follows the RustCrypto convention and is not a security boundary: the command set is.
7. <a id="CLI-UAL-26"></a>**CLI-UAL-26 — Tests that can fail (both).** `clients/ua-rs/tests/no_oracle.rs`: the 8·K crafted PQZ queries recover `s` through the
   `vectors`-only raw `dec` (positive control) and are refused by every production command in every bare shape with the key
   unused; consistent fabricated words are decrypted (the residual control: authenticity is the reading layer's). `ua-py`
   runs the same refusals through the C ABI. `facade_pqz_state.rs` and `facade_zether_state.rs` reproduce the contract's
   ciphertexts from the forge state rows (PQZ at two sets) and refuse every word and role negative with the key unused. Every
   binding over the facades (all but `ua-qt`, which wraps neither) decrypts the PQZ rows `smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json` (wallet keys, written by
   `gen_wallet_state.sh`) and the Zether forge rows through its own call path. Each guard has a killed mutant
   (`smartcontracts/evm/runs/2026-11-0[67]-ua-rs-sign-*-mutants.txt`).

<a id="CLI-UAL-27"></a>**CLI-UAL-27** — **`ua-rs` contains no light client and no chain-state verifier** (owner 2026-11-06). It reads no
chain and holds no anchors table, no Merkle-Patricia proof and no factory or registry proof; it stays I/O-free and holds no chain
trust. The check that words are chain state is [CLI-UAL-30](#CLI-UAL-30)'s. BUILT (the library has none). A later client-side **proof path**,
where the library verifies each credit's proof itself over raw words it already takes, is PLANNED: spec `2026-11-06-pqz-proof-path.md` §13.3 on
branch `ua-mtx-merge`; nothing here blocks it (requests carry slot words by index, binding tests assert membership in `COMMANDS`).

| Facade (`COMMANDS`) | Decrypts nothing | Location and raw words | `vectors` only (raw) |
|---|---|---|---|
| PQZ (`facade::pqz`) | `enc`, `proveRegister`, `proveKeyRecord` | `balance` (with `forOp7`), `proveTransfer`, `proveBurn`, `proveRefresh`, `proveTransferMulti` (with `mode`), `auditRead` (the auditor's handle), `proveDisclose` (`RECEIVER_X` or `AUDITOR`), `proveDiscloseSender` and `openMemo` (the sender's handle) | `dec`, `rawProveTransfer`, `rawProveBurn`, `rawProveRefresh`, `rawProveTransferMulti`, `rawProveDisclose`, `rawOpenMemo`, `rawProveDiscloseSender` |
| Zether (`facade::zether`) | `encrypt`, `pop`, `ownerAuth`, `uaSig`, `shieldCalldata`, `envelope`, `uaEnvelope`, `typedDigest`, `namedCall` | `balance`, `pendingBalance`, `checkBalance`, `proveTransfer`, `proveTransferMulti`, `proveBurn`, `openMemo`, `recoverTransfer`, `openDisclosure` | `decrypt`, `decryptPending`, `rawCheckBalance`, `rawProveTransfer`, `rawProveTransferMulti`, `rawProveBurn`, `rawOpenMemo`, `rawRecoverTransfer`, `rawOpenDisclosure` |

The words each command reads are in its rustdoc (`facade::pqz::COMMANDS` and `STATE_LAYOUT`; zether-prover `state`). The C ABI
carries them through `scaas_ua_pqz_call` and `scaas_ua_zether_call` (no new call or status). A binding test asserts that a
command is in `COMMANDS`, never that the list equals one, so a later proof path can add commands without breaking them.

<a id="CLI-UAL-30"></a>**CLI-UAL-30** — ***Requirements on the wallet layer that reads the chain: SPECIFIED*** (normative for every layer
that hands words to `ua-rs`, in this repository or outside it; `ua-rs` contains no light client and no chain-state verifier,
owner 2026-11-06). Reading the words from an untrusted RPC or indexer and passing them on is the oracle, and the fault is that
layer's. Stated plainly (Fable review 2026-11-07, verdict 1): `ua-rs` decrypts **any internally consistent fabricated words**,
so the **full key-recovery oracle** (8·K crafted PQZ queries recover the key `s`) exists for any app that breaks these
requirements; the library's word checks stop a careless caller, never a forger. Zether has a reference reading layer
(`zether-read-balance --rpc`, below), and so has PQZ (`pqz-read`, below; owner 2026-11-07, plan task T15m). EVM assertions; another family states its own before its layout parser lands. Numbered as in the spec's §4.2, one rule id each; this doc writes "requirement 1" where the spec uses its short form, which is an old-id token here (`docs_check` C4).

| # (rule id) | Requirement | Checkable assertion |
|---|---|---|
| 1 (<a id="CLI-UAL-31"></a>CLI-UAL-31) | **Trusted sources, one or several** (owner 2026-11-06; Change owner 2026-11-08, ARCH-POS-15): every source is an RPC endpoint the holder **named** (their own node or one they configured), a **default** in the release's own reviewed list (from public RPC information, trusted like a named one), a **discovered** endpoint (found at run time), or a verifying light client in the reading layer. A layer may take several (a wallet layer and the app may; the reference readers do, named only: `--rpc` repeated, `--rpc-agree`): by default **failover** in the order given, every word of a request from the one source that answered the whole read and the next source from scratch after a failure, never a mix; with the **agreement option** a **strict majority** of the sources (⌊n/2⌋ + 1) must return the same complete read at one block, counted per source over the whole read, else the read is refused. A discovered endpoint serves a read that feeds a decryption only under the agreement option with at least three sources | the request's words are one source's (failover) or the identical read of a strict majority (agreement); a discovered source alone, or under agreement with fewer than three sources, is refused |
| 2 (<a id="CLI-UAL-32"></a>CLI-UAL-32) | **Known chain**: `(chainId, chain_uid)` from the holder's configuration (genesis hashes as pinned in `smartcontracts/evm/chain-uids.json`, [NET-ALL-22](../networks/README.md#NET-ALL-22)) | `eth_chainId` and `eth_getBlockByNumber("0x0").hash` equal the configured pair |
| 3 (<a id="CLI-UAL-33"></a>CLI-UAL-33) | **One final block**: all words from one block final by the chain's rule, or at the holder's confirmation depth where the chain has no finality ([NET-EVM-04](../networks/evm.md#NET-EVM-04)) | every read names the same block number and hash; `head − block ≥ depth`, or the block is at or below the `finalized` tag |
| 4 (<a id="CLI-UAL-34"></a>CLI-UAL-34) | **Real storage, not views**: storage words by `eth_getStorageAt` / `eth_getProof` at that block; blob and key code by `eth_getCode`, whose `keccak256` equals the account's `codeHash`; `eth_call` views only from requirement 1's own or configured node, never as the sole source of a word a light client verifies | `keccak256(code) == codeHash` for each pointer; the method and block recorded per word |
| 5 (<a id="CLI-UAL-35"></a>CLI-UAL-35) | **Catalogued token**: catalogued by that chain's `OpenFactory` (its configured address) with a PQZ kind for the PQZ facade, a Zether kind for the Zether facade | the factory index's `_rec[token]` read as storage (slot and packing from ua-mtx-merge's pin `test/zether/ZetherStateVectors.t.sol`): `contractClass` TOKEN, `kind` among the facade's kinds; the token's code a clone of a chain-neutral release, its `ChainEnv` read at the fixed offsets (owner 2026-11-08) |
| 6 (<a id="CLI-UAL-36"></a>CLI-UAL-36) | **The selected leg belongs to the handle**: the leg's recipient UA's registered key equals the handle's (PQZ: `pqzKeyOf(ua)` `proven`, its key hash the handle's; Zether: the registered `Y`); an auditor read: the account is the token's `auditorUA`, `auditorMode` not NONE, an auditor copy on that leg; a disclosure kind allowed by the token's `disclosureMode` | the registry and token words read as storage at the same block; the comparisons above; the registry read is the one the token's `ChainEnv` names (owner 2026-11-08) |
| 7 (<a id="CLI-UAL-37"></a>CLI-UAL-37) | **Nothing back**: no result, failure, error code, result-dependent timing, follow-up read or log line that depends on a decryption goes back to the source; a result goes to the holder or a viewer the holder names | no request to the source after a decryption depends on its outcome (reviewable in the layer's code) |

Encryption to a public key is public: a debit's `pkT`, `pkA`, the op 7 legs' keys and the Zether `yTo` / `yAud` stay caller
fields, and a wrong key is refused on chain.

<a id="CLI-UAL-38"></a>**CLI-UAL-38** — **The source's residual is the holder's chosen trust** (owner 2026-11-06). The holder's own full node
trusts only the chain's rules; a light client trusts the chain's sealing keys (a sealer or a leaked sealing key can seal a header over a
fabricated `stateRoot`; one key on a single-signer chain); another operator's node trusts that operator. SPECIFIED.

<a id="CLI-UAL-39"></a>**CLI-UAL-39** — **Another family needs a trusted node and a layout parser, not a change of the rule** (owner 2026-11-06: the
question of chain adapters is moot for `ua-rs`). The library has no chain adapter, so nothing in it blocks Zether on another family; a
reading layer there meets requirement 1 with a trusted node of that family and states its own assertions, and the library refuses that
family's words until its parser exists. SPECIFIED.

<a id="CLI-UAL-40"></a>**CLI-UAL-40** — **Reference reading layers** (owner 2026-11-07 for PQZ). `zether-read-balance --rpc` (zether-prover) is a reading
layer under [CLI-UAL-30](#CLI-UAL-30) for the holder's own Zether account: requirements 1 to 3, 5 and 6 checked against the configured node, storage words by
block hash, every read before the key is used; it reads no entry, so the `codeHash` check of requirement 4 does not arise;
without `--rpc` it reads the holder's own sealed cache box; a typed-in ciphertext (`--ct`) exists only under `hazmat`. BUILT.

***The PQZ reference reading layer, `pqz-read`: BUILT*** (ua-rs-sign T15m, owner 2026-11-07; a binary of the `ua-rs` package,
`clients/ua-rs/src/bin/pqz-read.rs`, never in the library). It reads the words of `balance` (the holder's own account of key
version `--key-version`, with `--for-op7`) and `auditRead` (an audited leg, on the token's auditor's key of `--key-version`)
and feeds them to `ua-rs`; it never parses a
ciphertext or decrypts itself. Required: `--rpc` (requirement 1: a node the holder names, repeated for several, failover by default and a strict majority with `--rpc-agree`; named only),
`--chain-id` and `--chain-uid` (2), `--depth` or `--finalized` (3: every read by block hash, EIP-1898 with `requireCanonical`;
the node must answer the block asked for and the block must keep its hash until the last read), `--factory` (5: `_rec[token]`
class TOKEN with a PQZ kind), `--registry` and `--ua` (6: `pqzKey[ua][--key-version]`'s code must hold the handle's key; for
`auditRead`, `--ua` the token's `auditorUA` with `auditorMode` not NONE). Group 3g (ua-rs-sign T15o, spec
`2026-11-06-pqz-key-versions.md` on `ua-mtx-merge`): the account is `acct[ua][v]`, the counter `sendCounter[ua]`, the request
carries `keyVersion` and the registry's `pqzVersions[ua]` word; `ua-rs` refuses a version above `current`, and a debit of a
stale one other than the migration (op 1 to its own UA) or a refresh; a balance over every version is one call per version. Storage and code only (4), the token's slots by `STATE_LAYOUT` (the
`scaas.pqz` pin) under the namespace's ERC-7201 root, the pending window `[rolled, p)` by the facade's own rule; every read,
the block re-check included, before the key is used, nothing after it to the node (7). The key arrives as JSON on stdin, the
URL and body go to `curl` on its stdin; `--words` prints the request read without a key. `clients/ua-rs/tests/pqz_read.rs`:
against a local `anvil`, the words equal the forge rows byte for byte, the wallet rows and an audited op 1 decrypt with real
keys, and each refusal of requirements 2, 3, 5 and 6 is named (mutants:
`smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15m-mutants.txt`). Since T20b the factory record (`_rec[token]`, slot 8,
word 2) and the registry's slots (`UAStore.Layout` 2, 4, 5, 17) are read where their pins put them, in both reference layers.
Since the owner's ruling of 2026-11-08 both reference layers refuse a token whose code is no clone with a `ChainEnv` and a
`--registry` other than the one that env names (CLI-UAL-58). **Residuals:** requirement 4's `codeHash` check is not made (no `eth_getProof`); the
other words commands (`proveDisclose`, `proveDiscloseSender`, `openMemo`, the debits) are not wired; a debit request is not
built. UNAUDITED.

<a id="CLI-UAL-41"></a>**CLI-UAL-41** — ***Decoy selection for PQZ op 7 and classical Zether multi-recipient transfers: BUILT*** (ua-rs-sign T15n;
rule [CTR-UA-29](../contracts/accounts.md#CTR-UA-29), Change of 2026-11-07, owner). The candidates are the registry's per-kind list
of the token's family: `0x0142` (every holder with a proven PQZ key, one anonymity set across the signer kinds) for PQZ, `0x0141`
for classical Zether, up to the wallet's **last sync point**: a UA listed after it is never a candidate. **Default: uniform**
over the candidates. **Option, off by default:** the token-activity filter keeps only the candidates active in the token within
a look-back window and weights them by recency; with the stricter variant only holder-authorised activity (a `sendCounter` move)
counts. **The trade-off, stated to the holder:** registration is permissionless, so with the default an observer that registers
UAs of the kind can recognise its own decoys in a ring (threat S30; a PQZ holder costs one PQ registration); the filter raises
that to gas-level cost only (an observer keeps its UAs active), and it shrinks the anonymity set to the recently active.
- **The pick** (`ua-rs` `facade::decoys`, pure and I/O-free; command `pickDecoys` of both facades, on any key handle, the key
  unused): request `{candidates, exclude, count, weights?, recipient?}`, named fields: `count` = `M − 1`, `exclude` the sender
  and every real recipient, `weights` (the filter's, optional) one `u64` per candidate, `recipient` (optional) the real
  recipient, excluded implicitly; answer `{decoys}`: `count` distinct candidates, never an excluded one, drawn one at a time
  without replacement by the OS CSPRNG (rejection sampling, no modulo bias), uniform without `weights`; with `recipient`
  `{decoys, legs}`. Too few eligible candidates (not excluded, weight above 0), a candidate given twice, `weights` of another length or
  any other field: `Argument`. One command, not a field of `proveTransferMulti`: the pick comes before the decoys' keys are read
  (only the chosen keys are), and op 7's legs and the Zether recipients already take explicit keys.
- **The recipient's position** (ua-rs-sign T15n follow-up): the legs of op 7 and of a Zether multi-recipient transfer are
  public in their order, so **a fixed position of the real recipient (always first, always last, always after the decoys)
  names it** to every observer, whatever the decoys. The safe choice is the default: with `recipient`, `legs` is the full leg
  order (the recipient and the decoys, `M` UAs) shuffled uniformly by the OS CSPRNG (Fisher–Yates, each index by rejection
  sampling). **Callers build the transfer's legs in the `legs` order**, or shuffle themselves with a uniform shuffle from a
  CSPRNG; without `recipient` the answer is `{decoys}` as before and the order is the caller's duty.
- **The recency weight** of the filter (2 for a candidate active in the newer half of the window, 1 for one active only in
  the older half) is a documented choice, kept as built: a simple two-step recency preference; another shape (more steps, a
  decay) is not a rule.
- **The reading layers** (storage only, the list's length read at the sync point by block hash and everything else at the read
  block, every block re-checked after the last read; no key, no stdin): `pqz-read --command decoys --count <M−1> [--exclude …]
  [--sync-block <n>] [--decoy-filter activity|holder --window <blocks>]` reads the `0x0142` list, excludes `--ua` and `--exclude`,
  calls the pick in process and reads each chosen decoy's proven `pqzKey` record and key code: `{decoys: [{ua, pk}]}`, each an
  op 7 leg with amount 0 (`--words` prints the pick's request); `--recipient <ua>` passes the real recipient to the pick and
  adds its shuffled `legs`. `zether-read-balance … --registry <address> --decoy-count <M−1> --exclude … [--recipient <ua>]`
  prints the pick's request from the `0x0141` list (zether-prover does not link `ua-rs`); after `pickDecoys`,
  `--decoy-keys <ua>,…` reads each chosen UA's record (kind `0x0141`, its list index below the sync point's count and the list
  entry at that index equal to it) and its `Y`, with `UA(Y)` equal to it: `{decoys: [{ua, yTo}]}`, each a recipient with amount
  0. The filter reads the account's counters at `block − window`, `block − window/2` and `block` (PQZ `pendingCount`, `rolled`,
  `sendCounter`; Zether the counters word): moved in the newer half weight 2, only in the older half weight 1, else dropped;
  `holder` compares `sendCounter` only. The node must hold those blocks' state.
- Tests: the pick's distribution by chi-square at a fixed seed (unit tests only), no duplicates, exclusions, too few, the
  facades and the C ABI; each tool against a local `anvil` (UAs listed after the sync point never chosen, the filter on and off,
  its weights, the keys, the refusals); mutants `smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15n-mutants.txt`.
- **Group 3g (T15o):** `pqz-read --command decoys` never draws a UA with a pending key version (its latest version has this
  set's key length and is not current: a credit to it would fail), and reads each chosen decoy's key at its current version
  (`pqzKey[ua][current]`).
- **Residuals:** the registry's slots (`records` 0, `pqzKey` 2, `uaCount` 4, `uaAt` 5, `pqzVersions` 17) are hand-copied: the
  registry layout pin (`ua-mtx-merge` group 3g, `UAStoreLayout.t.sol`) is not on this branch; `--registry` must be the generation
  that lists the kind (a predecessor's list is not followed, the forwarding is in code); clientkeys' preference for UAs without a
  recent `UAPqzKeyCurrent` is not applied (storage only, no event read); a list longer than 50,000 UAs is refused (one storage read per UA); the
  Zether steps are two reads at two read blocks, both bounded by the same sync point; the order of the legs is the caller's
  only when it omits `recipient` (it must then shuffle itself). UNAUDITED.

<a id="CLI-UAL-42"></a>**CLI-UAL-42** — **pqz-core `hazmat`, defence in depth: PLANNED** (owner 2026-11-06, plan task T15h). A feature over `pqzl`
`decrypt_raw`, pqz-ffi's `dec` and `dec_win` and the C `pqz_dec` family, which then only pqz-ffi's self-test, its vectors and `ua-rs`'s private
decrypt path enable. It lands with the next pqz-core change; the four-set full gate is waived for this `cfg`-only change and replaced by a
build at all four sets plus `kat`. Not built: pqz-core is unchanged in this round. Since `ua-rs` enables it, it is in every `ua-rs` + `pqz` binary; the
command set is the boundary.

**Not here.** Per-kind derivation and clientkeys' API ([signers-clientkeys](signers-clientkeys.md)), group vectors, the registry contract, the UA ledger.
Not built yet: the FRB layer as a Flutter plugin and its Android and iOS builds (no web build: `SecretBytes` needs `dart:ffi`), the wasm-bindgen browser binding of `ua-rs` (the library compiles for wasm32), and Qt packaging for Windows and macOS.
