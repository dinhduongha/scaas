# UA phase (Universal Account F0, F1, F2) — Roadmap

**Scope (owner 2026-10-12).** The Universal Account streams F0 (kind libraries and vectors), F1 (the EVM `UARegistry`
generation 1 with the classical verifiers and the Zether re-point) and F2 (the UA ledger in the token base, CTR-UA-26),
run as their own phase before P6c ([P6 roadmap](2026-10-12-p6-roadmap.md) §3 item 1). P6c then adds only the PQ kinds
(UA F9) to registry generation 1. Spec: [accounts.md](../../contracts/accounts.md) §1 (CTR-UA-01…26); stream table in
`docs/history/specs/2026-10-06-universal-account-design.md` §16.

**Base:** `main` at `ce92ad5` (P1–P5, P3b and P6a merged; forge 917 passed / 10 skipped; clientkeys 75 / 73 / 2).

## 1. Survey (2026-10-12)

| Item | Status |
|---|---|
| Kind table libraries (F0) | **None.** `src/ua/PqUA.sol` and clientkeys `src/pq.js` (P6a) carry the PQ tags, ids and `ua_msg` only. No `UAKinds.sol`, `ua.js`, Rust crate, Python, Go or C# library; no `vectors/ua/kinds.json`. |
| `UARegistry` (F1) | **Not built.** `src/registry/UniversalAccountRegistry.sol` is the Zether-era registry (8 `AuthScheme`s, untagged `UA = keccak256(encodedY)`, PoP bound to `msg.sender`). |
| Verifiers (F1) | Built pieces to reuse: the scaas Schnorr (`UniversalAccountRegistry._schnorr`, bn254 and BLS12-381 G1), BLS min-sig (`Bls12381.verifyMinSig`, `HashToCurve`, `_blsBn254` with `G1Bn254.mapToG1`), the WebAuthn grammar of `SmartKeyAccount`, `MultiSig`; the PQ verifiers (P6a). Not built: `bip340`, `p256`, `ed25519`, MuSig2 KeyAgg, FROST (secp256k1, bn254) with the DKG check, `msig`. |
| UA ledger (F2) | **Not built.** No `_uaBalance`, `UA_POOL`, `ua*` functions, `UAMetaTransaction` / `UAMetaTransfer`. |

## 2. Sub-plans

Each sub-plan is one plan, accepted on its own (tests green, size gate, docs checkers, review), then merged; written one
at a time, like P1a–P1e.

| Sub-plan | Content | Depends on | Gate |
|---|---|---|---|
| **UA-1** kind libraries (F0) | The identity layer in six libraries — Solidity `UAKinds.sol`, clientkeys `ua.js`, Rust `clients/scaas-ua`, Python `clients/ua-py`, Go `clients/ua-go`, C# `clients/ua-cs`: kind table, tags, ids, keyHash (`GROUP(g)`), purpose tags, `ua_msg`, `popDigest`, `UAAuth` digest, member digest, canonical ids, closed sets, key-data validation (layout, range, curve, subgroup; `msig`, MuSig2 and FROST layouts); `vectors/ua/kinds.json` and `structures.json` from one generator, cross-checked by an independent implementation. Plan: [2026-10-12-ua1-kind-libraries.md](2026-10-12-ua1-kind-libraries.md) | — | all six pass the same vectors |
| UA-1b bindings (owner 2026-10-12: next after UA-1) | C++ in two layers over `scaas-ua` (owner 2026-10-12): a plain `cxx` bridge (a C++ API for non-Qt C++; CMake + corrosion) and CXX-Qt (a `QObject` defined in Rust, for QML; Qt 6 must be installed); Dart in two ways (owner 2026-10-12): flutter_rust_bridge v2 over a wrapper crate on `scaas-ua` (Android, iOS, desktop, web through WASM; cargokit, pinned version, codegen in CI) and a pure-Dart port (all platforms including web, no native build); all on the shared vectors | UA-1 | the same vectors |
| **UA-2** registry and verifiers (F1) | `UARegistry` gen 1 (records, `keyOwner`, PoP, `requireAuthorized`, the native ECDSA / ERC-1271 / EIP-7702 paths with `UAAuth`, `msig` with the structure gas bound, capped verifier `staticcall`s that fail closed, generations, `chainUid`, `hederaNative`), every classical verifier (`webauthn-p256`, `p256`, `ed25519`, `bip340`, `schnorr-bn254`, `schnorr-bls12381`, `bls12381-minsig`, `bls-bn254-minsig`, MuSig2 KeyAgg with hints, FROST secp256k1 and bn254 with the DKG check), the PoP signatures in `kinds.json`, `groups.json`, `structures.json` signatures; T-REG, T-AUTH, T-CHAIN, T-MEMBER, T-FROST, T-GAS (classical kinds). Carried from UA-1: (1) probe precompiles 0x08, 0x0c and 0x0e with the "outside the subgroup" rows at deployment on each target chain (chain 7622 first); (2) ecrecover's `address(0)` must not satisfy an `evm-eoa` msig member with id 0 (the layout allows that id); (3) bn254 G2 validation needs about 165k gas at the call site; (4) a chain that prices EIP-2537 or the bn254 pairing above 2× the EIP price refuses valid keys with `UAVerifyGas`: check the prices per chain before enabling those kinds | UA-1 | the T-* suites green |
| **UA-3** Zether re-point and migration (F1) | `zether-*` kinds in the registry (`requireZetherAuthorized`, `authRef` co-sign), `ZetherTypes.toUA` tagged, `ZetherLayer.registered` by `kindOf`, the prover and clientkeys Zether changes (one change set, CTR-UA-22), `DeployBase` deploys the registry, the old registry and `AuthScheme` to `legacy/` (owner: backup, not delete) | UA-2 | T-ZET, e2e on dev chains |
| **UA-4** UA ledger (F2) | `_uaBalance`, `UA_POOL`, `UATransfer`, the `ua*` functions with `UAMetaTransaction` / `UAMetaTransfer` (CTR-UA-18/19/26), the shared nonce map, `metatx3.json`; closes MT-2's UA path | UA-2 (UA-3 for Zether receivers) | T-V3-1…4 |

Then P6c (PQ kinds in registry gen 1), which needs UA-2.

## 3. Owner steps

None open. Decided 2026-10-12: UA F0/F1 as their own phase; three F0/F1 sub-plans plus the UA ledger (UA-4); the
Python library in this repo (`clients/ua-py`); Go and C# client libraries added to F0.
