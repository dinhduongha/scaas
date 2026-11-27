# Key schemes: the SCaaS kinds beside Sui, Cellframe and the target families

Which signature and key schemes the SCaaS Universal Account (UA) kinds use, by scheme, and how they compare with Sui's signature
flags, Cellframe's DAP SDK and the native schemes of the families SCaaS targets. This page defines no kind, no byte format and no
rule. The kind table is [accounts.md §1.6](../contracts/accounts.md#kinds) (numbers, key data, keyHash groups, verifiers); the
code authority is `clients/ua-rs/src/lib.rs` `KINDS`; the vectors are `smartcontracts/vectors/ua/kinds.json`
([NET-ALL-20](README.md#NET-ALL-20)). What each chain supports today is [chain-support.md](chain-support.md).

Status tags: **BUILT** (in code, tested), **SPECIFIED** (normative, code pending), **PLANNED** (direction). §1 states SCaaS
status, read from the code and the component docs on 2026-11-27. §2 to §4 are background about other systems: not normative,
nothing in them is a SCaaS rule.

**Contents**

1. [SCaaS kinds by scheme](#1-scaas-kinds-by-scheme)
2. [Beside Sui and Cellframe](#2-beside-sui-and-cellframe)
3. [Native schemes of the other target families](#3-native-schemes-of-the-other-target-families)
4. [Sources](#4-sources)

## 1. SCaaS kinds by scheme

Status: BUILT, except where a cell says otherwise.

Columns: **Kinds** the kind numbers and names of [accounts.md §1.6](../contracts/accounts.md#kinds); **EVM** the `UARegistry`
verifier on EVM chains (the chains where a kind fits or is disabled: [chain-support.md](chain-support.md)); **Clients** signing in
`ua-rs` (every `KINDS` row) and the `clientkeys` reference; **Other families** what the non-EVM families verify. The subject
signatures each non-EVM family verifies today are the table of [networks README §1](README.md#families-and-chains); PQ kinds and
`bls12381-multi` on those families belong to each family's `ua-<family>` round ([ARCH-POS-18](../decisions.md#ARCH-POS-18): a
missing host function means a software path, not a disabled kind).

| Scheme | Kinds | Key (B) | EVM | Clients | Other families |
|---|---|---|---|---|---|
| ECDSA secp256k1 | `0x0001` `evm-eoa` (native, EVM and Hedera); `0x0108` `secp256k1` (derived) | 20 (address); 64 | BUILT | BUILT | BUILT where README §1 lists secp256k1 (Cosmos ADR-036, Sui flag 1, NEAR, Algorand) and on Solana ([solana.md](solana.md)) |
| Schnorr secp256k1: BIP-340, MuSig2 (BIP-327), FROST (RFC 9591) | `0x0103` `bip340`, `0x0110` `musig2-secp256k1`, `0x0111` `frost-secp256k1` | 32; variable | BUILT | BUILT | PLANNED (accounts.md: EVM → Cosmos) |
| Ed25519 | `0x0102` `ed25519` (derived); natives `0x0010` Solana, `0x0011` Stellar, `0x0013` Aptos, `0x0014` Sui, `0x0016` GRAM, `0x0017` NEAR, `0x0018` Algorand | 32 | BUILT (Solidity, SHA-512 included) | BUILT | BUILT (each family's native key) |
| ECDSA P-256 | `0x0101` `p256` | 64 | BUILT (`P256VERIFY`, fallback) | BUILT | as WebAuthn below |
| WebAuthn P-256 (passkey) | `0x0100` `webauthn-p256` | 96 (`x ‖ y ‖ rpIdHash`) | BUILT | BUILT | BUILT on each family whose README §1 row lists a passkey ([NET-ALL-04](README.md#NET-ALL-04)) |
| Schnorr, BLS, MuSig2, FROST on bn254 | `0x0104`, `0x0107`, `0x0112`, `0x0113` | 64 / 128; variable | BUILT (bn254 precompiles; `0x0107` where the G2 probe passes) | BUILT | none (EVM only, accounts.md) |
| Schnorr and BLS on BLS12-381 | `0x0105` `schnorr-bls12381`, `0x0106` `bls12381-minsig` | 128; 256 | BUILT (EIP-2537 chains) | BUILT | none (EVM only, accounts.md) |
| Weighted t-of-n BLS12-381 multi-signature | `0x0121` `bls12381-multi` ([CTR-UA-47](../contracts/accounts.md#CTR-UA-47)) | variable | BUILT (EIP-2537 chains; disabled on Hedera) | BUILT | PLANNED ([CTR-UA-54](../contracts/accounts.md#CTR-UA-54)) |
| Weighted multi-kind multisig | `0x0120` `msig` (members of any MEMBER kind, PQ ones included) | variable | BUILT | BUILT | BUILT on Soroban; NEAR, Algorand: their rounds ([NET-ALL-84](README.md#NET-ALL-84) row 10) |
| ML-DSA (FIPS 204) | `0x0130` `mldsa44`, `0x0131` `mldsa65`, `0x0134` `mldsa87` ([CTR-UA-23](../contracts/accounts.md#CTR-UA-23), [CTR-UA-39](../contracts/accounts.md#CTR-UA-39)) | 1,312; 1,952; 2,592 | BUILT (EIP-8355 precompile where probed, else Solidity on a cached expanded key; disabled where the cap does not fit) | BUILT | PLANNED (`ua-near` and `ua-algorand` named; the rest family rounds) |
| FN-DSA / Falcon (specification v1.2, third NIST round) | `0x0132` `fndsa512`, `0x0135` `fndsa1024` ([CTR-UA-40](../contracts/accounts.md#CTR-UA-40)) | 897; 1,793 | BUILT (Solidity) | BUILT | PLANNED |
| SLH-DSA-SHA2-128s (FIPS 205) | `0x0133` `slhdsa128s` | 32 | BUILT (Solidity on SHA-256) | BUILT | PLANNED |
| Classical Zether account (Schnorr, BLS12-381 G1) | `0x0141` `zether-bls12381` | 128 | BUILT (EIP-2537 chains) | BUILT | PLANNED (`zether-<family>`) |
| PQZ key (MLWE), **a scheme, not a kind** | `0x0142` `pqz-mlwe` ([CTR-PQZ-13](../contracts/pq-zero-knowledge.md#CTR-PQZ-13)) | 16,384 – 22,528 by set | BUILT (the PQZ precompile on the SCaaS testnet; other EVM chains: [chain-support.md](chain-support.md) PQZ column) | BUILT | none ([chain-support.md](chain-support.md) PQZ column) |
| KEM: ML-KEM-1024 + X25519 (X-Wing-style combiner) | not a kind: the KEM record of a PQ-holder UA, scheme byte `0x01` ([CTR-UA-32](../contracts/accounts.md#CTR-UA-32)); scheme `0x02` (ML-KEM-1024 + HQC + X25519) reserved and refused | 1,601 (`kemPk`) | BUILT (registry records) | BUILT (`ua-rs` `wallet::kem`, `clientkeys`) | PLANNED (family rounds) |

The node's mesh transport uses X25519MLKEM768 (TLS key exchange, [gossip.md](../node/gossip.md)); it is transport, not a key
record. Zether and PQZ are separate rows on purpose: Zether is classical, PQZ is post-quantum.

## 2. Beside Sui and Cellframe

> **Background — research, not normative.** External facts read on 2026-11-27 from the sources of [§4](#4-sources); each moves
> fast, re-check before a plan uses it.

Sui is a SCaaS family ([sui.md](sui.md)). Its signature flag is the first byte of a serialized signature and of the address
preimage, `address = blake2b256(flag ‖ pk)` [S1]: `0x00` Ed25519, `0x01` ECDSA secp256k1, `0x02` ECDSA secp256r1, `0x03`
multisig, `0x05` zkLogin, `0x06` passkey. The SCaaS Sui contracts verify flags 0, 1, 2 and 6 in Move ([sui.md §4](sui.md#signatures));
a Sui zkLogin or multisig address acts in SCaaS only as a native sender (kind `0x0014`), never as the signer of a relayed
operation. Sui's post-quantum plan [S2, S3]: ML-DSA-65 as a native account scheme (Testnet by the end of 2026, Mainnet
authentication targeted for Q1 2027), SLH-DSA-SHA2-128s in Move vaults (Mainnet targeted for 2026), ML-DSA-65 in the multisig
authenticator, FN-DSA declined.

Cellframe's DAP SDK ([S4]–[S6]) lists its schemes in `enum dap_sign_type_enum` (`crypto/include/dap_sign.h`) and its key types
in `dap_enc_key_type_t` (`dap_enc_key.h`). The default branch `develop` (commit `0ba2a892e270`, 2026-11-19) has no Chipmunk, no
ML-DSA and no ML-KEM; branch `main` (commit `3b360f3a3bda`, 2026-07-30, layout `module/crypto/`, the same set on `release-6.0`
and `feature/chipmunk-ring`) adds them. The table quotes `main`.

| Scheme | SCaaS (§1) | Sui | Cellframe DAP SDK (`SIG_TYPE_*`) |
|---|---|---|---|
| Ed25519 | `0x0102` + natives | flag `0x00` | none |
| ECDSA secp256k1 | `0x0001`, `0x0108` | flag `0x01` | `ECDSA` `0x0105` |
| ECDSA P-256 | `0x0101` | flag `0x02` | none |
| WebAuthn passkey | `0x0100` | flag `0x06` | none |
| Schnorr secp256k1, MuSig2, FROST | `0x0103`, `0x0110`, `0x0111` | none | none |
| bn254 and BLS12-381 Schnorr / BLS, BLS multi | `0x0104`–`0x0107`, `0x0112`, `0x0113`, `0x0121` | none as an account flag | none |
| Multisig over mixed schemes | `0x0120` `msig` (weighted, PQ members included) | flag `0x03` (weighted; ML-DSA-65 members planned) | `MULTI_CHAINED` `0x0f00`, `MULTI_COMBINED` `0x0f01`, `MULTI_ECDSA_DILITHIUM` `0x0eff` |
| OpenID login proven in zero knowledge | none | flag `0x05` zkLogin (Groth16 over BN254) | none |
| ML-DSA (FIPS 204) | `0x0130`, `0x0131`, `0x0134` | ML-DSA-65 planned | `ML_DSA` `0x0201` (`main`); `DILITHIUM` `0x0102` (CRYSTALS-Dilithium, before FIPS 204) |
| FN-DSA / Falcon | `0x0132`, `0x0135` | declined | `FALCON` `0x0103` |
| SLH-DSA / SPHINCS+ | `0x0133` (FIPS 205) | SLH-DSA-SHA2-128s in Move vaults, planned | `SPHINCSPLUS` `0x0104` (SPHINCS+, before FIPS 205) |
| Lattice ring and threshold-ring signatures | none | none | `CHIPMUNK_MRING` `0x0108`, `CHIPMUNK_LRS` `0x010A`, `LOTRS` `0x010B`, `CHIPMUNK_RING` `0x010C` (marked experimental, signer anonymity "NOT yet claimed") |
| Other lattice, hash and code schemes | none | none | `BLISS` `0x0001`, `TESLA` `0x0003`, `PICNIC` `0x0101`, `SHIPOVNIK` `0x0106`, `CHIPMUNK` `0x0107` (stateful, hypertree), `NTRU_PRIME` `0x0113`; `PQLR_DILITHIUM` `0x1102`, `PQLR_FALCON` `0x1103`, `PQLR_SPHINCS` `0x1104` only in `DAP_PQLR` builds |
| Confidential amounts | Zether `0x0141` (classical); PQZ `0x0142` (post-quantum) | none | key type `SIG_RINGCT20` 22 ("ring signature for confidential transaction") |
| KEM | ML-KEM-1024 + X25519, scheme `0x01` | none in the account schemes | key types `RLWE_NEWHOPE_CPA_KEM` 8, `MSRLN` 11, `RLWE_MSRLN16` 12, `RLWE_BCNS15` 13, `LWE_FRODO` 14, `CODE_MCBITS` 15, `NTRU` 16, `MLWE_KYBER` 17, `KEM_KYBER512` 23, `ML_KEM` 29 (`main`), `KEM_NTRU_PRIME` 36 (`main`); `PQLR_KEM_SABER` 1051, `PQLR_KEM_MCELIECE` 1052, `PQLR_KEM_NEWHOPE` 1058 in `DAP_PQLR` builds |

Cellframe numbers key types separately from signature types: `DAP_ENC_KEY_TYPE_SIG_CHIPMUNK` is `0x0108` while
`SIG_TYPE_CHIPMUNK` is `0x0107`, and `SIG_TYPE_CHIPMUNK_MRING` is `0x0108`.

## 3. Native schemes of the other target families

> **Background — research, not normative.** Read on 2026-11-27 ([§4](#4-sources)); only the schemes that matter for a SCaaS kind.

| Family | Native account schemes | Contract-callable verification that matters for a kind |
|---|---|---|
| EVM | ECDSA secp256k1 (EOA) | `P256VERIFY` at `0x100`, EIP-7951 Final [S7]; bn254 and EIP-2537 precompiles; ML-DSA and Falcon precompiles still drafts (accounts.md) |
| Hedera | Ed25519, ECDSA secp256k1 ([hedera.md](hedera.md)) | the EVM set on HSCS, HIP-632 `isAuthorizedRaw` |
| Solana | Ed25519 | precompile programs for Ed25519, secp256k1 and secp256r1 [S8] |
| Stellar / Soroban | Ed25519 | host functions `verify_sig_ed25519`, `verify_sig_ecdsa_secp256r1` (CAP-0051) and, at Protocol 30, `verify_sig_ml_dsa_{44,65,87}` (CAP-0087, status Implemented) [S9] |
| Aptos | Ed25519, secp256k1, passkey (AIP-66), keyless OpenID accounts (AIP-61) | AIP-137 adds SLH-DSA-SHA2-128s as an account scheme, status Accepted [S10] |
| GRAM (TON) | Ed25519 in wallet contracts ([ton.md](ton.md)) | TVM `CHKSIGNS` (Ed25519) and `P256_CHKSIGNS` ([NET-ALL-20](README.md#NET-ALL-20)) |
| NEAR | Ed25519, secp256k1 and, since nearcore 2.13.0 (2026-07-09), ML-DSA-65 access keys and transaction signatures [S11] | host function `ml_dsa_verify` (ML-DSA-65, empty context, message as given) since nearcore 2.14.0, 2026-10-26 [S11] |
| Algorand | Ed25519 | opcodes `ed25519verify_bare`, `ecdsa_verify` (secp256k1, secp256r1), `falcon_verify` (deterministic Falcon-1024 from AVM v12, deterministic Falcon-512 from v14) and `mldsa_verify` (ML-DSA-44, ML-DSA-65; AVM v14) [S12]; the activation of v14 on MainNet was not checked |
| Cosmos | secp256k1 accounts (ADR-036 signing, [cosmos.md](cosmos.md)) | no PQ function callable from CosmWasm ([chain-support.md](chain-support.md) PQ column: family round) |

NEAR's ML-DSA-65 and Soroban's ML-DSA host functions verify the message as given with the FIPS 204 empty context, which matches
the `mldsa*` kinds' signing over the 32-byte `pq_msg` ([CTR-UA-23](../contracts/accounts.md#CTR-UA-23)); Algorand's
deterministic Falcon is not the `fndsa*` kinds' randomized signing.

## 4. Sources

Status: background. Every source read on 2026-11-27.

- [S1] Sui, "Transaction authentication overview": <https://docs.sui.io/develop/transactions/transaction-auth/auth-overview>
- [S2] Sui Foundation, "Making Sui quantum ready", 2026-08-06: <https://www.sui.io/blog/making-sui-quantum-ready>
- [S3] K. Chalkias, M. Sedaghat, "Sui's post-quantum signature schemes", 2026-08-18: <https://www.sui.io/blog/suis-post-quantum-signature-schemes>
- [S4] DAP SDK `develop`, `crypto/include/dap_sign.h` and `dap_enc_key.h` at `0ba2a892e270`: <https://github.com/demlabs-cellframe/dap-sdk/tree/develop/crypto/include>
- [S5] DAP SDK `main`, `module/crypto/include/dap_sign.h` and `dap_enc_key.h` at `3b360f3a3bda`: <https://github.com/demlabs-cellframe/dap-sdk/tree/main/module/crypto/include>
- [S6] DAP SDK `main`, `module/crypto/src/sig/chipmunk/README.md`: <https://github.com/demlabs-cellframe/dap-sdk/tree/main/module/crypto/src/sig/chipmunk>
- [S7] EIP-7951, "Precompile for secp256r1 curve support" (Final): <https://eips.ethereum.org/EIPS/eip-7951>
- [S8] Solana, "Precompiled programs": <https://solana.com/docs/core/programs/precompiles>
- [S9] Stellar CAP-0087, "Host functions for ML-DSA signature verification": <https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md>
- [S10] Aptos AIP-137, AIP-61, AIP-66: <https://github.com/aptos-foundation/AIPs/tree/main/aips>
- [S11] nearcore 2.13.0 and 2.14.0 release notes: <https://github.com/near/nearcore/releases/tag/2.13.0>, <https://github.com/near/nearcore/releases/tag/2.14.0>
- [S12] Algorand AVM opcodes: <https://dev.algorand.co/reference/algorand-teal/opcodes/>
