# Post-quantum Zether on private/PoA chains (component spec E)

Status: draft **rev 1.4**, 2026-10-07. **Rev 1.4** (owner 2026-10-07, §17.4): `PqzToken` follows the
meta-transaction interface — it is an ERC-20 + `IERC20MetaTx` token exactly like `ZetherToken` (R284 rewritten, new
§7.11), with the PQ-complete path through MetaToken v3's `UAMetaTransaction`; the statement header gains
`envelopeBinding` (576 B). Rev 1.1 folded the owner answers to §17 q1–q3 (licence gate G-LIC, Nethermind-only
v1, retail WASM prover moved up to E-S6). Rev 1.2 folds review 1 (FIX-THEN-GO, 17 findings, disposition §17.2): new
parameter set at Kyber-512-class core-SVP and above (`q = 2^42 − 215`, partially splitting, base-16 digits,
`K_MAX = 1024`), public `plainPending` instead of trivial ciphertexts, the LaZer fork re-scoped as a rewrite of its
arithmetic layers, a never-crash verifier requirement, and uniform op/proof-system binding. **Rev 1.3**
(2026-10-07) folds the Codex review (FIX-THEN-GO, 6 findings, disposition §17.3): authorization over F's exact
`ua_msg` (with `MSG_TAG`, the `authRef` record's own kind), PoP over `popDigest(ua, authRef)` plus the `authRef`
co-sign (F R295), the shared-randomness leakage model over the joint secret `(r, e1)` with a split-randomness
fallback, normative inline lengths, and a fixed-price, cached `OP_SELFTEST`. The owner moved the private chain id
from 9000 (also Evmos Testnet) to **7622**: the gate is `{31337, 1337, 7622}`, and the chain is identified by
`(chain id, chain_uid)` as F R330 (genesis hash, copied from the registry into every statement). Wherever rev 1.2
said chain 9000 this spec says chain 7622 (formerly 9000); repo paths and the foundry
profile are named `private7622` (renamed by the 7622 code stream). Component spec **E**. Short name **PQZ**. Code at `scaas` `main` 28c165c (classical
Zether BUILT on dev chains; nothing of PQZ is built). **UNAUDITED — NOT FOR PRODUCTION FUNDS**, like every Zether
artifact (R34). Rulings: **R270–R289** (§3). R290–R318 belong to spec F (UA), R250–R268 to spec D (S4F), R230–R247 to spec C (OPS).

Owner requirements (2026-10-04/06), all addressed here:

| # | Requirement | Where |
|---|---|---|
| O1 | Implement-grade: post-quantum confidential balances like Zether, on lattice homomorphic encryption (BFV/BGV, compare TFHE/CKKS) plus lattice ZK proofs | §2, §4–§8 |
| O2 | Target private/PoA chains (gas limit, block size, precompiles are ours) but keep gas reasonable | §2.7, §9 |
| O3 | Gate off public chains like today's Zether (R34); label UNAUDITED | R270 |
| O4 | Decide: Solidity lattice ops vs custom precompile vs off-chain co-processor | R279, §9.1 |
| O5 | Hybrid classical-now + PQ migration path; harvest-now-decrypt-later (HNDL) | §13, §12 |
| O6 | Key, ciphertext, proof sizes; verify cost | §4.4, §9.4 |
| O7 | Account/key model consistent with spec F "Universal Account" (kind-tagged ids, one key = one purpose, hardened per-kind derivation); define the PQZ UA kinds | §6, R282 |
| O8 | Authorization by ML-DSA/Falcon, verified on chain by precompile | R281, §9.3 |
| O9 | Interaction with existing Zether (curves, `n_v = 64`, registry, `ITransferDisclosure`, BSGS/balance cache), relayer/meta-tx, scaas-node, clientkeys, zether-prover | §7.9, §7.11, §11, R283–R285 |
| O11 | (2026-10-07) `PqzToken` follows the MetaTransaction interface `IERC20MetaTx` | R284, §7.11 |
| O10 | Per-family availability, private EVM first | §14 |

Sources read: [Zether design](2026-10-03-zether-design.md) (byte-exact classical spec), [limits](2026-10-05-zether-limits.md),
[ConsenSys MAX](2026-10-05-zether-consensys-max.md), `blockchain-research/03-zether-crypto.md` §3.1.3, U7,
`blockchain-research/02-account-registry.md` §2.6 (FALCON/PQ, HNDL), `docs/SCaaS.md` §6.8, §8, §9,
`smartcontracts/evm/src/zether/*`, [spec F](2026-10-06-universal-account-design.md) (UA, R290–R318), `zether-prover/src/*`, `clientkeys/src/zether.js`, `scaas-node` (`submit.rs`,
`gateway.rs`, `node.example.toml`), parent `TRAPS.md` "Private chain (Nethermind, chainId 9000)" (heading predates the move to 7622) and
`/home/dockers/mba-chain-nethermind/README-chainspec.md`, `smartcontracts/evm/src/chains/private7622/README.md`.
External sources in §18. Rev 1.4 also read `smartcontracts/evm/src/zether/ZetherToken.sol`, `ZetherMetaTx.sol`,
`metatx/IERC20MetaTx.sol`, `metatx/MetaTxCore.sol` (v2), `common/MetaTxLib.sol`, `common/FeePolicy.sol`, classical
spec §10 (RS2-5–RS2-7), F §5.3 (v3), MESH §1.2/R70 and NI §5 (job kinds, R321).

Amends (rev 1.4; pointers only — the text of those files is rewritten by the stream named):

| Short | File | How |
|---|---|---|
| F | `specs/2026-10-06-universal-account-design.md` §5.2, §5.3, R308–R309 | pointer: `PqzToken` is a second implementation of the v3 `UAMetaTransaction` struct, typehash, nonce map and nine steps on its own UA ledger, with ops `data` empty and the four PQZ ops of §7.11 (no `pay`/`unwrap`/`uaBatch`); §5.2 gains a `PqzToken.executeMetaTransaction`/`uaExecute` row like `ZetherToken`'s; T-V3-3b (`to` = `pqz-mlwe` ⇒ `UAKindNotAccepted`) holds there too (F stream) |
| NI | `specs/2026-10-06-node-independence-design.md` §5 job API, R321, `token.kind` | `metatx` and `ua_metatx` jobs accept configured PQZ tokens (`token.kind` gains `pqz`); `pqz_call` stays for direct open calls only; R321's "never batched" list gains every PQZ token job; 1 MiB body limit on job submissions to a `pqz` chain profile (§11.3; NI stream) |
| MESH | `specs/2026-10-05-relayer-mesh-design.md` §1.2, R70; gossip amendment §1 | **unchanged**: PQZ envelopes stay off the bus exactly like classical Zether intents, and F's `scaas-intent/1.3` `ua_meta_tx` bodies naming a PQZ token are not exported (§11.3) |
| SCaaS | `docs/SCaaS.md` §8 (meta-tx tokens, Zether) | pointer: `PqzToken` is an `IERC20MetaTx` token; its PQZ ops are envelope ops like `OP_ZTRANSFER`/`OP_ZBURN` (SCaaS stream) |
| INT | `docs/integration.md` (relay jobs, Odoo) | pointer: Odoo relays PQZ envelopes as ordinary `metatx`/`ua_metatx` jobs; no new model (§11.4; integration stream) |
| E rev 1.3 | this spec, R284 "No meta-tx envelope" | **superseded** by rev 1.4 R284 (owner 2026-10-07) |

Notation: `R = Z[X]/(X^64 + 1)`, `R_q = R/qR`. Bold-free: `s`, `r`, `e` are vectors in `R^32` (2048 integer
coefficients). `a^T b` for vectors in `R_q^32` is `Σ_j a_j·b_j ∈ R_q`; `x[i]` is coefficient `i` of a ring element.
`‖·‖` is the ℓ2 norm over all integer coefficients (centered representatives). `be8(x)` = 8-byte big-endian.
Everything else as in the classical spec (`‖`, `be32`, `u8`, ASCII strings without terminator).

---

## 1. Summary

**What it is.** A second confidential-token class, `PqzToken`, with the classical Zether *shape* (identity visible,
ring size 2, amounts and balances encrypted, fee as a public scalar, sender/receiver/auditor disclosure), rebuilt on
module-lattice assumptions:

| Layer | Classical Zether (BUILT) | PQZ (this spec) |
|---|---|---|
| Balance encryption | lifted ElGamal on bn254 / BLS12-381 G1 | additive module-LWE, BFV-style scaling `Δ`, digit-packed plaintext (§4) |
| Validity proofs | Σ-protocol + 2 Bulletproofs (`n_v = n_b = 64`) | one LNP22 lattice proof per op (§8): key, encryption, decryption and integer-carry relations with exact norms |
| Verification | Solidity + bn254/BLS precompiles | native precompile on chain 7622 (formerly 9000) (`0x…0F01`), same C core as the prover (R278, R279) |
| Authorization | 8 `AuthScheme`s (Schnorr, ECDSA multisig, FROST, MuSig2, BLS, PQ commitment, 1271); F replaces them by `authRef` | F `authRef` = `mldsa65` UA (default) or a PQ-dominant F `msig` (hybrid, t-of-n), verified via precompile `0x…0F10` (R281) |
| Relaying | ERC-20 + `IERC20MetaTx` (`ZetherMetaTx`): `OP_ZTRANSFER`/`OP_ZBURN` in an EIP-712 envelope, outer fee `NONE`/`FIXED` from the public balance, `envelopeBinding` in the statement | the same envelope and rules (R284, §7.11), plus MetaToken v3's `UAMetaTransaction` so a PQ UA pays the outer fee |
| Decryption | BSGS discrete log, device cache, `zether-read-balance` | direct rounding, microseconds, exact; no BSGS, no cache needed (R285) |
| State | points in storage | ciphertext **hashes** in storage, bytes in calldata + events; public amounts (`fund`, fees) as a public `plainPending` integer; public keys in SSTORE2 (R276, R275) |
| Chains | dev allowlist 31337/1337 | allowlist 31337/1337/**7622** (formerly 9000) **and** a constructor self-test through the precompile **and** the registry's `chain_uid` in every statement (R270, F R330) |

**Cost.** Ciphertext 16,512 B, public key 16,384 B, transfer proof ≈ 30–50 KB (estimate; spike E-S1 measures).
A transfer is ≈ 77 KB of calldata and ≈ **2.8 M gas** while the p99 verify time stays under ≈ 11 ms (the EIP-7623
calldata floor binds, §9.4), rising to ≈ 7.5 M at the 50 ms kill threshold — the same order as classical Zether's
measured 3.29–3.36 M. Consuming each received credit later costs ≈ 0.52 M gas more (its ciphertext enters calldata
once more, §7.6). Security of the encryption: primal-uSVP block size β ≈ 476 (core-SVP 139 classical / 126 quantum,
Kyber-512 is 406 → 118 / 107 under the same script, §4.1).

**What it protects.** Amounts and balances stay confidential against a future quantum adversary (no HNDL on
ciphertexts, §12.1), and validity (no money printing) rests on MSIS/MLWE instead of discrete log — a quantum
adversary against classical Zether does not only *read* balances, it can *forge* Σ/Bulletproof proofs and mint.
What stays classical is listed in §12.2 (Clique block signer, relayer lane keys, public ERC-20 legs, and a v1
envelope signer, which can only spend its public balance and nonces).

---

## 2. Research summary

### 2.1 Why classical Zether cannot be patched

ElGamal and Bulletproofs both rest on discrete log in G1; Shor breaks both, and breaks every ciphertext already
recorded (research 03 §3.1.3, U7: *"no PQ path; a new protocol is required, not a new signature"*). The
`PQ_COMMITMENT` auth scheme (registry #6) protects only future control of an account, never past amounts. A
private chain lowers exposure (only participants see state) but does not remove it: any participant that archives
the chain holds the ciphertexts (02 §2.6.6 option 1). Hence a new protocol, deployed beside the classical one.

### 2.2 Homomorphic encryption candidates

What Zether needs from the encryption is small: `Enc`, `Add` (credits), and a decryption **relation** a prover can
show in zero knowledge. No ciphertext multiplication, no rotations, no bootstrapping.

| Scheme | Arithmetic | Fit for "owner-key confidential balance" | Why not / why |
|---|---|---|---|
| **BFV** (Brakerski/Fan–Vercauteren, RLWE) | exact mod `t`, MSB encoding `Δ·m + e` | yes | Decryption relation `v − u·s = Δ·M + e` has independent bounds on `M` and `e`: simplest to prove. **Chosen in its additive-only, module form** (R271) |
| **BGV** (RLWE) | exact mod `t`, LSB encoding `m + t·e` | yes | Equivalent for additions; the relation couples `m` and `e` through `t`, which makes the norm argument and the integer-carry relation of §7.4 less direct. No gain for us |
| **CKKS** (RLWE) | approximate | **no** | Money must be exact; CKKS decryption leaks noise and is broken in the IND-CPA^D model ([Li–Micciancio](https://eprint.iacr.org/2020/1533)) |
| **TFHE / FHEW** (LWE + bootstrapping) | gate/LUT, comparisons on ciphertexts | **different model** | Enables fhEVM-style tokens: balances under one **network** key held by a threshold KMS, comparisons done homomorphically. Confidentiality then rests on the KMS quorum, not on the owner's key — not Zether. Zama's input ZKPoK (`tfhe-zk-pok`) is pairing-based ([docs.rs](https://docs.rs/crate/tfhe-zk-pok/latest), [fhEVM inputs](https://docs.zama.ai/protocol/solidity-guides/smart-contract/inputs)), so input validity is not PQ-sound; `tfhe-rs` is BSD-3-Clause-Clear and **commercial use needs Zama's patent licence** ([docs.rs/tfhe](https://docs.rs/crate/tfhe/)) |
| ML-KEM (FIPS 203) as-is | KEM with FO transform | no | The FO re-encryption check destroys homomorphism; `q = 3329` leaves no headroom for additions. Its inner K-PKE is exactly our base scheme with a larger modulus |

Exact-FHE implementations with a *noticeable* decryption-failure probability allow key recovery
([Cheon–Choe–Passelègue–Stehlé–Suvanto 2024](https://eprint.iacr.org/2024/127)). PQZ parameters are therefore set by
**worst-case** noise bounds over proven witness norms (§4.3): decryption of an accepted state **cannot** fail, so
there is no failure oracle (R272).

### 2.3 Lattice zero-knowledge proof systems

| System | Statement form | Proof size (published) | Prove / verify | Maturity, code | Fit |
|---|---|---|---|---|---|
| **LNP22 "Lantern"** ([ePrint 2022/284](https://eprint.iacr.org/2022/284), CRYPTO 2022) | short `s` with `As = t mod q`, exact ℓ2 norms, binary/quadratic relations, linear relations | ~14 KB reference statement (LaZer abstract); MLWE-secret proof ~29 KB in the TU Graz Sage implementation ([Lantern notebook](https://lattice-zk.isec.tugraz.at/)) | C: fractions of a second (Lether); Sage: ~35 s | **LaZer** C + Python, MIT ([GitHub](https://github.com/lazer-crypto/lazer), [ePrint 2024/1846](https://eprint.iacr.org/2024/1846), CCS 2024); **x86-64 + AVX-512 + AES-NI only**; links GMP, MPFR and Intel HEXL (§2.6) | **Chosen** (R278): our relations are linear with exact norms, witness ≈ 8 k short coefficients |
| **LaBRADOR** ([ePrint 2022/1341](https://eprint.iacr.org/2022/1341), CRYPTO 2023) | R1CS / dot-product constraints, recursive | ~58 KB for R1CS of 2^20 constraints | verifier linear-ish, recursion-heavy prover | in LaZer | Floor ≈ 50 KB gives nothing for small statements; original is not zero-knowledge. Future: block-level aggregation of many transfers |
| **Greyhound** ([ePrint 2024/1293](https://eprint.iacr.org/2024/1293), CRYPTO 2024) | polynomial commitment (with LaBRADOR) | 53 KB at degree 2^30 | `O(√N)` verifier | research code | A PCS, needs a full SNARK around it; no gain at our size |
| **MatRiCT / MatRiCT+** ([2019/1287](https://eprint.iacr.org/2019/1287), [2021/545](https://eprint.iacr.org/2021/545)) | UTXO RingCT, binary proofs | tens of KB (MatRiCT+ 2–18× shorter than MatRiCT) | sub-second | research | UTXO + ring anonymity; Zether is account-model with ring size 2 |
| **LNS20 integer relations** ([2020/1183](https://eprint.iacr.org/2020/1183), CCS 2020) | additions/multiplications of committed integers with carries | smallest PQ for 512-bit integers (abstract) | fast | research | The digit-carry technique we use for `b' + v + fee` (§7.4), expressed inside LNP22 |
| Hash-based (Ligero, STARK) | arbitrary circuits | 100–300 KB class | prover seconds to tens of seconds for ring arithmetic in-circuit | mature Rust (Plonky3, Winterfell) but zero-knowledge is not the default mode | Fallback only (R278 kill criterion) |
| "PQ inside a pairing SNARK" | — | small | cheap on chain | — | **Rejected**: soundness is pairing-based (02 §2.6.4) |

**Prior art for the whole protocol.** **Lether** ([ePrint 2026/076](https://eprint.iacr.org/2026/076), ACM CCS 2026;
Wang, Esgin, Steinfeld, Yiu) is the first practical lattice account-model protocol in the Anonymous Zether paradigm:
verifiable *refreshable* additively-homomorphic multi-message multi-recipient encryption (mmPKE), LNP22 via LaZer,
moduli ≤ 60 bits, ~68 KB per transaction of which ~51 KB proof, refresh overhead ~1.3 % amortized, prove and verify
each a fraction of a second. PQZ is the same family **without anonymity** (no ring, no linkable tags), which is why
its proof should be smaller. Only Lether's abstract was available (the ePrint PDF refused automated download);
spike E-S0 reads the full text and reconciles parameters before E-S2 freezes them. Multi-recipient shared
randomness is the mKEM technique of [Katsumata–Kwiatkowski–Pintore–Prest 2020](https://eprint.iacr.org/2020/1107).

### 2.4 Signatures for authorization

| Scheme | pk | sig | Standard | EVM verification |
|---|---|---|---|---|
| **ML-DSA-65** | 1,952 B | 3,309 B | FIPS 204 (final 2024) | Solidity 1.23 M gas ([Fireblocks](https://www.fireblocks.com/blog/post-quantum-signatures-ethereum-cheaper-gas)), 8.09 M (ZKNox ETHDILITHIUM); precompile drafts [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051) (0x12/0x13, 4,500 gas, expanded pk) and [EIP-8355](https://eips.ethereum.org/EIPS/eip-8355) (0x12–0x14, ML-DSA-65 9,000 gas, `pk ‖ sig ‖ msg`, pure ML-DSA, empty context) — **both drafts claim 0x12/0x13** |
| ML-DSA-87 | 2,592 B | 4,627 B | FIPS 204 | as above |
| FN-DSA-512 (Falcon) | 897 B | ~666 B | **FIPS 206 still a draft** (submitted for approval 2025-08-28; final expected late 2026/early 2027, [pqc-forum](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/1HXzjlMUU6Y/m/KNSPqC02BgAJ)); FN-DSA ≠ original Falcon encoding | [EIP-8052](https://pq.ethereum.org/blog/pq-precompiles-eip-8051-8052/) draft; floating-point signing is hard to make constant-time |
| SLH-DSA-SHA2-128s | 32 B | 7,856 B | FIPS 205 | ~0.6 M in Solidity (02 §2.6.3) |

### 2.5 Libraries

| Library | Language, licence | Scope | Use in PQZ |
|---|---|---|---|
| LaZer | C + Python, MIT; links GMP (LGPLv3/GPLv2), MPFR (LGPLv3), HEXL (Apache-2.0) | LNP22, LaBRADOR, codegen (Sage + lattice-estimator) | **forked** into `pqz-core`: protocol logic and codegen kept, integer, NTT, sampler, rejection, allocator and error layers rewritten (R278) |
| Lantern notebook (TU Graz) | Python/Sage | LNP22 reference | second oracle for transcript-level tests |
| [fhe.rs](https://github.com/tlepoint/fhe.rs) | Rust, MIT, unaudited | RNS-BFV | reference only — we need ~200 lines of K-PKE-style code, not a BFV stack |
| [OpenFHE](https://github.com/openfheorg/openfhe-development) / [openfhe-rs](https://github.com/fairmath/openfhe-rs) | C++ BSD-2 / Rust bindings (young) | BFV/BGV/CKKS/FHEW | none |
| [Lattigo](https://github.com/tuneinsight/lattigo) | Go, Apache-2.0 | BFV/BGV/CKKS, multiparty | none (Go) |
| tfhe-rs | Rust, BSD-3-Clause-Clear + patent licence | TFHE, fhEVM | none (different trust model, licence) |
| ML-DSA | `pqcrypto`/`fips204`-class Rust crates, liboqs (C) | FIPS 204 | precompile and clients; pick one audited/ACVP-tested implementation in E-S3 |
| [lattice-estimator](https://github.com/malb/lattice-estimator) | Sage | security estimates | parameter freeze (E-S0) |

### 2.6 Hardware fact that drives the build

LaZer requires AVX-512 and AES-NI and has no portable code path. The chain-7622 (formerly 9000) host is an **AMD Ryzen 5 7235HS (Zen
3+): AVX2 and AES-NI, no AVX-512** (`/proc/cpuinfo`, 2026-10-06), as are most phones and every WASM runtime. A verifier
that needs AVX-512 cannot run in the node. Hence the portable fork (R278) instead of linking LaZer.

The AVX-512 kernels are not the only problem. LaZer `main` at `3330e48` (2026-09-28), read through the GitHub API on
2026-10-06, depends on:

| Layer | Upstream | Why it cannot ship as is |
|---|---|---|
| Build | `Makefile`: `LIBS = -lm libhexl.a -lstdc++ -lmpfr -lgmp`; `CFLAGS_DEFAULT … -march=native` | host-specific code; C++ runtime; LGPL libraries |
| Integers | `src/int.c`: `int_t` arithmetic on GMP (`mpn_sec_*`, `mpz_t`), multi-limb | GMP in a consensus path and in WASM; LGPL relinking duties |
| Rejection sampling | `src/rejection.c`: `mpfr_exp((−2⟨z,v⟩ + ⟨v,v⟩)/(2σ²))` | MPFR on a secret-dependent value: not constant-time, not bit-exact across platforms |
| Gaussian sampler | `src/grandom.c`: `double` (`exp_small`, `BerExp`) | floating point: x87/FMA/libm differences break byte-exact proofs |
| NTT | Intel HEXL (C++, AVX-512-oriented, Apache-2.0) | no portable path |
| Errors, memory | `ERR()` = `fprintf(stderr, …); abort();` (`src/lazer-in2.h:1680`); `ASSERT_ERR` empty in release; `malloc`/`realloc` | an abort in the node halts chain 7622 (formerly 9000) (R279); no fixed memory bound |

So the fork keeps LaZer's protocol logic, specifications and codegen, and **rewrites** those six layers for the fixed
PQZ parameters (R278, E-S1).

### 2.7 Chain 7622 (formerly 9000) limits that bind the design

| Fact | Value | Consequence |
|---|---|---|
| Client | Nethermind 1.39.0, Clique, one signer, 5 s, base fee 0 (TRAPS; README-chainspec 2026-08-31) | gas is free in money, but still meters block capacity |
| Forks live | through Fusaka + BPO2, incl. EIP-2537, EIP-7951 (secp256r1 at `0x100`), **EIP-7825**, **EIP-7623**, **EIP-7934** | `smartcontracts/evm/src/chains/private7622/README.md` still says "pre-London" — stale (SCaaS §15 recorded contradiction) |
| [EIP-7825](https://eips.ethereum.org/EIPS/eip-7825) tx gas cap | 16,777,216 per transaction, independent of block limit | rules out a Solidity lattice verifier (§9.1) |
| Chain id | **7622** (owner, 2026-10-07; formerly 9000, which is **also Evmos Testnet**, a public chain: [chainlist](https://chainlist.org/chain/9000), [Sequence chainlist](https://docs.sequence.xyz/solutions/chainlist/non-integrated/evmos-testnet)). Chain ids are a registry convention, so 7622 is not assumed unique either | `chainid == 7622` does not prove "our chain"; the precompile self-test (R270), the registry's `chain_uid` (genesis hash, F R330) in every statement and the node's genesis-hash binding (§11.3) do |
| Block gas limit | 16,777,216 (Clique signer can move it without reset) | ~5 transfers per block unless raised (R280) |
| [EIP-7623](https://eips.ethereum.org/EIPS/eip-7623) calldata floor | `10 × tokens`, token = zero byte 1 / non-zero byte 4 ⇒ 40 gas per non-zero byte | dominates PQZ cost once verification is native |
| [EIP-7934](https://eips.ethereum.org/EIPS/eip-7934) | RLP block ≤ 8,388,608 B | a block can carry at most `gasLimit / 10` calldata bytes (all-zero calldata at the floor); R280's 80 M target keeps that ≤ 8.0 MB, so the limit cannot be hit |
| Tx-pool size limit | 128 KiB is the common client default (geth/reth); Nethermind `TxPool.MaxTxSize` to be confirmed in E-S3 | transfers with inline credits exceed it (R280) |
| Missing transition keys | Nethermind silently ignores unknown keys; `eip1108Transition` was once missing and made `ecMul` 6.4× dearer with no symptom | every PQZ activation is **probed**, never trusted (R279) |

---

## 3. Rulings

- **R270** **Scope and gate.** PQZ is a separate token class (`PqzToken`, plus kind `0x0142` in spec F's
  `UARegistry`), never an upgrade of `ZetherToken`. `PqzSafety.requireAllowedChain()`: `chainid ∈ {31337, 1337, 7622}` (7622 formerly 9000) — a hard-coded list,
  like RS2-1; adding a chain is a code change with review. **And** every constructor/`initialize` runs the precompile
  self-test (§10.4); a chain without the precompile (every public chain) fails it. **And** the chain is identified
  by `(chainid, chain_uid)` as F R330: `PqzToken.initialize` copies `registry.chainUid()` (the genesis hash, a
  registry constructor immutable, `≠ 0`) into an immutable `chainUid`, which enters every statement (§7.7, §7.9) and
  `entryRef`, so no proof, authorization or disclosure verifies on another chain with the same chain id; F's PoPs
  bind it through `popDigest` (R295). The node binds registry, `chainUid()` and the RPC genesis hash per chain profile
  and refuses a mismatch (§11.3). `OpenFactory.pqzEnabled` defaults to `false`. NatSpec and docs: **UNAUDITED — NOT
  FOR PRODUCTION FUNDS**. — Owner O3; chain 7622 (formerly 9000) is the owner's named target and runs our client.
  The owner moved it off 9000 because 9000 is also Evmos Testnet (§2.7); 7622 is not assumed unique either, hence
  `chain_uid`. The self-test is what keeps PQZ off chains whose client is not ours. **Release gates before any production or commercial use** (owner, rev 1.1):
  **G-LIC** patent/licence clearance (LaZer is MIT without an explicit patent grant; LNP22-family techniques come
  from IBM Research; GMP/MPFR are LGPL and must be absent from every shipped artifact after the E-S1 rewrite; plus
  the chosen ML-DSA implementations' licences) **and** Z1 (independent cryptographic audit).
  Development and research continue without them; nothing deploys outside the allowlist or holds real funds until
  both are recorded as passed. — Classical Z3 (chain 7622 (formerly 9000) for classical Zether) is unaffected.
- **R271** **Encryption = additive-only module-LWE with BFV-style encoding** ("MLWE-BFV-add", §4), implemented in
  `pqz-core`, not taken from an FHE library. CKKS and TFHE rejected (§2.2). — We use Enc/Add/Dec only; a BFV stack
  brings relinearization keys and failure probabilities we must not have. — The owner's "BFV/BGV (RLWE)" is met in
  substance: RLWE `n = 2048` and MLWE `d = 64, k = 32` have the same LWE dimension; the module form matches the LNP22
  proof ring.
- **R272** **Parameters** (§4.1, rev 1.2): `d = 64`, `k = 32`, `q = 2^42 − 215` (prime, `q ≡ 9 mod 16`, so
  `X^64 + 1` splits into `l = 4` irreducible factors), `Δ = 2^26 − 1 = ⌊q/2^16⌋`, secrets and encryption randomness
  CBD(1), errors CBD(20), norm thresholds 36 / 164 / 64, plaintext = 16 digits base 16, credit cap `K_MAX = 1024`.
  Security target, pinned cost model: every attack the pinned lattice-estimator runs on the encryption MLWE and on the
  proof's MSIS/MLWE instances costs at least Kyber-512's, under core-SVP **classical** (`0.292β`) **and quantum**
  (`0.265β`); in block-size terms β ≥ 450 (Kyber-512 is 406). Noise bounds are worst-case over proven norms, so an
  accepted state never fails to decrypt. — §4.1 estimate (β ≈ 476), §4.3 derivation. Rev 1.1's `q = 2^50 − 1791`
  reached only β ≈ 374 (core-SVP 109 / 99), below Kyber-512, and split fully, which defeats LNP22's challenge
  invertibility (§8). — E-S0/E-S2 may change them **only** with a new `proofSystemId` and a recomputed §4.3.
- **R273** **Multi-recipient shared randomness.** One `(r, e1)` per operation: the transfer's `u` is shared by the
  receiver's credit, the sender's new balance and the auditor copy; only `v` differs per recipient. — Saves two
  16 KB `u` per transfer (mKEM, §2.3). — Revealing `r` would reveal the sender's new balance, so disclosure never
  reveals `r` (R283). The **auditor** is as classical RS2-8: one immutable registered PQZ UA per
  token, set at `initialize` (or none); it reads exactly the per-transfer `v_a`, never anyone's balance. The
  security of shared `r` against **malicious** recipients is an explicit assumption, not KKPP's honest-key theorem:
  MLWE with at most 16 adversarially chosen integer linear hints on the **joint** secret `(r, e1)` per recipient
  key, 32 when receiver and auditor collude (§4.5, rev 1.3). If E-S0's estimate misses the target, the fallback is
  **split randomness**: `(r, e1)` shared by `v_t` and `v_a` only, and the sender's `v_f` under its own
  `(r_f, e1_f)` and `u_f` (+16,384 B, ≈ +0.5 M gas per transfer), so hints only open ciphertexts of amounts the
  hinting parties already know.
- **R274** **Every debit re-encrypts the remaining balance fresh.** The sender proves that the total ciphertext `T`
  decrypts to `M` with `Σ M_i·16^i = b' + v + fee` (digit-carry relation, §7.4) and publishes a fresh encryption
  of `b'`. No homomorphic subtraction on `acc`. — Resets noise and digit growth at every spend; the classical
  `C_deb` disappears. — The proof carries a decryption relation, which classical E5 also had in another form.
- **R275** **Credit cap and public amounts.** Public amounts never become ciphertexts: `fund` and fee credits add to
  a public `plainPending[ua]` (uint), and a debit consumes a declared `plainUsed ≤ plainPending` as **one** trivial
  term of `T` (§7.4). Only proven transfer credits take pending slots. Each account's live unit count
  `accUnits + (pendingCount − rolled) + 1` (the `+ 1` reserves the plain term) is ≤ `K_MAX = 1024`; a credit beyond it
  reverts `RefreshRequired(ua)`. Every debit also asserts `unitsOf(T) ≤ K_MAX` (§7.4). `REFRESH` = a burn of amount
  0 (no underlying moves) and resets `accUnits` to 1; it frees the cap only once the unrolled credits are rolled to
  within `INLINE_MAX` of `pendingCount`. — Keeps §4.3 worst-case bounds. Rev 1.1 counted `fund` and fee dust as
  16 KB pending entries: `fund(victim, 1)` × 4096 (≈ 0.33 G gas) locked a victim whose recovery cost ≈ 0.83 G, and
  a relayer's fee UA filled by design. — Filling a victim now takes proven transfers at ≈ 2.8 M each (≈ 2.9 G for
  1022), and recovery costs ≈ 0.57 G, ≈ 5× less (§12.1 T7). Gas on chain 7622 (formerly 9000) is free, so rate limiting still rests
  on permissioned submitters and node policy.
- **R276** **Ciphertexts live in calldata and events, hashes in storage.** `acc` and each pending credit are stored
  as `keccak256(ct)`; operations that need them take the bytes in calldata and the contract checks the hash. Public
  keys (PQZ and ML-DSA) are written once with SSTORE2 and read with `EXTCODECOPY`. — Storage of a 16 KB ciphertext
  costs 2.6–8.8 M gas per write; calldata 0.52 M; SSTORE2 reads ≈ 10 k. — Indexers rebuild state from events (§7.8).
- **R277** **Public rollover, race-free debits.** Anyone may roll pending credits into `acc`. A debit proves over
  `T = acc + Σ pending[rolled..p)` and the contract rebuilds that **same** `T` whether a rollover happened in
  between (`acc' − Σ pending[p..rolled')`) or not, because addition mod `q` is exact and associative. No
  `OWNER_ONLY` mode, no `accSeq`. At most `INLINE_MAX = 16` ciphertexts inline. — Removes the classical rollover
  grief (RS2-17/19) instead of mitigating it. — A griefer who rolls > 16 new credits past `p` forces a re-prove; it
  needs > 16 proven transfer credits of its own (≈ 2.8 M gas each; `fund` no longer creates pending entries).
  Honest keepers roll only credits older than `KEEPER_AGE = 24` blocks (2 min), and clients prove at
  `p = pendingCount` and retry once on `InlineTooFar` (§11.3), so a busy merchant's in-flight phone proof survives.
- **R278** **Proof engine = LNP22 through `pqz-core`, a fork of LaZer whose arithmetic layers are rewritten**
  (§2.6): integer-only, constant-time C99 for the fixed parameters, with one 64-bit modulus (no multi-limb `int_t`, no
  GMP), an incomplete negacyclic NTT of our own (no HEXL), an integer discrete-Gaussian or uniform-mask sampler (no
  `double`), rejection in fixed-point integer arithmetic (no MPFR), a caller-provided arena (no `malloc`), and error
  returns (no `abort`); optional AVX2 backend. LaZer's protocol logic, LaZer-format specifications and codegen are
  kept. One implementation serves the prover, the client-side verifier mirror and the precompile. No Solidity
  verifier. LaBRADOR/Greyhound deferred to aggregation work. **Kill criterion** (E-S1): stop and re-plan with the
  hash-based fallback if the transfer proof exceeds 96 KB, if p99 adversarial verify (§9.4) exceeds 50 ms on the
  chain host, or if the rewritten layers cannot reach arithmetic-layer KAT equality with upstream. — Single
  implementation; LaZer is MIT and protocol logic stays upstream-shaped. — We own a C fork with six rewritten
  layers, a rewrite rather than a kernel swap; upstream protocol fixes are merged by hand. **Versioning:**
  `proofSystemId = keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v1")`; every parameter, relation or serialization
  change bumps it; the token stores it at `initialize` and the precompile accepts only ids it implements.
- **R279** **On-chain verification is a native precompile on chain 7622 (formerly 9000)**: `PQZ` at
  `0x0000000000000000000000000000000000000F01` (first input byte = op) and `MLDSA65` at `…0F10` (EIP-8355 layout plus a
  context string, §9.3). **v1 runs only on our Nethermind chain** (owner, rev 1.1). Other
  private chains (customer-run Besu/geth/reth) get the off-chain co-processor attestation seam later (§9.1, §14);
  **no client ports in v1**; the co-processor is rejected on chain 7622 (formerly 9000) itself. **Determinism and probing:** integer-only code, no threads, no floating point, no CPU-feature-dependent
  results, bounded loops (a capped rejection loop that hits its cap ⇒ invalid); any parse error, panic or failed
  check ⇒ output `0x00…00`; gas by formula regardless of validity; activation by `pqzTransitionTimestamp`; contracts
  self-test (§10.4) and the node probes (`has_pqz_precompile`), because a missing transition key looks exactly like
  an enabled one (TRAPS). **The verify path never crashes the node** (rev 1.2): `pqz_verify` runs in-process, chain
  7622 (formerly 9000) has one Clique signer, and every `eth_call`/`eth_estimateGas` reaches the precompile, so one abort,
  out-of-bounds access or stack overflow on crafted input is a chain halt, not a split. Requirements: every
  upstream `ERR`/`ASSERT` becomes `return 0`; a bounds-checked decoder (Rust, in front of the C core) accepts only
  the fixed lengths of §4.4/§7.7 before any C code runs; fixed-size stack, no recursion, a compile-time arena; no
  timeouts (non-deterministic), only bounded loops; continuous ASan/UBSan fuzzing in CI (§15). Operationally a
  follower node serves all public RPC and pre-simulation, so `eth_call` never reaches the signer process (§10.3);
  a crashing input inside a transaction would still reach every node at its block, so never-crash is the
  requirement and the follower is only defence in depth. — §9.1 comparison. — Every node of chain 7622 (formerly 9000) must run the
  PQZ client build.
- **R280** **Gas.** Precompile prices are deterministic functions of the op and input length, calibrated on the
  p99 verify time over adversarial inputs against `ecMul` on the chain host (§9.4), frozen in the chainspec;
  `OP_SELFTEST` has a fixed price of its own and is computed once per process (§9.2, rev 1.3). EIP-7623 and EIP-7825 stay enabled. Operator change: Clique
  `TargetBlockGasLimit` **80,000,000** on chain 7622 (formerly 9000) (no data reset): at the calldata floor a block then carries at
  most 8.0 MB of calldata, under EIP-7934's 8,388,608-byte RLP limit even for all-zero calldata, so no block the
  producer builds can be oversized. Node and client limits on chain 7622 (formerly 9000): Nethermind `TxPool.MaxTxSize` ≥ 1 MiB (or
  the key E-S3 finds), scaas-node `max_gas_per_tx = 16_000_000`, gateway body limit 1 MiB on job submissions
  to the `pqz` chain profile only (64 KiB elsewhere; §11.3) — recommendations to node operators (OPS R247). — Keeps gas an honest capacity meter. — ≈ 28
  transfers per 5 s block while the floor binds, ≈ 10 at the 50 ms verify kill threshold; ≈ 45 GB/day of archive
  growth at sustained full load (§9.4).
- **R281** **PQZ authorization is always a separate PQ signing UA** (spec F R305 `authRef`, tightened). A
  `pqz-mlwe` record's `authRef` must be a registered `mldsa65` / `mldsa44` UA (`fndsa512` once F enables it,
  FIPS 206), or an F `msig` whose non-PQ members' total weight is **below** its threshold — so no classical-only
  subset can authorize. That `msig` rule is the hybrid (e.g. `mldsa65` w 1 + `p256` w 1, threshold 2) and the t-of-n
  ML-DSA form. Refused: `authRef = 0` (self), native ids (EOA/ERC-1271), any classical-only kind
  (`UAAuthRef`). — Owner O8; one key = one purpose: the PQZ key decrypts and proves, the ML-DSA key authorizes; F R313
  invites exactly this hybrid. — A leaked PQZ key is a read-only breach (`survivesEncKeyLeak`).
- **R282** **PQZ UA kind = spec F kind `0x0142` `pqz-mlwe`** (tag `scaas.ua.pqz-mlwe.v1`, `d = pk` 16,384 B, new
  keyHash group `pqz-mlwe`), a Zether-family kind under F R305 (binds only the encryption key, immutable
  `authRef`); `UA = keccak256(keccak256(tag) ‖ pk)` (F R290, R292); PoP over `popDigest(ua, authRef)` binds chain (`chain_key`
  and `chain_uid`, F R330), registry, UA and `authRef`, not the caller, and the `authRef` co-signs it (F R295, §7.2); key seed by F §8.1's PQ rule `HKDF-SHA256(BIP-39 seed, "scaas.ua.pq.v1", tag ‖ u32 account ‖ u32 i)`,
  derived **only in the key worker** (app R175) and sealed there as a 32-byte PQZ leaf that the Zether worker and
  `pqz-cli` open (`sealPqKey` / `openPqKey`, §6.3). Signing kinds are F's `mldsa65`/`mldsa44`/`fndsa512`; this spec adds no signing kind. — F owns identity; E adds
  one row and its verifier. — F's kind table, keyHash group list and vectors gain one row each (applied by F's
  stream, as a gen-1 kind since F is not built).
- **R283** **Disclosure by zero-knowledge proof**, never by revealing randomness or noise. `ITransferDisclosure` is
  kept (same three `OpeningKind`s; `opening = bundle ‖ proof`). `transferCiphertext(entryRef)` reverts
  `CiphertextOffState(bundleHash)`; new view `transferCiphertextHash(entryRef)`. — R273 and §2.2 (noise must not
  leak). — Indexer or the parties supply the bundle bytes.
- **R284** (owner 2026-10-07; replaces rev 1.3's "no meta-tx envelope") **`PqzToken` is an ERC-20 +
  `IERC20MetaTx` token exactly like `ZetherToken`.** A public ERC-20 ledger (`wrap`/`unwrap` of the underlying
  1:1, R26 allowances, escrow invariant) and the classical envelope unchanged: `MetaTxLib.MetaTransaction`,
  `METATX_TYPEHASH` and `canon`, the 2D nonce (`metaNonce`, `cancelMetaNonce`), `executeMetaTransaction`,
  `metaTxDigest`, `supportedModes() = MODE_KNOWN_MASK` (`0xF3`), the nine cheap-before-expensive steps,
  `MetaTransactionExecuted` and the `MetaTx*` errors, EIP-712 domain `("SCaaS PqzToken", "1", chainId, token)`. Every
  PQZ op — `fund`, transfer, burn, refresh, `rollOver` — is reachable as a direct open call **and** as an envelope op
  through `_executeOp`, whose `m.data` is byte-identical to the direct calldata (§7.11). Envelope ops take outer fee
  `NONE` or `FIXED` only, absolute; `PERCENT` reverts (`FeePolicy.requireConfidentialSafe`, classical RS2-6) and
  stays available only for plain public transfers (`data` empty). The outer fee is checked against the payer's
  public balance before any statement build or precompile call, and collected after the proof verifies, before any
  effect. Proof-carrying ops bind their envelope as classical `_envelopeBinding` (RS2-5): `envelopeBinding` is a
  statement header field (§7.7; 0 for a direct call), so the proof and the PQ `authSig` cover exactly one envelope.
  The inner confidential fee (`beneficiaryUA`, `confidentialFee`) stays beside it, as classical. **Authority is
  split:** confidential balances move only on the PQ `authSig` over the statement plus the PQZ proof (R281,
  unchanged); the envelope signer authorizes only the public-ledger part — the outer fee from its own public balance,
  its nonce, and for `fund` the public amount it shields from that balance. **PQ-complete path:** the same ops
  through MetaToken v3's `UAMetaTransaction` (F R309, §5.3) on `PqzToken`'s own `bytes32` UA ledger (F R308), so an
  `mldsa65`/`mldsa44` UA or a PQ-dominant `msig` pays the outer fee and signs the nonce, and no classical key signs
  anything on the op path. Envelopes are not carried on the mesh, exactly as classical Zether (MESH §1.2). — Owner:
  relayers, scaas-node, indexer and Odoo handle PQZ with the existing meta-tx path. A v1 envelope signer is
  ECDSA/1271, hence the v3 path. — A broken envelope key can spend that signer's public balance and burn its nonces;
  it can never move confidential value (§7.11). Envelope bytes add ≈ 0.6 KB (v1) / ≈ 4 KB (v3 with ML-DSA) and
  ≈ 0.2 M execution gas (§9.4); a changed outer-fee quote needs a new proof (the binding is in the statement).
- **R285** **Direct decryption.** `Dec` is rounding of 16 coefficients (§4.2); no BSGS, no discrete log, no
  `zether-read-balance`. A balance cache is a UX convenience only (offline display). — The single largest UX
  simplification over classical Zether.
- **R286** **Limits.** `MAX_TOTAL_SHIELDED = 2^62`; transfer and burn amounts `< 2^64` (16 base-16 digits);
  `confidentialFee < 2^64`; `plainPending ≤ maxShielded` (it is part of `totalShielded`); `shieldScale` as RS2-3. — No BSGS bound any more; 2^62 keeps `b' + v + fee < 2^64` for honest states and
  values in signed 64-bit for clients. — The classical 2^54 rationale (D3, BSGS) does not carry over.
- **R287** **Prover platforms** (owner, rev 1.1: retail provers come early): native x86-64 (portable/AVX2) and
  aarch64 for desktops, servers and the organization key oracle (E-S5), then **immediately** the browser/mobile
  WASM prover (E-S6, §11.5): `pqz-core` compiled freestanding to `wasm32-unknown-unknown` and linked into the
  `zether-prover` wasm-bindgen module, run in the app's Zether worker under the key-worker rule (app R164, R175),
  single-threaded, with budgets and a fallback to a **native prover service run by the user** (`pqz-cli serve`).
  Native iOS/Android libraries are the same aarch64 C build. — Retail on private chains is a near-term use. — WASM
  lacks a 64×64→128 multiply, which the single-prime `q < 2^42` needs; it is emulated on 32-bit limbs. E-S0/E-S1
  fix the `q` form (`l`, the prime) jointly for proof size and WASM speed before E-S2 freezes vectors. There is no
  RNS fallback (§11.5).
- **R288** **Encryption randomness is derived**, so the sender can re-create it for disclosure:
  `seed_enc = HKDF-SHA256(ikm = pqzKeySeed, salt = "SCAAS-PQZ-ENC-V1", info = be32(chainId) ‖ token(20) ‖ fromUA ‖
  be8(sendCounter) ‖ toUA ‖ be8(v) ‖ be8(b') ‖ u8(auditorOn))`. Message-bound, so a re-proof with another amount at
  the same counter uses other randomness. Masking randomness *inside* the proof is hedged (`H(secret ‖ statement ‖
  32 B CSPRNG)`). — Classical §8.9 used counter-only derivation; reusing `r` across two messages here would leak
  `Δ·(m − m')` up to small noise.
- **R289** **Migration classical → PQZ** is `ZetherToken.burn` to the owner's address then `PqzToken.fund`; the
  amount is public on chain 7622 (formerly 9000) once. No cross-system equality proof in v1. — Classical Zether holds no production
  funds (dev-only gate), so only pilots migrate. — §13.
---

## 4. Encryption scheme MLWE-BFV-add

### 4.1 Parameters (R272)

| Name | Value | Note |
|---|---|---|
| Ring | `R_q = Z_q[X]/(X^64 + 1)`, module rank `k = 32` | LWE dimension `n = 2048` |
| `q` | `2^42 − 215 = 4,398,046,510,889` (`0x3FFFFFFFF29`), prime, `q ≡ 9 mod 16` (`2l + 1 mod 4l` with `l = 4`) | `X^64 + 1 = Π_{j<4} (X^16 − ζ_j)`, each factor irreducible ([LS18](https://eprint.iacr.org/2017/523) Cor. 1.2); incomplete NTT, below |
| `Δ` | `2^26 − 1 = 67,108,863 = ⌊q / 2^16⌋` | |
| Secret `s`, randomness `r` | CBD(η = 1) per coefficient (values −1, 0, 1 with probability ¼, ½, ¼) | σ² = ½ |
| Errors `e`, `e1`, `e2` | CBD(η = 20) (σ = √10 ≈ 3.16) | HE-standard error width |
| Norm thresholds | `‖s‖, ‖r‖ ≤ β_s = 36`; `‖e‖, ‖e1‖ ≤ β_e = 164`; `‖e2_j‖ ≤ β_2 = 64` (16 coefficients) | key generation and encryption resample above them; proofs show them exactly |
| Plaintext | `L = 16` digits base 16 in coefficients 0..15 of `v` | 64-bit values |
| `K_MAX` | 1024 units per account between refreshes (proven credits, the account's `acc` units and one reserved plain term, R275) | §4.3 |
| Matrix `A` | global, `A[i][j] ∈ R_q`, from `SHAKE128("SCAAS-PQZ-A-V2" ‖ u8(i) ‖ u8(j))`: read 8-byte BE words, keep the low 42 bits, accept if `< q`, coefficient 0 first | nothing-up-my-sleeve; implementations cache `NTT(A)` (512 KB) at start |

**Multiplication.** `R_q` products use a Kyber-style **incomplete** NTT: two negacyclic layers map a polynomial to
its four residues mod `X^16 − ζ_j`, products there are degree-16 schoolbook (or Karatsuba) mod `X^16 − ζ_j`, and
two inverse layers return. The encryption ring and the proof ring are then the same `R_q`, with no lift to a larger
proof modulus. The challenge-invertibility bound of LS18 Cor. 1.2 is `q^{1/l}/√l ≈ 724` in ℓ∞ for `l = 4`, against
the `‖c − c'‖∞ ≤ 2κ` of LaZer-style challenges (κ a small constant). `l = 2` (`q ≡ 5 mod 8`, bound ≈ 1.5·10^6) and
`l = 8` (`q ≡ 17 mod 32`, bound ≈ 13.5) are the alternatives E-S0/E-S1 may choose for proof size or NTT speed. The
primes closest below `2^42` are `2^42 − 11` (`l = 2`) and `2^42 − 143` (`l = 8`); `Δ`, §4.3 and §4.4 are identical
for all three. A full split (`l = 64`, rev 1.1) gives an empty bound (`q^{1/64}/8 < 1`).

**Security** (rev 1.2). Rev 1.1 relied on the HE-standard tables, which use the "realistic" BKZ cost
`0.265β + 16.4 + log2(8d)`, not core-SVP. **Pinned cost model:** core-SVP, classical `2^{0.292β}` and quantum
`2^{0.265β}`, primal uSVP in the 2016 estimate ([ADPS16](https://eprint.iacr.org/2015/1092): success when
`σ_e·√β ≤ δ_β^{2β−d−1}·Vol^{1/d}`, secret rescaled by `σ_e/σ_s`, best number of samples `m`). Script output
(scratch Python, 2026-10-06), calibrated on Kyber-512:

| Instance | β | Core-SVP classical / quantum |
|---|---|---|
| Kyber-512 (n = 512, q = 3329, CBD(3)/CBD(3)) — reference | 406 (published 406) | 118.6 / 107.6 |
| rev 1.1: n = 2048, q = 2^50 | 374 | 109.2 / 99.1 |
| review option A: n = 2560, q = 2^50 | 508 | 148.3 / 134.6 |
| review option B: n = 2048, q = 2^41 | 492 | 143.7 / 130.4 |
| **rev 1.2: n = 2048, q = 2^42 − 215** | **476** | **139.0 / 126.1** |
| rev 1.2 with 32 perfect hints on `(r, e1)` (§4.5, approximated as 32 dimensions removed, n = 2016) | 466 | 136.1 / 123.5 |

`q ≈ 2^42` rather than the review's `2^41` buys a 4× accounting margin (§4.3) for 16 β-units. Option A keeps
`K_MAX = 4096` but adds 25 % to every key and ciphertext; after R275 the cap no longer needs that headroom. The
margin over Kyber-512 (≥ 60 β-units, ≥ 17 bits) absorbs dual and hybrid attacks (MATZOV 2022 takes a few bits off for
small secrets), CBD(1)'s lower variance than uniform ternary (≈ 0.5 β-units), and a few percent of estimator
generosity. Hybrid meet-in-the-middle does not apply (Hamming weight ≈ 1024 of 2048). E-S0 runs the
[lattice-estimator](https://github.com/malb/lattice-estimator) pinned at `53da598` (main, 2026-08-19) with
`LWE.estimate` under `RC.ADPS16` classical and quantum on the encryption MLWE (key and `u` instances), on the
proof's MSIS/MLWE instances, and on Kyber-512 through the same commit as the baseline. It records commands and
output in `pqz-core/params/estimator.txt`. **Target:** every attack costs ≥ Kyber-512's under both models. A miss is
a parameter ruling before E-S2.

### 4.2 Algorithms

```
CBD_η(stream):           per coefficient: a = Σ_{i<η} bit, b = Σ_{i<η} bit;  coeff = a − b    (bits LSB-first, FIPS 203 style)
KeyGen(seed32):          for ctr = 0,1,…: st = SHAKE256("SCAAS-PQZ-KEYGEN-V1" ‖ seed32 ‖ be4(ctr))
                           s ← CBD_1^{2048}(st), e ← CBD_20^{2048}(st)  (same stream, s first)
                           if ‖s‖ ≤ 36 and ‖e‖ ≤ 164: break         (ctr ≥ 64 ⇒ error; thresholds sit ≥ 10 s.d. above the mean norm)
                         pk = A·s + e ∈ R_q^32;  sk = seed32
Enc({(pk_j, m_j)}, seed_enc):
                         for ctr: st = SHAKE256("SCAAS-PQZ-ENC-V1" ‖ seed_enc ‖ be4(ctr))
                           r ← CBD_1^{2048}, e1 ← CBD_20^{2048}, e2_j ← CBD_20^16 for each j in recipient order
                           accept if ‖r‖ ≤ 36, ‖e1‖ ≤ 164, every ‖e2_j‖ ≤ 64
                         u = A^T·r + e1
                         v_j[i] = (pk_j^T·r)[i] + e2_j[i] + Δ·m_j[i]  mod q,   i < 16
                         output u and (v_j)_j
Add(ct, ct'):            coefficient-wise mod q on u (2048) and v (16)
Sub(ct, ct'):            coefficient-wise mod q
Trivial(m):              u = 0, v[i] = Δ·m[i]                      (built only inside a debit's T, from plainUsed, §7.4)
Dec(s, (u, v)):          w_i = centre(v[i] − (u^T·s)[i] mod q)  ∈ (−q/2, q/2]
                         M_i = round(w_i / Δ),  noise_i = w_i − Δ·M_i
                         value = Σ_{i<16} M_i · 16^i    (as an integer; M_i may exceed 15 before a refresh)
digits(x):               m[i] = (x >> 4i) & 0xF, i < 16;  x < 2^64
```

`(u^T·s)[i]` for `i < 16` is 16 dot products of length 2048 with negacyclic signs — microseconds. `Dec` is used by
the owner only and its `noise_i` never leaves the device (R283).

### 4.3 Noise and digit budget (worst case)

For a ciphertext encrypted to `pk_t = A·s_t + e_t`, decryption by `s_t` gives
`v − u^T s_t = e_t^T r + e2 − e1^T s_t + Δ·m`. With norms bounded as proven (registration proves `‖s_t‖ ≤ 36`,
`‖e_t‖ ≤ 164`; every encryption proves `‖r‖ ≤ 36`, `‖e1‖ ≤ 164`, `‖e2‖ ≤ 64`), Cauchy–Schwarz per coefficient gives

```
B_FRESH = β_e·β_s + β_s·β_e + β_2 = 164·36 + 36·164 + 64 = 11,872      (< 2^13.54)
```

The trivial plain term has noise 0. A sum of at most `K_MAX = 1024` units has
`|noise| ≤ 1024 · 11,872 = 12,156,928 < 2^24 = 16,777,216`, and digit sums `M_i ≤ 1024 · 15 = 15,360 < 2^14`.
The debit proof shows `|e_T[i]| < 2^24` and `0 ≤ M_i < 2^14` (complete for every honest state). Honest decryption
rounds correctly because `2^24 < Δ/2`, and `Δ·M_i + e < q/4 + 2^24 < q/2` stays inside the centred range.

**Uniqueness (soundness of the decryption relation).** Suppose `Δ·M + e ≡ Δ·M' + e' (mod q)` with both pairs in the
proven ranges. Then `|Δ(M − M')| ≤ Δ·(2^14 − 1) < q/4` and `|e − e'| ≤ 2^25 − 2 < Δ/2`, so the congruence is an
integer equation, `|Δ(M − M')| < Δ`, hence `M = M'`.

**Soundness depends on accounting, not only liveness.** Uniqueness assumes that the *true* noise of `T` is inside
the range the cap guarantees. If an accounting bug let it grow to `|e| ≥ Δ − 2^24 ≈ 3·2^24 ≈ 50.3 M`, a malicious
prover could claim `M' = M + 1` with an in-range `e' = e − Δ`, which mints. That threshold is **4.1×** the cap's
bound (12.16 M). The cap is therefore enforced twice: at every credit (R275) and at every debit
(`unitsOf(T) ≤ K_MAX`, §7.4), and a forge invariant checks that every reachable `T` has ≤ `K_MAX` units (§15). The key is unique too: two short preimages `(s, e) ≠ (s', e')` of the
same `pk` give a non-zero kernel vector of `[A | I]` of norm ≤ `2·√(36² + 164²) ≈ 336`, while the Gaussian-heuristic
shortest vector of that 4096-dimensional lattice of determinant `q^2048` is ≈ `15.5 · q^{1/2} ≈ 2^25`. That is a
statistical fact, not only MSIS: the number of integer vectors of norm ≤ 336 in dimension 4096 is a negligible
fraction of the lattice index `q^2048`, so for all but a negligible fraction of `A` no such kernel vector exists. The same argument makes `(r, e1)` unique for a given `u` (sender disclosure). So a proven decryption is
**the** decryption, and an accepted state never decrypts wrongly or fails (R272).

If E-S2 finds that a norm proof has extraction slack `γ > 1` for some bound, every `β` above is multiplied by `γ`
in this derivation, `K_MAX` is recomputed, and the change is a new `proofSystemId`.

### 4.4 Sizes

| Object | Bytes | Encoding |
|---|---|---|
| PQZ secret | 32 (seed) | never leaves the device / key oracle |
| PQZ public key `pk` | **16,384** | 32 polys × 64 coeffs × `be8`, coefficient 0 first, poly 0 first; each `< q` |
| Ciphertext `ct = u ‖ v` | **16,512** | `u` as `pk`; `v` = 16 × `be8` |
| Transfer outputs `u ‖ v_t ‖ v_f ‖ v_a` | 16,768 | `v_a` absent (0 bytes) when the auditor is off |
| Transfer proof | ≈ 30–50 KB (**estimate**; E-S1 measures; kill at 96 KB) | `pqz-core` serialization v1 |
| Burn / refresh proof | ≈ same as transfer minus one recipient | |
| Registration PoP proof | ≈ 15–25 KB (estimate) | |
| Disclosure proof | ≈ 15–25 KB (estimate) | |
| ML-DSA-65 pk / sig | 1,952 / 3,309 | FIPS 204 |

`be8` coefficients waste 22 bits each (≈ 34 %) against tight 42-bit packing; accepted: the Solidity `Add` works
on aligned 64-bit lanes, and bytes 0–1 of each word are zero (cheap calldata tokens: ≈ 25.2 tokens per coefficient
against 32 for random bytes). Boring wins.

### 4.5 Shared randomness against malicious recipients (R273)

KKPP-style mKEM security holds for honestly generated keys. `R_REG` proves only the ℓ2 norms of `(s, e)`, not their
distribution, and every recipient learns its own decryption-noise term. For a registered `pk = A s + e` the
recipient decrypts `d` and computes, per plaintext coefficient `i < 16`, the **integer** (centred, `|·| ≤ B_FRESH`)

```
h_i = (v_t − Δ·d − u^T s)[i] = (e^T r − s^T e1)[i] + e2_t[i]
```

a linear form in the **joint** secret `(r, e1)` (4096 coefficients) with coefficients the recipient chose at
registration, plus fresh `e2_t[i]` (CBD(20), `|e2| ≤ 20`). Rev 1.2 counted hints on `r` only and called this term
harmless; it is not (Codex H3). Examples of malicious keys that pass the norm checks:

- `s = 0`, `e = 164·X^0` in poly `j`: `h_i = 164·r_{j,i} + e2_t[i]`, 16 exact ternary coefficients of `r`;
- `s = 36·X^0` in poly `j`, `e = 0`: `h_i = −36·e1_{j,i} + e2_t[i]`, 16 exact coefficients of `e1` (`|e2| < 18`
  except with probability 1.5·10^-9), each turning one sample of `u = A^T r + e1` into a noise-free equation on `r`;
- mixed or dense `(s, e)`: arbitrary short integer forms on `(r, e1)`.

A colluding receiver and auditor register complementary keys and get 32 forms per operation; recovering `r` would
open `v_f`, the sender's new balance. A distribution proof on keys does not close this: even an ℓ∞ proof
(`‖s‖∞ ≤ 1`, `‖e‖∞ ≤ 20`) leaves `20·r_{j,i} + e2` decodable with probability 0.998 per coefficient. What bounds the
leak is the **count** (16 coefficients per recipient ciphertext), not the key shape.

**Assumption (stated, tracked for Z1):** MLWE on `(A^T, u = A^T r + e1)` stays hard given ≤ 32 adversarially chosen
**perfect** integer linear hints on `(r, e1)`. In the Dachman-Soled–Ducas–Gong–Rossi framework ("LWE with side
information", 2020) a perfect hint on the embedding secret removes one dimension (plus a volume change that depends
on the hint direction), whether it falls on `r`, on `e1` or on a mix; approximating 32 hints as 32 dimensions removed,
the §4.1 script gives β ≈ 466 (136 / 123.5), still above the target. `r, e1` are fresh per operation, so hints do not
accumulate across transfers. **E-S0** reruns this with the DDGR20 `leaky-LWE-Estimator`: 32 perfect hints in the
worst directions over unit vectors on `r`, unit vectors on `e1`, and maximal-norm mixed forms allowed by
`β_s`/`β_e`, recorded in `estimator.txt`. **If any direction misses the target**, PQZ switches to split
randomness (R273): `(r, e1)` shared by `v_t` and `v_a` only (both encrypt the same `d`, which both holders know) and
`v_f` under its own `(r_f, e1_f)`, `u_f`; `R_TX` gains rows 2'/4' for `u_f`, the transfer output grows by 16,384 B
(≈ +0.5 M gas, §9.4), and the change is a new `proofSystemId`. Hints then open only ciphertexts of amounts the
hinting parties already know.

---

## 5. Encodings shared by contract, precompile and clients

- Integers in statements: `be32` (`uint256` ABI words) unless stated; coefficients `be8`, canonical (`< q`); any
  other value ⇒ reject (`NonCanonical`).
- `ctHash(ct) = keccak256(ct)` over the 16,512 bytes.
- Polynomial vectors are never compressed. Lengths are fixed by the op; no length fields inside the cryptographic
  objects.
- **Statement prefix (every op):** the first 64 bytes of every statement are `opTag ‖ proofSystemId`, with
  `opTag = keccak256("SCAAS-PQZ-OP-<NAME>-V1")` for `TRANSFER`, `BURN`, `REFRESH`, `REGISTER`, `DISCLOSE-SENDER`,
  `DISCLOSE-RECEIVER`, `DISCLOSE-AUDITOR`. The precompile requires the `opTag` to belong to the input's `op` byte
  and the `proofSystemId` to be one it implements, for every op (§9.2).
- Transcript (inside `pqz-core`): SHAKE256, initialized with `"SCAAS-PQZ-TRANSCRIPT-V1"`, then `absorb("op", u8(op))`
  and `absorb("statement", be32(len) ‖ statement)` **before** any prover message (strong Fiat–Shamir, as classical
  §4); every later message is absorbed with a 1-byte label length, label, `be32` length, bytes. Challenges are
  derived, never sent.
- **Round-by-round soundness.** LNP22 has several challenge rounds (commitment, JL projection, the amortization or
  "garbage" challenges, the final challenge). Under Fiat–Shamir a prover can grind each round separately, so the
  soundness of the non-interactive proof is about `Q ×` the **worst single round** error, not the product.
  `estimator.txt` lists the soundness error of each round (with its repetitions), each ≤ `2^-128`; no parameter of
  the fork may rely on multiplying errors across rounds.

---

## 6. Keys, Universal Account kinds and derivation

### 6.1 Kind (R282, spec F)

PQZ adds **one** row to F's kind table (§4.2 there) and no signing kind:

| No. | Name (tag `scaas.ua.<name>.v1`) | `d` | keyHash group | PoP | Verifier (EVM) | Families |
|---|---|---|---|---|---|---|
| `0x0142` | `pqz-mlwe` | `pk` (16,384) | `pqz-mlwe` (new group) | `R_REG` proof over `uaMessage(0x0142, POP_TAG, popDigest(ua, authRef))` **plus** the `authRef` co-sign (F R295) | `UAPqzVerifier` → precompile `0x…0F01` op 3 | chain 7622 (formerly 9000) (R270) |

`UA = keccak256(keccak256("scaas.ua.pqz-mlwe.v1") ‖ pk)` (F R290, R292); `UA >> 160 ≠ 0` (F R291). The record is
F's `Record{kind, registeredAt, keyPtr}` with `keyPtr = SSTORE2(pk)` (F §6.2 step 7, PQ kinds) plus the immutable
`authRef`. `pqz-mlwe` is a Zether-family kind in F's sense (R305: binds only the encryption key).

Authorization UAs are F kinds (R281): `mldsa65` `0x0131` (default), `mldsa44` `0x0130`, `fndsa512` `0x0132` once F
enables it, or a PQ-dominant `msig` `0x0120`, e.g. hybrid `{mldsa65 w1, p256 w1}` threshold 2, or treasury
`{mldsa65 ×3, w1 each}` threshold 2. F's `msig` rules apply (members registered, sorted, one level, `count ≤ 16`);
R281 adds: Σ weight of members whose kind is not `mldsa*`/`fndsa512` `<` threshold. F keeps MuSig2 and FROST as
**separate kinds** (`musig2-*` `0x0110`/`0x0112`, `frost-*` `0x0111`/`0x0113`); they are classical aggregate
Schnorr, so they are refused as a direct `authRef` and count as non-PQ weight inside an `msig`.

### 6.2 Derivation (F §8.1)

```
PQZ key:     seed32 = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1",
                                  info = "scaas.ua.pqz-mlwe.v1" ‖ u32(account) ‖ u32(i));   pk = KeyGen(seed32) (§4.2)
ML-DSA auth: ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1",
                             info = "scaas.ua.mldsa65.v1" ‖ u32(account) ‖ u32(i));         FIPS 204 KeyGen_internal(ξ)
hybrid member (p256 / bip340): F's UA tree m/7622'/0'/<account>'/<kindNo>'/<i>'
```

Distinct tags in `info` give distinct keys per kind (one key = one purpose, F R298 layer 1); no PQ seed equals a
BIP-32/SLIP-10/EIP-2333 scalar of the same seed, and the classical Zether trees `…/7`, `…/8` are untouched. The PQ
rule is F's PQ branch of the UA tree: the same `account` and `i` indices as the `m/7622'/0'/<account>'/<kindNo>'/<i>'`
paths, with the kind tag in `info` instead of a `kindNo'` level, because PQ seeds are not curve scalars.

### 6.3 Seed custody and record storage

**Seed custody (app R175, rev 1.2).** The BIP-39 seed lives only in the key worker, so `seed32` is derived there
and nowhere else:

- `sealPqKey({account, index})` (key worker): derives `seed32` by §6.2 once and seals it as a 32-byte PQZ leaf in
  vault v2, key `vault:pqz:<account>:<index>` (AES-256-GCM with the device key and an AAD label of its own, the
  `sealConfKey` pattern).
- `openPqKey({account, index})` (Zether worker): opens that leaf only, never the seed.
- `pqz-cli` (and `pqz-cli serve`, §11.5) reads the 32-byte leaf from stdin, exported on the user's own machine,
  never the BIP-39 seed.
- Organizations keep the leaf in the key oracle (SCaaS §9.1 `conf_custody`) and the ML-DSA key in an HSM with
  FIPS 204 firmware where available (`auth_custody`).
- Change for the app/D streams (listed, applied there): `sealPqKey`/`openPqKey` join the vault v2 API next to
  `sealConfKey`/`openConfKey`.

**Record storage.** The record is F's `Record` plus `authRef`; `keyPtr = SSTORE2(pk)` (16,384 B, ≈ 3.3 M gas once)
and `UARegistered` carries `pk` (16 KB of log data, ≈ 0.13 M gas). Registration total: §9.4.

---

## 7. Protocol

### 7.1 State (per `(UA, token)`)

| Slot | Type | Changed by | Role |
|---|---|---|---|
| `accHash` | bytes32 | debit, rollover | `keccak256(acc)`; `acc` of a new account = `Trivial(0)` |
| `accUnits` | uint16 | debit (→ 1 + over-rolled), rollover (+n) | ciphertexts summed into `acc` (§4.3) |
| `pendingCount` | uint64 | every proven credit (+1) | |
| `rolled` | uint64 | rollover, debit | pending indexes `< rolled` are inside `acc` |
| `floor` | uint64 | debit (→ `p`) | pending indexes `< floor` were consumed by the last debit; a debit needs `floor ≤ p` |
| `cleared` | uint64 | debit | `pendingHash[i]` for `i < cleared` is deleted (`cleared ≤ floor`) |
| `pendingHash[i]` | bytes32 | proven credit `i`; deleted below `floor` | `ctHash` of credit `i` |
| `plainPending` | uint256 | `fund` (+amount), fee credit (+fee), debit (−`plainUsed`) | public amounts not yet in `acc` (R275) |
| `sendCounter` | uint64 | debit (+1) | in the statement; replay protection; R288 |
| `entry[entryRef]` | bytes32 | transfer | `bundleHash` for disclosure |

Credit cap: a proven credit reverts `RefreshRequired(ua)` when `accUnits + (pendingCount − rolled) + 1 + 1 > K_MAX`
(the new credit and the reserved plain term). `fund` and fee credits never hit the cap.
Token globals: `underlying`, `shieldScale`, `maxShielded ≤ 2^62`, `totalShielded`, `confidentialFee`, `auditorUA`
(or 0), `registry`, `proofSystemId`, `chainUid`. Public ledgers (R284, §7.11): the ERC-20 balances (`wrap`/`unwrap`
1:1 in raw underlying units, as `ZetherToken`), the F R308 UA ledger `_uaBalance[bytes32]` with `_uaTotal` shown as
`balanceOf(UA_POOL)`, and one nonce map `_uaNonce[bytes32][batch]`. Escrow invariant, checked after every outflow
as classical: `underlying.balanceOf(this) ≥ totalSupply() + totalShielded·shieldScale` (`totalSupply` includes
`_uaTotal`).

### 7.2 Register (F's `UARegistry`)

`register(0x0142, pk, pop, authRef, authPop)` follows F §6.2 step by step; PQZ-specific content of each step:

1. Kind enabled only where the registry generation was deployed with `UAPqzVerifier` (F R293, R313).
2. Key data: exactly 16,384 bytes, every coefficient `< q` (`UAKeyData`).
3. Id: `uaOf(0x0142, pk)`, not in the native space, not registered.
4. `keyHash = keccak256("pqz-mlwe" ‖ pk)` free (`UAKeyInUse`).
5. `authRef` per R281 (`UAAuthRef`); the auth UA registered first with its own PoP.
6. PoP: `UAPqzVerifier.verify(pk, message, pop)` = `PQZ(OP_REGISTER, stmt ‖ pop) == 1` with `stmt = opTag(REGISTER)
   ‖ proofSystemId ‖ message ‖ pk` (§5 prefix; `proofSystemId` is an immutable of `UAPqzVerifier`) and `message =
   uaMessage(0x0142, POP_TAG, popDigest(ua, authRef))` — relation `R_REG`: `pk = A s + e`, `‖s‖ ≤ 36`, `‖e‖ ≤ 164`,
   the message absorbed into the statement. `popDigest` is F R295's `keccak256(POP_TAG ‖ chainKeyHash ‖ chainUid ‖
   registry_id ‖ ua ‖ authRef)`: it binds chain (`chain_key` and `chain_uid`, F R330), registry, UA and `authRef`,
   not the caller, so anyone may submit and nobody can strip or swap the `authRef` (rev 1.3, Codex H2).
7. Co-sign: `requireAuthorized(authRef, PURPOSE_AUTHREF, popDigest(ua, authRef), authPop)` — the ML-DSA (or PQ
   `msig`) authority consents to this exact `(ua, authRef)` on this chain and registry, so nobody can name a victim's
   ML-DSA UA as the authority of their PQZ key — `UAUnauthorized(authRef)`. `authPop` is F's format (§7.10).
8. Store, `keyPtr = SSTORE2(pk)`, emit `UARegistered(ua, 0x0142, pk, authRef)` (16 KB of log data, ≈ 0.13 M gas).

No rotation (F R302): a new key is a new UA plus a confidential transfer to it.

### 7.3 Fund

`fund(bytes32 ua, uint256 amount)`: `ua` registered, `0 < amount`, `totalShielded + amount ≤ maxShielded`;
`plainPending[ua] += amount`; `transferFrom(msg.sender, this, amount·shieldScale)` (spender is the token contract,
R26); `totalShielded += amount`; emit `PqzPlainCredit(ua, amount, plainPending[ua])`. No ciphertext, no pending
slot, no cap check, no proof, no later rollover (R275). As an envelope op (§7.11) the only difference is the source:
`amount·shieldScale` is burned from the envelope signer's **public** balance (ERC-20 ledger, or `_uaBalance` on the
v3 path) instead of pulled with `transferFrom`, because the token cannot pull the signer's underlying.

### 7.4 Transfer

Caller: anyone, directly (`envelopeBinding = 0`) or as an envelope op (R284, §7.11; the outer-fee balance check
then runs before everything below). Inputs: `payload = be32(p) ‖ be32(validUntilBlock) ‖ be32(plainUsed) ‖ fromUA ‖ toUA ‖
beneficiaryUA ‖ out` (`out = u ‖ v_t ‖ v_f ‖ v_a`), `acc` (current, 16,512 B), `inline` (ciphertexts between `p` and
`rolled`), `proof`, `authSig`.

Contract checks, cheap first: `block.number ≤ validUntilBlock`; both UAs registered, `from ≠ to`; beneficiary
registered or 0; `plainUsed ≤ plainPending[from]`; `acc.length == 16,512` and `keccak256(acc) == accHash[from]`;
`floor ≤ p ≤ pendingCount`; with `n = (p ≥ rolled ? p − rolled : rolled − p)` and `lo = min(p, rolled)`:
`n ≤ INLINE_MAX` (`InlineTooFar`), **`inline.length == n` exactly**, and for every `i < n` `inline[i].length ==
16,512` and `keccak256(inline[i]) == pendingHash[lo + i]` (`InlineMismatch`; rev 1.3, Codex M1: too few entries
would let `floor` advance past credits missing from `T`, burning them; extras would make `T` and `unitsOf(T)`
diverge from state); receiver cap check (the fee goes to
`plainPending`, so `beneficiary == toUA` needs no extra slot); all coefficients canonical. Then

```
T = acc + Σ inline + Trivial(digits(plainUsed))     if p ≥ rolled   (inline = pending[rolled..p))
T = acc − Σ inline + Trivial(digits(plainUsed))     if p < rolled   (inline = pending[p..rolled))
unitsOf(T) = accUnits + (p − rolled) + 1            (signed; p < rolled subtracts)
require unitsOf(T) ≤ K_MAX                          (defence in depth, §4.3; unreachable if the credit cap holds)
```

The plain term is added even when `plainUsed = 0`; `+ 1` counts it either way. `plainPending` is safe against
races because third parties can only increase it. Clients set `plainUsed = plainPending` at prove time. The
contract then builds the statement (§7.7), verifies `authSig` (§7.10), calls `PQZ(OP_TRANSFER, statement ‖ proof)`,
then:

```
acc[from]    = (u, v_f);  accHash[from] = ctHash(u ‖ v_f)
               if p < rolled:  acc[from] += Σ inline  (those credits stay inside acc);  accUnits = 1 + (rolled − p)
               else:           rolled[from] = p;  accUnits = 1
               floor[from] = p
               delete pendingHash[from][cleared .. min(p, cleared + CLEAR_MAX)); cleared = that end   (CLEAR_MAX = 32)
plainPending[from] −= plainUsed
pending[to]  ← (u, v_t)                                       (pendingHash, pendingCount++)
plainPending[ben] += fee                 if fee > 0   (event PqzPlainCredit)
entry[entryRef] = keccak256(u ‖ v_t ‖ v_a ‖ toUA)
sendCounter[from]++
emit PqzTransfer(entryRef, fromUA, toUA, out);  emit PqzCredit(toUA, index, entryRef)
```

Deleting dead `pendingHash` slots is nearly free on floor-bound transactions (the refund comes off execution gas,
which sits under the floor) and keeps state from growing by 32 B per credit forever. Slots `< floor` are never read
again: a later debit needs `p' ≥ floor`, and rollover reads indexes `≥ rolled ≥ floor`.

`fee = confidentialFee` if `beneficiary ≠ 0`, else 0 (never a function of `v`). `entryRef =
keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), chainid, chainUid, token, fromUA, sendCounter))` (counter
before increment; `chainUid` per R270).

**Relation `R_TX`** (witness `s_f, e_f, r, e1, e2_t, e2_f, e2_a, d, d', M, c, e_T`; all mod `q` unless marked):

| # | Relation | Shows |
|---|---|---|
| 1 | `pk_f = A·s_f + e_f` | the sender holds **the** key of `fromUA` (unique, §4.3) |
| 2 | `u = A^T·r + e1` | well-formed shared encryption |
| 3 | `v_t[i] = (pk_t^T r)[i] + e2_t[i] + Δ·d_i`, `i < 16` | receiver credit encrypts `v = Σ d_i 16^i` |
| 4 | `v_f[i] = (pk_f^T r)[i] + e2_f[i] + Δ·d'_i` | new balance encrypts `b' = Σ d'_i 16^i` |
| 5 | `v_a[i] = (pk_a^T r)[i] + e2_a[i] + Δ·d_i` (auditor on) | auditor copy encrypts the same `v` |
| 6 | `v_T[i] − (u_T^T s_f)[i] = Δ·M_i + e_T[i]` | `T` decrypts to digits `M` |
| 7 | over Z: `M_i + c_{i−1} = d'_i + d_i + f_i + 16·c_i`, `c_{−1} = c_15 = 0`, `f = digits(fee)` | `Σ M_i 16^i = b' + v + fee` exactly |
| norms | `‖s_f‖, ‖r‖ ≤ 36`; `‖e_f‖, ‖e1‖ ≤ 164`; `‖e2_*‖ ≤ 64`; `d_i, d'_i ∈ [0, 16)`; `M_i ∈ [0, 2^14)`; `c_i + 64 ∈ [0, 2^11)`; `e_T[i] + 2^24 ∈ [0, 2^25)` | exact, via binary decomposition (917 bits = 2·16·4 + 16·14 + 15·11 + 16·25) and ℓ2 proofs |

Honest carries lie in `[−3, 1093]` (`M_i < 2^14`, `d, d', f < 16`), inside the proven `[−64, 1984)`. Row 7
telescopes: `Σ 16^i M_i = Σ 16^i (d'_i + d_i + f_i) + 2^64·c_15 − c_{−1}`, so with `c_15 = c_{−1} = 0` the balance
identity holds over the integers; every term is `< 2^15`, far below `q`, so the modular proof implies the integer
statement. `b' ≥ 0` is a digit property, so `v + fee ≤ balance` — no overspend, no
aliasing (the classical RS-NV64-1 argument becomes a digit argument).

### 7.5 Burn and refresh

`burn(payload, acc, inline, amount, recipient, proof, authSig)` with `payload = be32(p) ‖ be32(validUntilBlock) ‖
be32(plainUsed) ‖ fromUA ‖ beneficiaryUA ‖ u' ‖ v_f`. `0 < amount ≤ maxShielded` (burn) or `amount = 0` and
`recipient = 0` (`refresh`, op tag `REFRESH`). `T`, `unitsOf(T)`, `plainUsed` and every §7.4 check on `acc` and `inline` (`inline.length == n`, element lengths,
index mapping `lo + i`) as §7.4. Relation `R_BURN` =
`R_TX` rows 1, 2, 4, 6, 7 with `d = digits(amount)` **public** (no `d` witness, no rows 3/5). Effects: `acc[from]`,
`floor`, `cleared`, `plainPending[from]` as in §7.4; fee to `plainPending[ben]`; `totalShielded −= amount`;
underlying `amount·shieldScale` to `recipient`; `sendCounter++`.

### 7.6 Rollover

`rollOver(bytes32 ua, bytes acc, bytes[] cts)`: anyone; `1 ≤ cts.length ≤ ROLL_MAX = 16`; `rolled + cts.length ≤ pendingCount`;
`acc.length == 16,512`, `keccak256(acc) == accHash`; every `cts[j].length == 16,512` and `cts[j]` matches
`pendingHash[rolled + j]`; `acc' = acc + Σ cts` in Solidity (64-bit lanes, one
`mod q` per lane at the end — 16 additions of values `< 2^42` cannot overflow a lane); `accHash = ctHash(acc')`;
`rolled += n`; `accUnits += n`; emit `PqzRolled(ua, rolled, accHash)` (clients recompute `acc'`). No proof, no signature: rollover cannot hurt
anyone (R277). As an envelope op (§7.11) it is the same call with an outer fee, so an owner can pay a relayer to roll. Calldata is the cost: ≈ 0.52 M gas per ciphertext (§9.4); a relayer batches it off-peak. Only proven
credits exist as pending entries, so no rollover carries an all-zero `u`.

### 7.7 Statement layout

Header (576 bytes; rev 1.4 appended `envelopeBinding`):

| Offset | Field |
|---|---|
| 0 | `opTag` — `keccak256("SCAAS-PQZ-OP-TRANSFER-V1")`, `…-BURN-V1` or `…-REFRESH-V1` |
| 32 | `proofSystemId` (R278) |
| 64 | `chainId` |
| 96 | `token` (12 zero bytes ‖ address) |
| 128 | `registry` |
| 160 | `fromUA` |
| 192 | `toUA` (0 for burn/refresh) |
| 224 | `beneficiaryUA` (0 if none) |
| 256 | `fee` |
| 288 | `amount` (burn; else 0) |
| 320 | `recipient` (burn; else 0) |
| 352 | `sendCounter` |
| 384 | `p` |
| 416 | `validUntilBlock` |
| 448 | `auditorOn` (0/1) |
| 480 | `plainUsed` (R275) |
| 512 | `chainUid` (R270, F R330; the token's copy of `registry.chainUid()`, rev 1.3) |
| 544 | `envelopeBinding` (R284, §7.11): 0 for a direct call, else the v1 or v3 binding of the envelope that carries the op (rev 1.4) |

Body: `pk_f ‖ [pk_t] ‖ [pk_a] ‖ T ‖ out` (`T` already includes the plain term). Transfer with auditor:
576 + 3·16,384 + 16,512 + 16,768 = **83,008 B**; burn: 576 + 16,384 + 16,512 + 16,512 = **49,984 B**. The contract
builds it from storage, SSTORE2 reads and calldata; the prover builds it identically (vector `statement_*.json`,
§15).

`authDigest = keccak256("SCAAS-PQZ-AUTH-V1" ‖ keccak256(statement))`. The authorization signature is over these 32
bytes, wrapped as F's `ua_msg` and signed by ML-DSA with `ctx = kind_tag` (§7.10, §9.3), not with EIP-8355's empty
context.

### 7.8 Events and indexing

`PqzCredit(bytes32 indexed ua, uint64 indexed index, bytes32 entryRef)` (the bytes `u ‖ v_t` are in that
`PqzTransfer`), `PqzPlainCredit(bytes32 indexed ua, uint256 amount, uint256 plainPending)`, `PqzTransfer(bytes32
indexed entryRef, bytes32 indexed fromUA, bytes32 indexed toUA, bytes out)`, `PqzRolled(bytes32 indexed ua, uint64
rolled, bytes32 accHash)`, `PqzBurned(bytes32 indexed ua, uint256 amount, address recipient, bytes newAcc)`,
`PqzRegistered(…)`. A client rebuilds `acc`, the pending list and `plainPending` of its UA from these logs alone and
checks each against the stored hashes and values before proving. Logs cost 8 gas/byte (≈ 134 k per transfer) — the
price of not trusting an indexer for state.

### 7.9 Disclosure (`ITransferDisclosure`, R283)

`verifyTransferAmount(entryRef, amount, kind, opening)` with `opening = abi.encode(bytes bundle, bytes proof)`,
`bundle = u ‖ v_t ‖ v_a ‖ toUA`, `keccak256(bundle) == entry[entryRef]`, `amount < 2^64`; statement
`opTag(DISCLOSE-<KIND>) ‖ proofSystemId ‖ chainId ‖ chainUid ‖ token ‖ registry ‖ entryRef ‖ be32(amount) ‖ u8(kind) ‖ pk ‖ u ‖
v`. The contract loads `pk` from the **registry** (`keyPtr` of `toUA` for `SENDER_S`/`RECEIVER_X`, of the token's
`auditorUA` for `AUDITOR`), never from the opening; `v = v_t`, or `v_a` for `AUDITOR`:

| Kind | Prover | Relation |
|---|---|---|
| `SENDER_S` | sender, re-deriving `r, e1, e2_t` (R288) | `u = A^T r + e1`, `v_t[i] = (pk_t^T r)[i] + e2_t[i] + Δ·digits(amount)_i`, norms as §4.1 |
| `RECEIVER_X` | receiver | `pk_t = A s + e`, `v_t[i] − (u^T s)[i] = Δ·digits(amount)_i + e'_i`, `abs(e'_i) < 2^24` |
| `AUDITOR` | auditor | as `RECEIVER_X` with `pk_a`, `v_a` |

Uniqueness by §4.3. `verifyTransferAmount` is a view (the precompile runs in `eth_call`); `attestTransferAmount`
emits `AmountAttested` as classical. `transferCiphertextHash(entryRef)` returns the bundle hash; the bundle bytes
come from `PqzTransfer` logs. Nothing reveals `r` (which would open `v_f`, the sender's balance) or decryption noise.

### 7.10 Authorization check

`registry.requireZetherAuthorized(fromUA, authDigest, authSig, zkCovered = true)`. Because R281 forbids `authRef =
0`, this always runs F's `requireAuthorized(authRef, PURPOSE_ZETHER_AUTH, authDigest, authSig)` with
`PURPOSE_ZETHER_AUTH = keccak256("scaas.ua.purpose.zether-auth.v1")`: `authSig = abi.encode(bytes keyData, bytes
sig)` with empty `keyData` for stored PQ kinds (F R306), `msig` member signatures in F's format. The signed message is
**exactly F R301**, computed by the registry from the `authRef` record's **actual** kind, never a kind fixed here
(rev 1.3, Codex H1/M2):

```
ua_msg = keccak256(MSG_TAG ‖ TAG(authKind) ‖ PURPOSE_ZETHER_AUTH ‖ authDigest)
MSG_TAG = keccak256("scaas.ua.msg.v1");   authKind = kindOf(authRef) ∈ {mldsa65, mldsa44, fndsa512, msig}
```

`mldsa65`/`mldsa44` sign `ua_msg` with `ctx = kind_tag` (F §4.2), `fndsa512` as F R313; for an `msig` `authRef`
each member signs F's `member` purpose over `keccak256(structureUA ‖ ua_msg)` with its own kind (native members
inside `UAAuth`, F §6.1), and F's threshold rule plus R281's PQ-weight rule apply. PQZ adds no signing domain of
its own: a signature valid here is valid through `UARegistry.requireAuthorized(authRef, PURPOSE_ZETHER_AUTH,
authDigest, authSig)` and vice versa (vectors §15). F's `zether-auth` purpose covers the PQZ digest, which carries its
own domain string. Both the proof (knowledge of the PQZ key) **and** the signature (the auth UA) are required
(classical invariant #1).

### 7.11 Meta-transactions (R284, rev 1.4)

**Two envelopes over one pipeline.** Mixin `PqzMetaTx` (ERC20 + EIP712 + `IERC20MetaTx`, the `ZetherMetaTx`
pattern with F's shared nonce map) gives `PqzToken`:

| | v1 path — exactly as `ZetherToken` | v3 path — exactly as MetaToken v3 (F §5.3) |
|---|---|---|
| Entry point | `executeMetaTransaction(MetaTxLib.MetaTransaction m, bytes sig)` | `uaExecute(UAMetaTransaction m, bytes auth)` |
| Struct, typehash | `MetaTxLib`'s, read-only (RS2-7) | F R309's `UAMetaTransaction` (`bytes32 from, to`) |
| EIP-712 domain | `("SCaaS PqzToken", "1", chainId, token)` — classical shape, so existing digest code (SDK, node R89, Odoo builder) is unchanged | `("SCaaS PqzToken", "3", chainId, token, salt = chainUid)` — F's v3 shape (R309, R330) |
| `from`, step 5 | address: ECDSA low-s if `_isContract(from)` is false, else ERC-1271 (50 k gas), as `ZetherMetaTx` | native id (`from >> 160 == 0`, classified per F R331) as v1; else a registered SIGNING UA through `registry.requireAuthorized(from, PURPOSE_METATX, digest, auth)`; ZETHER kinds (incl. `pqz-mlwe`) ⇒ `UAKindNotAccepted` |
| Pays the outer fee from | its ERC-20 balance | `_uaBalance[from]` (derived) or the ERC-20 balance (native), F R308 |
| Nonce | one map `_uaNonce[bytes32][batch]` for both paths (F T-V3-1); `metaNonce(address, batch)` reads `pad(from)`; `cancelMetaNonce(batch)` by the sender, emits `MetaNonceCancelled` | the same map; `uaNonce(bytes32, batch)`; `uaCancelNonce(ua, batch, validUntil, auth)` for derived UAs (purpose `metatx-cancel`) |
| Event | `MetaTransactionExecuted` | `UAMetaTransactionExecuted` (its `digest` is the `intent_id`, F R316) |
| Binding tag | `SCAAS-PQZ-ENVELOPE-V1` | `SCAAS-PQZ-UA-ENVELOPE-V1` |

Plus F R308's `transferToUA(bytes32, uint256)`, `balanceOfUA(bytes32)`, `UA_POOL` and `UATransfer`, so a PQ UA can
hold the public fee float. Same surface as `ZetherToken` (owner check 2026-10-07): **`wrap`/`unwrap` exist as direct calls** exactly as
classical (`ZetherToken.sol:189-200`), and the envelope ops are the confidential ones — as classical, whose
`_executeOp` carries only `zetherTransfer`/`zetherBurn` (`ZetherToken.sol:447-455`). The **gasless exit is the
envelope `burn`**, which pays the underlying straight to `recipient` (classical `ZetherToken.sol:406`), so no envelope
`unwrap` op is needed. No `mtxBatch`/`uaBatch` and no `pay` op: a PQZ op is ≈ 3 M gas and ≈ 80 KB.

**Ops in `m.data`.** `data` empty ⇒ plain public transfer `from → to` with the full `FeePolicy` (incl. `PERCENT`,
1 % cap) and v2's `FeeRecipientIsPayee` check, as every meta token. Otherwise `m.to = 0` and `m.value = 0` (else
`PqzOpNotCanonical`) and `m.data` is **byte-identical to the direct call's calldata**, so a client builds one
calldata and either submits it or wraps it:

| `m.data` selector | Effect | Statement binding |
|---|---|---|
| `pqzTransfer(bytes,bytes,bytes[],bytes,bytes)` | §7.4 | `envelopeBinding` = this envelope's |
| `pqzBurn(bytes,bytes,bytes[],uint256,address,bytes,bytes)` (burn and refresh) | §7.5 | as above |
| `fund(bytes32,uint256)` | §7.3, source = the signer's public balance | none: no statement; the envelope signature covers `(ua, amount)` |
| `rollOver(bytes32,bytes,bytes[])` | §7.6 | none (no authority needed) |

Any other selector ⇒ `PqzOpNotCanonical`. `supportedModes()` returns `0xF3` on both paths: flag bits
`MODE_RESTRICT_RELAYER` (`0x01`) and `MODE_RESTRICT_FEE_RECIPIENT` (`0x02`) apply to every op; fee nibble `NONE`
(`0x00`) and `FIXED` (`0x20`) apply to every op, `FIXED` absolute (no 1 % cap, the amount is hidden — RS2-6);
`PERCENT` (`0x10`) applies to plain public transfers only and reverts `PercentFeeForbiddenOnConfidential` on the
four PQZ ops; other bits ⇒ `ModeUnknownBits`/`ModeFeeInvalid` (step 3).

**Pipeline** (classical order; nonce spent with the fee as `MetaTxCore` v2, TW2 §3.2):

1. relayer; 2. `validUntil`; 3. `MetaTxLib.validateMode`; 4. nonce; 5. signature (per path, table above);
6. **checks**, cheap first: canonical shape, `requireConfidentialSafe`, `fee = FIXED ? m.fee : 0`,
   `FeePolicy.validateRecipient`, payer public balance `≥ fee` (`+ amount·shieldScale` for `fund`) — before any
   SSTORE2 read, statement build or precompile call (`MetaTxInsufficientForFee`); then the op's own checks in
   §7.4/§7.5 order, the statement with `envelopeBinding`, `requireZetherAuthorized` (the PQ `authSig`, §7.10) and
   the `PQZ` verify;
7. collect the outer fee and spend the nonce;
8. effects (§7.3–§7.6); burn's underlying transfer last, then the escrow check;
9. emit the path's event.

Anything failing ⇒ the whole transaction reverts: no fee, nonce unspent; the relayer loses its gas (free on chain
7622) and protects itself by simulating on a follower (§11.3). Op arguments are read from `m.data` as calldata slices,
not decoded into memory and re-sent through a `this.relayed*` self-call as `ZetherToken` does: at +16 inline credits
`m.data` is ≈ 340 KB, and three memory copies would cost ≈ 2 M gas of quadratic memory expansion (§9.4).

**Binding** (classical §10 / RS2-5, plus `chainUid`; `m.data` excluded because it contains the proof):

```
envelopeBinding = keccak256(abi.encode(keccak256("SCAAS-PQZ-ENVELOPE-V1"), chainid, chainUid, token,
                    m.from, m.to, m.value, m.batch, m.nonce, m.validUntil, m.mode, canonRelayer, m.fee, canonFeeRecipient))
                  (v3: tag "SCAAS-PQZ-UA-ENVELOPE-V1", `m.from`/`m.to` as bytes32; direct call: 0)
```

Views `envelopeBinding(m)`, `uaEnvelopeBinding(m)`, `metaTxDigest(m)`, `uaDigest(m)` and `transferStatement` /
`burnStatement(…, binding)` let clients cross-check before proving. As classical: stripping the op out of its
envelope and calling directly (binding 0), re-wrapping it in another envelope (other `from`, nonce, validity, fee,
relayer or fee recipient), or using it on another token or chain changes the statement ⇒ `AuthRejected` (the
`authSig` is checked before the precompile; the proof would fail too); a replay after execution meets an advanced
`sendCounter` and nonce. The client fixes every envelope field **before proving**; a relayer quotes its fee first.
`entryRef` and `authDigest` keep their §7.4/§7.7 formulas (the binding enters through the statement).

**Who can do what with a broken key** (quantum adversary or leak):

| Broken key | Can | Cannot |
|---|---|---|
| v1 envelope signer (ECDSA EOA, or a 1271 wallet with classical validation) | sign envelopes as `from`: spend its public balance (public transfers, outer fees to a recipient it picks, `fund` that shields that balance into any UA); spend or cancel its nonces, which kills its own bound in-flight PQZ ops (liveness only) | move confidential value (needs the PQ `authSig` and the PQZ proof); change a bound op's fee, relayer, recipient, nonce or validity; re-wrap or strip a signed op; touch another account's balance |
| relayer lane key (gas only) | delay or drop its own submissions; submit an envelope it saw (same effect as the owner's submission; with `feeRecipient` unbound it collects the fee, MESH R84) | anything else |
| v3 `from` = `mldsa*` UA or PQ-dominant `msig` (R281 weight rule) | — (no classical key on the path) | — |

So the v1 path's exposure is bounded by the signer's public fee float. **Default (clients):** PQZ accounts relay
through the v3 path with a dedicated `mldsa65` **fee UA** (same derivation as §6.2, its own index `i`, holding only
the float); the `authRef` key signs only `zether-auth`, per F R298's one key per role. The v1 path serves existing
EOA/1271 payers; a 1271 wallet whose own validation is ML-DSA is PQ on the v1 path too.

---

## 8. Proof engine `pqz-core`

- **Origin.** Fork of LaZer at a pinned commit (`main` was `3330e48`, 2026-09-28; E-S1 records the pin), MIT,
  repo path `scaas/pqz-core/`. Kept: LNP22 protocol logic, codegen (`scripts/lin-codegen.sage` with
  lattice-estimator), parameter headers. **Rewritten** (§2.6, R278), for the fixed parameters only:
  - integers: one 64-bit modulus `q < 2^42`, Montgomery/Barrett on `uint64` with 128-bit products (32-bit limbs on
    WASM); no `int_t`, no GMP;
  - NTT: the incomplete negacyclic NTT of §4.1 in portable C99, optional AVX2; no HEXL, no C++;
  - masking sampler: integer discrete Gaussian (CDT with a constant-time full-table scan), or uniform masks with
    integer rejection if E-S0 shows the proof-size cost acceptable; no `double`;
  - rejection: the acceptance test in fixed-point integer arithmetic with a constant-time exp approximation whose
    error is inside the proof's statistical-distance budget; no MPFR;
  - memory and errors: a caller-provided arena of compile-time size, every `ERR`/`ASSERT` an error return; no
    `malloc`, no `abort`, no stdio;
  - PRNG: AES-NI replaced by a bit-exact constant-time software AES (bitsliced; the T-table form is forbidden for
    secret-keyed streams) or by SHAKE where the fork changes the stream (then all KATs are fork-generated).

  Upstream cannot produce our transcripts once the samplers and PRNG change, so the only cross-check against
  upstream is at the **arithmetic layer** (NTT, ring products, norms on the same inputs) on a CI runner with
  AVX-512. CI asserts that `libpqz.so`, the WASM module and the mobile libraries link no GMP, MPFR, libstdc++ or
  libm symbols and contain no floating-point instructions on the verify and prove paths (`nm`/`objdump` check).
- **Relations.** `R_TX`, `R_BURN` (also REFRESH), `R_REG`, `R_DS`, `R_DR` written as LaZer specifications
  (`pqz-core/params/*.py`) → generated `*params.h` checked in, regenerated only on purpose (codegen takes minutes).
- **Proof modulus = `q`.** `q` was chosen for the proof system first (rev 1.2): `q ≡ 2l + 1 mod 4l` with `l = 4`
  keeps differences of small challenges invertible (§4.1), so the relation modulus is the proof modulus and no row
  is lifted. Rev 1.1's fallback (lift to `q·q₁`) would have added ≈ 4096 quotient witnesses of 11–12 bits, each
  range-proven, growing the binary witness from hundreds of bits to ≈ 50 k; it is removed. If E-S0/E-S1 still find
  `q` unusable as the proof modulus, that is a parameter ruling (new `q`, new `proofSystemId`), not a lift.
- **API (C ABI, stable):**
  ```c
  int pqz_prove(uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *wit, size_t wit_len,
                const uint8_t rnd32[32], uint8_t *proof, size_t *proof_len);   /* 0 = ok */
  int pqz_verify(uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *proof, size_t proof_len);
                                                                               /* 1 = valid, 0 = anything else */
  int pqz_keygen(const uint8_t seed32[32], uint8_t pk[16384]);
  int pqz_enc(...); int pqz_dec(const uint8_t seed32[32], const uint8_t ct[16512], uint64_t M[16], int64_t noise[16]);
  ```
  `pqz_verify` never crashes (R279): it is reached only through a bounds-checked Rust decoder that accepts exactly the
  fixed lengths of §4.4/§7.7 and canonical coefficients; it uses a compile-time arena and a fixed stack, has no
  recursion and no unbounded loop, and returns 0 on any malformed input or internal error.
- **Proof serialization v1** = the engine's own (polynomials as packed integers of the generated widths), versioned
  by `proofSystemId`. The contract never parses a proof; only its length is bounded (`MAX_PROOF = 98,304`).
- **Fiat–Shamir.** Transcript §5: `op` and the statement (with its `opTag ‖ proofSystemId` prefix) are absorbed
  first; every challenge round must be ≥ 128-bit sound on its own (round-by-round, §5), listed in `estimator.txt`.
  Soundness of multi-round Fiat–Shamir with aborts in the quantum random-oracle model is less settled than for
  3-move Σ-protocols; this is an explicit assumption of the threat model (§12.1 T10).

---

## 9. On-chain verifier architecture

### 9.1 Where lattice verification runs

| Option | Cost per transfer | Trust | Verdict |
|---|---|---|---|
| Solidity LNP22 verifier | `A` expansion with keccak instead of SHAKE ≈ 0.8 M; `A^T z` ≈ 65 k mulmods ≈ 1.5–2 M; commitment checks ≈ 5 M; NTTs, norms, transcript ≈ 1–3 M; plus calldata ⇒ **≈ 10–25 M (estimate)** | public | **No**: at or above the EIP-7825 16.78 M per-transaction cap; a second implementation of the verifier (Solidity + C) doubles audit surface and invites cross-language divergence |
| **Native precompile (chain 7622 (formerly 9000))** | ≈ 0.12 M per ms of p99 verify time (§9.4) + calldata | every full node re-executes | **Chosen** (R279) |
| Off-chain co-processor (quorum of verifiers signs ML-DSA attestations; contract checks t-of-n) | ≈ 30–60 k verification + calldata | the quorum, not re-verifiable from chain data | The later path for customer-run private chains (owner, rev 1.1; §14); rejected on chain 7622 (formerly 9000), where the precompile gives the same latency with public verifiability |
| STARK proof of the lattice verifier | multi-M + prover minutes | public, PQ | Disproportionate |

### 9.2 Precompile `PQZ` (`0x…0F01`)

Input `u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ proof`; output 32 bytes, `…01` valid, `…00` otherwise; never reverts on
cryptographic failure; reverts (consumes all gas) only on input `> MAX_INPUT = 262,144` bytes.

| op | Name | `stmt` |
|---|---|---|
| 1 | `OP_TRANSFER` | §7.7 |
| 2 | `OP_BURN` | §7.7 (also REFRESH: `opTag` differs) |
| 3 | `OP_REGISTER` | `opTag ‖ proofSystemId ‖ message ‖ pk` (§7.2) |
| 4 | `OP_DISCLOSE_SENDER` | §7.9 |
| 5 | `OP_DISCLOSE_RECEIVER` | §7.9 (also auditor: `opTag` differs) |
| 6 | `OP_SELFTEST` | empty: the whole input is exactly `u8(6) ‖ be32(0)`, anything else ⇒ `0` at the same price; computed at the first call in a process and cached for the process's life (same binary ⇒ same output, so caching keeps determinism and turns repeated calls into a lookup, rev 1.3); the first call recomputes the engine's fixed KATs (matrix digest, keygen, enc/dec) **and** verifies one compiled-in valid and one invalid `R_REG` vector; returns `keccak256` of the KAT outputs ‖ `u8(valid result)` ‖ `u8(invalid result)` (§10.4) |

For **every** op except 6 the precompile checks, before any cryptography, that `stmt` starts with an `opTag` that
belongs to `op` and a `proofSystemId` it implements (§5), and that the total length is one of the op's fixed lengths;
anything else returns `0`.

### 9.3 Precompile `MLDSA65` (`0x…0F10`)

Input `pk(1952) ‖ sig(3309) ‖ u8(len(ctx)) ‖ ctx ‖ msg`, FIPS 204 `ML-DSA.Verify(pk, msg, sig, ctx)` (pure
ML-DSA); output `…01`/`…00`. This is EIP-8355's layout plus the context field, because F signs with `ctx = kind_tag`
and EIP-8355 fixes an empty context. A private address because EIP-8051 and EIP-8355 both claim `0x12/0x13`. F's
`mldsa44`/`mldsa65` verifier for chain 7622 (formerly 9000) (`UAMldsaVerifier`, an `IUAKindVerifier`) calls it; the address is an
immutable constructor argument checked by self-test, so a later standard precompile means a new verifier in a new
registry generation (F §6.5). Fallback for chains
without it: none in v1 (Solidity ML-DSA at ≈ 1.23 M is possible but out of scope).

### 9.4 Gas model

Precompile price (R280), frozen per activation:

```
gas(PQZ, op, len) = G_op + 3·⌈len / 32⌉
G_op = 1000·⌈ 6000 · t_op / t_ecMul / 1000 ⌉
```

`t_op` = **p99** verify time on the chain host inside Nethermind over 1,000 runs each of the op's valid KATs and of
**adversarial** inputs that pass decoding and fail only at the last check (the most work a caller can force), not
the median of valid KATs; `t_ecMul` = median of `0x07` (priced 6,000) on the same host and build — so the price is
relative to work the chain already meters. With `t_ecMul ≈ 50 µs` (to be measured in E-S3) that is ≈ 0.12 M gas per
ms. Inputs rejected by the decoder or the prefix check cost the same formula (gas never depends on validity).
`OP_SELFTEST` has a **fixed** price `G_6` (no length term; its input length is fixed), set from the p99 of its
**cold** (first-in-process, uncached) time, so a block that happens to hit it first is paid for; repeated calls are
cache hits but pay the same `G_6` (rev 1.3, Codex L1). Contracts call it once at construction. Gas does not protect
`eth_call`, which costs the caller nothing on any chain, so CPU spam through the RPC is bounded by the follower's
rate limits (§10.3 step 5), for every op, not only op 6. `MLDSA65`: 9,000 + 6 per message word
(EIP-8355 numbers) unless calibration says more.

Estimates for a typical transfer (auditor on, no inline credits, 40 KB proof), **to be replaced by E-S3/E-S4
measurements**. Calldata: `out` 16,768 + `acc` 16,512 B at ≈ 25.2 tokens per `be8` coefficient, proof and signature
at ≈ 3.99 tokens per byte, ≈ 1.5 k tokens of ABI and header (scratch Python, 2026-10-06):

| Item | Gas |
|---|---|
| Calldata ≈ 77.2 KB ⇒ ≈ 279 k tokens: standard `4·tokens` | 1.12 M |
| `PQZ` verify, `0.12 M × t_p99[ms]` | ≈ 0.84–1.8 M at 7–15 ms (guess); **6.0 M at the 50 ms kill threshold** |
| Statement build: 3 × SSTORE2 reads, memory ≈ 83 KB, `T` add | ≈ 0.08 M |
| ML-DSA-65 auth | ≈ 0.01 M |
| Storage: `accHash`, `rolled`, `accUnits`, `floor`/`cleared`, `sendCounter`, `pendingHash`, `plainPending` ×2, `entry` | ≈ 0.09 M |
| Events (≈ 16.8 KB) | ≈ 0.13 M |
| Intrinsic | 0.021 M |
| **Total** = `max(standard + execution, EIP-7623 floor 2.81 M)` | **≈ 2.8 M** while `t_p99 ≲ 11 ms`; ≈ 3.3 M at 15 ms; **≈ 7.5 M** at 50 ms |

| Operation | Gas (estimate, floor-bound case) | Note |
|---|---|---|
| `transfer`, +1 / +4 / +16 inline credits | ≈ 3.3 M / ≈ 4.9 M / ≈ 11.1 M | +0.52 M per 16,512 B ciphertext; +16 stays under EIP-7825's 16.78 M even at 50 ms verify |
| `transfer` in a v1 envelope (R284, §7.11) | ≈ 2.82 M while `t_p99 ≲ 9.7 ms`; ≈ 3.5 M at 15 ms; ≈ 7.7 M at 50 ms | +≈ 0.6 KB calldata (struct head, offsets, 65 B ECDSA; ≈ 1 k tokens, +0.01 M floor); +≈ 0.2 M execution (ecrecover, one copy of `m.data` for `keccak256`, nonce, fee transfer, event), which shrinks the floor-bound range |
| `transfer` in a v3 envelope, `mldsa65` fee UA | ≈ 2.95 M while `t_p99 ≲ 10 ms`; ≈ 3.5 M at 15 ms; ≈ 7.7 M at 50 ms | + the ≈ 3.4 KB ML-DSA `auth` (≈ 13.5 k tokens, +0.135 M floor) + verify via `0x…0F10` and the fee UA's SSTORE2 key read ≈ 0.02 M |
| envelope at +16 inline credits | ≤ 16.78 M at 50 ms (requirement) | args sliced in place (§7.11); a decode-and-self-call copy of ≈ 340 KB would add ≈ 2 M; forge gas test in E-S4 |
| `rollOver` of 16 credits | ≈ 8.9 M | calldata-bound (17 ciphertexts); amortizes to ≈ 0.55 M per credit |
| `fund` | ≈ 0.07 M | ERC-20 pull, `plainPending` and `totalShielded` updates, small event; nothing to roll later; as an envelope op ≈ 0.1 M (v1) / ≈ 0.2 M (v3, ML-DSA) |
| `burn` / `refresh` | ≈ 2.6 M | one recipient, no auditor, ≈ 258 k tokens |
| `register` | ≈ 4.7–5.2 M once | SSTORE2 of a 16 KB pk ≈ 3.3 M + PoP verify + `UARegistered` log ≈ 0.13 M + standard calldata ≈ 0.59 M incl. the ≈ 3.4 KB ML-DSA `authPop` + its verify ≈ 0.01 M (above its ≈ 1.46 M floor) |
| Classical reference (measured) | 3.29 M / 3.36 M transfer, 0.115 M rollover | SCaaS §8.4 |

Per received payment PQZ costs ≈ 3.3 M (transfer plus the later roll of its credit) against classical ≈ 3.4–3.5 M,
while the floor binds. At the R280 block target (80 M): ≈ 28 transfers per 5 s block (≈ 10 at the 50 ms
threshold). **Archive growth** at sustained full load: ≈ 430 KB/s of calldata plus ≈ 95 KB/s of logs, ≈ 45 GB/day;
operators size archive disks for that or prune (OPS R247).

### 9.5 Contracts

| Contract | Role | Notes |
|---|---|---|
| `PqzSafety` (library) | R270 allowlist + self-test helper | |
| `UAPqzVerifier` | F `IUAKindVerifier` for `0x0142` (§7.2) | stateless; precompile address immutable |
| `UAMldsaVerifier` | F verifier for `mldsa44`/`mldsa65` on chain 7622 (formerly 9000) (§9.3) | stateless; used by F's `UARegistry` (built by F's stream) |
| `PqzMetaTx` (abstract) | ERC20 + EIP712 + `IERC20MetaTx`, v1 and v3 envelopes, UA ledger (§7.11) | `MetaTxLib`/`FeePolicy` read-only (RS2-7); not `ZetherMetaTx` itself, whose nonce map is address-keyed; `PqzToken --sizes` ≤ 24,576 B, else the `ua*` entry points move to a `fallback` decoder as F §5.3 |
| `PqzToken` | §7.3–§7.9, §7.11, `ITransferDisclosure`, `wrap`/`unwrap` | clone per token via `OpenFactory.createPqzToken` (flag-gated); immutable |
| `PqzCt` (library) | `add`/`sub` on 64-bit lanes, `addTrivial(digits)` for the plain term, canonical check (`< q`), `ctHash` | pure Solidity, no precompile |
| `Sstore2` | existing pattern (classical generator blob) | reused |

Selectors (normative ABI): `fund(bytes32,uint256)`, `pqzTransfer(bytes,bytes,bytes[],bytes,bytes)` (payload, acc,
inline, proof, authSig), `pqzBurn(bytes,bytes,bytes[],uint256,address,bytes,bytes)`, `rollOver(bytes32,bytes,bytes[])`,
views `accountState(bytes32) returns (bytes32 accHash, uint16 accUnits, uint64 pendingCount, uint64 rolled, uint64
floor, uint64 cleared, uint64 sendCounter, uint256 plainPending)`, `pendingHash(bytes32,uint64)`,
`transferCiphertextHash(bytes32)`; meta-tx (§7.11): `executeMetaTransaction`, `metaTxDigest`, `metaNonce`,
`cancelMetaNonce`, `supportedModes`, `envelopeBinding`, `uaExecute`, `uaDigest`, `uaNonce`, `uaCancelNonce`,
`uaEnvelopeBinding`, `transferToUA`, `balanceOfUA`, `wrap(uint256)`, `unwrap(uint256,address)`, and
`transferStatement`/`burnStatement` views taking `binding`. Errors (plus `IERC20MetaTx`'s, F's `UA*`,
`PercentFeeForbiddenOnConfidential`, `PqzOpNotCanonical`): `NotAllowedChain`, `SelfTestFailed`, `NonCanonical`, `StaleSendCounter`,
`AccMismatch`, `InlineMismatch`, `InlineTooFar`, `RefreshRequired`, `UnitsInvariant` (the debit-time
`unitsOf(T) > K_MAX` assert; unreachable unless accounting is broken), `PlainOverdraw` (`plainUsed > plainPending`),
`Expired`, `ProofRejected`, `AuthRejected`, `AmountOutOfRange`, `CiphertextOffState`.

---

## 10. Nethermind precompile (chain 7622 (formerly 9000))

### 10.1 Build

- Library `libpqz.so` = `pqz-core` (portable build, `-O2`, no `-march=native`) + ML-DSA-65 implementation, C ABI
  (§8). One build artifact for every node; its SHA-256 is pinned in the image and printed at start.
- **Never crash (R279).** The C core sits behind a Rust decoder (`pqz-ffi`: no `unsafe` except the one FFI call;
  built with `panic = "unwind"` and every entry point wrapped in `catch_unwind` → output 0) that checks op, prefix, every length and
  every coefficient before any C code runs. The C core is built with stack-protector and a fixed arena; release
  builds keep the invariant checks as error returns (upstream's `ASSERT_ERR` compiles to nothing). CI runs libFuzzer
  on ASan + UBSan builds of the decoder + core continuously from E-S2 on, plus a P/Invoke harness under the .NET
  host, not a one-off pass before E-S8.
- Nethermind integration `Nethermind.Pqz` (C#): two precompile classes calling `pqz_verify` / `mldsa65_verify` through
  P/Invoke, gas per §9.4, activated at `pqzTransitionTimestamp` from the chainspec. E-S3 decides between a plugin (the
  Nethermind Arbitrum plugin, which adds 16 precompiles, shows plugins can extend the EVM —
  [nethermind-arbitrum](https://github.com/NethermindEth/nethermind-arbitrum)) and a minimal patch of the precompile
  table on a pinned 1.39.x tag. Either way it ships as image `scaas/nethermind-pqz:<nethermind>-pqz<n>`.
- `reth` would make this trivial (Rust, `PrecompilesMap`) but has no Clique; switching clients is not in scope.

### 10.2 Consensus rules

Every node of chain 7622 (formerly 9000) runs the same image (R279). A node without the precompile executes a `STATICCALL` to
`0x…0F01` as a call to an empty account: success with empty output. `PqzToken` requires `returndata.length == 32`
and value 1, so such a node reverts where others succeed — a visible state-root split, never a silent
acceptance (fail closed).

### 10.3 Operational steps (chain 7622 (formerly 9000))

1. Build the image; start a throwaway copy of chain 7622 (formerly 9000) (same chainspec + `pqzTransitionTimestamp` in the future).
2. Probe: `eth_getBlockByNumber(0).hash` equals the profile's genesis hash and the registry's `chainUid()`
   (F R330; chain id 7622 alone is not assumed unique, and its former id 9000 is also Evmos Testnet, §2.7); `eth_call` to `0x…0F01` with `OP_SELFTEST` returns the KAT hash; `eth_estimateGas` matches §9.4
   formula; a valid and a one-bit-flipped transfer vector give 1 / 0; same for `0x…0F10`. Compare with the formula,
   not with "it answered" (the `eip1108` lesson).
3. Roll the signer and every follower to the image before the timestamp; then repeat step 2 on the live chain.
4. Raise `TargetBlockGasLimit` to 80 M and `TxPool.MaxTxSize` (R280).
5. **RPC topology.** The signer exposes no public RPC; a follower node serves all public `eth_call`,
   `eth_estimateGas` and scaas-node pre-simulation, and the signer peers only with our followers. A crash on a
   crafted `eth_call` then takes down a follower, not block production (R279; defence in depth only, since an
   included transaction runs on every node). **Rate limits** (rev 1.3, Codex L1): `eth_call` and `eth_estimateGas`
   are free to the caller, so each verify-class call (any op of `0x…0F01`, `0x…0F10`) is CPU the follower gives
   away. The follower's RPC sits behind a reverse proxy (or the scaas-node gateway) with per-client rate limits and
   a concurrency cap on `eth_call`/`eth_estimateGas` (Nethermind's own JSON-RPC concurrency and gas-cap keys
   confirmed in E-S3); public RPC is authenticated where the deployment allows it.

### 10.4 Contract self-test

Constructors of `UAPqzVerifier`, `UAMldsaVerifier` and `PqzToken.initialize` call `OP_SELFTEST` and require the
expected hash (a constant compiled into the contract; it folds in the precompile's own valid and invalid verify
results, §9.2). `UAPqzVerifier`'s constructor and `PqzToken.initialize` also take a valid `R_REG` vector (≈ 40 KB,
too large to compile into code under EIP-170) as an argument, require `keccak256(vector) ==
SELFTEST_VECTOR_HASH`, require `OP_REGISTER` on it to return 1, then flip one proof bit in memory and require 0.
`UAMldsaVerifier` checks `MLDSA65` on one valid and one invalid vector. Any mismatch ⇒ `SelfTestFailed`. This, not the allowlist alone, is
what keeps PQZ off chains whose client is not ours.

---

## 11. Off-chain components

### 11.1 `zether-prover` (feature `pq`)

- New modules behind `--features pq` (native first in E-S5; the `wasm32-unknown-unknown` build gains `pq` in E-S6,
  §11.5):
  `pq/keys.rs` (§6.2), `pq/mlwe.rs` (thin Rust over `pqz-core` C ABI via `cc` build; plus a pure-Rust reference
  `Enc/Add/Dec` used only in tests to cross-check the C), `pq/statement.rs` (§7.7), `pq/api.rs`
  (`prove_transfer`, `prove_burn`, `prove_refresh`, `prove_register`, `prove_disclosure`, `decrypt`, `rebuild_state`
  from logs), `pq/vectors.rs`.
- CLI `pqz-cli`: `keygen`, `register`, `balance` (decrypt from RPC logs, checks hashes), `transfer`, `burn`, `refresh`,
  `rollover`, `disclose`, `vectors`; every op takes `--envelope none|v1|v3` (default `v3`, §7.11): the CLI fixes the
  envelope fields, reads `envelopeBinding`/`uaEnvelopeBinding` from the token as a cross-check, proves, and emits the
  `metatx`/`ua_metatx` job body; the envelope signature itself comes from clientkeys or the org signer, never from
  `pqz-cli`. Keys only from stdin pipes, as `zether-read-balance` (no terminal input, never
  leaves the machine).
- `zether-read-balance` and BSGS stay for classical tokens; PQZ never uses them (R285).

### 11.2 clientkeys

- F's `deriveUAKey(seed, {kind: 'mldsa65', account, index})` / `signUA('zether-auth', authDigest)` (F stream F3)
  with a vetted JS/WASM ML-DSA package chosen in E-S5. `sealPqKey({account, index})` runs only in the key worker
  (derives `seed32` by §6.2 and seals the leaf); `openPqKey` opens it in the Zether worker (§6.3); an explicit
  export of the 32-byte leaf (never the BIP-39 seed) feeds the native prover or the org key oracle — PQZ proving is
  **not** in JS (R287).
- Envelopes (R284): the existing `MetaTransaction` EIP-712 builder (v1, domain `("SCaaS PqzToken", "1", …)`) and
  F's `UAMetaTransaction` builder (v3, `salt = chainUid`), with `signUA('metatx', digest)` by the dedicated
  `mldsa65` fee UA (§7.11); no new signing code.
- Vectors: F's `smartcontracts/vectors/ua/kinds.json` gains the `pqz-mlwe` row (seed → pk, UA, keyHash).

### 11.3 scaas-node (recommendations to operators, OPS R247)

- Chain profile flag `pqz = { genesis_hash = "0x…", registry = "0x…", tokens = ["0x…"] }`; start-up probe
  `has_pqz_precompile` (§10.3 step 2, genesis hash first) — a chain that fails it refuses PQZ jobs. The node checks
  RPC genesis hash `==` profile `genesis_hash` `==` `registry.chainUid()` `==` each token's `chainUid` and refuses a
  mismatch (F R330's node binding): the chain id (7622, formerly 9000, which is also Evmos Testnet, §2.7) does not
  identify our chain.
- Job kinds (R284; NI amended, see Amends): envelope ops use the **existing** `metatx` (v1) and `ua_metatx` (v3)
  jobs, with the node-computed digest (NI R89) over the token's domain (§7.11), idempotency and lanes unchanged; the
  token row has `kind = pqz`. Job kind `pqz_call` stays for **direct open calls** only: `{chain, contract, selector ∈
  {pqzTransfer, pqzBurn, rollOver}, calldata}` (direct `fund` pulls the caller's underlying, so it is never a node
  job). For all three: contract must be a configured PQZ token; pre-simulation by `eth_estimateGas` on a
  **follower**, never the signer (§10.3 step 5; fails ⇒ job rejected, no gas spent); `max_gas_per_tx = 16_000_000`
  on chain 7622 (formerly 9000) (today's default 3,000,000 already rejects classical Zether transfers at 3.36 M);
  never batched (NI R321; `PqzToken` has no `mtxBatch`). Gateway body limit 1 MiB on job submissions to the `pqz`
  chain profile only (R280; a v3 transfer job is ≈ 170 KB as hex).
- Optional rollover keeper: per configured PQZ token, when an account has ≥ 16 unrolled credits **older than
  `KEEPER_AGE = 24` blocks** (2 min) and the chain is idle, submit `rollOver` of those old credits only, with
  ciphertexts from logs (anyone may; it is harmless, R277). A proof in flight chose `p ≥` every credit older than
  its own state read, so the keeper never pushes `rolled` more than 16 past it. Clients prove at
  `p = pendingCount` and, on `InlineTooFar`, refresh state and re-prove once.
- The node never holds a PQZ secret or an ML-DSA key of a user (as classical: "the node never needs `x`"); it holds
  no envelope key either — envelopes arrive signed.
- Indexer: `MetaTransactionExecuted`, `UAMetaTransactionExecuted`, `Transfer` and `UATransfer` of a PQZ token are
  normalized like any meta token's (F §11.2), beside the `Pqz*` events of §7.8.
- Not on the mesh, exactly as classical Zether (MESH §1.2, R70; R284): the bus never exports a `metatx` or
  `ua_metatx` intent naming a PQZ token, and chain 7622 is private anyway.

### 11.4 Odoo

No new model in v1: the ERP sees PQZ like classical Zether (amounts known to the ERP from its own documents;
attestations through `attestTransferAmount`). Relaying uses the existing meta-tx path (R284): Odoo pushes PQZ
envelopes as ordinary `metatx`/`ua_metatx` jobs (`m.data` is opaque to it) and books the outer fee from
`MetaTransactionExecuted`/`UAMetaTransactionExecuted` like any token's. A later stream may add a `pqz-cli` connector
for organizations.

### 11.5 Retail WASM prover (stream E-S6, R287)

**Build target.** `pqz-core` compiled with clang `--target=wasm32-unknown-unknown -O2 -msimd128 -ffreestanding
-nostdlib` (no libc: after the E-S1 rewrite the fork's portable path uses no stdio, threads, `malloc`, GMP, MPFR or
floating point — upstream LaZer uses all of them, §2.6; memory comes from a caller-provided arena) and linked by `cc` into `zether-prover --features pq` built with `wasm-bindgen --target web`, as a separate
lazy module `pqz_bg.wasm` next to the classical one. SIMD128 is a baseline in current browsers; a no-SIMD build is
kept for the test matrix. Results are bit-identical to the native builds (integer-only samplers and rejection,
fixed `rnd32` vectors; a WASM/native sampler bit-exactness test, §15).

**Worker isolation (app R164, R175).** Proving runs in the app's Zether worker, which opens the sealed PQZ leaf
itself (`openPqKey`, §6.3; the key worker derived and sealed it with `sealPqKey`), so neither the BIP-39 seed, the
PQZ leaf nor the ML-DSA key crosses `postMessage`; the main thread sends
public inputs (statement parts fetched from logs, amount, recipient) and receives `proof ‖ out`. The ML-DSA signature
over `authDigest` comes from the **key worker** (`signUA('zether-auth', authDigest)`, F §8.3), and so does the
envelope signature (`signUA('metatx', uaDigest)` by the fee UA, §7.11): the envelope fields are fixed before proving
(the binding is in the statement), the signature is made after it (its digest covers `m.data`, which holds the proof). Both workers terminate
on lock, 5 min idle or 5 min hidden. App spec change (listed, applied by the app stream): R164's chain list gains 7622 (formerly 9000)
for configured PQZ tokens; the CSP already allows `'wasm-unsafe-eval'`.

**Budgets** (p95, per transfer; E-S1 measures a first cut, E-S6 enforces in CI on reference devices):

| Item | Desktop browser | Mid-range phone (2022, 8 GB) | Hard limit |
|---|---|---|---|
| Prove `R_TX` | ≤ 5 s | ≤ 15 s | 30 s ⇒ offer the fallback |
| Peak WASM memory | ≤ 128 MiB | ≤ 128 MiB | 256 MiB (iOS WebKit kills larger tabs) |
| Module size | ≤ 1.0 MB gzip for `pqz_bg.wasm` (the classical module keeps its 1.2 MB app budget) | same | — |
| Decrypt + state rebuild from logs | ≤ 200 ms for 64 ciphertexts | ≤ 1 s | — |
| Upload | ≈ 77 KB per transfer (≈ 81 KB in a v3 envelope) | same | — |

The prover streams commitment-matrix expansion from its seed (no tables beyond `NTT(A)`, 512 KB) and reports
rejection-sampling rounds to the UI; LNP22 retries make prove time variable, hence p95 budgets. Single-threaded in
v1: WASM threads need cross-origin isolation (COOP/COEP), which the app does not set.

**Fallback: native prover service run by the user.** `pqz-cli serve` holds the user's 32-byte PQZ leaf (stdin, as
§11.1; never the BIP-39 seed) and answers `POST /v1/prove` with the same request/response as the worker. **v1 binds
loopback only**, `127.0.0.1:8547` (a loopback origin is a secure context, so the app may call it); CORS limited to the
app origin; a pairing token printed at start, sent as a bearer header. So the fallback serves desktop browsers; a
phone that misses its budget proves through the user's desktop session or waits. LAN mode (TLS certificate, QR
pairing) is deferred to E-S9. The service is the user's (or the organization's key oracle), never a third party's —
a prover learns the balance.

**Parameter and proof-size implications.**
- Proof bytes and sizes are platform-independent. The `q` form is **not** an off-chain detail: `q`, `l` and `Δ` fix
  the contract's canonical bound and plain-term encoding (`PqzCt`), the precompile, every vector and the
  `proofSystemId`, so any change is an on-chain change.
- The single prime `q < 2^42` needs 42×42→84-bit products, which WASM (no 64×64→128) emulates on 32-bit limbs
  (≈ 3–4× slower Montgomery/Barrett steps). E-S0/E-S1 pick `l ∈ {2, 4, 8}` and the prime jointly for proof size and
  WASM speed before E-S2 freezes vectors. **No RNS fallback** (rev 1.1 had one): two NTT-friendly primes of ≈ 2^21
  would split fully again and shrink the challenge-invertibility bound and the soundness terms to the smallest
  prime (§8). If the phone budget is missed with the chosen `q`, the phone WASM prover waits and phone users prove from a desktop session.
- The kill criterion (R278, ≤ 96 KB proof) also bounds phone upload and memory; a proof that passes native budgets but
  not the phone budget keeps native provers and the fallback, and the WASM prover waits.
- JIT-compiled WASM gives no constant-time guarantee; the code avoids secret-dependent branches and indices, the
  residual timing risk is stated (T11), and the native service is the choice for high-value treasury keys.

---

## 12. Threat model

### 12.1 Threats and controls

| # | Threat | Control |
|---|---|---|
| T1 | **HNDL on ciphertexts** (archive the chain, decrypt in 2035+) | MLWE ciphertexts at β ≈ 476, core-SVP 139 / 126 (§4.1; target ≥ Kyber-512 under classical and quantum core-SVP); no classical encryption of amounts in PQZ; transports already X25519MLKEM768 (SCaaS §6.8) |
| T2 | Quantum forgery of validity proofs (mint) | MSIS/MLWE-based LNP22; no pairing or DL anywhere in PQZ proofs |
| T3 | Quantum forgery of authorization | ML-DSA-65; hybrid scheme 2 only adds a classical check, never replaces it |
| T4 | Malformed ciphertexts (non-canonical coefficients, wrong lengths, huge noise) | canonical checks in Solidity and precompile; every ciphertext comes with a proof of exact norms; the only trivial term (the plain term of `T`) is built by the contract |
| T5 | Noise growth ⇒ wrong decryption or failure oracle | worst-case bound + `K_MAX`, enforced at credit **and** at debit (`unitsOf(T)`, §4.3, R275), 4.1× margin before soundness is at risk; no bootstrapping needed; a failure is impossible, not merely unlikely ([2024/127](https://eprint.iacr.org/2024/127)) |
| T6 | Decryption-noise leakage (IND-CPA^D style) | noise never leaves `pqz_dec`; disclosure is ZK (R283); no "decrypt and publish" API |
| T7 | Credit flood to hit `K_MAX` | `fund` and fees go to `plainPending` and take no slot (R275), so only proven transfers fill the cap: ≈ 2.8 M each, ≈ 2.9 G gas for 1022 (≈ 36 full blocks). Recovery = rolling all but the last ≤ 16 credits (64 rollovers ≈ 0.57 G) **plus** a refresh (≈ 2.6 M); a refresh alone does not free the cap while unrolled credits remain. Defender ≈ 5× cheaper; relayer fee UAs never fill. Gas is free on chain 7622 (formerly 9000), so permissioned submitters and node rate limits remain the real control; rollover is public |
| T8 | Rollover grief against in-flight proofs | impossible by construction (R277); > 16 attacker transfer credits rolled past `p` force a re-prove only; honest keepers roll only credits older than `KEEPER_AGE`, clients retry once (§11.3) |
| T9 | Replay / proof transplant | `sendCounter`, `chainId`, `chainUid`, `token`, `registry`, `validUntilBlock`, UAs, fee, beneficiary and `envelopeBinding` in the statement; envelope 2D nonce and `validUntil`; strong FS |
| T10 | Fiat–Shamir for multi-round LNP22 (round-by-round grinding; QROM) | `op` and statement absorbed first; every challenge round ≥ 128-bit sound on its own, listed in `estimator.txt` (§5); QROM soundness an assumption, stated; tracked for the audit (Z1) |
| T11 | Side channels in the prover (timing of sampling, rejection, Gaussian masks; WASM JIT gives no constant-time guarantee, §11.5) | constant-time CBD; masking sampler **rewritten** integer-only and constant-time (CDT full-table scan or uniform masks) — upstream uses `double` and MPFR on secret-dependent values (§2.6); rejection test in constant-time fixed point, since rejected attempts would otherwise leak `⟨z, v⟩` through timing; no secret-indexed tables (software AES bitsliced) |
| T12 | Randomness reuse | R288 message-bound derivation; hedged proof masks |
| T13 | Precompile bug ⇒ consensus split or false accept | single C core shared with prover tests; continuous ASan/UBSan fuzzing of `pqz_verify` (§15); fail-closed returndata check; deterministic integer code (R279) |
| T13a | Precompile **crash** (abort, OOB, stack overflow) on crafted input ⇒ the single signer dies ⇒ chain halt | never-crash requirement: Rust bounds-checked decoder, error returns instead of `abort`, fixed arena and stack, bounded loops, no timeouts (R279, §10.1); follower-only public RPC and pre-simulation (§10.3 step 5) |
| T13b | Malicious recipient keys extract hints on the shared `(r, e1)` (forms `e^T r − s^T e1 + e2`) | assumption "MLWE with ≤ 32 adversarial perfect hints on `(r, e1)`", approximated at β ≈ 466, E-S0 worst-direction estimate (§4.5); fresh `(r, e1)` per operation; split-randomness fallback if E-S0 misses (R273) |
| T13c | Chain-id collision (former id 9000 = Evmos Testnet; 7622 not assumed unique) | owner move to 7622; precompile self-test (R270); `chainUid` (genesis hash, F R330) in every statement, `entryRef` and PoP; node binds genesis hash, registry `chainUid()` and token (§11.3) |
| T14 | Rogue / stolen public key registration; naming a victim's ML-DSA UA as `authRef` | `R_REG` PoP over F's `popDigest(ua, authRef)` (chain key, `chain_uid`, registry, UA, `authRef`) plus the `authRef` co-sign (F R295, §7.2); keyHash group `pqz-mlwe`; front-running yields the identical record |
| T15 | Leaked PQZ key | read-only breach (auth key separate, R281); move funds to a new UA |
| T16 | Leaked ML-DSA key | cannot spend without the PQZ key's proof; no rotation (F R302): move funds to a new UA |
| T18 | Broken v1 envelope key (quantum ECDSA, leaked EOA) | authority split (R284, §7.11): the envelope signer authorizes only its public balance and nonces; confidential value needs the PQ `authSig` + proof; bound ops cannot be re-pointed. Residual: loss of that signer's public float and liveness of its own relayed ops; v3 path with an `mldsa65` fee UA removes the classical key |
| T19 | Envelope stripping or re-wrapping (relayer takes the op out, or into an envelope with its own fee/recipient) | `envelopeBinding` in the statement (0 for direct calls), checked through the `authSig` before the precompile, as classical RS2-5 |
| T20 | Fee griefing: envelopes that fail late to burn relayer gas | outer fee checked before any SSTORE2 read or precompile call; fee and nonce taken only after verify, so a failing op reverts whole; relayers pre-simulate on a follower (§11.3); gas on chain 7622 is free, the cost is block capacity |
| T17 | Implementation immaturity (research-grade LaZer, unaudited fork with six rewritten layers) | UNAUDITED label, allowlist, self-test, owner gates G-LIC and Z1 (independent audit) before any real funds |

### 12.2 What stays classical (stated, not hidden)

- Clique block signing (secp256k1): a quantum adversary with the signer key could produce blocks; it cannot decrypt
  PQZ amounts or forge PQZ proofs, but it could censor or reorder. Consensus PQ is out of scope.
- Relayer lane keys (gas only) and the public ERC-20 underlying, `fund`/`burn` amounts (public by design).
- A v1 envelope signer (ECDSA/1271, R284): it controls only its public `PqzToken` balance and its nonces (T18); the
  v3 path with a PQ fee UA has no classical key on the op path.
- Classical Zether tokens on the same chain keep their HNDL exposure; R289 moves pilots off them.
- Metadata: identities and the transaction graph are visible (ring size 2), exactly as classical.

---

## 13. Hybrid path and migration

| Phase | What runs | HNDL status |
|---|---|---|
| H0 (today) | classical Zether on dev chains only (RS2-1); owner gate Z3 decides chain 7622 (formerly 9000) | exposed, but no production funds |
| H1 | PQZ on chain 7622 (formerly 9000) behind R270 (this spec, after E-S1…E-S7), dev and pilot only | amounts PQ-safe from first use |
| H2 | pilots migrate classical → PQZ (R289): `ZetherToken.burn(amount, ownerAddress)` then `PqzToken.fund(ua, amount)` with `approve(PqzToken)` (spender is a contract, R26) | each migrated amount is public once on chain 7622 (formerly 9000) |
| H3 | release gates **G-LIC** (licence/patent clearance) and **Z1** (audit), R270 — both before any production or commercial use | — |

No dual-stack ciphertexts (ElGamal ⊕ lattice secret-sharing of every balance) and no cross-system equality proof:
both would make every transfer carry two proof systems for the benefit of balances that, by gate, do not exist.

---

## 14. Per-family availability

| Family / chain | PQZ | Why |
|---|---|---|
| **EVM chain 7622 (formerly 9000)** (Nethermind, ours) | **v1** | precompile in our client (R279) |
| Dev chains 31337 / 1337 | tests only | anvil cannot host the precompile: forge tests mock it (`vm.mockCall` on KAT inputs); e2e on a chain-7622 (formerly 9000) copy |
| Other private EVM chains (customer-run Besu, geth, reth) | **not in v1**; later via the co-processor attestation seam (§9.1) | owner, rev 1.1: **no client ports in v1**; the seam needs its own spec (verifier quorum, ML-DSA attestations checked on that chain) |
| Public EVM (Gnosis, Celo, Ethereum) | **never** without an owner ruling | R270; no precompile; gas |
| Cosmos SDK private chains | feasible later (Go module calling `libpqz` via cgo) | needs its own spec |
| Hedera, Soroban, Sui, Aptos, Solana, TON | no | public networks, no custom natives |

---

## 15. Tests and vectors

**KATs** (`pqz-core/vectors/`, copied to `smartcontracts/evm/test/vectors/pqz/` and `zether-prover/vectors/pq/`):

| File | Content |
|---|---|
| `matrix.json` | `keccak256` of `A` coefficient bytes + first/last 8 coefficients of `A[0][0]`, `A[31][31]` |
| `cbd.json` | SHAKE inputs → CBD(1), CBD(20) samples |
| `keygen.json` | seed32 → `pk`, `ua`, ctr used; plus a seed forcing ≥ 1 resample (searched offline) |
| `enc.json` | `seed_enc`, recipients, messages → `u`, `v_j`; `Add`/`Sub`/`Trivial`; `Dec` → `M`, value (noise omitted from public vectors) |
| `derive.json` | BIP-39 seed → §6.2 seeds, PQZ pk, ML-DSA pk, UAs, keyHashes (rows also in F's `kinds.json`) |
| `statement_{transfer,burn,refresh}.json` | inputs → statement bytes, `keccak256(statement)`, `authDigest`, `entryRef` |
| `proof_{transfer,burn,refresh,register,disclose_*}.json` | statement, proof, `expect: true` (fixed `rnd32`, so byte-exact across backends) |
| `selftest.json` | the `OP_SELFTEST` hash, the vectors it covers (including its valid and invalid `R_REG` verify), and the constructor vector with `SELFTEST_VECTOR_HASH` (§10.4) |
| `worstcase_noise.json` | completeness KAT: the harness knows the receiver key; a malicious-but-valid prover builds `K_MAX − 1` credits whose `e2`, `e1`, `r` are aligned to maximise `e_t^T r − s_t^T e1 + e2` within the proven norms; the debit over all of them must still prove and verify |
| `mldsa65.json` | NIST ACVP-style vectors via the chosen implementation |
| `auth_{mldsa65,mldsa44,msig}.json` | `authDigest` → F R301 `ua_msg` (with `MSG_TAG`, `TAG(authKind)`, `PURPOSE_ZETHER_AUTH`) → signature, for an `mldsa65`, an `mldsa44` and a hybrid `msig {mldsa65 w1, p256 w1} t=2` `authRef`; each verifies through `requireZetherAuthorized` **and** directly through `UARegistry.requireAuthorized(authRef, PURPOSE_ZETHER_AUTH, …)`; rows shared with F's vectors (rev 1.3) |
| `register_pqz.json` | `popDigest(ua, authRef)` (with `chainKeyHash`, `chainUid`), the `R_REG` PoP and the `authRef` co-sign `authPop` (rev 1.3) |
| `metatx_pqz.json` | (rev 1.4) per op and path: envelope fields → `metaTxDigest` (v1 domain, no salt) / `uaDigest` (v3, `salt = chainUid`), `envelopeBinding` / `uaEnvelopeBinding`, the bound statement and `authDigest`, the signature (ECDSA, `mldsa65` fee UA); the direct form with binding 0; typehashes pinned to the classical meta-tx vectors and F's `metatx3.json` |

**Cross-language and cross-backend.** Same vectors through: `pqz-core` portable, AVX2, aarch64, freestanding
`wasm32` (bit-exact samplers: the same `rnd32` gives the same masks, rejection decisions and proof bytes on native and
WASM); upstream LaZer on an AVX-512 runner for the **arithmetic layer only** (NTT, ring products, norms), since
transcripts differ once samplers and PRNG change; Rust reference
`Enc/Dec`; Solidity `PqzCt` (add/sub/hash/canonical); JS clientkeys (derivation, ML-DSA, `authDigest`); a pure-Python
`pqz_kat.py` (no numpy) for encoding, `A`, CBD, keygen, `Enc`/`Dec`, statements (`--check` reports drift, like
classical `kat.py`).

**Negative cases** (each must give `0` from the precompile or a named revert):

- any single bit flipped in proof or statement; truncated/extended proof; wrong op for statement; wrong
  `proofSystemId`;
- a coefficient `= q` or `≥ 2^42` in `pk`, `acc`, inline, `out`; wrong lengths;
- **malicious-prover harness** (a debug build of `pqz-core` with checks disabled, never shipped): `v > balance`;
  digit 16; `M_i = 2^14`; carry out of range; `e_T` at `2^24`; `‖r‖ = 37`, `‖e1‖ = 165`, `‖e2‖ = 65`; `v_t` and `v_a`
  with different `d`; `T` from a different `acc`; `T` without the plain term or with another `plainUsed`; key of
  another UA;
- stale `sendCounter`; `validUntilBlock` passed; `acc` hash mismatch; inline ciphertext out of order; `|p − rolled|
  = 17`; `p > pendingCount`; `p < floor` (would subtract credits the last debit consumed); proven credit when units
  would exceed `K_MAX` (with the reserved plain unit); `plainUsed > plainPending` (`PlainOverdraw`); a third-party
  `fund` between prove and submit (must still succeed); self-transfer; unregistered receiver; auditor flag mismatch;
  `beneficiary == toUA`; 4096 `fund` calls to one UA leave its transfer path open;
- **inline length** (rev 1.3): in transfer, burn and refresh, for both `p ≥ rolled` and `p < rolled`, `inline.length
  = n − 1` and `n + 1` ⇒ `InlineMismatch`; an element of 16,511 or 16,513 bytes ⇒ `InlineMismatch`; entries in the
  right order but shifted by one index ⇒ `InlineMismatch`; `rollOver` past `pendingCount` reverts; invariant (1)
  holds after every accepted debit (no credit below `floor` is missing from `T`);
- **chain uid** (rev 1.3): a proof, authorization or disclosure valid on one chain-7622 copy is replayed on a second
  copy with the same chain id, token and registry addresses but another genesis/`chainUid` ⇒ 0 / `AuthRejected`;
  `initialize` with `registry.chainUid() == 0` reverts;
- **op / proofSystemId confusion:** each valid proof submitted under every other `op` byte, under its own op with
  another op's `opTag`, and with a `proofSystemId` the precompile does not implement ⇒ 0; register and disclosure
  statements without the 64-byte prefix ⇒ 0; a disclosure proof replayed against another registry ⇒ 0;
- rollover race: a debit proven at `p`, then `rollOver` of 3 / 16 / 17 credits, then the debit ⇒ ok / ok /
  `InlineTooFar`; then decrypt both accounts and check conservation;
- registry: PoP for another chain/registry/UA; same `pk` twice (`UAKeyInUse`); `authRef` = 0, an EOA, a classical
  `msig` (non-PQ weight ≥ threshold), a Zether UA — all `UAAuthRef`; ML-DSA signature with empty instead of
  kind-tag context; **`authRef` binding** (rev 1.3, F R295): a PQZ key registered naming a victim's ML-DSA UA as
  `authRef` without the victim's `authPop` ⇒ `UAUnauthorized`; `authPop` replayed with another `authRef`, or the
  PoP replayed with `authRef` stripped or changed ⇒ `UAPoP`/`UAUnauthorized`; an `authSig` over the rev 1.2 message
  (no `MSG_TAG`) or with `TAG(mldsa65)` for an `mldsa44` or `msig` `authRef` ⇒ `AuthRejected`;
- disclosure: right amount ⇒ true, amount ± 1 ⇒ false, wrong `entryRef`, bundle bytes not matching the hash;
- **meta-tx** (rev 1.4), each on the v1 and the v3 path: `PERCENT` on a PQZ op ⇒ `PercentFeeForbiddenOnConfidential`
  (and accepted on a plain public transfer); `m.to ≠ 0`, `m.value ≠ 0` or an unknown selector ⇒
  `PqzOpNotCanonical`; outer fee above the payer's public balance ⇒ `MetaTxInsufficientForFee` **with the
  precompile mock asserting zero calls**; invalid proof or `authSig` ⇒ revert, no fee moved, nonce unspent; an op
  stripped from its envelope and called directly, or re-wrapped with another nonce / fee / `validUntil` / bound
  relayer / bound fee recipient / `from` ⇒ `AuthRejected`; v1 binding presented on the v3 path (and vice versa) ⇒
  `AuthRejected`; `cancelMetaNonce` / `uaCancelNonce` kills a bound in-flight op; v1 and v3 share one nonce per
  native id; v3 `from` = a `pqz-mlwe` UA ⇒ `UAKindNotAccepted`; a broken-key simulation (the test owns the v1
  envelope key, not the `authRef` key) can drain the public float and burn nonces but every confidential op it
  builds reverts; envelope `fund` debits the public balance and keeps the escrow invariant; relayed `+16` inline
  transfer at the mocked 50 ms price stays ≤ 16.78 M gas;
- precompile absent (call an empty address) ⇒ `ProofRejected` / `SelfTestFailed`;
- determinism: 10^4 random valid and invalid inputs give identical outputs on portable, AVX2 and aarch64 builds; gas
  equals the formula for every input length;
- fuzzing: libFuzzer/`cargo fuzz` on ASan + UBSan builds of the Rust decoder + C core, and a harness through the
  .NET P/Invoke boundary, **continuously in CI** from E-S2 on (corpus kept, crashes block merges), plus forge
  invariant tests of the Solidity decoders; any crash, sanitizer report or non-`0`/`1` output is a release blocker;
- self-test input other than `u8(6) ‖ be32(0)` ⇒ 0 at the same fixed `G_6`; 10^4 repeated self-test `eth_call`s give
  identical output and gas (cache hit), and the cold first call stays within the calibrated `G_6`;
- self-test: a precompile build whose valid-vector verify returns 0 (or whose invalid returns 1) fails `OP_SELFTEST`
  and the constructor check;
- `estimator.txt` reproducible: CI reruns the pinned lattice-estimator commit on the recorded commands and diffs the
  output.

**Invariants** (forge, with mocked precompile and real `PqzCt`): (1) `Σ_ua decrypted(acc + pending) + Σ_ua
plainPending = totalShielded` (decryption computed off-chain by the test harness from the logged ciphertexts and known
test keys) after every random sequence of fund/transfer/rollover/burn/refresh; (2) every reachable `T` has
`unitsOf(T) ≤ K_MAX`, and every account has `accUnits + (pendingCount − rolled) + 1 ≤ K_MAX`; (3) `cleared ≤ floor ≤ rolled ≤
pendingCount`, and no deleted `pendingHash` slot is ever read; (4) (rev 1.4) escrow `underlying.balanceOf(token) ≥
totalSupply() + totalShielded·shieldScale` and `balanceOf(UA_POOL) = Σ _uaBalance`, over random mixes of direct and
envelope ops on both paths.

---

## 16. Streams

Research spikes first; at most 3 agents; **one heavy build at a time** (owner OOM cap). Each stream ends with its
tests green and a review.

| Stream | Content | Heavy build? | Depends | Exit criterion |
|---|---|---|---|---|
| **E-S0** spike: literature & parameters | read Lether full text, LNP22, LaZer docs, LS18 (exact invertibility constant for the chosen `l`); run lattice-estimator `53da598` under `RC.ADPS16` classical and quantum for §4.1 (key and `u` instances), the proof's MSIS/MLWE instances and Kyber-512 as baseline; leaky-LWE estimate with 32 perfect hints on the joint `(r, e1)` in the worst directions (unit on `r`, unit on `e1`, maximal mixed forms; §4.5); soundness error of **each** challenge round (§5); confirm exactness of every norm proof | no | — | `estimator.txt` (commands, commit, output); every instance ≥ Kyber-512 under both models and every round ≥ 128 bits, or a parameter ruling; a leaky-LWE miss switches R273 to split randomness before E-S2 |
| **E-S1** spike: `pqz-core` fork (a **rewrite** of six layers, R278) | pin LaZer; rewrite integer (GMP), NTT (HEXL, incomplete NTT for `l`), Gaussian sampler (`double`), rejection (MPFR), allocator (`malloc`) and error (`abort`) layers in integer-only constant-time C99 for the fixed parameters; optional AVX2; software AES; arithmetic-layer KAT equality vs upstream on an AVX-512 runner; measure a toy `R_REG` and a first `R_TX` on the chain host (p99 adversarial verify) **and** as freestanding `wasm32` in a desktop and a phone browser (with E-S0, fixes `l` and the prime, §11.5) | yes (C) | E-S0 | proof ≤ 96 KB, p99 adversarial verify ≤ 50 ms portable, prove ≤ 3 s desktop; verify and prove paths free of GMP, MPFR, floating point, `abort` and `malloc` (link-map and `objdump` check in CI) — else kill (R278) |
| **E-S2** relations | `R_TX`, `R_BURN`, `R_REG`, `R_DS`, `R_DR` specs, codegen, serialization v1, all §15 KATs from C (incl. `worstcase_noise.json`); Rust decoder `pqz-ffi`; continuous ASan/UBSan fuzzing starts | yes (codegen) | E-S1 | vectors frozen, `proofSystemId` frozen (R278) |
| **E-S3** Nethermind precompile | plugin vs patch, P/Invoke (+ fuzz harness), p99 adversarial gas calibration incl. the cold `OP_SELFTEST` (fixed `G_6`, per-process cache), image, chainspec key, probes (genesis hash = registry `chainUid()`), follower-only RPC topology with rate limits and `eth_call` concurrency cap (Nethermind keys confirmed), throwaway chain | yes (.NET image) | E-S2 | §10.3 steps 1–2 and 5 pass on a chain-7622 (formerly 9000) copy |
| **E-S4** contracts | `PqzSafety`, `UAPqzVerifier`, `UAMldsaVerifier`, `PqzMetaTx` (v1 + v3 envelopes, UA ledger, §7.11), `PqzToken`, `PqzCt`, factory flag, forge tests with mocks, e2e on the chain copy | yes (forge) | E-S2 (vectors), E-S3 (e2e), F's registry stream | §15 contract cases + invariant |
| **E-S5** clients | `zether-prover --features pq`, `pqz-cli` (incl. `--envelope`), clientkeys `pq-keys.js` and the PqzToken domains in the existing envelope builders, ML-DSA package choice | yes (cargo) | E-S2 | cross-language vectors green |
| **E-S6** retail WASM prover | §11.5: freestanding `wasm32` build of `pqz-core`, `zether-prover --features pq` wasm-bindgen module, Zether-worker integration (app R164/R175, `openPqKey`), WASM/native bit-exactness, budgets in CI on reference devices, loopback-only `pqz-cli serve` fallback | yes (cargo + wasm) | E-S5; the E-S0/E-S1 measurement fixes `l` and `q` before E-S2 | §11.5 budgets met, or the fallback green and the WASM prover marked "waits" |
| **E-S7** node | `pqz` profile (genesis hash), probe, `metatx`/`ua_metatx` for `kind = pqz` tokens and `pqz_call` (follower pre-simulation, never batched), limits, age-gated rollover keeper | yes (cargo) | E-S4, F5 (`ua_metatx`) | e2e: fund → transfer → rollover → burn → disclose through the node, direct and in v1 and v3 envelopes |
| **E-S8** review & audit prep | Claude-subagent reviews (external reviewers out of credit), fuzz corpus review (fuzzing itself runs continuously since E-S2), threat-model walk-through | no | E-S7 | review log in this spec |
| **G-LIC** licence/patent gate | legal review of LaZer (MIT, no patent grant) and any code retained from it; LNP22-family IP (IBM Research); GMP (LGPLv3/GPLv2) and MPFR (LGPLv3): confirm from link maps that no shipped artifact (`libpqz.so`, WASM module, iOS/Android libraries) contains them, or else record the static-linking/relinking duties — the CI-only upstream cross-check runner ships nothing; HEXL Apache-2.0 notice if any of its code is retained; ML-DSA and WASM toolchain licences; written clearance | no (legal) | may start any time | **release gate** with Z1: required before any production or commercial use; does not block E-S0–E-S8 |
| E-S9 (later) | LaBRADOR aggregation; FN-DSA when FIPS 206 is final; co-processor seam for customer-run chains; `pqz-cli serve` LAN mode (TLS + QR pairing) | — | owner | — |

Serial heavy chain: E-S1 (incl. a WASM measurement of a toy relation) → E-S2 → E-S3 → E-S4 → E-S5 → E-S6 → E-S7; E-S0,
G-LIC and reviews run beside them.

---

## 17. Owner answers and review disposition

### 17.1 Owner answers (rev 1.1)

| # | Question (rev 1) | Owner answer (2026-10-06) | Applied in |
|---|---|---|---|
| 1 | Patent/licence check (LaZer MIT without patent grant; LNP22 from IBM Research)? | Required gate **before any production/commercial use**; dev/research continues | R270 (G-LIC), §13 H3, §16 G-LIC |
| 2 | PQZ on customer-run private chains? | v1 only on our Nethermind chain; others later via the co-processor attestation seam; no client ports in v1 | R279, §9.1, §14, E-S9 |
| 3 | Retail provers earlier? | Yes: WASM/mobile right after E-S5 | R287, §11.5, E-S6 |

No open questions remain.

### 17.2 Review 1 disposition (rev 1.2)

Review: `docs/reviews/specs/2026-10-06-pq-zether-review-1.md` (Claude subagent, verdict FIX-THEN-GO, 17 findings).
I reran its primal-uSVP estimate independently: Kyber-512 came out at β = 406, exactly the published value (the
review's script gave 394), and rev 1.1 at β = 374, matching the review. The LaZer facts were rechecked through the
GitHub API at `3330e48`.

| # | Sev. | Finding | Disposition | Where |
|---|---|---|---|---|
| 1 | HIGH | Encryption below Kyber-512 under core-SVP | **Applied, modified**: `n = 2048`, `q = 2^42 − 215` (not the review's `2^41`: one more bit of `q` gives a 4.1× accounting margin for 16 β-units), base-16 digits, `K_MAX = 1024`; β ≈ 476, 139 / 126; cost model pinned (core-SVP 0.292β / 0.265β, ADPS16 primal, lattice-estimator `53da598`, Kyber-512 baseline); noise bounds, sizes and gas re-derived | R272, §4.1, §4.3, §4.4, §9.4 |
| 2 | HIGH | `K_MAX` lock-out by `fund`/fee dust | **Applied**: public `plainPending` consumed by a declared `plainUsed` (one trivial term of `T`); `K_MAX` counts proven credits only, plus one reserved plain unit; T7 corrected (refresh alone does not free the cap). The separate `feeBalance`/`claimFees` alternative is not needed: `plainPending` covers fees too | R275, §7.1, §7.3–§7.5, T7 |
| 3 | HIGH | LaZer = GMP/MPFR/double/HEXL/malloc/`-march=native` | **Applied**: the fork is a rewrite of six layers; constant-time integer sampler and fixed-point rejection; E-S1 scope, exit and kill criterion updated; G-LIC covers LGPL; T11 corrected; §11.5 "no malloc" claim now conditional on the rewrite | §2.6, R278, §8, §11.5, T11, E-S1, G-LIC |
| 4 | HIGH | Verifier crash = chain halt | **Applied, scope corrected**: never-crash requirement (no `abort`, Rust bounds-checked decoder, fixed arena/stack, bounded loops, no timeouts), continuous ASan/UBSan fuzzing, follower-only public RPC. The follower protects only the RPC path; a crashing *transaction* reaches every node, so never-crash is the requirement and the follower is defence in depth | R279, §8, §10.1, §10.3, T13a, §15 |
| 5 | MEDIUM | Fully splitting `q` vs LNP22 invertibility; RNS worse | **Applied**: `q ≡ 2l + 1 mod 4l`, `l = 4` (`l = 2, 8` alternatives listed with primes), incomplete NTT, proof modulus = `q`, lift fallback and RNS fallback removed; "nothing changes on chain" corrected | R272, R287, §4.1, §8, §11.5 |
| 6 | MEDIUM | Shared `r` has no reduction against malicious recipients | **Applied, count corrected**: with 16 plaintext coefficients a recipient gets ≤ 16 hints and a colluding receiver + auditor ≤ 32 (the review's 16 was for 8 coefficients); approximated β ≈ 466; DDGR20 run in E-S0; noise-term remark added | R273, §4.5, T13b, E-S0 |
| 7 | MEDIUM | Multi-round FS needs round-by-round soundness | **Applied** | §5, §8, T10, E-S0 |
| 8 | MEDIUM | Soundness depends on `K_MAX` accounting | **Applied**: `unitsOf(T) ≤ K_MAX` asserted at every debit, forge invariant, margin stated (4.1×) | §4.3, §7.4, §15 |
| 9 | MED-LOW | `proofSystemId`/`op` not bound for register/disclosure | **Applied**: uniform `opTag ‖ proofSystemId` prefix, `u8(op)` absorbed, `registry` in disclosure, precompile checks prefix for every op | §5, §7.2, §7.9, §9.2, §15 |
| 10 | LOW | Gas from median, too narrow | **Applied**: p99 over adversarial inputs, `OP_SELFTEST` priced, range up to 7.5 M at 50 ms | R280, §9.4 |
| 11 | LOW | Keeper can invalidate in-flight proofs | **Applied**: keeper rolls credits older than 24 blocks; clients prove at `pendingCount`, retry once | R277, §11.3, T8 |
| 12 | LOW | PQZ seed derived in the Zether worker | **Applied**: `sealPqKey` in the key worker, `openPqKey` in the Zether worker and `pqz-cli`; derivation stays F §8.1's PQ HKDF rule (the PQ branch of F's UA tree; PQ seeds are not BIP-32 leaves) | R282, §6.2, §6.3, §11.2, §11.5 |
| 13 | LOW | Inconsistencies | **Applied**: ML-DSA `ctx = kind_tag` everywhere; statement 82,944 B / burn 49,920 B; F §14's "spec E §6.3" now resolves (§6.3 added); `beneficiary == toUA` moot after #2 (fees take no slot); disclosure loads `pk` from the registry | §6.3, §7.4, §7.7, §7.9 |
| 14 | LOW | chainId 9000 = Evmos Testnet | **Applied**: noted; node profile and probe bound to the genesis hash; unique chain id left to the owner | §2.7, R270, §10.3, §11.3, T13c |
| 15 | LOW | Block bytes, archive growth, `pendingHash` never cleared | **Applied, modified**: target gas 80 M instead of relying on the producer, so EIP-7934 cannot be hit even with all-zero calldata; ≈ 45 GB/day stated; dead `pendingHash` slots deleted at debit with a `cleared` cursor (≤ 32 per debit) | R280, §2.7, §7.1, §7.4, §9.4 |
| 16 | LOW | Test gaps | **Applied**: worst-case-noise completeness KAT, valid-vector self-test, WASM/native sampler bit-exactness, ASan/UBSan + P/Invoke fuzzing, `unitsOf` invariant, op/proofSystemId confusion, reproducible `estimator.txt` | §10.4, §15 |
| 17 | LOW | Over-engineering | **Applied**: `pqz-cli serve` loopback only (LAN mode → E-S9); trivial-ciphertext pending entries removed (#2); upstream transcript-level cross-check dropped, arithmetic-layer cross-check kept | §8, §11.5, §15, E-S9 |

Counts: 17 applied, 5 of them with a modification or scope correction (1, 4, 6, 12, 15); 0 rejected.

### 17.3 Codex review disposition (rev 1.3)

Review: `docs/reviews/specs/2026-10-06-pq-zether-codex-review-1.md` (Codex, verdict FIX-THEN-GO, 6 findings). Each
was checked against this spec and F rev 1.4 before applying: F R301 (`ua_msg` with `MSG_TAG`), F R295 and §6.2 steps
6–7 (`popDigest(ua, authRef)`, `authRef` co-sign) and F's `0x0142` kind row all say what the review quotes; the
`h_i` identity of §4.5 was re-derived by hand, and the ℓ∞ and `e2` tail probabilities computed exactly from CBD(20)
(scratch Python, 2026-10-07).

| # | Sev. | Finding | Disposition | Where |
|---|---|---|---|---|
| H1 | HIGH | PQZ auth message omits F's `MSG_TAG` | **Applied**: §7.10 states F R301 exactly, `ua_msg = keccak256(MSG_TAG ‖ TAG(authKind) ‖ PURPOSE_ZETHER_AUTH ‖ authDigest)`; PQZ adds no signing domain; vectors verify the same signature through `requireAuthorized` | §7.10, §15 |
| H2 | HIGH | Registration omits `authRef` binding and co-sign | **Applied**: PoP over `popDigest(ua, authRef)` (incl. `chain_uid`), `register(…, authRef, authPop)` with the `PURPOSE_AUTHREF` co-sign as F §6.2 step 7; register gas +≈ 0.07 M; negative cases for unsigned victim, stripped and changed `authRef` | R282, §6.1, §7.2, §9.4, T14, §15 |
| H3 | HIGH | Leaky-hint model ignores attacker-chosen hints on `e1` | **Applied, modified**: the model is now ≤ 32 adversarial perfect integer linear hints on the joint `(r, e1)` (the count per op is unchanged: one form per plaintext coefficient per recipient; the "harmless" claim is withdrawn); E-S0 estimates the worst hint direction. Of the two remedies offered, the key-distribution proof is **not** taken: even ℓ∞ bounds (`‖s‖∞ ≤ 1`, `‖e‖∞ ≤ 20`) leave `20·r + e2` decodable with probability 0.998 per coefficient, so it does not reduce the leak. The fallback is "stop sharing `r`": split randomness (`v_f` under its own `u_f`, +16,384 B, ≈ +0.5 M gas) if the estimate misses | R273, §4.1, §4.5, T13b, E-S0 |
| M1 | MEDIUM | Inline length equality not normative | **Applied**: `inline.length == n`, element length 16,512, index `lo + i`, for transfer, burn and refresh; also `acc.length`, `cts[j].length` and `rolled + n ≤ pendingCount` in rollover; ±1 negative cases | §7.4–§7.6, §15 |
| M2 | MEDIUM | Auth kind hard-coded to `mldsa65` | **Applied** with H1: the registry uses the `authRef` record's kind (`mldsa65`, `mldsa44`, `fndsa512`, `msig` via F's `member` purpose); vectors for `mldsa44` and a hybrid `msig` | §7.10, §15 |
| L1 | LOW | `OP_SELFTEST` has no anti-spam guard | **Applied, modified**: fixed `G_6` (it already had no length term in effect; now explicit, and any non-empty input ⇒ 0), calibrated on the cold call; result cached per process, so repeated calls are lookups and a repeated-call p99 is moot. Gas does not protect `eth_call` for **any** op, so the RPC rate limits and concurrency cap apply to every verify-class call, not only op 6 | R280, §9.2, §9.4, §10.3, §15, E-S3 |
| O | owner | Private chain id 9000 → **7622** (9000 is Evmos Testnet) | **Applied**: "chain 7622 (formerly 9000)" throughout; gate `{31337, 1337, 7622}`; `chainUid` (genesis hash, F R330) copied from the registry at `initialize` into the statement header (544 B; transfer 82,976 B, burn 49,952 B), `entryRef` and disclosure statements; node binds genesis hash = registry `chainUid()` = token `chainUid`. Supersedes §17.2 #14's "unique chain id left to the owner" | §2.7, R270, §7.4, §7.7, §7.9, §10.3, §11.3, T13c, §15 |

Counts: 6 findings, 6 applied, 2 of them modified (H3, L1); 0 rejected; plus 1 owner change (chain id 7622).

### 17.4 Owner ruling (rev 1.4)

| # | Source | Ruling | Disposition | Where |
|---|---|---|---|---|
| O2 | owner 2026-10-07 | "PqzToken => Cái này cũng phải theo MetaTransaction IERC20MetaTx chứ." (`PqzToken` must also follow `IERC20MetaTx`) | **Applied**: R284 rewritten — ERC-20 + `IERC20MetaTx` exactly like `ZetherToken` (struct, typehash, 2D nonce, modes `0xF3`, nine steps, absolute fee, `PERCENT` refused on PQZ ops, fee checked before verify and taken after), every PQZ op direct and as an envelope op with `m.data` = the direct calldata, `envelopeBinding` in the statement header (576 B; transfer 83,008 B, burn 49,984 B); authority split (PQ `authSig` for confidential value, envelope signer for its public balance and nonce); PQ-complete v3 `UAMetaTransaction` path on a `PqzToken` UA ledger with an `mldsa65` fee UA; broken-key table; off-mesh as classical; `metatx`/`ua_metatx` jobs, `pqz_call` for direct calls; gas rows; T18–T20; vectors, negatives, invariant (4); Amends rows for F, NI, MESH, SCaaS, INT. **Defaults taken:** nonce spent with the fee after verify (`MetaTxCore` v2 order) rather than at step 9 as `ZetherMetaTx`; v1 domain without salt (classical shape, so existing digest code is unchanged) and v3 domain with `salt = chainUid` (F's shape); one `envelopeBinding` field (0 = direct) instead of classical's tag + binding pair; op args sliced from calldata instead of the classical self-call; a dedicated `mldsa65` fee UA, not the `authRef` key; no batch, `pay` or `unwrap` ops | R284, §1, §7.1, §7.3–§7.7, §7.11, §9.4, §9.5, §11, §12, §15, §16, Amends |

---

## 18. Sources

- Lether: Wang, Esgin, Steinfeld, Yiu, *Lether: Post-Quantum Private Blockchain Payments*, ACM CCS 2026,
  <https://eprint.iacr.org/2026/076>
- LNP22: Lyubashevsky, Nguyen, Plançon, CRYPTO 2022, <https://eprint.iacr.org/2022/284>
- LS18 (short invertible elements in partially splitting rings, Cor. 1.2): Lyubashevsky, Seiler, EUROCRYPT 2018,
  <https://eprint.iacr.org/2017/523>
- Core-SVP / primal uSVP 2016 estimate: Alkim, Ducas, Pöppelmann, Schwabe (NewHope), <https://eprint.iacr.org/2015/1092>;
  Kyber round-3 specification (Kyber-512 core-SVP 118), <https://pq-crystals.org/kyber/resources.shtml>
- MATZOV, *Report on the Security of LWE: Improved Dual Lattice Attack*, 2022, <https://doi.org/10.5281/zenodo.6412487>
- LWE with side information (hints): Dachman-Soled, Ducas, Gong, Rossi, CRYPTO 2020, <https://eprint.iacr.org/2020/292>;
  code <https://github.com/lducas/leaky-LWE-Estimator>
- LaZer source facts (§2.6): `Makefile`, `src/int.c`, `src/rejection.c`, `src/grandom.c`, `src/lazer-in2.h` at
  `3330e48` via the GitHub API, 2026-10-06; Intel HEXL licence Apache-2.0 <https://github.com/intel/hexl>; GMP
  <https://gmplib.org/> (LGPLv3/GPLv2), MPFR <https://www.mpfr.org/> (LGPLv3)
- Former chain id 9000 = Evmos Testnet (reason for the move to 7622): <https://chainlist.org/chain/9000>
- LaZer: Lyubashevsky, Seiler, Steuer, CCS 2024, <https://eprint.iacr.org/2024/1846>; code (MIT, AVX-512 required)
  <https://github.com/lazer-crypto/lazer>
- Lantern Sage implementation (TU Graz): <https://lattice-zk.isec.tugraz.at/>
- LaBRADOR: Beullens, Seiler, <https://eprint.iacr.org/2022/1341>
- Greyhound: Nguyen, Seiler, <https://eprint.iacr.org/2024/1293>
- LNS20 integer relations: <https://eprint.iacr.org/2020/1183>
- MatRiCT: <https://eprint.iacr.org/2019/1287>; MatRiCT+: <https://eprint.iacr.org/2021/545>
- mKEM / shared randomness: Katsumata, Kwiatkowski, Pintore, Prest, <https://eprint.iacr.org/2020/1107>
- IND-CPA^D: Li, Micciancio <https://eprint.iacr.org/2020/1533>; Cheon et al. <https://eprint.iacr.org/2024/127>
- HE security standard: <https://homomorphicencryption.org/standard/>; lattice-estimator
  <https://github.com/malb/lattice-estimator>
- FIPS 203/204/205: <https://csrc.nist.gov/pubs/fips/203/final>, <https://csrc.nist.gov/pubs/fips/204/final>,
  <https://csrc.nist.gov/pubs/fips/205/final>; FIPS 206 status:
  <https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/1HXzjlMUU6Y/m/KNSPqC02BgAJ>
- EVM: EIP-8051 <https://eips.ethereum.org/EIPS/eip-8051>, EIP-8355 <https://eips.ethereum.org/EIPS/eip-8355>,
  EIP-8051/8052 overview <https://pq.ethereum.org/blog/pq-precompiles-eip-8051-8052/>, Fireblocks ML-DSA 1.23 M gas
  <https://www.fireblocks.com/blog/post-quantum-signatures-ethereum-cheaper-gas>, EIP-7825
  <https://eips.ethereum.org/EIPS/eip-7825>, EIP-7623 <https://eips.ethereum.org/EIPS/eip-7623>, EIP-7934
  <https://eips.ethereum.org/EIPS/eip-7934>
- FHE libraries: tfhe-rs <https://docs.rs/crate/tfhe/>, tfhe-zk-pok <https://docs.rs/crate/tfhe-zk-pok/latest>,
  Zama fhEVM inputs <https://docs.zama.ai/protocol/solidity-guides/smart-contract/inputs>, fhe.rs
  <https://github.com/tlepoint/fhe.rs>, OpenFHE <https://github.com/openfheorg/openfhe-development>, openfhe-rs
  <https://github.com/fairmath/openfhe-rs>, Lattigo <https://github.com/tuneinsight/lattigo>
- Nethermind plugin precedent: <https://github.com/NethermindEth/nethermind-arbitrum>
- Repo: `2026-10-03-zether-design.md`, `2026-10-05-zether-limits.md`, `2026-10-05-zether-consensys-max.md`,
  `blockchain-research/02-account-registry.md` §2.6, `03-zether-crypto.md` §3.1.3/U7, parent `TRAPS.md` private-chain
  section, `/home/dockers/mba-chain-nethermind/README-chainspec.md`.
