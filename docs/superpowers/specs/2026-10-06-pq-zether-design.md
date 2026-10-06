# Post-quantum Zether on private/PoA chains (component spec E)

Status: draft rev 1, 2026-10-06. Component spec **E**. Short name **PQZ**. Code at `scaas` `main` 28c165c (classical
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
| O9 | Interaction with existing Zether (curves, `n_v = 64`, registry, `ITransferDisclosure`, BSGS/balance cache), relayer/meta-tx, scaas-node, clientkeys, zether-prover | §7.9, §11, R283–R285 |
| O10 | Per-family availability, private EVM first | §14 |

Sources read: [Zether design](2026-10-03-zether-design.md) (byte-exact classical spec), [limits](2026-10-05-zether-limits.md),
[ConsenSys MAX](2026-10-05-zether-consensys-max.md), `blockchain-research/03-zether-crypto.md` §3.1.3, U7,
`blockchain-research/02-account-registry.md` §2.6 (FALCON/PQ, HNDL), `docs/SCaaS.md` §6.8, §8, §9,
`smartcontracts/evm/src/zether/*`, [spec F](2026-10-06-universal-account-design.md) (UA, R290–R318), `zether-prover/src/*`, `clientkeys/src/zether.js`, `scaas-node` (`submit.rs`,
`gateway.rs`, `node.example.toml`), parent `TRAPS.md` "Private chain (Nethermind, chainId 9000)" and
`/home/dockers/mba-chain-nethermind/README-chainspec.md`, `smartcontracts/evm/src/chains/private9000/README.md`.
External sources in §18.

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
| Verification | Solidity + bn254/BLS precompiles | native precompile on chain 9000 (`0x…0F01`), same C core as the prover (R278, R279) |
| Authorization | 8 `AuthScheme`s (Schnorr, ECDSA multisig, FROST, MuSig2, BLS, PQ commitment, 1271); F replaces them by `authRef` | F `authRef` = `mldsa65` UA (default) or a PQ-dominant F `msig` (hybrid, t-of-n), verified via precompile `0x…0F10` (R281) |
| Decryption | BSGS discrete log, device cache, `zether-read-balance` | direct rounding, microseconds, exact; no BSGS, no cache needed (R285) |
| State | points in storage | ciphertext **hashes** in storage, bytes in calldata + events; public keys in SSTORE2 (R276) |
| Chains | dev allowlist 31337/1337 | allowlist 31337/1337/**9000** **and** a constructor self-test through the precompile (R270) |

**Cost.** Ciphertext 16,448 B, public key 16,384 B, transfer proof ≈ 30–50 KB (estimate; spike E-S1 measures).
A transfer is ≈ 77 KB of calldata and ≈ **3.0–3.2 M gas** — the same order as classical Zether's measured
3.29–3.36 M — because on Prague the EIP-7623 calldata floor, not the lattice arithmetic, dominates once
verification is native (§9.4). Consuming each received credit later costs ≈ 0.58 M gas more (its ciphertext enters
calldata once more, §7.6).

**What it protects.** Amounts and balances stay confidential against a future quantum adversary (no HNDL on
ciphertexts, §12.1), and validity (no money printing) rests on MSIS/MLWE instead of discrete log — a quantum
adversary against classical Zether does not only *read* balances, it can *forge* Σ/Bulletproof proofs and mint.
What stays classical is listed in §12.2 (Clique block signer, relayer lane keys, public ERC-20 legs).

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
| **LNP22 "Lantern"** ([ePrint 2022/284](https://eprint.iacr.org/2022/284), CRYPTO 2022) | short `s` with `As = t mod q`, exact ℓ2 norms, binary/quadratic relations, linear relations | ~14 KB reference statement (LaZer abstract); MLWE-secret proof ~29 KB in the TU Graz Sage implementation ([Lantern notebook](https://lattice-zk.isec.tugraz.at/)) | C: fractions of a second (Lether); Sage: ~35 s | **LaZer** C + Python, MIT ([GitHub](https://github.com/lazer-crypto/lazer), [ePrint 2024/1846](https://eprint.iacr.org/2024/1846), CCS 2024); **x86-64 + AVX-512 + AES-NI only** | **Chosen** (R278): our relations are linear with exact norms, witness ≈ 8 k short coefficients |
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
| LaZer | C + Python, MIT | LNP22, LaBRADOR, codegen (Sage + lattice-estimator) | **forked** into `pqz-core` with portable kernels (R278) |
| Lantern notebook (TU Graz) | Python/Sage | LNP22 reference | second oracle for transcript-level tests |
| [fhe.rs](https://github.com/tlepoint/fhe.rs) | Rust, MIT, unaudited | RNS-BFV | reference only — we need ~200 lines of K-PKE-style code, not a BFV stack |
| [OpenFHE](https://github.com/openfheorg/openfhe-development) / [openfhe-rs](https://github.com/fairmath/openfhe-rs) | C++ BSD-2 / Rust bindings (young) | BFV/BGV/CKKS/FHEW | none |
| [Lattigo](https://github.com/tuneinsight/lattigo) | Go, Apache-2.0 | BFV/BGV/CKKS, multiparty | none (Go) |
| tfhe-rs | Rust, BSD-3-Clause-Clear + patent licence | TFHE, fhEVM | none (different trust model, licence) |
| ML-DSA | `pqcrypto`/`fips204`-class Rust crates, liboqs (C) | FIPS 204 | precompile and clients; pick one audited/ACVP-tested implementation in E-S3 |
| [lattice-estimator](https://github.com/malb/lattice-estimator) | Sage | security estimates | parameter freeze (E-S0) |

### 2.6 Hardware fact that drives the build

LaZer requires AVX-512 and AES-NI and has no portable code path. The chain-9000 host is an **AMD Ryzen 5 7235HS (Zen
3+): AVX2 and AES-NI, no AVX-512** (`/proc/cpuinfo`, 2026-10-06), as are most phones and every WASM runtime. A verifier
that needs AVX-512 cannot run in the node. Hence the portable fork (R278) instead of linking LaZer.

### 2.7 Chain 9000 limits that bind the design

| Fact | Value | Consequence |
|---|---|---|
| Client | Nethermind 1.39.0, Clique, one signer, 5 s, base fee 0 (TRAPS; README-chainspec 2026-08-31) | gas is free in money, but still meters block capacity |
| Forks live | through Fusaka + BPO2, incl. EIP-2537, EIP-7951 (secp256r1 at `0x100`), **EIP-7825**, **EIP-7623**, **EIP-7934** | `smartcontracts/evm/src/chains/private9000/README.md` still says "pre-London" — stale (SCaaS §15 recorded contradiction) |
| [EIP-7825](https://eips.ethereum.org/EIPS/eip-7825) tx gas cap | 16,777,216 per transaction, independent of block limit | rules out a Solidity lattice verifier (§9.1) |
| Block gas limit | 16,777,216 (Clique signer can move it without reset) | ~5 transfers per block unless raised (R280) |
| [EIP-7623](https://eips.ethereum.org/EIPS/eip-7623) calldata floor | `10 × tokens`, token = zero byte 1 / non-zero byte 4 ⇒ 40 gas per non-zero byte | dominates PQZ cost once verification is native |
| [EIP-7934](https://eips.ethereum.org/EIPS/eip-7934) | RLP block ≤ 8,388,608 B | ≥ 100 transfers per block fit |
| Tx-pool size limit | 128 KiB is the common client default (geth/reth); Nethermind `TxPool.MaxTxSize` to be confirmed in E-S3 | transfers with inline credits exceed it (R280) |
| Missing transition keys | Nethermind silently ignores unknown keys; `eip1108Transition` was once missing and made `ecMul` 6.4× dearer with no symptom | every PQZ activation is **probed**, never trusted (R279) |

---

## 3. Rulings

- **R270** **Scope and gate.** PQZ is a separate token class (`PqzToken`, plus kind `0x0142` in spec F's
  `UARegistry`), never an upgrade of `ZetherToken`. `PqzSafety.requireAllowedChain()`: `chainid ∈ {31337, 1337, 9000}` — a hard-coded list, like
  RS2-1; adding a chain is a code change with review. **And** every constructor/`initialize` runs the precompile
  self-test (§10.4); a chain without the precompile (every public chain) fails it. `OpenFactory.pqzEnabled`
  defaults to `false`. NatSpec and docs: **UNAUDITED — NOT FOR PRODUCTION FUNDS**. — Owner O3; 9000 is the owner's
  named target and runs our client. — Classical Z3 (9000 for classical Zether) is unaffected.
- **R271** **Encryption = additive-only module-LWE with BFV-style encoding** ("MLWE-BFV-add", §4), implemented in
  `pqz-core`, not taken from an FHE library. CKKS and TFHE rejected (§2.2). — We use Enc/Add/Dec only; a BFV stack
  brings relinearization keys and failure probabilities we must not have. — The owner's "BFV/BGV (RLWE)" is met in
  substance: RLWE `n = 2048` and MLWE `d = 64, k = 32` have the same LWE dimension; the module form matches the LNP22
  proof ring.
- **R272** **Parameters** (§4.1): `d = 64`, `k = 32`, `q = 2^50 − 1791`, `Δ = 2^28 − 1`, secrets and encryption
  randomness CBD(1), errors CBD(20), norm thresholds 36 / 164 / 64, plaintext = 8 digits base 256, credit cap
  `K_MAX = 4096`. Noise bounds are worst-case over proven norms, so an accepted state never fails to decrypt. —
  §4.3 derivation. — E-S0/E-S2 may change them **only** with a new `proofSystemId` and a recomputed §4.3.
- **R273** **Multi-recipient shared randomness.** One `(r, e1)` per operation: the transfer's `u` is shared by the
  receiver's credit, the sender's new balance and the auditor copy; only `v` differs per recipient. — Saves two
  16 KB `u` per transfer (mKEM, §2.3). — Revealing `r` would reveal the sender's new balance, so disclosure never
  reveals `r` (R283). The **auditor** is as classical RS2-8: one immutable registered PQZ UA per
  token, set at `initialize` (or none); it reads exactly the per-transfer `v_a`, never anyone's balance.
- **R274** **Every debit re-encrypts the remaining balance fresh.** The sender proves that the total ciphertext `T`
  decrypts to `M` with `Σ M_i·256^i = b' + v + fee` (digit-carry relation, §7.4) and publishes a fresh encryption
  of `b'`. No homomorphic subtraction on `acc`. — Resets noise and digit growth at every spend; the classical
  `C_deb` disappears. — The proof carries a decryption relation, which classical E5 also had in another form.
- **R275** **Credit cap.** Each account's live ciphertext count (`accUnits + unrolled pending`) is ≤ `K_MAX = 4096`;
  a credit beyond it reverts `RefreshRequired(ua)`. `REFRESH` = a burn of amount 0 (no underlying moves) and resets
  `accUnits` to 1. — Keeps §4.3 worst-case bounds. — A sender can fill a victim's cap with dust; on a permissioned
  PoA chain that costs the attacker ≈ 5× what the refresh costs the victim (§12.1 T7).
- **R276** **Ciphertexts live in calldata and events, hashes in storage.** `acc` and each pending credit are stored
  as `keccak256(ct)`; operations that need them take the bytes in calldata and the contract checks the hash. Public
  keys (PQZ and ML-DSA) are written once with SSTORE2 and read with `EXTCODECOPY`. — Storage of a 16 KB ciphertext
  costs 2.6–8.8 M gas per write; calldata 0.58 M; SSTORE2 reads ≈ 10 k. — Indexers rebuild state from events (§7.8).
- **R277** **Public rollover, race-free debits.** Anyone may roll pending credits into `acc`. A debit proves over
  `T = acc + Σ pending[rolled..p)` and the contract rebuilds that **same** `T` whether a rollover happened in
  between (`acc' − Σ pending[p..rolled')`) or not, because addition mod `q` is exact and associative. No
  `OWNER_ONLY` mode, no `accSeq`. At most `INLINE_MAX = 16` ciphertexts inline. — Removes the classical rollover
  grief (RS2-17/19) instead of mitigating it. — A griefer who rolls > 16 new credits past `p` forces a re-prove; it
  needs > 16 credits of its own to do so.
- **R278** **Proof engine = LNP22 through `pqz-core`, a portable fork of LaZer** (portable C99 kernels + optional
  AVX2; AVX-512 kept as a CI backend). One implementation serves the prover, the client-side verifier mirror and the
  precompile. No Solidity verifier. LaBRADOR/Greyhound deferred to aggregation work. **Kill criterion** (E-S1): if
  the transfer proof exceeds 96 KB or portable verify exceeds 50 ms on the chain host, stop and re-plan with the
  hash-based fallback. — Single implementation; LaZer is MIT and protocol logic stays upstream-shaped. — We own a C
  fork; upstream fixes are merged by hand. **Versioning:** `proofSystemId =
  keccak256("scaas/pqz/lnp22/mlwe-d64k32-q50/v1")`; every parameter, relation or serialization change bumps it; the
  token stores it at `initialize` and the precompile accepts only ids it implements.
- **R279** **On-chain verification is a native precompile on chain 9000**: `PQZ` at
  `0x0000000000000000000000000000000000000F01` (first input byte = op) and `MLDSA65` at `…0F10` (EIP-8355 layout plus a
  context string, §9.3). Off-chain co-processor attestation is rejected on chain 9000 and kept as a seam for EVM chains whose client
  we do not control (§14). **Determinism and probing:** integer-only code, no threads, no floating point, no CPU-feature-dependent
  results, bounded loops (a capped rejection loop that hits its cap ⇒ invalid); any parse error, panic or failed
  check ⇒ output `0x00…00`; gas by formula regardless of validity; activation by `pqzTransitionTimestamp`; contracts
  self-test (§10.4) and the node probes (`has_pqz_precompile`), because a missing transition key looks exactly like
  an enabled one (TRAPS). — §9.1 comparison. — Every node of chain 9000 must run the PQZ client build.
- **R280** **Gas.** Precompile prices are deterministic functions of the op and input length, calibrated against
  `ecMul` on the chain host (§9.4), frozen in the chainspec. EIP-7623 and EIP-7825 stay enabled. Operator change:
  Clique `TargetBlockGasLimit` 100,000,000 on chain 9000 (no data reset). Node and client limits on chain 9000: Nethermind `TxPool.MaxTxSize` ≥ 1 MiB (or the key E-S3 finds),
  scaas-node `max_gas_per_tx = 16_000_000`, gateway body limit 1 MiB on the PQZ route only (64 KiB elsewhere) —
  recommendations to node operators (OPS R247). — Keeps gas an honest capacity meter. — ~30 transfers per 5 s block.
- **R281** **PQZ authorization is always a separate PQ signing UA** (spec F R305 `authRef`, tightened). A
  `pqz-mlwe` record's `authRef` must be a registered `mldsa65` / `mldsa44` UA (`fndsa512` once F enables it,
  FIPS 206), or an F `msig` whose non-PQ members' total weight is **below** its threshold — so no classical-only
  subset can authorize. That `msig` rule is the hybrid (e.g. `mldsa65` w 1 + `p256` w 1, threshold 2) and the t-of-n
  ML-DSA form. Refused: `authRef = 0` (self), native ids (EOA/ERC-1271), any classical-only kind
  (`UAAuthRef`). — Owner O8; one key = one purpose: the PQZ key decrypts and proves, the ML-DSA key authorizes; F R313
  invites exactly this hybrid. — A leaked PQZ key is a read-only breach (`survivesEncKeyLeak`).
- **R282** **PQZ UA kind = spec F kind `0x0142` `pqz-mlwe`** (tag `scaas.ua.pqz-mlwe.v1`, `d = pk` 16,384 B, new
  keyHash group `pqz-mlwe`), a Zether-family kind under F R305 (binds only the encryption key, immutable
  `authRef`); `UA = keccak256(keccak256(tag) ‖ pk)` (F R290, R292); PoP binds chain, registry and UA, not the caller
  (F R295); key seed by F §8.1's PQ rule `HKDF-SHA256(BIP-39 seed, "scaas.ua.pq.v1", tag ‖ u32 account ‖ u32 i)`.
  Signing kinds are F's `mldsa65`/`mldsa44`/`fndsa512`; this spec adds no signing kind. — F owns identity; E adds
  one row and its verifier. — F's kind table, keyHash group list and vectors gain one row each (applied by F's
  stream, as a gen-1 kind since F is not built).
- **R283** **Disclosure by zero-knowledge proof**, never by revealing randomness or noise. `ITransferDisclosure` is
  kept (same three `OpeningKind`s; `opening = bundle ‖ proof`). `transferCiphertext(entryRef)` reverts
  `CiphertextOffState(bundleHash)`; new view `transferCiphertextHash(entryRef)`. — R273 and §2.2 (noise must not
  leak). — Indexer or the parties supply the bundle bytes.
- **R284** **No meta-tx envelope.** PQZ ops are open calls: anyone (a relayer lane, the user) submits; authority is
  the ML-DSA signature over the statement plus the proof; `beneficiary`, `fee` and `validUntilBlock` are in the
  statement. Inner confidential fee only; no outer fee, no EIP-712. Not carried on the mesh (as classical, MESH R70).
  — Removes the only classical signature from the PQZ op path; front-running a submission has the same effect as the
  submission. — Relayers on chain 9000 pay gas that costs nothing.
- **R285** **Direct decryption.** `Dec` is rounding of 8 coefficients (§4.2); no BSGS, no discrete log, no
  `zether-read-balance`. A balance cache is a UX convenience only (offline display). — The single largest UX
  simplification over classical Zether.
- **R286** **Limits.** `MAX_TOTAL_SHIELDED = 2^62`; transfer and burn amounts `< 2^64` (8 digits); `confidentialFee <
  2^64`; `shieldScale` as RS2-3. — No BSGS bound any more; 2^62 keeps `b' + v + fee < 2^64` for honest states and
  values in signed 64-bit for clients. — The classical 2^54 rationale (D3, BSGS) does not carry over.
- **R287** **Prover platforms v1**: native x86-64 (portable/AVX2) and aarch64 — desktops, servers and the
  organization key oracle of SCaaS §9.1. WASM (`wasm32-wasip1` of `pqz-core`) and mobile are stream E-S8. — B2B
  treasury on private chains is the target user; phones are not. — Retail PQ is out of v1.
- **R288** **Encryption randomness is derived**, so the sender can re-create it for disclosure:
  `seed_enc = HKDF-SHA256(ikm = pqzKeySeed, salt = "SCAAS-PQZ-ENC-V1", info = be32(chainId) ‖ token(20) ‖ fromUA ‖
  be8(sendCounter) ‖ toUA ‖ be8(v) ‖ be8(b') ‖ u8(auditorOn))`. Message-bound, so a re-proof with another amount at
  the same counter uses other randomness. Masking randomness *inside* the proof is hedged (`H(secret ‖ statement ‖
  32 B CSPRNG)`). — Classical §8.9 used counter-only derivation; reusing `r` across two messages here would leak
  `Δ·(m − m')` up to small noise.
- **R289** **Migration classical → PQZ** is `ZetherToken.burn` to the owner's address then `PqzToken.fund`; the
  amount is public on chain 9000 once. No cross-system equality proof in v1. — Classical Zether holds no production
  funds (dev-only gate), so only pilots migrate. — §13.
---

## 4. Encryption scheme MLWE-BFV-add

### 4.1 Parameters (R272)

| Name | Value | Note |
|---|---|---|
| Ring | `R_q = Z_q[X]/(X^64 + 1)`, module rank `k = 32` | LWE dimension `n = 2048` |
| `q` | `2^50 − 1791 = 1,125,899,906,840,833` (`0x3FFFFFFFFF901`), prime, `q ≡ 1 mod 128` | full negacyclic NTT for `d = 64` |
| `Δ` | `2^28 − 1 = 268,435,455 = ⌊q / 2^22⌋` | |
| Secret `s`, randomness `r` | CBD(η = 1) per coefficient (values −1, 0, 1 with probability ¼, ½, ¼) | ternary, as the HE standard assumes |
| Errors `e`, `e1`, `e2` | CBD(η = 20) (σ = √10 ≈ 3.16) | HE-standard error width |
| Norm thresholds | `‖s‖, ‖r‖ ≤ β_s = 36`; `‖e‖, ‖e1‖ ≤ β_e = 164`; `‖e2_j‖ ≤ β_2 = 64` (8 coefficients) | key generation and encryption resample above them; proofs show them exactly |
| Plaintext | `L = 8` digits base 256 in coefficients 0..7 of `v` | 64-bit values |
| `K_MAX` | 4096 ciphertexts per account between refreshes | §4.3 |
| Matrix `A` | global, `A[i][j] ∈ R_q`, from `SHAKE128("SCAAS-PQZ-A-V1" ‖ u8(i) ‖ u8(j))`: read 8-byte BE words, keep the low 50 bits, accept if `< q`, coefficient 0 first | nothing-up-my-sleeve; implementations cache `NTT(A)` (512 KB) at start |

Security: LWE dimension 2048, `log2 q ≈ 50`, ternary secret, σ ≈ 3.2. The
[HE standard](https://homomorphicencryption.org/standard/) tables put `n = 2048` at `log q ≤ 54` for 128-bit classical
and ≈ 51 for 128-bit quantum security with these distributions. E-S0 re-runs the
[lattice-estimator](https://github.com/malb/lattice-estimator) (the tables predate current attacks) for both the
encryption MLWE and the proof system's MSIS/MLWE instances and records the output in `pqz-core/params/estimator.txt`;
target ≥ 128-bit quantum (NIST category 1) for every instance.

### 4.2 Algorithms

```
CBD_η(stream):           per coefficient: a = Σ_{i<η} bit, b = Σ_{i<η} bit;  coeff = a − b    (bits LSB-first, FIPS 203 style)
KeyGen(seed32):          for ctr = 0,1,…: st = SHAKE256("SCAAS-PQZ-KEYGEN-V1" ‖ seed32 ‖ be4(ctr))
                           s ← CBD_1^{2048}(st), e ← CBD_20^{2048}(st)  (same stream, s first)
                           if ‖s‖ ≤ 36 and ‖e‖ ≤ 164: break         (ctr ≥ 64 ⇒ error; thresholds sit ≥ 10 s.d. above the mean norm)
                         pk = A·s + e ∈ R_q^32;  sk = seed32
Enc({(pk_j, m_j)}, seed_enc):
                         for ctr: st = SHAKE256("SCAAS-PQZ-ENC-V1" ‖ seed_enc ‖ be4(ctr))
                           r ← CBD_1^{2048}, e1 ← CBD_20^{2048}, e2_j ← CBD_20^8 for each j in recipient order
                           accept if ‖r‖ ≤ 36, ‖e1‖ ≤ 164, every ‖e2_j‖ ≤ 64
                         u = A^T·r + e1
                         v_j[i] = (pk_j^T·r)[i] + e2_j[i] + Δ·m_j[i]  mod q,   i < 8
                         output u and (v_j)_j
Add(ct, ct'):            coefficient-wise mod q on u (2048) and v (8)
Sub(ct, ct'):            coefficient-wise mod q
Trivial(m):              u = 0, v[i] = Δ·m[i]                      (public amounts: fund, fee, burn)
Dec(s, (u, v)):          w_i = centre(v[i] − (u^T·s)[i] mod q)  ∈ (−q/2, q/2]
                         M_i = round(w_i / Δ),  noise_i = w_i − Δ·M_i
                         value = Σ_{i<8} M_i · 256^i    (as an integer; M_i may exceed 255 before a refresh)
digits(x):               m[i] = (x >> 8i) & 0xFF, i < 8;  x < 2^64
```

`(u^T·s)[i]` for `i < 8` is 8 dot products of length 2048 with negacyclic signs — microseconds. `Dec` is used by
the owner only and its `noise_i` never leaves the device (R283).

### 4.3 Noise and digit budget (worst case)

For a ciphertext encrypted to `pk_t = A·s_t + e_t`, decryption by `s_t` gives
`v − u^T s_t = e_t^T r + e2 − e1^T s_t + Δ·m`. With norms bounded as proven (registration proves `‖s_t‖ ≤ 36`,
`‖e_t‖ ≤ 164`; every encryption proves `‖r‖ ≤ 36`, `‖e1‖ ≤ 164`, `‖e2‖ ≤ 64`), Cauchy–Schwarz per coefficient gives

```
B_FRESH = β_e·β_s + β_s·β_e + β_2 = 164·36 + 36·164 + 64 = 11,872      (< 2^13.54)
```

Trivial ciphertexts have noise 0. A sum of at most `K_MAX = 4096` accepted ciphertexts has
`|noise| ≤ 4096 · 11,872 = 48,627,712 < 2^26 = 67,108,864`, and digit sums `M_i ≤ 4096 · 255 = 1,044,480 < 2^20`.
The debit proof shows `|e_T[i]| < 2^26` and `0 ≤ M_i < 2^20` (complete for every honest state).

**Uniqueness (soundness of the decryption relation).** Suppose `Δ·M + e ≡ Δ·M' + e' (mod q)` with both pairs in the
proven ranges. Then `|Δ(M − M')| ≤ Δ·(2^20 − 1) < q/4` and `|e − e'| < 2^27 < Δ/2`, so the congruence is an integer
equation, `|Δ(M − M')| < Δ`, hence `M = M'`. The key is unique too: two short preimages `(s, e) ≠ (s', e')` of the
same `pk` give a non-zero kernel vector of `[A | I]` of norm ≤ `2·√(36² + 164²) ≈ 336`, while the Gaussian-heuristic
shortest vector of that 4096-dimensional lattice of determinant `q^2048` is ≈ `15.5 · q^{1/2} ≈ 2^29`; finding one
is MSIS. The same argument makes `(r, e1)` unique for a given `u` (sender disclosure). So a proven decryption is
**the** decryption, and an accepted state never decrypts wrongly or fails (R272).

If E-S2 finds that a norm proof has extraction slack `γ > 1` for some bound, every `β` above is multiplied by `γ`
in this derivation, `K_MAX` is recomputed, and the change is a new `proofSystemId`.

### 4.4 Sizes

| Object | Bytes | Encoding |
|---|---|---|
| PQZ secret | 32 (seed) | never leaves the device / key oracle |
| PQZ public key `pk` | **16,384** | 32 polys × 64 coeffs × `be8`, coefficient 0 first, poly 0 first; each `< q` |
| Ciphertext `ct = u ‖ v` | **16,448** | `u` as `pk`; `v` = 8 × `be8` |
| Transfer outputs `u ‖ v_t ‖ v_f ‖ v_a` | 16,576 | `v_a` absent (0 bytes) when the auditor is off |
| Transfer proof | ≈ 30–50 KB (**estimate**; E-S1 measures; kill at 96 KB) | `pqz-core` serialization v1 |
| Burn / refresh proof | ≈ same as transfer minus one recipient | |
| Registration PoP proof | ≈ 15–25 KB (estimate) | |
| Disclosure proof | ≈ 15–25 KB (estimate) | |
| ML-DSA-65 pk / sig | 1,952 / 3,309 | FIPS 204 |

`be8` coefficients waste 14 bits each (≈ 28 %) against tight 50-bit packing; accepted: the Solidity `Add` works
on aligned 64-bit lanes, and byte 0 of each word is zero (cheap calldata token). Boring wins.

---

## 5. Encodings shared by contract, precompile and clients

- Integers in statements: `be32` (`uint256` ABI words) unless stated; coefficients `be8`, canonical (`< q`); any
  other value ⇒ reject (`NonCanonical`).
- `ctHash(ct) = keccak256(ct)` over the 16,448 bytes.
- Polynomial vectors are never compressed. Lengths are fixed by the op; no length fields inside the cryptographic
  objects.
- Transcript (inside `pqz-core`): SHAKE256, initialized with `"SCAAS-PQZ-TRANSCRIPT-V1"`, then
  `absorb("statement", be32(len) ‖ statement)` **before** any prover message (strong Fiat–Shamir, as classical §4);
  every later message is absorbed with a 1-byte label length, label, `be32` length, bytes. Challenges are derived,
  never sent.

---

## 6. Keys, Universal Account kinds and derivation

### 6.1 Kind (R282, spec F)

PQZ adds **one** row to F's kind table (§4.2 there) and no signing kind:

| No. | Name (tag `scaas.ua.<name>.v1`) | `d` | keyHash group | PoP | Verifier (EVM) | Families |
|---|---|---|---|---|---|---|
| `0x0142` | `pqz-mlwe` | `pk` (16,384) | `pqz-mlwe` (new group) | `R_REG` proof over `uaMessage(0x0142, POP_TAG, popDigest(ua))` | `UAPqzVerifier` → precompile `0x…0F01` op 3 | chain 9000 (R270) |

`UA = keccak256(keccak256("scaas.ua.pqz-mlwe.v1") ‖ pk)` (F R290, R292); `UA >> 160 ≠ 0` (F R291). The record is
F's `Record{kind, registeredAt, keyPtr}` with `keyPtr = SSTORE2(pk)` (F §6.2 step 7, PQ kinds) plus the immutable
`authRef`. `pqz-mlwe` is a Zether-family kind in F's sense (R305: binds only the encryption key).

Authorization UAs are F kinds (R281): `mldsa65` `0x0131` (default), `mldsa44` `0x0130`, `fndsa512` `0x0132` once F
enables it, or a PQ-dominant `msig` `0x0120`, e.g. hybrid `{mldsa65 w1, p256 w1}` threshold 2, or treasury
`{mldsa65 ×3, w1 each}` threshold 2. F's `msig` rules apply (members registered, sorted, one level, `count ≤ 16`);
R281 adds: Σ weight of members whose kind is not `mldsa*`/`fndsa512` `<` threshold.

### 6.2 Derivation (F §8.1)

```
PQZ key:     seed32 = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1",
                                  info = "scaas.ua.pqz-mlwe.v1" ‖ u32(account) ‖ u32(i));   pk = KeyGen(seed32) (§4.2)
ML-DSA auth: ξ = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1",
                             info = "scaas.ua.mldsa65.v1" ‖ u32(account) ‖ u32(i));         FIPS 204 KeyGen_internal(ξ)
hybrid member (p256 / bip340): F's UA tree m/7225'/0'/<account>'/<kindNo>'/<i>'
```

Distinct tags in `info` give distinct keys per kind (one key = one purpose, F R298 layer 1); no PQ seed equals a
BIP-32/SLIP-10/EIP-2333 scalar of the same seed, and the classical Zether trees `…/7`, `…/8` are untouched. Vault:
as classical (`sealConfKey` pattern) — the BIP-39 seed or the 32-byte leaves in the AES-256-GCM vault; organizations
put the PQZ leaf in the key oracle (SCaaS §9.1 `conf_custody`) and the ML-DSA key in an HSM with FIPS 204 firmware
where available (`auth_custody`).

---

## 7. Protocol

### 7.1 State (per `(UA, token)`)

| Slot | Type | Changed by | Role |
|---|---|---|---|
| `accHash` | bytes32 | debit, rollover | `keccak256(acc)`; `acc` of a new account = `Trivial(0)` |
| `accUnits` | uint16 | debit (→ 1 + over-rolled), rollover (+n) | ciphertexts summed into `acc` (§4.3) |
| `pendingCount` | uint64 | every credit (+1) | |
| `rolled` | uint64 | rollover, debit | pending indexes `< rolled` are inside `acc` |
| `floor` | uint64 | debit (→ `p`) | pending indexes `< floor` were consumed by the last debit; a debit needs `floor ≤ p` |
| `pendingHash[i]` | bytes32 | credit `i` | `ctHash` of credit `i` |
| `sendCounter` | uint64 | debit (+1) | in the statement; replay protection; R288 |
| `entry[entryRef]` | bytes32 | transfer | `bundleHash` for disclosure |

Credit cap: a credit reverts `RefreshRequired(ua)` when `accUnits + (pendingCount − rolled) + 1 > K_MAX`.
Token globals: `underlying`, `shieldScale`, `maxShielded ≤ 2^62`, `totalShielded`, `confidentialFee`, `auditorUA`
(or 0), `registry`, `proofSystemId`.

### 7.2 Register (F's `UARegistry`)

`register(0x0142, pk, pop, authRef)` follows F §6.2 step by step; PQZ-specific content of each step:

1. Kind enabled only where the registry generation was deployed with `UAPqzVerifier` (F R293, R313).
2. Key data: exactly 16,384 bytes, every coefficient `< q` (`UAKeyData`).
3. Id: `uaOf(0x0142, pk)`, not in the native space, not registered.
4. `keyHash = keccak256("pqz-mlwe" ‖ pk)` free (`UAKeyInUse`).
5. `authRef` per R281 (`UAAuthRef`); the auth UA registered first with its own PoP.
6. PoP: `UAPqzVerifier.verify(pk, message, pop)` = `PQZ(OP_REGISTER, message ‖ pk ‖ pop) == 1` with `message =
   uaMessage(0x0142, POP_TAG, popDigest(ua))` — relation `R_REG`: `pk = A s + e`, `‖s‖ ≤ 36`, `‖e‖ ≤ 164`, the
   message absorbed into the statement. It binds chain, registry and UA, not the caller (F R295): anyone may submit.
7. Store, `keyPtr = SSTORE2(pk)`, emit `UARegistered(ua, 0x0142, pk, authRef)` (16 KB of log data, ≈ 0.13 M gas).

No rotation (F R302): a new key is a new UA plus a confidential transfer to it.

### 7.3 Fund

`fund(bytes32 ua, uint256 amount)`: `0 < amount`, `totalShielded + amount ≤ maxShielded`, cap check;
`ct = Trivial(digits(amount))`; `pendingHash[pendingCount++] = ctHash(ct)`; `transferFrom(msg.sender, this,
amount·shieldScale)` (spender is the token contract, R26); `totalShielded += amount`; emit
`PqzTrivialCredit(ua, index, amount)` (log data costs 8 gas per byte even for zeros, so the 16 KB `ct` is not
logged; clients rebuild `Trivial`). No proof.

### 7.4 Transfer

Caller: anyone (R284). Inputs: `payload = be32(p) ‖ be32(validUntilBlock) ‖ fromUA ‖ toUA ‖ beneficiaryUA ‖ out`
(`out = u ‖ v_t ‖ v_f ‖ v_a`), `acc` (current, 16,448 B), `inline` (ciphertexts between `p` and `rolled`), `proof`,
`authSig`.

Contract checks, cheap first: `block.number ≤ validUntilBlock`; both UAs registered, `from ≠ to`; beneficiary
registered or 0; `keccak256(acc) == accHash[from]`; `floor ≤ p ≤ pendingCount`, `|p − rolled| ≤ INLINE_MAX`,
each inline ciphertext matches `pendingHash`; receiver and beneficiary cap checks; all coefficients
canonical. Then

```
T = acc + Σ inline           if p ≥ rolled   (inline = pending[rolled..p))
T = acc − Σ inline           if p < rolled   (inline = pending[p..rolled))
```

builds the statement (§7.7), verifies `authSig` (§7.10), calls `PQZ(OP_TRANSFER, statement ‖ proof)`, then:

```
acc[from]    = (u, v_f);  accHash[from] = ctHash(u ‖ v_f)
               if p < rolled:  acc[from] += Σ inline  (those credits stay inside acc);  accUnits = 1 + (rolled − p)
               else:           rolled[from] = p;  accUnits = 1
               floor[from] = p
pending[to]  ← (u, v_t)                                       (pendingHash, pendingCount++)
pending[ben] ← Trivial(digits(fee))      if fee > 0   (event PqzTrivialCredit, not the 16 KB bytes)
entry[entryRef] = keccak256(u ‖ v_t ‖ v_a ‖ toUA)
sendCounter[from]++
emit PqzTransfer(entryRef, fromUA, toUA, out);  emit PqzCredit(…) for each credit
```

`fee = confidentialFee` if `beneficiary ≠ 0`, else 0 (never a function of `v`). `entryRef =
keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), chainid, token, fromUA, sendCounter))` (counter before
increment).

**Relation `R_TX`** (witness `s_f, e_f, r, e1, e2_t, e2_f, e2_a, d, d', M, c, e_T`; all mod `q` unless marked):

| # | Relation | Shows |
|---|---|---|
| 1 | `pk_f = A·s_f + e_f` | the sender holds **the** key of `fromUA` (unique, §4.3) |
| 2 | `u = A^T·r + e1` | well-formed shared encryption |
| 3 | `v_t[i] = (pk_t^T r)[i] + e2_t[i] + Δ·d_i`, `i < 8` | receiver credit encrypts `v = Σ d_i 256^i` |
| 4 | `v_f[i] = (pk_f^T r)[i] + e2_f[i] + Δ·d'_i` | new balance encrypts `b' = Σ d'_i 256^i` |
| 5 | `v_a[i] = (pk_a^T r)[i] + e2_a[i] + Δ·d_i` (auditor on) | auditor copy encrypts the same `v` |
| 6 | `v_T[i] − (u_T^T s_f)[i] = Δ·M_i + e_T[i]` | `T` decrypts to digits `M` |
| 7 | over Z: `M_i + c_{i−1} = d'_i + d_i + f_i + 256·c_i`, `c_{−1} = c_7 = 0`, `f = digits(fee)` | `Σ M_i 256^i = b' + v + fee` exactly |
| norms | `‖s_f‖, ‖r‖ ≤ 36`; `‖e_f‖, ‖e1‖ ≤ 164`; `‖e2_*‖ ≤ 64`; `d_i, d'_i ∈ [0, 256)`; `M_i ∈ [0, 2^20)`; `c_i + 64 ∈ [0, 2^13)`; `e_T[i] + 2^26 ∈ [0, 2^27)` | exact, via binary decomposition (595 bits) and ℓ2 proofs |

Row 7 telescopes: `Σ 256^i M_i = Σ 256^i (d'_i + d_i + f_i) + 2^64·c_7 − c_{−1}`, so with `c_7 = c_{−1} = 0` the
balance identity holds over the integers; every term is `< 2^22`, far below the proof modulus, so the modular
proof implies the integer statement. `b' ≥ 0` is a digit property, so `v + fee ≤ balance` — no overspend, no
aliasing (the classical RS-NV64-1 argument becomes a digit argument).

### 7.5 Burn and refresh

`burn(payload, acc, inline, amount, recipient, proof, authSig)` with `payload = be32(p) ‖ be32(validUntilBlock) ‖
fromUA ‖ beneficiaryUA ‖ u' ‖ v_f`. `0 < amount ≤ maxShielded` (burn) or `amount = 0` and `recipient = 0`
(`refresh`, op tag `REFRESH`). Relation `R_BURN` = `R_TX` rows 1, 2, 4, 6, 7 with `d = digits(amount)` **public**
(no `d` witness, no rows 3/5). Effects: `acc[from]` as in §7.4; fee credit; `totalShielded −= amount`; underlying
`amount·shieldScale` to `recipient`; `sendCounter++`.

### 7.6 Rollover

`rollOver(bytes32 ua, bytes acc, bytes[] cts)`: anyone; `1 ≤ cts.length ≤ ROLL_MAX = 16`; `keccak256(acc) ==
accHash`; `cts[j]` matches `pendingHash[rolled + j]`; `acc' = acc + Σ cts` in Solidity (64-bit lanes, one
`mod q` per lane at the end — 16 additions of values `< 2^50` cannot overflow a lane); `accHash = ctHash(acc')`;
`rolled += n`; `accUnits += n`; emit `PqzRolled(ua, rolled, accHash)` (clients recompute `acc'`). No proof, no signature: rollover cannot hurt
anyone (R277). Calldata is the cost: ≈ 0.58 M gas per ciphertext (§9.4); a relayer batches it off-peak.

### 7.7 Statement layout

Header (512 bytes):

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
| 480 | reserved, 0 |

Body: `pk_f ‖ [pk_t] ‖ [pk_a] ‖ T ‖ out` — transfer ≈ 115 KB, burn ≈ 49 KB. The contract builds it from storage,
SSTORE2 reads and calldata; the prover builds it identically (vector `statement_*.json`, §15).

`authDigest = keccak256("SCAAS-PQZ-AUTH-V1" ‖ keccak256(statement))`. The ML-DSA signature is over these 32 bytes
(pure ML-DSA, empty context, EIP-8355 convention).

### 7.8 Events and indexing

`PqzCredit(bytes32 indexed ua, uint64 indexed index, bytes ct)`, `PqzTrivialCredit(bytes32 indexed ua, uint64 indexed
index, uint256 amount)`, `PqzTransfer(bytes32 indexed entryRef, bytes32
indexed fromUA, bytes32 indexed toUA, bytes out)`, `PqzRolled(bytes32 indexed ua, uint64 rolled, bytes32 accHash)`,
`PqzBurned(bytes32 indexed ua, uint256 amount, address recipient, bytes newAcc)`, `PqzRegistered(…)`. A client
rebuilds `acc` and the pending list of its UA from these logs alone and checks each against the stored hashes before
proving. Logs cost 8 gas/byte (≈ 133 k per transfer) — the price of not trusting an indexer for state.

### 7.9 Disclosure (`ITransferDisclosure`, R283)

`verifyTransferAmount(entryRef, amount, kind, opening)` with `opening = abi.encode(bytes bundle, bytes proof)`,
`bundle = u ‖ v_t ‖ v_a ‖ toUA`, `keccak256(bundle) == entry[entryRef]`, `amount < 2^64`; statement
`keccak256("SCAAS-PQZ-DISCLOSE-V1") ‖ chainId ‖ token ‖ entryRef ‖ be32(amount) ‖ u8(kind) ‖ pk ‖ u ‖ v`:

| Kind | Prover | Relation |
|---|---|---|
| `SENDER_S` | sender, re-deriving `r, e1, e2_t` (R288) | `u = A^T r + e1`, `v_t[i] = (pk_t^T r)[i] + e2_t[i] + Δ·digits(amount)_i`, norms as §4.1 |
| `RECEIVER_X` | receiver | `pk_t = A s + e`, `v_t[i] − (u^T s)[i] = Δ·digits(amount)_i + e'_i`, `abs(e'_i) < 2^26` |
| `AUDITOR` | auditor | as `RECEIVER_X` with `pk_a`, `v_a` |

Uniqueness by §4.3. `verifyTransferAmount` is a view (the precompile runs in `eth_call`); `attestTransferAmount`
emits `AmountAttested` as classical. `transferCiphertextHash(entryRef)` returns the bundle hash; the bundle bytes
come from `PqzTransfer` logs. Nothing reveals `r` (which would open `v_f`, the sender's balance) or decryption noise.

### 7.10 Authorization check

`registry.requireZetherAuthorized(fromUA, authDigest, authSig, zkCovered = true)`. Because R281 forbids `authRef =
0`, this always runs F's `requireAuthorized(authRef, PURPOSE_ZETHER_AUTH, authDigest, authSig)`: `authSig =
abi.encode(bytes keyData, bytes sig)` with empty `keyData` for stored PQ kinds (F R306), `msig` member signatures in
F's format. ML-DSA signs `ua_msg = keccak256(TAG(mldsa65) ‖ keccak256("scaas.ua.purpose.zether-auth.v1") ‖
authDigest)` with `ctx = kind_tag` (F §4.2). F's `zether-auth` purpose covers the PQZ digest, which carries its own
domain string. Both the proof (knowledge of the PQZ key) **and** the signature (the auth UA) are required (classical
invariant #1).

---

## 8. Proof engine `pqz-core`

- **Origin.** Fork of LaZer at a pinned commit (E-S1 records it), MIT, repo path `scaas/pqz-core/`. Kept: LNP22
  protocol logic, codegen (`scripts/lin-codegen.sage` with lattice-estimator), parameter headers. Replaced: AVX-512
  kernels by portable C99 (NTT, poly arithmetic, sampling) with an optional AVX2 backend; AES-NI PRNG by a
  bit-exact constant-time software AES (bitsliced; the T-table form is forbidden for secret-keyed streams) or by
  SHAKE where the fork changes the stream (then all KATs are fork-generated). The upstream AVX-512 backend stays as a
  CI-only cross-check.
- **Relations.** `R_TX`, `R_BURN` (also REFRESH), `R_REG`, `R_DS`, `R_DR` written as LaZer specifications
  (`pqz-core/params/*.py`) → generated `*params.h` checked in, regenerated only on purpose (codegen takes minutes).
- **Proof modulus.** The relation is fixed mod `q` (§7.4). If LNP22's challenge-invertibility conditions forbid
  using the fully-splitting `q` as the proof modulus, the proof runs over `q_p = q·q₁` and every mod-`q` row is
  lifted (`… = q·k` with a bounded witness `k`) — E-S2 decides with sizes measured; either way the relation text
  here is unchanged.
- **API (C ABI, stable):**
  ```c
  int pqz_prove(uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *wit, size_t wit_len,
                const uint8_t rnd32[32], uint8_t *proof, size_t *proof_len);   /* 0 = ok */
  int pqz_verify(uint8_t op, const uint8_t *stmt, size_t stmt_len, const uint8_t *proof, size_t proof_len);
                                                                               /* 1 = valid, 0 = anything else */
  int pqz_keygen(const uint8_t seed32[32], uint8_t pk[16384]);
  int pqz_enc(...); int pqz_dec(const uint8_t seed32[32], const uint8_t ct[16448], uint64_t M[8], int64_t noise[8]);
  ```
  `pqz_verify` never allocates more than a compile-time bound, never reads outside its inputs, and returns 0 on any
  malformed input (R279).
- **Proof serialization v1** = the engine's own (polynomials as packed integers of the generated widths), versioned
  by `proofSystemId`. The contract never parses a proof; only its length is bounded (`MAX_PROOF = 98,304`).
- **Fiat–Shamir.** Transcript §5. Soundness of multi-round Fiat–Shamir with aborts in the quantum random-oracle model
  is less settled than for 3-move Σ-protocols; this is an explicit assumption of the threat model (§12.1 T10).

---

## 9. On-chain verifier architecture

### 9.1 Where lattice verification runs

| Option | Cost per transfer | Trust | Verdict |
|---|---|---|---|
| Solidity LNP22 verifier | `A` expansion with keccak instead of SHAKE ≈ 0.8 M; `A^T z` ≈ 65 k mulmods ≈ 1.5–2 M; commitment checks ≈ 5 M; NTTs, norms, transcript ≈ 1–3 M; plus calldata ⇒ **≈ 10–25 M (estimate)** | public | **No**: at or above the EIP-7825 16.78 M per-transaction cap; a second implementation of the verifier (Solidity + C) doubles audit surface and invites cross-language divergence |
| **Native precompile (chain 9000)** | ≈ 1–1.5 M for verification (§9.4) + calldata | every full node re-executes | **Chosen** (R279) |
| Off-chain co-processor (quorum of verifiers signs ML-DSA attestations; contract checks t-of-n) | ≈ 30–60 k verification + calldata | the quorum, not re-verifiable from chain data | Seam for EVM chains we do not run (§14); on chain 9000 the precompile gives the same latency with public verifiability |
| STARK proof of the lattice verifier | multi-M + prover minutes | public, PQ | Disproportionate |

### 9.2 Precompile `PQZ` (`0x…0F01`)

Input `u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ proof`; output 32 bytes, `…01` valid, `…00` otherwise; never reverts on
cryptographic failure; reverts (consumes all gas) only on input `> MAX_INPUT = 262,144` bytes.

| op | Name | `stmt` |
|---|---|---|
| 1 | `OP_TRANSFER` | §7.7 |
| 2 | `OP_BURN` | §7.7 (also REFRESH: `opTag` differs) |
| 3 | `OP_REGISTER` | `c ‖ pk` |
| 4 | `OP_DISCLOSE_SENDER` | §7.9 |
| 5 | `OP_DISCLOSE_RECEIVER` | §7.9 (also auditor) |
| 6 | `OP_SELFTEST` | empty; returns `keccak256` of the engine's fixed KAT outputs (§10.4) |

The precompile checks `proofSystemId` (header offset 32) against the ids it implements.

### 9.3 Precompile `MLDSA65` (`0x…0F10`)

Input `pk(1952) ‖ sig(3309) ‖ u8(len(ctx)) ‖ ctx ‖ msg`, FIPS 204 `ML-DSA.Verify(pk, msg, sig, ctx)` (pure
ML-DSA); output `…01`/`…00`. This is EIP-8355's layout plus the context field, because F signs with `ctx = kind_tag`
and EIP-8355 fixes an empty context. A private address because EIP-8051 and EIP-8355 both claim `0x12/0x13`. F's
`mldsa44`/`mldsa65` verifier for chain 9000 (`UAMldsaVerifier`, an `IUAKindVerifier`) calls it; the address is an
immutable constructor argument checked by self-test, so a later standard precompile means a new verifier in a new
registry generation (F §6.5). Fallback for chains
without it: none in v1 (Solidity ML-DSA at ≈ 1.23 M is possible but out of scope).

### 9.4 Gas model

Precompile price (R280), frozen per activation:

```
gas(PQZ, op, len) = G_op + 3·⌈len / 32⌉
G_op = 1000·⌈ 6000 · t_op / t_ecMul / 1000 ⌉
```

`t_op` = median verify time over 1,000 runs of the op's KAT on the chain host inside Nethermind; `t_ecMul` = median
of `0x07` (priced 6,000) on the same host and build — so the price is relative to work the chain already meters.
`MLDSA65`: 9,000 + 6 per message word (EIP-8355 numbers) unless calibration says more.

Estimates for a typical transfer (auditor on, no inline credits), **to be replaced by E-S3/E-S4 measurements**:

| Item | Gas |
|---|---|
| Calldata 76.9 KB ⇒ 292 k tokens: standard `4·tokens` | 1.19 M |
| `PQZ` verify (estimate: 5–20 ms native ⇒ calibrated) | ≈ 1.0–1.5 M |
| Statement build: 3 × SSTORE2 reads, memory ≈ 120 KB, `T` add | ≈ 0.08 M |
| ML-DSA-65 auth | ≈ 0.01 M |
| Storage: `accHash`, `rolled`, `accUnits`, `sendCounter`, `pendingHash` ×2, `entry` | ≈ 0.09 M |
| Events (≈ 16.6 KB) | ≈ 0.13 M |
| Intrinsic | 0.021 M |
| **Total** = `max(standard + execution, EIP-7623 floor 2.94 M)` | **≈ 3.0–3.2 M** |

| Operation | Gas (estimate) | Note |
|---|---|---|
| `transfer`, +1 / +4 inline credits | ≈ 3.6 M / ≈ 5.3 M | floor-bound, +0.58 M per 16,448 B ciphertext |
| `rollOver` of 16 credits | ≈ 9.5 M | calldata-bound; amortizes to 0.58 M per credit |
| `fund` | ≈ 0.08 M | trivial ciphertext, small event; its later rollover costs ≈ 0.16 M (16 KB of zero calldata) |
| `burn` / `refresh` | ≈ 2.4 M | one recipient, no auditor |
| `register` | ≈ 5.5 M once | SSTORE2 of a 16 KB pk ≈ 3.3 M, PoP proof calldata ≈ 1.6 M floor, `UARegistered` log ≈ 0.13 M |
| Classical reference (measured) | 3.29 M / 3.36 M transfer, 0.115 M rollover | SCaaS §8.4 |

Per received payment PQZ costs ≈ 3.6–3.8 M against classical ≈ 3.4–3.5 M. At the R280 block target (100 M) ≈ 30
transfers per 5 s block; the per-transaction cap keeps `inline ≤ 16` comfortably under 16.78 M.

### 9.5 Contracts

| Contract | Role | Notes |
|---|---|---|
| `PqzSafety` (library) | R270 allowlist + self-test helper | |
| `UAPqzVerifier` | F `IUAKindVerifier` for `0x0142` (§7.2) | stateless; precompile address immutable |
| `UAMldsaVerifier` | F verifier for `mldsa44`/`mldsa65` on chain 9000 (§9.3) | stateless; used by F's `UARegistry` (built by F's stream) |
| `PqzToken` | §7.3–§7.9, `ITransferDisclosure` | clone per token via `OpenFactory.createPqzToken` (flag-gated); immutable |
| `PqzCt` (library) | `add`/`sub` on 64-bit lanes, canonical check, `ctHash` | pure Solidity, no precompile |
| `Sstore2` | existing pattern (classical generator blob) | reused |

Selectors (normative ABI): `fund(bytes32,uint256)`, `pqzTransfer(bytes,bytes,bytes[],bytes,bytes)` (payload, acc,
inline, proof, authSig), `pqzBurn(bytes,bytes,bytes[],uint256,address,bytes,bytes)`, `rollOver(bytes32,bytes,bytes[])`,
views `accountState(bytes32) returns (bytes32 accHash, uint16 accUnits, uint64 pendingCount, uint64 rolled, uint64
floor, uint64 sendCounter)`, `pendingHash(bytes32,uint64)`, `transferCiphertextHash(bytes32)`. Errors: `NotAllowedChain`,
`SelfTestFailed`, `NonCanonical`, `StaleSendCounter`, `AccMismatch`, `InlineMismatch`, `InlineTooFar`,
`RefreshRequired`, `Expired`, `ProofRejected`, `AuthRejected`, `AmountOutOfRange`, `CiphertextOffState`.

---

## 10. Nethermind precompile (chain 9000)

### 10.1 Build

- Library `libpqz.so` = `pqz-core` (portable build, `-O2`, no `-march=native`) + ML-DSA-65 implementation, C ABI
  (§8). One build artifact for every node; its SHA-256 is pinned in the image and printed at start.
- Nethermind integration `Nethermind.Pqz` (C#): two precompile classes calling `pqz_verify` / `mldsa65_verify` through
  P/Invoke, gas per §9.4, activated at `pqzTransitionTimestamp` from the chainspec. E-S3 decides between a plugin (the
  Nethermind Arbitrum plugin, which adds 16 precompiles, shows plugins can extend the EVM —
  [nethermind-arbitrum](https://github.com/NethermindEth/nethermind-arbitrum)) and a minimal patch of the precompile
  table on a pinned 1.39.x tag. Either way it ships as image `scaas/nethermind-pqz:<nethermind>-pqz<n>`.
- `reth` would make this trivial (Rust, `PrecompilesMap`) but has no Clique; switching clients is not in scope.

### 10.2 Consensus rules

Every node of chain 9000 runs the same image (R279). A node without the precompile executes a `STATICCALL` to
`0x…0F01` as a call to an empty account: success with empty output. `PqzToken` requires `returndata.length == 32`
and value 1, so such a node reverts where others succeed — a visible state-root split, never a silent
acceptance (fail closed).

### 10.3 Operational steps (chain 9000)

1. Build the image; start a throwaway copy of chain 9000 (same chainspec + `pqzTransitionTimestamp` in the future).
2. Probe: `eth_call` to `0x…0F01` with `OP_SELFTEST` returns the KAT hash; `eth_estimateGas` matches §9.4 formula;
   a valid and a one-bit-flipped transfer vector give 1 / 0; same for `0x…0F10`. Compare with the formula, not
   with "it answered" (the `eip1108` lesson).
3. Roll the signer and every follower to the image before the timestamp; then repeat step 2 on the live chain.
4. Raise `TargetBlockGasLimit` and `TxPool.MaxTxSize` (R280).

### 10.4 Contract self-test

Constructors of `UAPqzVerifier`, `UAMldsaVerifier` and `PqzToken.initialize` call `OP_SELFTEST` and require the expected hash (a
constant compiled into the contract), then call `OP_REGISTER` on a fixed invalid vector and require 0, then
`MLDSA65` on one valid and one invalid vector. Any mismatch ⇒ `SelfTestFailed`. This, not the allowlist alone, is
what keeps PQZ off chains whose client is not ours.

---

## 11. Off-chain components

### 11.1 `zether-prover` (feature `pq`)

- New modules behind `--features pq` (native targets only; the existing `wasm32-unknown-unknown` build is untouched):
  `pq/keys.rs` (§6.2), `pq/mlwe.rs` (thin Rust over `pqz-core` C ABI via `cc` build; plus a pure-Rust reference
  `Enc/Add/Dec` used only in tests to cross-check the C), `pq/statement.rs` (§7.7), `pq/api.rs`
  (`prove_transfer`, `prove_burn`, `prove_refresh`, `prove_register`, `prove_disclosure`, `decrypt`, `rebuild_state`
  from logs), `pq/vectors.rs`.
- CLI `pqz-cli`: `keygen`, `register`, `balance` (decrypt from RPC logs, checks hashes), `transfer`, `burn`, `refresh`,
  `rollover`, `disclose`, `vectors`. Keys only from stdin pipes, as `zether-read-balance` (no terminal input, never
  leaves the machine).
- `zether-read-balance` and BSGS stay for classical tokens; PQZ never uses them (R285).

### 11.2 clientkeys

- F's `deriveUAKey(seed, {kind: 'mldsa65', account, index})` / `signUA('zether-auth', authDigest)` (F stream F3)
  with a vetted JS/WASM ML-DSA package chosen in E-S5; `derivePqzSeed(seed, {account, index})` (§6.2) only to hand
  the seed to the native prover or the org key oracle — PQZ proving is **not** in JS (R287).
- Vectors: F's `smartcontracts/vectors/ua/kinds.json` gains the `pqz-mlwe` row (seed → pk, UA, keyHash).

### 11.3 scaas-node (recommendations to operators, OPS R247)

- Chain profile flag `pqz = { registry = "0x…", tokens = ["0x…"] }`; start-up probe `has_pqz_precompile` (§10.3 step
  2) — a chain that fails it refuses PQZ jobs.
- Job kind `pqz_call` in the NI job API: `{chain, contract, selector ∈ {pqzTransfer, pqzBurn, rollOver, fund},
  calldata}`; contract must be a configured PQZ token; pre-simulation by `eth_estimateGas` (fails ⇒ job rejected, no
  gas spent); `max_gas_per_tx = 16_000_000` on chain 9000 (today's default 3,000,000 already rejects classical
  Zether transfers at 3.36 M). Gateway body limit 1 MiB on this route only (R280).
- Optional rollover keeper: per configured PQZ token, when an account's unrolled credits ≥ 16 and the chain is idle,
  submit `rollOver` with ciphertexts from logs (anyone may; it is harmless, R277).
- The node never holds a PQZ secret or an ML-DSA key of a user (as classical: "the node never needs `x`").
- Not on the mesh (R284).

### 11.4 Odoo

None in v1: the ERP sees PQZ like classical Zether (amounts known to the ERP from its own documents; attestations
through `attestTransferAmount`). A later stream may add a `pqz-cli` connector for organizations.

---

## 12. Threat model

### 12.1 Threats and controls

| # | Threat | Control |
|---|---|---|
| T1 | **HNDL on ciphertexts** (archive the chain, decrypt in 2035+) | MLWE ciphertexts (§4.1, ≥ 128-bit quantum target); no classical encryption of amounts in PQZ; transports already X25519MLKEM768 (SCaaS §6.8) |
| T2 | Quantum forgery of validity proofs (mint) | MSIS/MLWE-based LNP22; no pairing or DL anywhere in PQZ proofs |
| T3 | Quantum forgery of authorization | ML-DSA-65; hybrid scheme 2 only adds a classical check, never replaces it |
| T4 | Malformed ciphertexts (non-canonical coefficients, wrong lengths, huge noise) | canonical checks in Solidity and precompile; every non-trivial ciphertext comes with a proof of exact norms; trivial ones are built by the contract |
| T5 | Noise growth ⇒ wrong decryption or failure oracle | worst-case bound + `K_MAX` (§4.3, R275); no bootstrapping needed; a failure is impossible, not merely unlikely ([2024/127](https://eprint.iacr.org/2024/127)) |
| T6 | Decryption-noise leakage (IND-CPA^D style) | noise never leaves `pqz_dec`; disclosure is ZK (R283); no "decrypt and publish" API |
| T7 | Credit flood to hit `K_MAX` | permissioned PoA chain, relayer rate limits; victim's `refresh` ≈ 2.4 M vs attacker ≈ 3 M per dust credit; rollover is public |
| T8 | Rollover grief against in-flight proofs | impossible by construction (R277); > 16 attacker credits rolled past `p` force a re-prove only |
| T9 | Replay / proof transplant | `sendCounter`, `chainId`, `token`, `registry`, `validUntilBlock`, UAs, fee, beneficiary in the statement; strong FS |
| T10 | Fiat–Shamir in the QROM for multi-round LNP22 | assumption, stated; parameters follow LaZer's QROM-aware choices; tracked for the audit (Z1) |
| T11 | Side channels in the prover (timing of sampling, rejection, Gaussian masks) | constant-time CBD; masking sampler constant-time (CDT full-table scan or uniform masks, as the fork's code already does); rejection decisions depend only on public-safe values per LNP22; no secret-indexed tables (software AES bitsliced) |
| T12 | Randomness reuse | R288 message-bound derivation; hedged proof masks |
| T13 | Precompile bug ⇒ consensus split or false accept | single C core shared with prover tests; fuzzing of `pqz_verify` (§15); fail-closed returndata check; deterministic integer code (R279) |
| T14 | Rogue / stolen public key registration | `R_REG` PoP over F's `popDigest` (chain, registry, UA); keyHash group `pqz-mlwe`; front-running yields the identical record (F R295) |
| T15 | Leaked PQZ key | read-only breach (auth key separate, R281); move funds to a new UA |
| T16 | Leaked ML-DSA key | cannot spend without the PQZ key's proof; no rotation (F R302): move funds to a new UA |
| T17 | Implementation immaturity (research-grade LaZer, unaudited fork) | UNAUDITED label, allowlist, self-test, owner gate Z1 (independent audit) before any real funds |

### 12.2 What stays classical (stated, not hidden)

- Clique block signing (secp256k1): a quantum adversary with the signer key could produce blocks; it cannot decrypt
  PQZ amounts or forge PQZ proofs, but it could censor or reorder. Consensus PQ is out of scope.
- Relayer lane keys (gas only) and the public ERC-20 underlying, `fund`/`burn` amounts (public by design).
- Classical Zether tokens on the same chain keep their HNDL exposure; R289 moves pilots off them.
- Metadata: identities and the transaction graph are visible (ring size 2), exactly as classical.

---

## 13. Hybrid path and migration

| Phase | What runs | HNDL status |
|---|---|---|
| H0 (today) | classical Zether on dev chains only (RS2-1); owner gate Z3 decides 9000 | exposed, but no production funds |
| H1 | PQZ on chain 9000 behind R270 (this spec, after E-S1…E-S6) | amounts PQ-safe from first use |
| H2 | pilots migrate classical → PQZ (R289): `ZetherToken.burn(amount, ownerAddress)` then `PqzToken.fund(ua, amount)` with `approve(PqzToken)` (spender is a contract, R26) | each migrated amount is public once on chain 9000 |
| H3 | audit (Z1) | — |

No dual-stack ciphertexts (ElGamal ⊕ lattice secret-sharing of every balance) and no cross-system equality proof:
both would make every transfer carry two proof systems for the benefit of balances that, by gate, do not exist.

---

## 14. Per-family availability

| Family / chain | PQZ | Why |
|---|---|---|
| **EVM chain 9000** (Nethermind, ours) | **v1** | precompile in our client (R279) |
| Dev chains 31337 / 1337 | tests only | anvil cannot host the precompile: forge tests mock it (`vm.mockCall` on KAT inputs); e2e on a chain-9000 copy |
| Other private EVM chains (customer-run Besu, geth, reth) | **not in v1**; seam | needs a port of §10 to that client (reth: `PrecompilesMap`; geth: precompile table patch; Besu: to be researched) or the attestation seam of §9.1 |
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
| `selftest.json` | the `OP_SELFTEST` hash and the vectors it covers |
| `mldsa65.json` | NIST ACVP-style vectors via the chosen implementation |

**Cross-language and cross-backend.** Same vectors through: `pqz-core` portable, AVX2, upstream-LaZer AVX-512 (CI
runner with AVX-512; arithmetic layers and full proofs where the transcript is shared), aarch64; Rust reference
`Enc/Dec`; Solidity `PqzCt` (add/sub/hash/canonical); JS clientkeys (derivation, ML-DSA, `authDigest`); a pure-Python
`pqz_kat.py` (no numpy) for encoding, `A`, CBD, keygen, `Enc`/`Dec`, statements (`--check` reports drift, like
classical `kat.py`).

**Negative cases** (each must give `0` from the precompile or a named revert):

- any single bit flipped in proof or statement; truncated/extended proof; wrong op for statement; wrong
  `proofSystemId`;
- a coefficient `= q` or `≥ 2^50` in `pk`, `acc`, inline, `out`; wrong lengths;
- **malicious-prover harness** (a debug build of `pqz-core` with checks disabled, never shipped): `v > balance`;
  digit 256; `M_i = 2^20`; carry out of range; `e_T` at `2^26`; `‖r‖ = 37`, `‖e1‖ = 165`, `‖e2‖ = 65`; `v_t` and `v_a`
  with different `d`; `T` from a different `acc`; key of another UA;
- stale `sendCounter`; `validUntilBlock` passed; `acc` hash mismatch; inline ciphertext out of order; `|p − rolled|
  = 17`; `p > pendingCount`; `p < floor` (would subtract credits the last debit consumed); credit at `K_MAX + 1`; self-transfer; unregistered receiver; auditor flag mismatch;
- rollover race: a debit proven at `p`, then `rollOver` of 3 / 16 / 17 credits, then the debit ⇒ ok / ok /
  `InlineTooFar`; then decrypt both accounts and check conservation;
- registry: PoP for another chain/registry/UA; same `pk` twice (`UAKeyInUse`); `authRef` = 0, an EOA, a classical
  `msig` (non-PQ weight ≥ threshold), a Zether UA — all `UAAuthRef`; ML-DSA signature with empty instead of
  kind-tag context;
- disclosure: right amount ⇒ true, amount ± 1 ⇒ false, wrong `entryRef`, bundle bytes not matching the hash;
- precompile absent (call an empty address) ⇒ `ProofRejected` / `SelfTestFailed`;
- determinism: 10^4 random valid and invalid inputs give identical outputs on portable, AVX2 and aarch64 builds; gas
  equals the formula for every input length;
- fuzzing: `cargo fuzz`/libFuzzer on `pqz_verify` and on the Solidity decoders (forge invariant tests), ≥ 24 h before
  E-S7.

**Invariant** (forge, with mocked precompile and real `PqzCt`): `Σ_ua decrypted(acc + pending)` (computed off-chain
by the test harness from the logged ciphertexts and known test keys) `= totalShielded` after every random sequence of
fund/transfer/rollover/burn/refresh.

---

## 16. Streams

Research spikes first; at most 3 agents; **one heavy build at a time** (owner OOM cap). Each stream ends with its
tests green and a review.

| Stream | Content | Heavy build? | Depends | Exit criterion |
|---|---|---|---|---|
| **E-S0** spike: literature & parameters | read Lether full text, LNP22, LaZer docs; run lattice-estimator for §4.1 and the proof instances; confirm exactness of every norm proof | no | — | `estimator.txt`; §4 confirmed or a parameter ruling |
| **E-S1** spike: `pqz-core` fork | pin LaZer; portable C99 + AVX2 kernels; software AES; KAT equality vs upstream on an AVX-512 runner; measure a toy `R_REG` and a first `R_TX` on the chain host | yes (C) | E-S0 | proof ≤ 96 KB, verify ≤ 50 ms portable, prove ≤ 3 s desktop (kill criterion R278) |
| **E-S2** relations | `R_TX`, `R_BURN`, `R_REG`, `R_DS`, `R_DR` specs, codegen, proof modulus decision, serialization v1, all §15 KATs from C | yes (codegen) | E-S1 | vectors frozen, `proofSystemId` frozen (R278) |
| **E-S3** Nethermind precompile | plugin vs patch, P/Invoke, gas calibration, image, chainspec key, probes, throwaway chain | yes (.NET image) | E-S2 | §10.3 steps 1–2 pass on a chain-9000 copy |
| **E-S4** contracts | `PqzSafety`, `UAPqzVerifier`, `UAMldsaVerifier`, `PqzToken`, `PqzCt`, factory flag, forge tests with mocks, e2e on the chain copy | yes (forge) | E-S2 (vectors), E-S3 (e2e), F's registry stream | §15 contract cases + invariant |
| **E-S5** clients | `zether-prover --features pq`, `pqz-cli`, clientkeys `pq-keys.js`, ML-DSA package choice | yes (cargo) | E-S2 | cross-language vectors green |
| **E-S6** node | `pqz` profile, probe, `pqz_call` job, limits, rollover keeper | yes (cargo) | E-S4 | e2e: fund → transfer → rollover → burn → disclose through the node |
| **E-S7** review & audit prep | Claude-subagent reviews (external reviewers out of credit), fuzz 24 h, threat-model walk-through | no | E-S6 | review log in this spec |
| E-S8 (later) | `wasm32-wasip1` and mobile provers; LaBRADOR aggregation; FN-DSA when FIPS 206 is final | — | owner | — |

Serial heavy chain: E-S1 → E-S2 → E-S3 → E-S4 → E-S5 → E-S6; E-S0 and reviews run beside them.

---

## 17. Open questions (owner)

1. **Patents and licence diligence.** LaZer is MIT (no explicit patent grant); LNP22-family techniques come from IBM
   Research. Do we need a legal check before production, as with Zama's TFHE licence? (Does not block E-S0–E-S6.)
2. **Customer-run private chains.** Is PQZ on private EVM chains we do not operate (Besu/geth/reth) a product goal?
   If yes, a client port (§14) or the attestation seam (§9.1) needs its own spec.
3. **Retail PQ.** R287 leaves phones and browsers out of v1. Is there a near-term retail use on private chains that
   would pull E-S8 forward?

---

## 18. Sources

- Lether: Wang, Esgin, Steinfeld, Yiu, *Lether: Post-Quantum Private Blockchain Payments*, ACM CCS 2026,
  <https://eprint.iacr.org/2026/076>
- LNP22: Lyubashevsky, Nguyen, Plançon, CRYPTO 2022, <https://eprint.iacr.org/2022/284>
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
