> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# In-contract PQ signature verification, per family (2026-10-29)

Question (owner 2026-10-29): which families can verify a UA's post-quantum signature **inside a contract** (UA-8 P11:
portable registrations and KEM records need it; a chain's native PQ account signatures are not enough). Method: web
research by three agents (appendices A–C, every source listed there with its read date), then the two decisive claims
re-checked by the controller against the primary sources (nearcore 2.14.0 release notes; CAP-0087 text). Self-reported
community claims are marked in the appendices. These facts move fast: re-check before each plan.

Our kinds (accounts.md §1.6): `mldsa44` / `mldsa65` (FIPS 204, empty context, over the 32-byte `pq_msg`), `fndsa512`
(Falcon-512 spec v1.2, SHAKE256 hash-to-point, padded sig 666 B, pk 897 B), `slhdsa128s` (SLH-DSA-SHA2-128s, sig
7,856 B, pk 32 B).

## Summary

| Family | Contract-callable PQ verify today | Fits our kinds | Status of the primitive |
|---|---|---|---|
| EVM, Hedera | our pure-Solidity verifiers (P6a); EIP-8051 / -8052 / -8355 still drafts (no fork, no deployment); no L2 with a live PQ precompile found; Hedera: no HIP | all four | ours BUILT; precompiles draft |
| NEAR | **host function `ml_dsa_verify`** (nearcore 2.14.0, released 2026-10-26, protocol 87 → 88; mainnet activation date not confirmed): ML-DSA-65, sig 3,309 B, raw pk 1,952 B, message as-is with empty context, 540 Ggas + 11 Mgas / byte | **`mldsa65` exactly** (32-byte message); others pure Wasm only (unmeasured) | released; our near-sandbox already runs protocol 88 |
| Soroban | **CAP-0087** host functions `verify_sig_ml_dsa_{44,65,87}` (status Implemented, Protocol 30; SDK wrapper merged 2026-10-19; not on mainnet yet); pure-Rust ML-DSA in a contract measured by a third party on testnet: ML-DSA-65 77.5 M / ML-DSA-44 51.0 M CPU instructions [self-reported] | **`mldsa44`, `mldsa65` exactly** (pure FIPS 204, empty context valid); `fndsa512` / `slhdsa128s` pure only | spec implemented, mainnet pending |
| Algorand | **opcode `falcon_verify`** (AVM v12+, mainnet): deterministic Falcon-1024 only (pk 1,793 B, compressed sig ≤ 1,423 B, cost 1,700; fixed salt `version‖0x0A‖"FALCON DET"‖0`, header MSB set; a randomized round-3 / FIPS 206 signature is refused); AVM v14 (go-algorand master, unreleased) adds deterministic Falcon-512 (pk 897 B, sig ≤ 713 B, cost 850) | today: none of ours (a new `fndsa1024-det` kind would fit); after AVM v14: `fndsa512` **if the client signs deterministically** (re-encoding a Det512 signature as our padded 666 B form is an inference that needs a test vector) | v12 live; v14 unreleased |
| Sui | none callable from Move; ML-DSA-65 native **account** signatures on devnet (2026-10-12, mainnet target Q1 2027); SLH-DSA-SHA2-128s Move vaults announced for mainnet 2026, code not published | `slhdsa128s` via Mysten's vault code when published; pure-Move ML-DSA / Falcon judged infeasible in 5 M computation units (estimate) | planned |
| Cosmos (CosmWasm) | none: SDK 0.55 `ml_dsa_65` is for account / consensus keys only; no `Api` function in cosmwasm 3.0.11 | all four as pure Rust → Wasm (estimate: fits normal gas limits; unmeasured) | none |
| Aptos | none callable from Move; AIP-137 (proposed, 2025-12) adds SLH-DSA-SHA2-128s as an account signature | `slhdsa128s` pure Move plausible (estimate) | proposal |
| Solana | none; SIMD-0416 proposes a Falcon-512 verify syscall (2026 roadmap; not activated); a tx is 1,232 B, so PQ keys / signatures need account-stored chunks | `fndsa512` if SIMD-0416 matches our encoding (unknown) | proposal |
| TON | nothing found | — | none |

## Consequences for UA-8 (P11)

- NEAR moves from relayer-checked to on-chain for `mldsa65` (host function, cheap: ≈ 0.54 Tgas).
- Soroban's on-chain path is the host function once Protocol 30 is on mainnet; until then pure Rust (measured order:
  20 % of a 400 M-instruction budget for ML-DSA-65 — the budget figure itself needs `stellar network settings`).
- Algorand can verify on chain today only a deterministic Falcon-1024 kind; our `fndsa512` after AVM v14 with
  deterministic signing.
- Sui's on-chain path waits for Mysten's published code (SLH-DSA vault, or a Move ML-DSA function).
- Cosmos needs our own Wasm verifier (spike).
- Aptos, Solana, TON stay relayer-checked until their proposals land.


## Appendix: algorand-evm (agent research, verbatim)

### PQ signature verification inside contracts: Algorand + EVM/Hedera (read 2026-10-29)

Targets: mldsa44/65 (FIPS 204, empty ctx, 32-byte msg), fndsa512 (EIP-8052 SHAKE256 h2p, padded sig 666 B, pk 897 B), slhdsa128s (SHA2-128s, sig 7856 B, pk 32 B).

#### 1. Algorand

### What exists
- `falcon_verify` opcode 0x85, introduced AVM v12 (go-algorand 4.3.0), Modes=3 (usable in BOTH application/stateful and LogicSig/stateless). Source: go-algorand `opcodes.go`, `langspec_v12.json` (master).
- Mainnet today: consensus v42 = AVM v13 (go-algorand v5.0.0, native Falcon-1024 account signatures; roadmap blog footnote says live on MainNet August 2026). Latest release v5.0.5-stable 2026-10-28. v43 (fix-only) exists in the tree. falcon_verify under v12/v13 = Falcon-DET-1024 only, no immediate.
- AVM v14 (`LogicVersion = 14`, consensus `vFuture` only, NOT released): `falcon_verify` gets an immediate `F` choosing FalconDet1024 (cost 1700) or FalconDet512 (cost 850). Sig max 1423 B (Det1024) / 713 B (Det512); pk exactly 1793 B / 897 B. `EnablePQSchemeFalcon512` is also vFuture only. Roadmap blog: Falcon-512 accounts planned "year-end 2026". So Falcon-512 in a contract = future, no date commitment beyond that.

### Scheme / encoding (deterministic Falcon, falcon-det.pdf, Lazar and Peikert, Algorand; dated 2026-09-24 in the PDF)
- Same keys as standard Falcon (pk 1793 B for n=1024, 897 B for n=512: 0x00|log n header + 14-bit packed h). Keys interoperable between modes.
- Signature = "unsalted" format: `header byte (MSB = 1, low nibble = log2 n) || salt_version byte || s bytes` (compressed encoding only; padded format NOT supported; CT format only in the Go/C lib, the opcode takes compressed).
- Verification = rebuild the standard salted sig: clear header MSB, insert the 40-byte salt `salt_version || preversioned_salt_l` where preversioned_salt_l = byte l (0x09 for 512, 0x0A for 1024) || ASCII "FALCON DET" || zero padding to 39 B, then run ordinary Falcon verify. So hash-to-point is the standard Falcon SHAKE256(salt || message) (message hashed raw, no pre-hash, no domain byte), same as round-3 / EIP-8052 SHAKE256 variant.
- Consequence for verification: falcon_verify accepts ONLY signatures with the fixed DET salt and MSB-1 header. A standard randomized Falcon signature (random 40 B salt, header 0x3A/0x39/0x2A...) is REJECTED (header MSB 0, salt not recoverable). So "can falcon_verify verify a standard FIPS 206 / round-3 Falcon-1024 sig": NO. Fixed salt means the signer must use deterministic mode (algorand/falcon C lib or algorandfoundation/falcon-signatures).
- Inference (mine, not in a source): a Det512 signature over our 32-byte digest is mathematically a valid standard Falcon-512 signature with a known 40-byte salt; its (salt, s) can be re-encoded to the 666 B padded EIP-8052 form without the secret key (transcoding is public per the PDF section 3.3). So one signer output could feed both Algorand (v14) and EVM (8052) if the signer uses the DET salt. Needs a test vector before relying on it.
- FIPS 206 (FN-DSA) final differs from round-3 Falcon (pre-hash/ctx, different salt/domain handling). Not verified here; assume FN-DSA final is NOT what falcon_verify checks.

### Limits relevant to us
- Cost 1700 (Det1024) / 850 (Det512, v14). App program budget: 700 per app txn, pooled over a group (up to 16 txns = 11,200); LogicSig 20,000 per lsig (dev.algorand.co Cryptographic Tools). One verify therefore needs 3 pooled app txns or one lsig-style budget.
- Arg sizes: consensus `MaxAppArgs=16`, `MaxAppTotalArgLen=2048` (since v24); v42 raises `MaxAbsoluteTotalArgLen` to 16384 (surcharge-based "larger args", my reading of the code comment, unverified in docs). pk 1793 + sig up to 1423 = 3216 B exceeds 2048, so either use the v42 large-arg mechanism, or store pk in a box (MaxBoxSize 32768 B, box refs) and pass only sig + digest. For Det512 (897 + 713 = 1610 B) it fits inside 2048 even without that.
- Use as a delegated signer: v5.0.0 also adds native PQ accounts and PQ delegated LogicSigs (not what we need, we verify inside an app).

### Tooling
- algorand/falcon (C, Thomas Pornin core + deterministic.h, deterministic512.c / 1024.c) - official.
- algorandfoundation/falcon-signatures (Go 1.25+, CLI + Go packages falcongo/, algorand/, mnemonic/): FALCON-1024 deterministic; README says sig 1538 B (uncompressed/CT) - the compressed form is what the opcode wants (check the CLI). No Rust/JS/Python bindings mentioned there.
- Community (self-reported, unverified): PyPI `avm-proofpack` (says its Falcon-1024 verifier is "experimental"), TRELYAN forum post claiming a falcon_verify consumer protocol.

### Roadmap (algorand.co blog)
- Only FALCON_VERIFY is named as an opcode; no new opcodes announced. ML-DSA: mentioned as a scheme possibly supported later "if viable and secure", no date. SLH-DSA: not mentioned. Falcon-512 accounts YE2026; consensus-message Falcon (hybrid with Ed25519) details end of 2026; native PQ multisig by end of 2026; LogicSig budget to be raised for hybrid accounts.

### Fit with our kinds
| kind | Algorand |
|---|---|
| mldsa44 / mldsa65 | NO (no opcode, no date). Would need pure-AVM verifier: not practical in budget (700/txn). |
| fndsa512 (as defined: 666 B padded, EIP-8052) | NO as-is. Needs new kind `fndsa512-det` (DET salt, compressed sig <= 713 B) and AVM v14, which is unreleased (vFuture) today. |
| (new) fndsa1024-det | YES today on mainnet (AVM v13: pk 1793, sig <= 1423, cost 1700). Needs a new kind, it is Falcon-1024 not 512. |
| slhdsa128s | NO (not planned in any source read). |

#### 2. EVM

### Status (all drafts; nothing deployed that I could find)
- EIP-8051 (ML-DSA verification, Dubois/Masson): Draft, Core, created 2025-10-15/17, requires EIP-7932. Two precompiles at 0x12 (FIPS 204 hash) and 0x13 (ETH variant, Keccak-based XOF), 4500 gas each (EIP page; addresses may change). Input = 32-byte message || 2420 B ML-DSA-44 sig || 20,512 B PRE-EXPANDED pk (A_hat 16384 + tr 32 + t1 NTT 4096). ML-DSA-44 only. No fork named.
- EIP-8355 (ML-DSA, Danno Ferrin): Draft, Core, created 2026-07-30 (PR #12048). Addresses 0x12/0x13/0x14 = ML-DSA-44/65/87 (placeholders, collide with 8051's numbers, unassigned per thread). Input = pk || sig || message (standard pk 1312/1952/2592, sig 2420/3309/4627, variable message last), empty ctx "", raw message (no pre-hash). Returns 32-byte 1/0, no revert. Gas base 6500/9000/13500 + 6 per 32 B message word (placeholders pending benchmarks). Thread latest post 2026-09-21: no client implementations, no target fork, no external reviews; one core participant (asanso) opposes; relation to 8051 undecided. Fits mldsa44/65 exactly (32-byte msg appended; standard pk).
- EIP-8052 (Falcon-512, BTQ/Dubois et al.): Draft, Core, created 2025-10-17, requires EIP-7932. Three precompiles: FALCON_HASH_TO_POINT_SHAKE256 and ..._KECCAKPRNG (32 B hash + 666 B sig -> 896 B packed challenge, 1000 gas each) and FALCON_CORE (666 B sig, 896 B pk, 896 B challenge -> 1, 2000 gas). Addresses TBD, no fork named. Sig 666 B = 40 B salt + 626 B compressed s2 (round-3, padded to 666). Public key is 896 B NTT-form coefficients (computed off-chain), NOT the 897 B standard encoding (no header byte, NTT domain). SHAKE256 variant is the NIST-compatible one; Keccak-PRNG variant is not fully specified. A community Rust revm-precompile fork passes KATs for core + SHAKE256 h2p, no addresses (self-reported, ethereum-magicians thread, undated).
- Fit: EIP-8052 matches our fndsa512 definition except pk: contract/relayer must pass the 896 B NTT form (derive from 897 B pk off-chain, or store both). Verify the exact meaning of "896 B" in the final EIP before freezing.
- Ethereum pq.ethereum.org blog (EF) on 8051/8052; EF brief (via search summary, Feb 2026) calls Hegota H2 2026 "plausible if prioritized" - not confirmed. No EIP page names a fork; none is in a scheduled fork as of the pages read.
- No L2 / rollup with a live ML-DSA or Falcon precompile found in search (no RIP-7212-style PQ RIP found). Tron Nile testnet release "v4.8.2-PQ1" adds Falcon-512 + ML-DSA-44 (testnet only; I did not read it, search-summary only).
- Pure-EVM Solidity verifiers exist (self-reported/vendor): Fireblocks MLDSA44Verifier ~1.23M gas (their measurement), ZKNox ETHDILITHIUM ~8.09M gas (as cited by Fireblocks). SLH-DSA: no precompile proposal found in these sources (Magicians thread mentions hash-based/SPHINCS testnet only).

### Hedera
- No HIP found that adds a PQ signature precompile. Existing HIP-632 (isAuthorized / isAuthorizedRaw) covers ED25519 and ECDSA only. Hedera PQ roadmap (April 2026; secondary source autheo.com, plus hedera.com blog) targets FN-DSA (FIPS 206), user-key migration aimed at 2027. A March 2025 community-call mention of a PQ HIP was found but no number/spec. => treat Hedera as NO today.

### Fit with our kinds (EVM, if/when shipped)
| kind | EVM |
|---|---|
| mldsa44 / mldsa65 | EIP-8355 matches (draft, 0x12/0x13 placeholders); 8051 only mldsa44 with 20,512 B expanded pk (different pk encoding) |
| fndsa512 | EIP-8052 SHAKE256 variant matches (pk in 896 B NTT form); draft |
| slhdsa128s | no precompile proposal; Solidity verifier only |
| Today | none deployed: a PQ verify on EVM chains today = pure Solidity/Yul (1.2M+ gas) or our own chain's precompile |

#### Sources (all read 2026-10-29)
- https://dev.algorand.co/concepts/smart-contracts/cryptographic-tools/ (v12 availability, budgets)
- https://algorand.co/blog/technical-brief-quantum-resistant-transactions-on-algorand-with-falcon-signatures
- https://algorand.co/blog/algorand-post-quantum-cryptography-roadmap
- https://github.com/algorand/falcon and https://raw.githubusercontent.com/algorand/falcon/main/falcon-det.pdf (full text read via pdftotext)
- https://raw.githubusercontent.com/algorand/go-algorand/master/data/transactions/logic/langspec_v12.json (falcon_verify entry, v14 immediate docs)
- go-algorand master via gh api: data/transactions/logic/opcodes.go, protocol/consensus.go; raw config/consensus.go (consensus v24/v42/v43/vFuture params)
- gh api repos/algorand/go-algorand/releases (v5.0.5-stable 2026-10-28)
- https://newreleases.io/project/github/algorand/go-algorand/release/v5.0.0-stable
- https://github.com/algorandfoundation/falcon-signatures
- Search-only (not fetched): https://pypi.org/project/avm-proofpack/ , https://forum.algorand.co/t/trelyan-first-end-user-falcon-verify-consumer-protocol-swiss-stiftung-in-formation/15355 (community, self-reported)
- https://eips.ethereum.org/EIPS/eip-8051 , /eip-8052 , /eip-8355
- https://ethereum-magicians.org/t/eip-8355-precompiles-for-ml-dsa-verification/29211 (latest post 2026-09-21)
- Search snippets only: https://ethereum-magicians.org/t/eip-8052-precompile-for-falcon-support/25860 , https://pq.ethereum.org/blog/pq-precompiles-eip-8051-8052/ , https://www.fireblocks.com/blog/post-quantum-signatures-ethereum-cheaper-gas , https://newreleases.io/project/github/tron-nile-testnet/nile-testnet/release/GreatVoyage-Nile-v4.8.2-PQ1-build1
- Hedera (search snippets only): https://www.autheo.com/signals/hedera-post-quantum-cryptography-roadmap-april-2026 , https://hedera.com/blog/post-quantum-cryptography-and-blockchain/ , https://docs.hedera.com/evm/hedera-services/system-contracts/account-service

Caveats: dev.algorand.co opcode page 404'd; Algorand arg-limit semantics (MaxAbsoluteTotalArgLen) read from code only; EIP gas/addresses are draft placeholders; AVM v14 status judged from vFuture in master, not from an announcement.

## Appendix: cosmos-soroban-sui-near (agent research, verbatim)

### In-contract PQ signature verification: Cosmos/CosmWasm, Soroban, Sui, NEAR (as of 2026-10-29)

Method: web search + page fetch only (no repo clones). "Measured" = a published number from someone's run; "estimated" = my reasoning. Self-reported community claims are marked [SELF-REPORTED].

#### Summary table (contract-callable verify of a 32-byte digest, empty context)

| Family | Native/host verify callable from a contract today? | mldsa44 | mldsa65 | fndsa512 | slhdsa128s |
|---|---|---|---|---|---|
| NEAR | YES: `ml_dsa_verify` (nearcore 2.14.0, released 26 Oct 2026; protocol 88 vote was scheduled from 21 Oct, mainnet activation not confirmed) | no host fn; pure only | host fn, 0.54 Tgas + 11 Mgas/byte | pure only (estimate: feasible) | pure only (estimate: feasible with sha256 host fn) |
| Soroban | CAP-0087 `verify_sig_ml_dsa_{44,65,87}`: Protocol 30, SDK wrapper merged 2026-10-19; NOT on mainnet as far as found | host fn once P30 live; pure measured today | host fn once P30 live; pure measured today | no (CAP says FN-DSA not final); pure only | no (CAP: "could be added later"); pure only |
| Sui | NO Move-callable ML-DSA/SLH-DSA verify found | pure Move: no data | native account auth only (devnet), not callable | no | SLH-DSA vault in Move, "mainnet 2026"; code not found |
| Cosmos/CosmWasm | NO (nothing found in cosmwasm-std/vm/wasmvm/wasmd) | pure Wasm only | pure Wasm only (SDK 0.55 key type is not exposed to contracts) | pure Wasm only | pure Wasm only |

#### 1. Cosmos / CosmWasm

**What exists.** Cosmos SDK v0.55.0 + CometBFT v0.40.0 ("2026.1 Ledger Security" release) add `ml_dsa_65` (FIPS 204 ML-DSA-65, category 3) for consensus keys and user account keys; pk 1,952 B, sig ~3,309 B. Docs give no byte-level encoding, no gas figures, and do not mention CosmWasm. Docs say the default gas limit may run out with the larger keys (use `--gas auto`). Accounts cannot rotate keys.

**Contract-callable?** No evidence. Searched cosmwasm-std/cosmwasm-crypto/wasmvm/wasmd for ML-DSA / Dilithium / post-quantum: nothing. cosmwasm release page (read 2026-10-29) shows latest v3.0.11 (8 Oct), v2.3.6, v2.2.11, no PQ mention in the release list (changelog bodies not read). `Api` still exposes only secp256k1, secp256r1, ed25519 (+batch), BLS12-381 as far as the results show. Absence of evidence, not proof: I did not read CHANGELOG.md of cosmwasm or wasmd release notes line by line.

**Gas / limits.** CosmWasm 2.x gas: ~150 gas per Wasm op (down from 150,000 in 1.x), target 1 Tgas/s; the SDK<->CosmWasm multiplier is reported as 140,000 for 2.x (from a search snippet, not verified on the official page, which I could not load: redirect loop). wasmd README: block gas limit should be set explicitly in genesis (default -1 = unlimited); per-tx limit is the user-supplied gas limit capped by chain block max gas, so there is no universal default. Query gas default 3,000,000 (CosmWasm gas units; separate from tx). A 2024 advisory (RUSTSEC-2024-0361) says some Wasm ops were ~10x under-priced before wasmvm 1.5.4/2.0.3/2.1.2.

**Pure implementation.** No CosmWasm-specific measurement found. Estimate (not measured): ML-DSA-65 verify is ~77.5M Soroban-VM instructions (measured, see section 2); on a Wasm VM metered per op that is the same order, tens of millions of Wasm ops. At 150 gas/op that is ~1-3e10 CosmWasm gas, i.e. roughly 1e5-2e5 SDK gas after the 140,000 multiplier (if that multiplier is right). That would fit any normal tx gas limit by a wide margin. Treat as order-of-magnitude only. Wasm size: ml-dsa crate contract ~61 KB (opt 3) per Soroban measurement; wasmd max code size default is 800 KiB, fine. Needs `no_std`-clean crate with SHAKE; RustCrypto `ml-dsa` 0.1.x/`fips204` are the usual candidates; not audited (the Soroban author notes no audited pure-Rust ML-DSA exists).

**Fit.** mldsa44/65: feasible as pure Wasm (estimate), no host fn. fndsa512: feasible (n=512, one NTT product, SHAKE256 hash-to-point; cheaper than ML-DSA by estimate; no CosmWasm measurement). slhdsa128s: ~2.1k SHA-256 compressions (my count from d=7,h'=9,k=14,a=12,w=16) plus 7,856 B sig input; feasible in Wasm (estimate), tx size is the main constraint.

#### 2. Soroban (Stellar)

**What exists.**
- Stellar Quantum Preparedness Plan (Stellar Foundation blog, read 2026-10-29): Stage 1 in 2026 = native Soroban host functions for ML-DSA-44 and ML-DSA-65; FN-DSA later "once standardized"; no CAP number in the post.
- CAP-0087 "ML-DSA signature verification" (stellar-protocol, created 2026-06-05, status Implemented, Protocol 30; Implementation section "TBD"). Host functions `verify_sig_ml_dsa_44/65/87`, args (public_key, msg, signature, context) all BytesObject, return Void, traps on failure. FIPS 204 external "pure" interface, context 0-255 B (empty valid), M' = 0x00||len(ctx)||ctx||M, SHAKE-256. Sizes: 44: pk 1312 / sig 2420; 65: pk 1952 / sig 3309; 87: pk 2592 / sig 4627. New cost types (XDR 86-94): decode key and decode sig constant, verify linear in msg+ctx length. Final calibration TBD. Only a preliminary estimate "a few times an Ed25519 verify", 16-57 KB transient host memory. No absolute numbers.
- rs-soroban-sdk PR #2138 (Crypto::ml_dsa_{44,65,87}_verify wrappers) merged 2026-10-19 (commit 6ce5223); host fns in rs-soroban-env#1737. Mainnet protocol: P26 went live ~May 2026 per Blockworks snippet; I found no evidence that P27-P30 is live on mainnet. P27 is on testnet (per the latticework repo). So: not usable on mainnet today.
- SLH-DSA, FN-DSA: not in CAP-0087 (SLH-DSA "if demand arises"; FN-DSA not final).

**In-contract measurement [SELF-REPORTED, third party, repo latticework-dev/soroban-ml-dsa, testnet protocol 27, simulateTransaction]**: ML-DSA-65 verify 77,519,116 CPU instructions (19.4% of a stated 400M per-tx budget), resource fee 90,837 stroops; ML-DSA-44 51,025,589 instr (12.8%), 64,944 stroops; Ed25519 host fn 2,963,805; VM no-op 2,515,683. opt-level=3 -> 61,457 B contract; opt-level="z" -> 204,957,239 instr (2.64x worse), 33,384 B. Memory use not reported. Crates referenced: `ml-dsa` 0.1.1 / `fips204`. Author states testnet only, not production-ready, no audited pure-Rust ML-DSA.

**Limits.** The 400M instr per-tx figure comes only from that repo; official docs pages I could load (developers.stellar.org resource-limits-fees) give no numbers and defer to Stellar Lab / `stellar network settings`. A search snippet quoted older docs of 100M instr / 40 MB / 40 read / 25 write entries. CONFLICT: treat current mainnet limit as unverified; read it with `stellar network settings` before relying on it. Ledger budget stated 580M instr in the same repo.

**Community Falcon contract [SELF-REPORTED].** The only evidence found is a Stellar Community Fund (SCF) submission by the Soundness team (`communityfund.stellar.org/submissions/receJ5whfzBRWXFdW`), status "Awarded", $150K in 3 tranches. The page does not name Falcon-512 vs 1024, gives no gas figures, no repo, and no mainnet contract ID; mainnet is listed as a future deliverable ("Mainnet contract ID published" as completion marker). A search summary said the proposal claims it is deployed on mainnet, but the fetched page shows it only as a planned deliverable. So: the "deployed on mainnet" claim is unverified; parameter set and cost unknown.

**Fit.**
- mldsa65 / mldsa44: host fn exists at spec/SDK level (P30), exact fit (empty context, message = our 32-byte digest, FIPS 204 encodings). Until P30 is live: pure in-contract works per the measurement above (20% / 13% of the stated budget; ~14 / ~22 authorizations per ledger, so not high-throughput).
- fndsa512: no host fn. Pure feasibility estimated, not measured: smaller than ML-DSA arithmetic, but SHAKE256 is not a Soroban host fn (only keccak256/sha256), so it runs in guest code; fits by estimate. The 897 B pk / 666 B sig are small.
- slhdsa128s: no host fn; SHA-256 host function exists, so ~2.1k hash calls (estimate) fit the budget comfortably if each call is a host call; the 7,856 B signature must fit tx/ledger-entry size limits (not checked).

#### 3. Sui

**What exists.** Sui blog "Sui's post-quantum signature schemes" (Kostas Chalkias, Mahdi Sedaghat; announced 2026-08-06): ML-DSA-65 as a native protocol signature scheme (testnet end-2026, mainnet auth Q1 2027, "worst case", audits underway); SLH-DSA-SHA2-128s as Move smart-contract vaults (mainnet 2026), "mostly Merkle-tree work", ships without a protocol upgrade because the byte handling and hash primitives already exist in Move; two-transaction withdrawals. Falcon/FN-DSA explicitly declined (non-final standard, no L3 set, floating-point sampling, slower verify). Timing numbers (Apple M2 Max): ML-DSA-65 verify ~23.2 us, FN-DSA-1024 ~49.8 us; SLH-DSA verify "considerably more expensive than Ed25519". Devnet: devnet-v1.82.0, protocol 139, first native tx on 2026-10-12 (`SignatureScheme::MLDSA65 = 7`), per Crypto Briefing 2026-10-13.

**Contract-callable?** No. Sui docs "Signature Verification in Move" (docs.sui.io/develop/cryptography/signing) list ed25519, secp256k1, secp256r1, BLS12-381 only. No `sui::ml_dsa`/`slh_dsa` module found, no SIP found. Repos named in the blog: MystenLabs/fastcrypto/fastcrypto-pq (Rust, benchmarks), MystenLabs/mysten-mldsa-native-rs, pq-code-package/mldsa-native, SoundnessLabs/pqchain; none is a Move SLH-DSA vault. I found no published Move vault code; whether it is live is unstated.

**Limits.** Sui docs (gas-in-sui): max 5,000,000 computation units per tx (bucketed), max gas budget 50 SUI (50e9 MIST); no explicit tx-size limit on that page (blog says tx up to 128 KB).

**Pure-Move feasibility.** Not measured by me or found. SLH-DSA-SHA2-128s: ~2.1k SHA-256 compressions (my count) via the Move `std::hash::sha2_256` native plus byte-vector manipulation; Mysten asserts it is practical (their own plan, unpublished code, so [SELF-REPORTED]). Whether it fits 5M units is unverified; byte-vector-heavy Move loops are the risk. ML-DSA / Falcon in pure Move: NTT with 256/512 coefficients, multiply-heavy, no SHAKE native in Move (only sha2/sha3-256/keccak256) => SHAKE128/256 would have to be written in Move: I judge this infeasible in 5M units (estimate, no measurement).

**Fit.** mldsa44/65: no callable verify (native account signature only); pure Move impractical. fndsa512: no; SHAKE256 hash-to-point missing in Move. slhdsa128s: the only kind with a stated Move path and the exact parameter set (sig 7,856 B, pk 32 B), but code unpublished/unconfirmed; the vault variant's exact message framing (our 32-byte digest, FIPS 205 vs raw) is unknown.

#### 4. NEAR

**What exists.**
- NEP-645 (near/neps PR #645): ML-DSA-65 (FIPS 204, cat 3) as third transaction-signature type; approved by Contracts Standard WG 2026-07-15, merged 2026-07-21; protocol 85, neard 2.13, `ProtocolFeature::PostQuantumSignatures`. Access keys stored by SHA3-256 hash of the 1,952 B pk (borsh tag 3; tag 2 = full key); RPC shows `ml-dsa-65-hash:<bs58>`. Tx verification cost 100 Ggas per signature, charged at tx conversion. This is the TX signature, not a contract API; NEP lists on-chain verify host functions as out-of-scope follow-up.
- nearcore 2.14.0 (release page read 2026-10-29, released 26 Oct, protocol 87->88 per rc.4 notes, voting from 21 Oct): adds host function `ml_dsa_verify`: FIPS 204 ML-DSA-65; inputs 3,309 B signature, arbitrary-length message, 1,952 B raw public key (each from memory or register); returns 1 valid / 0 invalid; wrong sizes abort with `MlDsaVerifyInvalidInput`; message verified as-is with EMPTY context (callers must not pre-hash; ours is a 32-byte digest used as message M, which matches). Gas: 540 Ggas fixed + 11 Mgas per message byte, i.e. ~0.54 Tgas + 352 Mgas for a 32 B message (0.00035 Tgas), well under 300 Tgas. Whether protocol 88 is active on mainnet: not confirmed.
- NEAR roadmap (secondary reposts, youmind.com / diariobitcoin) mentions future host functions for verifying other chains' PQ consensus sigs; no scheme list. FN-DSA "under consideration" per press.

**Pure implementation.** No measurement of ml-dsa/Falcon in a NEAR contract found (a `mldsa65` crate on docs.rs wraps RustCrypto ml-dsa to Wasm; no gas data). Estimate: Wasm gas is injected per basic block; tens of millions of Wasm ops for ML-DSA-65 would be on the order of a few to tens of Tgas (rough: ~1 Tgas ~ 1 ms native-equivalent), i.e. well inside 300 Tgas but ~10-50x worse than the 0.54 Tgas host fn. Estimate only.

**Fit.**
- mldsa65: exact host fn, empty context. 
- mldsa44: no host fn; pure Wasm estimated feasible.
- fndsa512: no host fn; pure Wasm estimated feasible (SHAKE256 not a NEAR host fn; keccak256/sha256/ripemd160 exist), cost estimate low single-digit Tgas, unmeasured.
- slhdsa128s: no host fn; NEAR has `sha256` host fn, ~2.1k calls (estimate); cost dominated by host-call base costs; sig 7,856 B must be passed as call args (tx size/ args limit, not checked).

#### Cross-cutting notes
- Only NEAR (2.14, host fn) and Soroban (P30, not yet mainnet) offer a native contract call, and only for ML-DSA (NEAR: 65 only; Soroban: 44/65/87). Both use the pure FIPS 204 interface with empty-context support, so a 32-byte digest as M with empty ctx matches our kind definition on both.
- No family has a native Falcon or SLH-DSA contract verifier. Sui is the only one with a stated (unpublished) SLH-DSA-SHA2-128s contract path.
- Open items to verify if needed: Soroban P30 mainnet date and real per-tx limits (`stellar network settings`); NEAR protocol 88 mainnet activation; CosmWasm CHANGELOG/wasmd release notes line-by-line; Sui framework source for `sui::` PQ natives; official CosmWasm gas page (redirect loop).

#### Sources (all read/fetched 2026-10-29 unless noted)
- https://www.sui.io/blog/suis-post-quantum-signature-schemes (fetched)
- https://www.sui.io/blog/making-sui-quantum-ready (search result only)
- https://cryptobriefing.com/sui-first-quantum-safe-devnet-transaction/ (fetched; article 2026-10-13)
- https://docs.sui.io/develop/cryptography/signing.md (search snippet only)
- https://docs.sui.io/concepts/tokenomics/gas-in-sui (fetched)
- https://www.analyticsinsight.net/news/sui-prepares-quantum-safe-accounts-without-new-wallet-addresses (search snippet only, secondary)
- https://hackernoon.com/sui-adopts-post-quantum-signature-schemes-in-move-toward-quantum-readiness (search snippet only, secondary)
- https://github.com/near/neps/pull/645 (fetched)
- https://github.com/near/nearcore/releases (fetched; 2.14.0 notes)
- https://bitcoinist.com/near-ships-nearcore-2-14-0-rc-with-protocol-and-database-upgrade/amp/ (fetched, thin)
- https://newreleases.io/project/github/near/nearcore/release/2.13.0 (search result only)
- https://github.com/near/nearcore/pull/16392 (search result only)
- https://www.diariobitcoin.com/blockchain/near-acelera-su-defensa-contra-el-riesgo-de-las-computadoras-cuanticas/ and youmind.com NEAR roadmap reposts (search snippets only, secondary)
- https://stellar.org/blog/foundation-news/introducing-the-quantum-preparedness-plan (fetched)
- https://github.com/stellar/rs-soroban-sdk/pull/2138 (fetched; merged 2026-10-19)
- https://github.com/stellar/stellar-protocol/blob/master/core/cap-0087.md (fetched)
- https://github.com/latticework-dev/soroban-ml-dsa (fetched; third-party, SELF-REPORTED)
- https://communityfund.stellar.org/submissions/receJ5whfzBRWXFdW (fetched; SELF-REPORTED, Soundness Falcon proposal)
- https://developers.stellar.org/docs/reference/resource-limits-fees and https://developers.stellar.org/docs/networks/resource-limits-fees.md (fetched; no numbers)
- https://docs.cosmos.network/sdk/next/keys/post-quantum-keys (fetched)
- https://docs.cosmos.network/sdk/next/upgrade/v0.55-release (fetched)
- https://cosmos.network/blog/post-quantum-ledger-security-20261 (search snippet only)
- https://github.com/CosmWasm/cosmwasm/releases (fetched)
- https://cosmwasm.cosmos.network/core/architecture/gas (not loaded: redirect; figures from search snippets)
- https://github.com/Finschia/wasmd/blob/main/README.md (search snippet only, block gas advice)
- https://api.osv.dev/v1/vulns/RUSTSEC-2024-0361 (search snippet only)

## Appendix: aptos-solana-ton (agent research, verbatim)

### PQ signature verification inside contracts: Aptos, Solana, TON (read 2026-10-29)

Search-engine level research only. Primary texts (AIP-137, SIMD-0416) returned HTTP 404 from the guessed GitHub URLs, so everything below on them is SECONDARY (news/blog). Marked [community] = self-reported / secondary, [est] = my estimate, not measured.

#### Summary
| Family | Contract-callable PQ verify today? | Status |
|---|---|---|
| Aptos | No evidence of any | AIP-137 (Dec 2025): optional SLH-DSA-SHA2-128s *account* signature, proposed; no deployment found |
| Solana | No | SIMD-0416 Falcon-512 verify syscall proposed (Apr 2026 roadmap); no activation found. Winternitz vault (hash-based OTS) exists as a user program, not a general verifier |
| TON | No evidence of any | Nothing found (no TVM opcode, TEP, or contract) |

#### 1. Aptos
- Exists: AIP-137 "post-quantum signatures" [community: mpost.io, cointelegraph, MEXC, Dec 2025]. Adds SLH-DSA (FIPS 205), variant SLH-DSA-SHA2-128s, as an OPTIONAL ACCOUNT authenticator (feature-gated in the VM), opt-in per account. Preliminary devnet "early 2026" per news; I found no confirmation it shipped, nor governance result. ML-DSA / Falcon: only mentioned as possible future additions. Sig 7,856 B [community, tokenpost.kr] matches FIPS 205 128s.
- Contract-callable: NOT stated anywhere. It is transaction auth, i.e. the "chain's native tx signature" - exactly what we do not need. No `aptos_std` PQ module found.
- Cost: gas pricing to be adjusted, no figures.
- Pure Move [est, not measured]:
  - SLH-DSA-SHA2-128s: ~ a few thousand SHA-256 calls (aptos_std::aptos_hash / std::hash sha2_256 are native); the 7,856 B sig fits as vector<u8>. Heavy but plausibly inside the per-tx gas cap if SHA-256 native cost dominates; needs a measurement. Most feasible of our four on Aptos.
  - Falcon-512: needs SHAKE256 hash-to-point (no native SHAKE256 found; Keccak256 and SHA3-512 natives exist, SHAKE would be pure Move Keccak-f = expensive) plus a 512-point NTT mod 12289; tens of thousands of Move ops [est]; probably fits the gas cap, risky.
  - ML-DSA-44/65: SHAKE128/256 expansion of matrix A (4x4 / 6x5 polys) + NTTs mod 8380417 with 256 coeffs: several hundred thousand ops [est]; likely over budget.
  - Precedent: our pure-Move P-256 (in-repo) shows heavy arithmetic is possible but P-256 is far cheaper than ML-DSA.
- Fit: slhdsa128s only if AIP-137 byte format = FIPS 205 sig/pk (pk 32 B); not callable natively; fndsa512 / mldsa44 / mldsa65 = no native, pure Move doubtful (SHAKE).

#### 2. Solana
- Exists:
  - SIMD-0416: syscall for Falcon-512 verification, "immediate next step" of the April 2026 roadmap by Solana Foundation, Anza, Jump (Firedancer) [community: KuCoin blog, single source reposted in many languages]. No syscall name, CU cost, byte encoding, or activation date found. Claimed: Firedancer Falcon verifier 2-3x faster than reference, under audit; Falcon-512 verify ~0.25x Ed25519 time (the same post also says "~4x faster": inconsistent) [community, unverified]. Falcon FIPS 206 still draft per the same sources.
  - ML-DSA-44 judged "too large for Solana" (sig 2,420 B) in that post; SLH-DSA not mentioned.
  - Winternitz Vault (Blueshift, running ~2 years per post; Jan 2025 press): hash-based WOTS one-time vault as a normal program, hash truncation used to fit CU and tx-size limits; no CU numbers found [community: quantumzeitgeist, thequantuminsider]. One-time signatures, not our schemes.
- Contract-callable: not today. If SIMD-0416 lands, a syscall is callable from programs (CPI-free), but is Falcon only, unknown encoding (round-3 vs FIPS 206, padded vs compressed) -> must be checked against the SIMD text before relying on it.
- Limits: 1.4 M CU per tx; tx size 1,232 B [from memory, standard Solana limit]. Our signatures cannot ride in one tx: Falcon sig 666 + pk 897 = 1,563 B already exceeds it; ML-DSA-44 sig 2,420 B, SLH-DSA 7,856 B far exceed. Needs chunk upload into an account, then verify instruction reading account data.
- Pure SBF [est]: sha256 syscall exists (~85 CU base + per-byte). SLH-DSA-128s with several thousand hashes: order of 0.5-1.5 M CU, borderline [est]. Falcon-512 (SHAKE256 in SBF + NTT, 4 KB stack frame limit, 32 KB heap): plausibly several hundred K to >1 M CU [est]. ML-DSA: likely over 1.4 M CU [est]. No measured on-chain Falcon/ML-DSA/SLH-DSA verify in an SBF program found.
- Fit: fndsa512 is the only kind with a native path (future, encoding unknown). Others: pure only, tight or infeasible.

#### 3. TON
- Exists: nothing found. No TVM opcode, TEP, or deployed contract for Falcon / ML-DSA / SLH-DSA / hash-based sigs. One MEXC table lists "quantum resistance research" for 2027, uncited [community]. TVM native crypto remains Ed25519 (CHKSIGNU/S), plus later additions (secp256k1/P-256/BLS12-381 per my memory, not re-verified here).
- Contract-callable: no. Cost/limits [from memory, not verified]: tx gas cap about 1 M gas units on basechain, sha256 as an instruction (HASHEXT variants incl. SHA-256/512, Keccak), data in cells (1,023 bits each, max ~2^16 cells per message limits) so 7,856 B sig needs ~65+ cells chained; cell traversal/load gas dominates.
- Pure TVM [est]: SLH-DSA-SHA2-128s thousands of HASHEXT calls plus cell slicing: probably over 1 M gas or close. Falcon / ML-DSA NTT with TVM integer ops (257-bit ints are fine for arithmetic) but ~tens of thousands to millions of ops at 18-26+ gas each: Falcon borderline-infeasible, ML-DSA infeasible [all est].
- Fit: none of our four has a native path; pure implementations unlikely to fit.

#### Cross-chain survey (quick)
- No single 2025-26 survey covering these three found. Related: arXiv 2510.10436 (PQC survey), 2508.17071 "Post-Quantum Blockchain: Challenges and Opportunities", 2609.24689 "Domain Specific Post Quantum Signatures for Blockchains" (not read), PQSigAbstract (Colorado, Jun 2026, Ethereum gas models for ML-DSA-44, Falcon-512, SLH-DSA-128f; abstract only).
- Side facts (not our families): Algorand falcon_verify AVM opcode since v4.3.0 Sep 2024 [Hacken, vendor]; Sui devnet 1.82.0 ML-DSA-65 native account + SLH-DSA-SHA2-128s Move vaults, 2026-10-12 [cryptobriefing]; Ethereum EIP-8052 Falcon precompile draft [ethereum-magicians]; TRON PQ migration issue java-tron #6793.

#### Conclusion
No family offers a contract-callable verifier for any of our four kinds today. Best case: Solana syscall for Falcon (proposal only). Plan on "relayer/off-chain-checked" or pure in-contract: only slhdsa128s (Aptos, maybe Solana) is plausible; Falcon borderline; ML-DSA unlikely on all three. Re-verify AIP-137 and SIMD-0416 primary texts before design decisions.

#### Sources (all read 2026-10-29; search-result level unless noted)
- https://mpost.io/aptos-proposes-aip-137-to-introduce-post-quantum-signatures-for-enhanced-security/ (fetched)
- https://cointelegraph.com/news/aptos-introduces-post-quantum-signatures-proposal (search snippet only)
- https://www.mexc.com/news/311053 , /303128 , /301843 , /302390 , /306948 (search snippets)
- https://tokenpost.kr/news/tech/316685 (snippet; 7,856 B figure)
- https://www.kucoin.com/blog/ae-solana-quantum-roadmap-falcon-selected-for-post-quantum-security (fetched)
- https://quantumzeitgeist.com/solana-develops-quantum-resistant-blockchain-technology-solution/ , https://thequantuminsider.com/2025/01/04/solana-takes-a-step-toward-pqc-era-with-quantum-resistant-vault/ (snippets)
- https://cryptobriefing.com/sui-first-quantum-safe-devnet-transaction/ (snippet)
- https://hacken.io/discover/falcon-post-quantum-signature-algorithm/ (snippet)
- https://scholar.colorado.edu/concern/reports/05741t70f ; https://ethereum-magicians.org/t/eip-8052-precompile-for-falcon-support/25860 ; https://arxiv.org/pdf/2510.10436 ; https://arxiv.org/pdf/2508.17071 ; https://arxiv.org/pdf/2609.24689 ; https://github.com/tronprotocol/java-tron/issues/6793 (snippets/partial)
- https://www.mexc.com/news/596456 (TON 2027 research line, snippet)
- 404 (not available): github aip-137.md, github SIMD-0416 md, docs.ton.org TVM changelog URL.
