# AI audit prompt, unit `crypto-signatures` (DRAFT, 2026-11-24)

Contracts audit at the pre-freeze target (owner rulings 2026-11-12: pre-freeze -> audit -> audit fixes -> freeze). This file is
self-contained: run it as it is, with any tool (Codex, agy, a Claude workflow, Fable, ...). Placeholders the controller fills
before the run: `<TAG>`, `<SHA>`.

## 1. Role and limits

You are one AI reviewer of the SCaaS contracts audit. The audit is an AI audit (decision ARCH-POS-14): reports name the tool and
model that wrote them. Everything under audit is `UNAUDITED`. Nothing is live with value; every chain is test-only.

**STRICTLY READ-ONLY.** Allowed: reading files; `git -C T log | show | diff | grep | blame | rev-parse`; `grep` / `rg` / `sed
 -n` /
`cat`; `python3 scripts/docs_check.py resolve <id>` (it only prints). Not allowed: any build, test, fuzz, benchmark, gas or timing
run (`forge`, `cargo`, `npm`, `dotnet`, `anvil`, `docker`, `gate.sh`, `at-set.sh`, which rewrites `PqzSet.sol` in place); any
edit, file creation (except the one result file below), deletion, commit, checkout, stash or push; any network access to a
chain or RPC. The machine runs other heavy jobs: a large build here gets the terminal killed.

## 2. Target

- Run from the root of the main checkout of the SCaaS repository (public).
- Code under audit: the detached worktree `.claude/worktrees/audit-<TAG>` at tag `<TAG>`, commit `<SHA>`. Below, `T/` means that
  directory. Read code and docs **only** under `T/`; the main checkout's own tree may be on another branch.
- First step: `git -C .claude/worktrees/audit-<TAG> rev-parse HEAD` must print `<SHA>`. If it does not, stop and write only that.
- Prior reports named below live in the main checkout's `scratchpad/` (git-ignored, local; not under `T/`).
- The whole unit is in scope, including code that did not change since an earlier review.

## 3. Result file

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-crypto-signatures.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-crypto-signatures.md`, `20261120-09-agy-gemini-4-argon-high-crypto-signatures.md`). Use the tool's
  configured model and effort (read from its config at run time; the owner may change any reviewer's model); do not
  override them. Name that model in the report's title line; the ledger records it. The unit name is always last.
- If your sandbox cannot write files, print the whole report as your final message; the runner saves it under that name.

## 4. Which source wins

1. Owner rulings: entries in `T/docs/decisions.md` with `owner: yes`, and their dated `Change` lines. They override code that has
   not caught up: **a difference between code and an owner ruling is a finding against the code.**
2. Component docs: `T/docs/contracts/`, `T/docs/clients/`, `T/docs/node/`, `T/docs/networks/`, `T/docs/integration.md`.
3. Code, for pinned byte formats only; `T/smartcontracts/vectors/` is the authority for bytes.
4. `T/docs/history/`; 5. `T/docs/research/`: background only.

`T/docs/decisions.md` is about 1.8 MB: search it by rule id (`### CTR-UA-37`, `<a id="...">`), never read it whole. An old id in a
comment resolves with `python3 scripts/docs_check.py resolve <id>`. Follow a stated rule as stated; do not propose reopening it.

## 5. Absolute rules (a break of any one is at least P1)

1. **Never lose ciphertext.** PQZ and Zether ciphertexts stay in contract state, never only a hash plus calldata or events (logs
   and history expire; state does not).
2. **No decryption oracle** (ARCH-POS-13). Nothing decrypts a ciphertext someone else chose and leaks anything about the result
   (a revert, a status, an error code, a timing, a signed verdict). Scoped exceptions are under section 7.
3. **Explicit parameters** (CTR-MTX-28, CTR-MTX-29, CTR-UA-36). Named, typed parameters and typed EIP-712, one entry point per
   operation; no packed `bytes` holding several fields, no hex bundles. Only a single crypto object stays `bytes` (a proof, a
   ciphertext, a key, a signature). Node JSON uses named fields; the old hex forms are refused (`HEX_ARGS_REFUSED`,
   `HEX_DATA_REFUSED`).
4. **Every state-changing `mtx*` is relayable**, with a fee of 0 too. A relayer can refuse or delay, never forge or alter.
5. **No EIP-7702.** An EOA signs with its own key and runs no code; a 7702 delegate never authorises (no ERC-1271 through it) and
   a delegated caller is refused (CTR-UA-24 and its Change of 2026-10-30, NET-EVM-07).
6. **No assumption about a chain:** no gas price 0, no block gas limit of ours; the PQZ / ML-DSA precompiles may ship to customer
   chains. **One rule on every chain:** never a rule split by L1, L2 or chain kind.
7. **EIP-8037 inclusion:** a transaction fits only if its regular gas plus its state gas fit the block gas limit;
   `gas_used = max(...)` is accounting, not inclusion. Do not conclude from it that a large deploy or call fits.
8. **EIP-7825 cap:** regular gas per transaction is at most 2^24 = 16,777,216 on Osaka and later (Nethermind enforces it, in
   `eth_call` too). forge / anvil 1.8.5 do not enforce it by default, so a path that is green in `forge test` above 2^24 fails on
   a chain (example found 2026-11-15: pure-Solidity ML-DSA-65 verify on an uncached key, about 19.0 M).
9. **Nothing deployed is upgraded.** Contracts are immutable; versions live in the factory's catalogue.
10. **Authorization lives in contracts.** Off-chain checks are extra, never the only guard. Fail closed: a refusal, a named error,
    zero sends.
11. **Zether is not PQZ** (separate systems, separate rules); **NEAR is not Algorand**.

A green gate is not evidence of soundness: three P0s in this repository sat behind green tests. Do not trust a test because it
passes; check that a negative test can fail. When you find a transcript, statement, digest or signature bug, check the same class
everywhere it can recur (C, Rust, wasm32, generic and specialised verifiers, Solidity, clients) and list each place.

## 6. Threat model

The whole system, read across its layers: the contracts (EVM, and the Soroban registry where a rule claims one rule on every
chain), `pqz-core` and the Nethermind precompiles, the signers (`ua-rs`, clientkeys and every `ua-*` wrapper), the SDK and its
bindings, the app cores, and the open node. Attackers: any EOA or contract; a relayer (may refuse, delay or reorder, never
forge or alter); a front-runner; a malicious subject, holder or group member; a malicious admin or role holder exceeding its
grant; a colluding key holder or `msig` member; a party that left or was removed; a malicious token, DEX, executor, verifier,
gateway, bundler or node; an RPC endpoint that lies, lags or forks, alone or with others; a malicious app calling the SDK or a
binding out of order; a local reader of logs, errors, metrics, stores or backups; a replayer across chain id, `chainUid`,
registry generation, token, release, kind, operation, purpose or nonce lane; a chain whose gas, block limit, precompiles or
host functions differ from the SCaaS testnet. Goals: forgery, theft, an unbacked mint, a leak of amounts, balances, keys or
plaintext, a permanent lock, replay, griefing that blocks others, a call that cannot fit a block (EIP-8037, EIP-7825), a
decryption oracle through any layer, a secret out of its place, and **a fork between layers**: a record the contract accepts
that clients cannot follow, a record clients build that the contract refuses, or a check that one path makes and its sibling
skips. Prefer a concrete call sequence to a pattern match. Across units: every optimisation that replaced code with shared code,
a library or a module (DELEGATECALL) must keep behaviour; say so when it does not.

## 7. Do not report (accepted by the owner; skip unless the code does something worse than the accepted behaviour)

- **Hybrid wrapped tokens:** a minter may mint unbacked units and unwrap them against the reserve users deposited (CTR-GOV-30,
  CTR-TOK-05 "not claimed on a hybrid"; owner 2026-11-13, USDC -> VND CBDC).
- **`BURNER`:** holders cannot stop a user sending to an unspendable address (not a burn; CTR-GOV-29).
- **Own-key `OFFCHAIN` PQZ token** (`pqzOwnKey = true`, `pqzOpening = false`): whoever can make that token's verifier sign can
  recover that token's key; the risk lies in that token only (ARCH-POS-13 Change 2026-11-13, CTR-PQZ-37).
- **The hybrid KEM** (ML-KEM-1024 + X25519, IND-CCA by its combiner): a decapsulation of a sender-chosen ciphertext and its
  one-shot AEAD are outside ARCH-POS-13 (Change 2026-11-13). Still report any PQZ or Zether key applied to a value that was
  not first shown well formed by re-encryption and byte comparison.
- **Shared-key `OFFCHAIN` class (class 2):** `msig` refused and op 7 unsupported at first; the auditor guarantee as ruled (an
  honest recipient cannot spend an unreadable credit; collusion leaves a named unreadable leg) (three-key spec, Q8 / Q9).
- **CTR-DEX-19:** `dex` must be a contract, nothing more; a contract made to look like a DEX can report any fill and take the
  signed amount (owner-accepted residual risk).
- **CTR-TOK-31:** R10 Sybil on the net wrap / unwrap rule; Q17 (a) the shielded id of a confidential kind is not always the
  public id (disclosed).
- **Classical Zether:** handing `s` over opens every leg, decoys included (CTR-ZTH-37); the sender may leave the auditor out of
  one transfer (CTR-ZTH-42); `fund` burns public Zether units from the caller (CTR-ZTH-35).
- **`msig`:** one with no `pop` is unusable until enough weight accepted, on each registry (CTR-UA-37).
- **`fndsa1024`:** built on the Falcon round-3 specification v1.2, the FIPS 206 risk accepted (CTR-UA-40 Q1).
- **`PqChat`:** a member can take the slot first and make the admin rekey again (CTR-CHAT-09, O2); what an open topic accepts
  cannot be removed, and its state-gas cost per KiB is accepted (CTR-CHAT-16, D20).
- **`OPERATOR_TRANSFER` / grants:** a `WHOLE` holder is unbounded by design (CTR-GOV-20).
- **PQZ rollover floor C0-6** of the 2026-10-26 review: accepted, spec corrected (CTR-PQZ-08 (a)).
- **Sizes and deploy gas:** the code-size ceiling is 64 KiB (Amsterdam / Glamsterdam is required on every chain, NET-EVM-06):
  never report the old 24 KiB limit. `WrappedToken`, `WrappedRegulatedToken` and the confidential regulated releases miss 60 /
  70 M
  public blocks and deploy where the block takes them (owner 2026-11-05). Report a size only if it breaks EIP-8037 / EIP-7825 on
  a path a user must take.
- **Gas prices:** the schedule's provisional rows and calibration figures are the owner's (no timing runs here).
- The `UNAUDITED` label itself, Vietnamese source comments, style, naming, gas opinions that break no rule.
- Findings an earlier report below lists as fixed: report them only if the fix is wrong, incomplete or undone since; findings a
  triage marked REJECT or accepted (the ledgers named below): skip unless you have new evidence.

## 8. Your unit: `crypto-signatures`

The signature schemes of every UA kind, their purposes and domains, read vertically through the contracts, the precompile, the
Soroban host, `ua-rs`, clientkeys and the node's kind rules.

**How to read (dimension 2, read vertically, `T/docs/review.md` §1-§2).** One primitive at a time, through every
implementation and layer listed below: C, Rust, wasm32, JS, Solidity, C#, the generic and the specialised verifier, the
signer and every verifier. First read the standard or the spec's mathematics; then each implementation against it; then the
implementations against each other on the shared vectors. **A bug class found once is checked everywhere it can recur**, and
the finding lists every place. Where a primitive comes from a library (`ml-dsa`, `@noble/post-quantum`, .NET `MLDsa`, a
Soroban host function), audit our use of it (parameters, encodings, context, lengths, error handling), not the library
itself, and name its pinned version.

This unit leads dimension 2 for signatures; units `evm-ua-verifiers`, `ua-rs-sign` and `nethermind-precompiles` audit each layer
alone.

**Primitives and every implementation (paths under `T/`; find any implementation this list misses and name it):**
- **ML-DSA-44 / -65 / -87** (kinds 0x0130, 0x0131, 0x0134; FIPS 204, empty context, `pq_msg = keccak256(TAG(kind) ||
  ua_msg)`): Solidity `smartcontracts/evm/src/ua/MlDsa.sol`, `MlDsaVerifyOnly.sol`, `PqNtt.sol`, `Shake.sol`, `PqUA.sol`; the
  cached expanded key (CTR-PQZ-28) `clients/ua-rs/src/mldsa_cache.rs`, `smartcontracts/vectors/ua/gen_mldsa_cache.mjs`; the
  precompile `pqz-core/nethermind/Nethermind.Pqz/MlDsaPrecompile.cs`, `MlDsaKat.cs` (.NET `System.Security.Cryptography.MLDsa`,
  EIP-8355 layout, addresses `0x...5caa0012` to `...0014`); Soroban `smartcontracts/soroban/contracts/ua-registry/src/verify.rs`
  (host `ml_dsa_44_verify`, `ml_dsa_65_verify`; `mldsa87` refused there until the Soroban round: check against ARCH-POS-18);
  `ua-rs` `src/pq.rs` (crate `ml-dsa` =0.1.1), `src/wallet/pqsign.rs` (hedged signing); clientkeys `src/pq.js`
  (`@noble/post-quantum` 0.7.1 `ml_dsa44` / `ml_dsa65` / `ml_dsa87`), `src/uakey.js`, `src/ua-verify.js`
- **Falcon / FN-DSA** (`fndsa512` 0x0132, `fndsa1024` 0x0135; round-3 specification v1.2, padded form; FIPS 206 risk accepted,
  CTR-UA-40 Q1): Solidity `src/ua/FnDsa.sol` (pure Solidity on every EVM chain, no precompile: CTR-UA-40); `ua-rs`
  `src/falcon.rs` over the vendored PQClean `vendor/pqclean-falcon-seeded` (repository root) (no Falcon on wasm32: say what a wasm caller gets);
  clientkeys `src/pq.js` (`falcon512padded`, `falcon1024padded`); Soroban: the kind tag in `ua-registry/src/digest.rs` (say
  whether Soroban verifies or refuses it)
- **SLH-DSA-SHA2-128s** (`slhdsa128s` 0x0133; FIPS 205): Solidity `src/ua/SlhDsa.sol`; `ua-rs` `src/pq.rs` (crate `slh-dsa`
  =0.2.0-rc.5, `slh_verify_internal`: check the message form against FIPS 205's external interface and the contract);
  clientkeys `src/pq.js` (`slh_dsa_sha2_128s`)
- **Ed25519** (RFC 8032; S < L, canonical points, small-order keys): Solidity `src/common/Ed25519.sol`, `Sha512.sol`,
  `src/ua/verifiers/Ed25519Verifier.sol`; `ua-rs` (`ed25519-dalek` =2.2.0: `src/wallet/sign.rs`, `src/verify.rs`); clientkeys
  (`@noble/curves`: `src/ua.js`, `src/uakey.js`); Soroban `verify.rs` (`ed25519_key_ok`, host `ed25519_verify`); the native
  families' Ed25519 (`clients/ua-rs/src/families/{solana,sui}.rs`, `clients/clientkeys/src/fam/`, `near.js`)
- **secp256k1** ECDSA (SEC 1, low-s, RFC 6979) and BIP-340: Solidity `src/common/SigCheck.sol`, `CurveSigs.sol`,
  `src/ua/verifiers/Secp256k1Verifier.sol`, `Bip340.sol`, `Bip340Verifier.sol`; `ua-rs` (`k256` =0.14.0: `src/wallet/sign.rs`,
  `signer.rs`, `tx.rs`); clientkeys (`@noble/curves`: `src/evm.js`, `src/ua.js`); Soroban `verify.rs` (`secp256k1_recover`,
  `check_evm_eoa`)
- **P-256 / WebAuthn** (RIP-7212 / EIP-7951, WebAuthn L3): Solidity `src/ua/verifiers/P256Verifier.sol`, `P256Precompile.sol`,
  `WebAuthnP256Verifier.sol`, `src/common/WebAuthnClientData.sol`; `ua-rs` (`p256` =0.14.0, `src/wallet/webauthn.rs`);
  clientkeys `src/webauthn.js`, `passkey-signer.js`; Soroban `ua-registry/src/webauthn.rs`
- **MuSig2 / FROST / DKG** (BIP-327, RFC 9591): Solidity `src/ua/verifiers/Musig2Secp256k1Verifier.sol`,
  `Musig2Bn254Verifier.sol`, `FrostSecp256k1Verifier.sol`, `FrostBn254Verifier.sol`; `ua-rs` `src/musig2.rs`, `src/frost.rs`
  (`frost-secp256k1` =3.0.0), `src/groups.rs` and their vector files (`clients/ua-rs/tests/key_agg_vectors.json`,
  `nonce_gen_vectors.json`, `sign_verify_vectors.json`, `rfc9591_e5.json`, `zf_frost_secp256k1_dkg.json`); clientkeys group
  key data (`src/ua.js`, `src/uakey.js`); Soroban `ua-registry/src/lib.rs` (group layouts), `ua-common/src/lib.rs`
- **BLS** (BLS12-381 and bn254 multi-signatures, RFC 9380 hash-to-curve, EIP-2537): Solidity `src/common/Bls12381.sol`,
  `HashToCurve.sol`, `src/ua/verifiers/PairingVerifiers.sol`, `BlsMultiBls12381Verifier.sol`, `src/ua/BlsMultiKeyData.sol`;
  `ua-rs` `src/bls_multi.rs`; clientkeys `src/bls-multi.js`; SDK `clients/scaas-sdk/src/op/bls_multi.rs`
- **Purposes and domains**: `src/ua/UAKinds.sol` (`uaMessage(kind, purpose, typedDigest)`, `TAG(kind)`, the purpose
  constants, `uaAuthDigest`), `src/common/SaltedEIP712.sol`; `ua-rs` `src/wallet/uasig.rs`, `src/wallet/eip712.rs`; clientkeys
  `src/ua.js`, `src/ua-verify.js`; the node's kind rules (`scaas-node/src/guard.rs`); the verifier service's
  `purpose_pqz_verdict` (`scaas-pqz-verifier/src/lib.rs`)

**Specifications and standards to read first:**
- FIPS 204, FIPS 205, Falcon round-3 v1.2, RFC 8032, SEC 1, RFC 6979, BIP-340, BIP-327, RFC 9591, RIP-7212 / EIP-7951,
  WebAuthn L3, RFC 9380, EIP-2537, EIP-8355
- `T/docs/contracts/accounts.md` (the kind table), `T/docs/clients/signers-clientkeys.md`, `T/pqz-core/nethermind/README.md`;
  decisions CTR-UA-14, -24, -36, -39, -40, CTR-PQZ-28, ARCH-POS-18

**Invariants to check (beyond section 5; each a finding when it fails):**
1. Each verifier accepts exactly its standard's valid signatures for the bound message and key, and the signer produces
   only those: malleability (low-s, S < L, Falcon's norm and padding, SLH-DSA's address encoding), identity, infinity and
   small-order points, subgroup checks, canonical encodings, lengths checked before parsing, in every implementation above.
2. The message each kind signs is the same bytes everywhere: `pq_msg` and `TAG(kind)` for the PQ kinds, the ECDSA prehash,
   the BIP-340 tag, the WebAuthn challenge (equal to the bound digest, client-data JSON parsed without ambiguity), the group
   schemes' session message; FIPS 204's empty context and FIPS 205's message form as the contract verifies them.
3. Purposes and domains: every purpose constant distinct and closed (`requirePortable`), every EIP-712 domain with salt
   `chainUid`, no signature valid under two purposes or two kinds; `0x0142` a scheme, never an id kind.
4. Nonces and randomness: RFC 6979, BIP-340 aux, hedged ML-DSA, Falcon from the seed, MuSig2 / FROST secret nonces consumed
   and never reused or exported; DKG complaints and rogue-key defence.
5. Verdict parity: the ML-DSA precompile, the pure-Solidity path on a cached key, the Soroban host function, `ua-rs` and
   clientkeys give the same verdict on every shared vector, negative rows included; the precompile's absence never reads as
   true, and the software path stays within 2^24 regular gas on a path a user must take.
6. Constant time where a secret is used (signing in `ua-rs` and clientkeys; no secret-dependent branch in the vendored Falcon
   wrapper's length checks).

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/docs/research/security-review-record.md` (index of every review, and what no review covered)
- `T/pqz-core/research/code-review-2026-10-26/README.md`, `code-review-2026-10-19/README.md`
- `scratchpad/review-ua-mtx-merge/` (A to E, recheck-*, recheck2-*), `scratchpad/review-3w/` (`triage.md`),
  `scratchpad/review-3zh/`, `scratchpad/review-t21/` (`ledger.md`, O1-O8), `scratchpad/sdk-complete-review/`,
  `scratchpad/sdk-review-20261123-0621/` (T26, `STATUS.md`), `scratchpad/pqvault-review/`,
  `scratchpad/treekem-review-20261123-1426/`
- the reports of the layer units of this round under `scratchpad/ai-audit/results/` when they exist: read them for leads,
  do not repeat their findings; a finding of yours that a layer unit already reported names that unit's id
- `T/docs/research/zether-msm-crypto-review.md`, `T/docs/research/pqz-specialised-verifier.md` §7,
  `docs/reviews/specs/2026-10-13-pqz-sv-review.md` in the main checkout (git-ignored, local), the Fable crypto reviews named in
  `T/docs/research/security-review-record.md`

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/smartcontracts/evm/runs/2026-11-18-prefreeze-matrix-summary.txt`, `2026-11-19-pr-a-matrix-summary.txt`, and the tag's own
  closing matrix (every forge directory at the default set, the set-sensitive tests at the other three sets, node and e2e,
  clients, vectors)
- `T/pqz-core/runs/gate/3zh-g2-<set>-summary.txt` for the four sets

**Also accepted for this unit (do not report):** `fndsa1024` on Falcon round-3 v1.2 (CTR-UA-40 Q1); `crypto-bigint`
 RUSTSEC-2026-0387 through `frost-secp256k1` =3.0.0 (known, `deny.toml`); an `msig` with no `pop` unusable until accepted
 (CTR-UA-37).

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CTR-UA-14, -39, -40, CTR-PQZ-28 and the kind table, read for each implementation. |
| 2 | Cryptography | **Leads this dimension for its family, read vertically.** Section 8's invariants 1-6 for each primitive, every implementation against its standard and against each other. |
| 3 | Security | Kind confusion, a signature valid for two purposes or chains, a verifier that reads an empty precompile return as true, a group signature replayed across sessions. |
| 4 | Rules that do not bend | Maximal support (ARCH-POS-18): a kind missing a precompile or host function verifies in software or is refused only with the owner's confirmation (`mldsa87` on Soroban, Falcon on wasm32); one rule on every chain; no EIP-7702. |
| 5 | Secrets and privacy | N/A for verifiers (public data); for signers: keys, nonces and seeds only in the arena, never in an error or log. |
| 6 | Robustness and denial of service | Short or oversized keys and signatures in every parser; the worst-case verify gas (Falcon decode, SLH-DSA, ML-DSA uncached about 19.0 M against 2^24). |
| 7 | Failure handling | A malformed signature refused by name or `false` in every layer, never an exception mapped to success. |
| 8 | Consistency across languages and layers | The same verdict in every implementation on every shared vector, negative rows included (invariant 5); the vectors every language reads (`T/smartcontracts/vectors/ua/`, `typed/`, the ua-rs vector files). |
| 9 | Contract specifics | The Solidity verifiers' size, library linking and gas pins; the precompile addresses as constants. |
| 10 | Performance and cost | Verify gas per kind and chain against the docs; sign time on mobile and wasm. |
| 11 | Interfaces and misuse | Signer APIs that take a caller RNG where the spec forbids it; a verify API that skips the length check. |
| 12 | Tests | KATs and negative rows per kind read by every implementation; malleability and small-order rows; mutants of each check. |
| 13 | Operations and the supply chain | Library pins (`ml-dsa` =0.1.1, `slh-dsa` =0.2.0-rc.5, `ed25519-dalek` =2.2.0, `k256` / `p256` =0.14.0, `frost-*` =3.0.0, `@noble/*` 2.4.0, `@noble/post-quantum` 0.7.1, the vendored PQClean Falcon), their advisories and licences. |

## 9. Report format (Markdown, English)

```
# crypto-signatures: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### CSG-1 [P1] <short title>
- Where: T/<path>:<line>[-<line>] (every place, if the class recurs)
- Rule or invariant: <rule id or invariant from section 8>
- Dimension: <number and name, from the dimension table of section 8 (`docs/review.md` §1)>
- Claim: <one or two sentences>
- Failure scenario: <concrete inputs or call sequence -> wrong outcome (forgery, loss, leak, lock, crash, divergence)>
- Evidence: <quoted code, doc or standard clause, and the reasoning>
- Fix: <concrete change>
- Confidence: CONFIRMED (traced end to end) | PLAUSIBLE (say what is not traced)

## Earlier findings in this unit
<for each finding of the prior reports in section 8 that touches this unit: closed / open / regressed, with file:line>

## Checked and sound
<what you checked and found holding, with file:line, so a reader knows the coverage>

## Not covered
<what you did not reach>
```

Severity: **P0** forgery, theft or loss of funds, an unbacked mint, a break of privacy of amounts, balances or keys, a permanent
lock, a decryption oracle, a lost ciphertext, a consensus split; **P1** a break of a section-5 rule or an owner ruling with a
real path, a relayer able to alter an intent, a DoS of a whole contract or node; **P2** a bounded loss, griefing, a wrong
refusal that blocks a legitimate user, a missing check with a defence elsewhere; **P3** low impact; **info** a note with a
security
angle. No padding: no style findings, no generic advice. A claim that something is sound is a result too: say what you checked.
Say "no findings" explicitly if there are none.

Every finding names its dimension number (ARCH-POS-22, `T/docs/review.md` §3); a finding that touches several names
the main one first. Under "Not covered", name each row of the dimension table you did not reach.
