# AI audit prompt, unit `evm-ua-verifiers` (DRAFT, 2026-11-16)

Contracts audit at the pre-freeze target (owner rulings 2026-11-12: pre-freeze -> audit -> audit fixes -> freeze). This file is
self-contained: run it as it is, with any tool (Codex, agy, a Claude workflow, Fable, ...). Placeholders the controller fills
before the run: `<TAG>`, `<SHA>`.

## 1. Role and limits

You are one AI reviewer of the SCaaS contracts audit. The audit is an AI audit (decision ARCH-POS-14): reports name the tool and
model that wrote them. Everything under audit is `UNAUDITED`. Nothing is live with value; every chain is test-only.

**STRICTLY READ-ONLY.** Allowed: reading files; `git -C T log | show | diff | grep | blame | rev-parse`; `grep` / `rg` / `sed -n` /
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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-evm-ua-verifiers.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.1-sol-high-evm-ua-verifiers.md`, `20261120-09-agy-gemini-4-argon-high-evm-ua-verifiers.md`). Use the tool's
  configured model and effort; do not override them. The unit name is always last.
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

Attackers: any EOA or contract; a relayer (may refuse or delay, must never forge or alter); a front-runner; a colluding key holder
or `msig` member; a malicious token, DEX, executor, verifier or factory caller; a role holder exceeding its grant; a replayer
across chain id, `chainUid`, registry generation, token, release, kind, operation or nonce lane; a chain whose gas, block limit or
precompiles differ from the SCaaS testnet. Goals: forgery, theft, an unbacked mint, a leak of amounts or balances, a permanent
lock, replay, griefing that blocks others, a call that cannot fit a block (EIP-8037, EIP-7825). Prefer a concrete call sequence
to a pattern match. Across units: every optimisation that replaced code with shared code, a library or a module (DELEGATECALL)
must keep behaviour; say so when it does not.

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
  never report the old 24 KiB limit. `WrappedToken`, `WrappedRegulatedToken` and the confidential regulated releases miss 60 / 70 M
  public blocks and deploy where the block takes them (owner 2026-11-05). Report a size only if it breaks EIP-8037 / EIP-7825 on
  a path a user must take.
- **Gas prices:** the schedule's provisional rows and calibration figures are the owner's (no timing runs here).
- The `UNAUDITED` label itself, Vietnamese source comments, style, naming, gas opinions that break no rule.
- Findings an earlier report below lists as fixed: report them only if the fix is wrong, incomplete or undone since; findings a
  triage marked REJECT or accepted (the ledgers named below): skip unless you have new evidence.

## 8. Your unit: `evm-ua-verifiers`

The signature verifiers of every UA kind and the curve, hash and encoding libraries they use, including the PQ verifiers (ML-DSA in Solidity and through the precompile, SLH-DSA, Falcon-1024) and the PQZ key verifier.

**Scope (paths under `T/`):**
- `smartcontracts/evm/src/ua/{MlDsa,MlDsaVerifyOnly,FnDsa,SlhDsa,Shake,PqNtt,PqUA,BlsMultiKeyData}.sol`, `src/ua/verifiers/`
  (added 2026-11-24: `MlDsaVerifyOnly.sol`, the verify-only ML-DSA verifiers a later registry generation uses for a
  predecessor's records, with the constructor probe that picks `PRECOMPILE` (CTR-UA-58, -68; spec
  `T/docs/superpowers/specs/2026-11-19-registry-verify-only-kinds.md` §2, §5, §7, §9): invariants 2 and 3 apply, and the probe
  must never take a candidate that answers `1` to a negative row; `BlsMultiKeyData.sol`, the `bls12381-multi` (0x0121) key-data
  forms (`compress`, `expand`, `point`; spec `2026-11-19-bls12381-multi.md` §2), inlined, unvalidated by design: invariants 1
  and 6 apply, and every caller must pass only key data `UAKinds.validateKeyData` accepted)
- `smartcontracts/evm/src/common/{Bls12381,HashToCurve,Ed25519,Sha512,CurveSigs,SigCheck,WebAuthnClientData,MultiSig}.sol`
- `smartcontracts/evm/src/pqz/PqzKeyVerifier.sol`

**Specifications and rules to read first:**
- `T/docs/contracts/accounts.md` (the kind table and each kind's verifier), decisions CTR-UA-14, -24, -39 (`mldsa87` only through a precompile), -40 (`fndsa1024` pure Solidity on every EVM chain), CTR-PQZ-28 (cached expanded keys)
- standards: FIPS 204 (ML-DSA, empty context; SCaaS signs `pq_msg = keccak256(TAG(kind) || ua_msg)`), FIPS 205, Falcon round-3 v1.2, RFC 8032, BIP-340, SEC 1 ECDSA (low-s), RIP-7212 / EIP-7951 P-256, WebAuthn L3, RFC 9380 hash-to-curve, EIP-2537, EIP-8355 layout for the ML-DSA precompile
- `T/smartcontracts/vectors/` KATs for each kind

**Invariants to check (beyond section 5):**
1. Each verifier accepts exactly its standard's valid signatures for the bound message and key: no malleability (s range, S < L, low-s), no identity / infinity / small-order points, subgroup checks, canonical encodings, length checks before parsing.
2. Precompile calls: success flag, exact return length and value, gas forwarded, the right address (`0x...5caa0012`, `...0013`, `...0014`), behaviour when the precompile is absent (empty return must never read as true).
3. ML-DSA path: precompile vs pure Solidity on a cached expanded key give the same verdict; `mldsa87` never verifies without the precompile; every pure-Solidity path a user must take stays <= 2^24 regular gas (EIP-7825).
4. Falcon-1024 (`FnDsa.sol`): norm bound, NTT arithmetic mod q, hash-to-point (SHAKE256), signature decoding (compressed form, padding, trailing bytes).
5. SLH-DSA and SHAKE: the parameter set claimed; tree indices and address encoding; no out-of-bounds read in assembly.
6. Group schemes: MuSig2 and FROST (secp256k1, bn254) verify against the aggregated key the registry stored; BLS pairing verifiers; the Zether Schnorr kind on BLS12-381.
7. WebAuthn: the client-data JSON parse (type, challenge equal to the bound digest, no ambiguity), authenticator flags, P-256 path.
8. Assembly: memory bounds, free-memory pointer, scratch space, return-data handling.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/pqz-core/research/code-review-2026-10-26/README.md` (whole-contract review at `64549aa4`) and `code-review-2026-10-19/README.md`
- `T/docs/research/security-review-record.md` (index of every review, and what no review covered)
- `scratchpad/review-ua-mtx-merge/` (A-regulated, B-metatx-ua, C-pqz-zether, D-factory-gov-dex-pqchat, recheck-*, recheck2-*)
- `T/docs/research/zether-msm-crypto-review.md`
- `scratchpad/review-3zh/20261115-12-fable-fable5.2-high-spec-mldsa.md`

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- the tag's closing gate summary under `T/smartcontracts/evm/runs/` (every forge directory at the default set, the set-sensitive tests at the other three sets)
- `T/smartcontracts/evm/runs/2026-11-15-3zh-core-g2.txt`, `2026-11-15-burner-wrap-caps.txt`, `2026-11-15-pqz-three-keys-round/summary.txt`, `2026-11-13-fix3-chainuid/summary.txt`, `2026-11-14-msig-members/mutants.txt`, `2026-11-15-3zh-mldsa.txt`
- `T/smartcontracts/evm/size-baseline.json` with `T/scripts/size_gate.py` (the size ratchet, ceiling 64 KiB)
- `T/pqz-core/nethermind/runs/2026-11-15-mldsa87-calib.txt` (the ML-DSA prices the verifiers rely on)

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | Each kind's verifier against the kind table of `docs/contracts/accounts.md` and CTR-UA-14, -24, -39, -40, CTR-PQZ-28: the kind id, the key and signature lengths, the precompile address, the claimed parameter set. |
| 2 | Cryptography | Leads this unit. Read each primitive against its standard: ML-DSA (`MlDsa.sol`, `MlDsaVerifyOnly.sol`, `PqNtt.sol`, `Shake.sol`; FIPS 204, empty context, `pq_msg = keccak256(TAG(kind) || ua_msg)`), Falcon-1024 (`FnDsa.sol`; round-3 v1.2 norm bound, hash-to-point, decoding), SLH-DSA (`SlhDsa.sol`; FIPS 205 address encoding), Ed25519 (`Ed25519.sol`, `Sha512.sol`; RFC 8032, S < L, canonical points), BIP-340 (`verifiers/Bip340*.sol`), secp256k1 ECDSA low-s (`SigCheck`, `CurveSigs`), P-256 / WebAuthn (`P256*.sol`, `WebAuthnClientData.sol`), MuSig2 / FROST (secp256k1, bn254), BLS (`Bls12381.sol`, `HashToCurve.sol` RFC 9380, `PairingVerifiers.sol`, `BlsMultiBls12381Verifier.sol`), `PqzKeyVerifier.sol`; small-order and identity points, subgroup checks, malleability; domain tags per kind. |
| 3 | Security | A signature for one kind accepted under another (kind confusion, tag reuse); a verifier that accepts an empty precompile return as true; a WebAuthn challenge that is not the bound digest; replay of a group signature across sessions; `PqzKeyVerifier` accepting a key for another UA or version. |
| 4 | Rules that do not bend | No chain assumption: precompile absent on a customer chain gives a named refusal or the software path (ARCH-POS-18), `mldsa87` only through a precompile as CTR-UA-39 rules; every pure-Solidity path a user must take within 2^24 regular gas (EIP-7825); one rule on every chain. |
| 5 | Secrets and privacy | N/A for secrets (verifiers hold none); timing is public on chain. Say if any verifier writes a key or a message to an event. |
| 6 | Robustness and denial of service | Assembly reads out of bounds on short input; unbounded loops over signature or key length; the worst-case gas of a valid-looking invalid signature (Falcon decode, SLH-DSA tree walk); ML-DSA uncached verify about 19.0 M against 2^24. |
| 7 | Failure handling | Every malformed input refused by name or `false`, never a revert that the caller maps to success; return-data handling of every precompile call (success flag, exact length, value). |
| 8 | Consistency across languages and layers | Each verifier accepts exactly the vectors clientkeys (`pq.js`, `ua-verify.js`, `webauthn.js`), `ua-rs` (`pq.rs`, `falcon.rs`, `verify.rs`, `musig2.rs`, `frost.rs`) and `T/smartcontracts/vectors/` produce, and refuses their negative rows; the precompile path and the Solidity path give the same verdict on one cached key; the Soroban verifier (`smartcontracts/soroban/contracts/ua-registry/src/verify.rs`) agrees where the same kind exists. |
| 9 | Contract specifics | Library linking (`DELEGATECALL` vs internal), the size gate for `MlDsa` / `FnDsa` / `SlhDsa`, gas pins of the verify tests with old -> new figures; immutability of verifier addresses in the registry. |
| 10 | Performance and cost | Verify gas per kind against the figures `docs/contracts/accounts.md` quotes and `T/pqz-core/nethermind/runs/2026-11-15-mldsa87-calib.txt`; who pays the ML-DSA cache write. |
| 11 | Interfaces and misuse | N/A: libraries with no user-facing API beyond the registry's; say if a verifier's interface lets a caller skip the length check. |
| 12 | Tests | KATs per kind read by the forge tests; a negative test per refusal that can fail (mutate one byte of key, message and signature in turn); the identity / small-order / non-canonical rows exist for Ed25519, BLS and P-256. |
| 13 | Operations and the supply chain | N/A for dependencies (pure Solidity, no imported crypto library beyond what `smartcontracts/evm/lib/` pins: say if one is); SPDX headers. |

## 9. Report format (Markdown, English)

```
# evm-ua-verifiers: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### UAV-1 [P1] <short title>
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
refusal that blocks a legitimate user, a missing check with a defence elsewhere; **P3** low impact; **info** a note with a security
angle. No padding: no style findings, no generic advice. A claim that something is sound is a result too: say what you checked.
Say "no findings" explicitly if there are none.

Every finding names its dimension number (ARCH-POS-22, `T/docs/review.md` §3); a finding that touches several names
the main one first. Under "Not covered", name each row of the dimension table you did not reach.
