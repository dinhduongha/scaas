# AI audit prompt, unit `crypto-pqz` (DRAFT, 2026-11-24)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-crypto-pqz.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-crypto-pqz.md`, `20261120-09-agy-gemini-4-argon-high-crypto-pqz.md`). Use the tool's
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

## 8. Your unit: `crypto-pqz`

The PQZ proof systems read vertically: statements and relations, transcripts, `pqzl`, `pqzh`, `stmt`, the proofs in C, Rust and
wasm, the on-chain answer (precompile and OFFCHAIN verdict), the parameter sets and the three-key model.

**How to read (dimension 2, read vertically, `T/docs/review.md` §1-§2).** One primitive at a time, through every
implementation and layer listed below: C, Rust, wasm32, JS, Solidity, C#, the generic and the specialised verifier, the
signer and every verifier. First read the standard or the spec's mathematics; then each implementation against it; then the
implementations against each other on the shared vectors. **A bug class found once is checked everywhere it can recur**, and
the finding lists every place. Where a primitive comes from a library (`ml-dsa`, `@noble/post-quantum`, .NET `MLDsa`, a
Soroban host function), audit our use of it (parameters, encodings, context, lengths, error handling), not the library
itself, and name its pinned version.

This unit leads dimension 2 for PQZ; units `pqz-core-pqzl`, `pqz-core-pqzh-stmt-ffi`, `pqz-core-params-vectors`,
`nethermind-precompiles` and `evm-tokens-pqz` audit each layer alone. Do not repeat their per-layer findings; find what only a
vertical read shows.

**Primitives and every implementation (paths under `T/`; find any implementation this list misses and name it):**
- **Statements and relations** (`R_REG`, `R_TX`, `R_TX0`, `R_TXS`, `R_TXS0`, `R_TXM`, `R_BURN`, `R_DS`, `R_DR`, refresh,
  disclosure with its kind byte): builders `pqz-core/stmt/src/` (`lib.rs`, `sets.rs`); Solidity
  `smartcontracts/evm/src/pqz/PqzLayer.sol`,
  `PqzCore.sol`, `PqzCt.sol`, `PqzTransferLib.sol`, `PqzBurnLib.sol`, `PqzSafety.sol` (the bytes the contract packs); clients
  `clients/ua-rs/src/facade/pqz.rs`, `facade/pqz/proven.rs` (statements rebuilt from state),
  `clients/scaas-sdk/src/confidential/pqz.rs`,
  `pqz_debit.rs`; the verifier service `scaas-pqz-verifier/src/lib.rs` (statement lengths, the token's own statement view)
- **Transcripts and Fiat-Shamir**: `pqzl` Rust `pqz-core/pqzl/rust/src/proof/` (`tbox`, `quad`, `abdlop`), `rust/src/arith/`,
  `rust/src/rand/`; the C oracle `pqz-core/pqzl/src/*.c`, `pqzl/lazer/`; `pqzh` Ligero `pqz-core/pqzh/ligero/src/transcript.rs`,
  `merkle.rs`, `ligero.rs`
- **Verifiers, generic and specialised**: Rust general (`pqzl/rust/src/proof/`), Rust specialised `pqzl/rust/src/sv.rs`
  (`setup`, `verify_body`), C general `pqzl/lazer/lnp-tbox.c`, `lnp-quad.c`, `lnp-quad-many.c`, `dcompress.c`, C specialised
  `pqzl/src/pqz_sv.c`; Ligero verifier `pqzh/ligero/src/ligero.rs`; dispatch `pqz-core/ffi/src/lib.rs`, `ffi/src/pqzl.rs`,
  `ffi/src/pqzl/{c,rust}.rs`, `ffi/src/pqzh.rs`, `pqzh_none.rs`
- **wasm32 and JS**: `pqz-core/pqzl/rust/wasm/`, `pqz-core/ffi/wasm/`, `ffi/wallet-wasm/`; clientkeys `src/pqzopen.js`,
  `src/pqzopenWasm.js`
- **The on-chain answer**: the precompile `pqz-core/nethermind/Nethermind.Pqz/PqzPrecompile.cs`, `Native.cs`, `PqzSetIds.cs`
  (into `pqz-ffi`'s C ABI `ffi/pqz_ffi.h`); the contract's verdict check (exactly 32 bytes equal to 1, D13) in `PqzCore.sol`;
  the OFFCHAIN `PqzVerdict` path (`ffi/offchain/`, `scaas-pqz-verifier`); `src/pqz/PqzKeyVerifier.sol`. There is no PQZ
  proof verifier in Solidity: say so if one exists
- **Parameter sets**: `pqz-core/params/sets/` (`gen_set.py`, each `<set>/set.toml`, `id-digests.json`), the generated
  `pqzl/rust/src/params/`, `pqz_*_params.h`, `PqzSet.sol`, at `n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`,
  `n2816-kmax65536`
- **The three-key model** (registry key PRECOMPILE; shared OFFCHAIN key with the sealed opening and holder-signed rollover;
  optional per-token OFFCHAIN key): `PqzCore.sol`, `src/ua/UARegistry*.sol` (scoped key records, CTR-UA-43), `ua-rs`
  `src/pqz3k.rs`, `src/pqz3k/handle.rs`, `pqz-core/ffi/src/opening.rs`, clientkeys `src/pqzopen.js`, the verifier service

**Specifications and standards to read first:**
- `T/pqz-core/pqzl/README.md`, `T/pqz-core/pqzh/README.md`, `T/pqz-core/ffi/README.md`, `T/pqz-core/params/sets/README.md`,
  `T/docs/contracts/pq-zero-knowledge.md`, `T/docs/research/pqz-specialised-verifier.md`
- specs `T/docs/superpowers/specs/2026-11-13-pqz-three-keys.md`, `2026-11-06-pqz-proof-path.md`, `2026-11-06-attested-verify.md`,
  `2026-11-06-pqz-key-versions.md`; decisions ARCH-POS-13 and its Changes of 2026-11-13, CTR-PQZ-03, -07, -08, -28, -37,
  CTR-UA-43, CLI-SGN-51

**Invariants to check (beyond section 5; each a finding when it fails):**
1. Every public input is bound into Fiat-Shamir in every implementation (C, Rust, wasm32, Ligero), and every field the
   contract packs into a statement is a public input: chain, `chainUid`, token, key version, op, counter,
   `memoHash || ownTag`, the `v_f` group, `proofSystemId`.
2. Soundness of each relation as the spec states it; the specialised verifier's checks equal the general verifier's line by
   line (norms, ranges, representatives, `≤` against `<`) in C and Rust at all four sets (the `pqz-core-pqzl` unit's
   invariant 6, here read across both cores and the dispatch); a bound applied more loosely in one is a forgery.
3. `stmt` = Solidity = clients' rebuilt statements, byte for byte, at all four sets; the statement lengths the verifier
   service accepts equal the set's.
4. The dispatch maps each `proofSystemId` to exactly one verifier everywhere (`pqz-ffi`, the precompile's `PqzSetIds.cs`, the
   verifier service, `PQZL_SPLIT_ID` only off chain); retired ids refused.
5. The three-key model: each token class uses the key the ruling names and no other; a sealed opening per credit checked by
   re-encryption and byte comparison, never by decrypting with `s` (`opening.rs`, CLI-SGN-51); no PQZ key applied to a value
   not first shown well formed.
6. No decryption oracle in any layer (ARCH-POS-13): no verdict, error, timing or later action depends on decrypting a
   ciphertext someone else chose; the own-key OFFCHAIN risk stays in that token (accepted).
7. Constant time and zeroize in the provers; parameters at or above the claimed level (CTR-PQZ-03) at every set.

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

**Also accepted for this unit (do not report):** the own-key OFFCHAIN token risk (CTR-PQZ-37); the shared-key OFFCHAIN class
 rulings (three-key spec Q8 / Q9); the rollover floor C0-6 (CTR-PQZ-08 (a)); the pqz-core audit-fix batch 8b-2 (fixture gaps
 already known: name them, do not count them as new).

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CTR-PQZ-03 parameters, the relations as the README states them, the three-key rulings. |
| 2 | Cryptography | **Leads this dimension for its family, read vertically.** Section 8's invariants 1-7 through C, Rust, wasm32, the precompile and the verifier service, at all four sets. |
| 3 | Security | A verdict for a statement the contract did not build; `PQZL_SPLIT_ID` reachable on chain; a key used outside its class. |
| 4 | Rules that do not bend | No decryption oracle in any layer; ciphertexts in state; maximal support (the OFFCHAIN mode where no precompile exists). |
| 5 | Secrets and privacy | Prover secrets (witness, randomness, `m`, `e`, `ss_x`) zeroized; no secret in an FFI or wasm error. |
| 6 | Robustness and denial of service | Verifier decode bounded by length and depth in every implementation; overflow at `n2816-kmax65536`; the 345 KB input. |
| 7 | Failure handling | Every internal error a reject in every verifier, never an accept; a `setup` refusal fails init. |
| 8 | Consistency across languages and layers | C = Rust = wasm32 = precompile = verifier service on every vector (`T/smartcontracts/vectors/pqz/`, `pqz-core/ffi/vectors/`), at four sets; `stmt` = Solidity. |
| 9 | Contract specifics | `PqzSet.sol` generated, the verdict check exactly 32 bytes; gas pins per set. |
| 10 | Performance and cost | Prove and verify time per set from the gate logs only (no timing runs). |
| 11 | Interfaces and misuse | The C ABI and wasm exports: lengths with pointers, the set explicit, no default set a caller relies on by accident. |
| 12 | Tests | The cheating fixtures per norm and per relation at four sets in C and Rust, generic and specialised; KATs; fuzz corpora. |
| 13 | Operations and the supply chain | `pqz-ffi`'s `build.rs`, the vendored LaZer sources, the Rust crate pins. |

## 9. Report format (Markdown, English)

```
# crypto-pqz: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### CPZ-1 [P1] <short title>
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
