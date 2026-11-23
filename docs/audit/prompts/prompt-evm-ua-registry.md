# AI audit prompt, unit `evm-ua-registry` (DRAFT, 2026-11-16)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-evm-ua-registry.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-evm-ua-registry.md`, `20261120-09-agy-gemini-4-argon-high-evm-ua-registry.md`). Use the tool's
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

## 8. Your unit: `evm-ua-registry`

The universal-account registry and the account contracts: identity, registration, PoP, `msig`, KEM and PQZ key records, generations, the registry library split, `SmartKeyAccount`, `MandateWallet`, Hedera.

**Scope (paths under `T/`):**
- `smartcontracts/evm/src/ua/{UARegistry,UARegistryCoreLib,UARegistryAuxLib,UARegistryRegLib,UAStore,UAKinds,IUARegistry,IUAVerifier}.sol`
  (`UARegistryRegLib.sol` added 2026-11-24: every `register` form and the registration-bound helpers, moved verbatim from
  `UARegistryCoreLib` and run by nested DELEGATECALL (owner 2026-11-19, candidate (2) of the split): invariants 1 and 2 apply)
- `smartcontracts/evm/src/account/`, `src/wallet/`, `src/hedera/`, `src/governance/UAAdmin.sol`
- read-only references: `src/common/{MultiSig,SigCheck}.sol`, the verifiers it calls (unit `evm-ua-verifiers` audits them)

**Specifications and rules to read first:**
- `T/docs/contracts/accounts.md` (CTR-UA-*, CTR-ACC-*), `T/docs/contracts/mandates.md`
- decisions: CTR-UA-03, -07, -14, -16, -24, -31, -32, -36, -37, -38, -39, -40, -42, -44; CTR-ACC-08, -11; CTR-PQZ-28; NODE-JOB-29 (the client side of the ML-DSA cache); the gen-1 kind rule (owner 2026-10-31 (a), Change 2026-11-15)
- `T/smartcontracts/vectors/ua/` (registration, portable records, `msig`, KEM, id display)

**Invariants to check (beyond section 5):**
1. The library split keeps behaviour: DELEGATECALL storage layout, `this`, `msg.sender`, return data and revert bubbling, reentrancy guards, `LinkClosure` release pins; `UARegistryAuxLib` holds only what the owner allowed to move.
2. A registration is portable (CTR-UA-07, CTR-UA-31): the same bytes on every chain, every field in state, the typed digest binds every field it must (kind, key data, `pqzKeyHash`, KEM record hash, `pqzPopHash`), one accepted form; an identical record or a revert.
3. `msig` minimal form: with T the slots' total weight and N the threshold, T >= N and T - weight(i) < N for every slot; a front-runner cannot drop a slot and register the same id with other `pop` bytes.
4. `msig` members (CTR-UA-44): the id is the first structure's for ever; disable by bitmap, append new slots, re-enable allowed; an update is signed by a threshold of the enabled slots, `version == stored + 1`, carries `chainUid`, enabled weight >= threshold after it; every path that recognised an `msig` by re-hashing caller key data (`UAKinds.uaSig`, generic `uaExecute` / `uaBatch`) reads registry state after the first change; `UAMembership` replay after disable + re-add.
5. Member acceptance (CTR-UA-37): only accepted members count at verify; the acceptance hash in state; generations as ruled.
6. KEM and PQZ key records: every version write-once, version 0 included; an `msig` holds no KEM key; key reuse refused; the token view names the version (CTR-UA-42).
7. ML-DSA cached keys: an uncached key on a no-precompile registry reverts `UAKeyNotCached` and cannot be made to verify a wrong key; the cache parts bind the key; every verify path stays <= 2^24 regular gas.
8. No EIP-7702 path: classification by code at verify time; a delegated EOA's delegate never authorises; a delegated caller is refused.
9. `SmartKeyAccount`: key add / remove / rotate, guardian and recovery, `mtxExecute` with `AccountSig`, nonce cancel; WebAuthn blob compare (CTR-ACC-08); `MandateWallet` mandates, payees, revoke; the Hedera account auth.
10. Replay across chain id, `chainUid`, registry generation, kind and purpose (`requirePortable` purpose set closed); `0x0142` is a scheme, never an id kind.
11. `rescue(asset)` on the registry: anyone, the whole balance, only to the constant destination, nothing else movable.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/pqz-core/research/code-review-2026-10-26/README.md` (whole-contract review at `64549aa4`) and `code-review-2026-10-19/README.md`
- `T/docs/research/security-review-record.md` (index of every review, and what no review covered)
- `scratchpad/review-ua-mtx-merge/` (A-regulated, B-metatx-ua, C-pqz-zether, D-factory-gov-dex-pqchat, recheck-*, recheck2-*)
- `scratchpad/review-3w/20261115-16-codex-gpt-6.1-sol-high-three-keys-u4.md` (registry class records), `scratchpad/review-3zh/20261115-12-fable-fable5.2-high-spec-mldsa.md` (ML-DSA cache)

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- the tag's closing gate summary under `T/smartcontracts/evm/runs/` (every forge directory at the default set, the set-sensitive tests at the other three sets)
- `T/smartcontracts/evm/runs/2026-11-15-3zh-core-g2.txt`, `2026-11-15-burner-wrap-caps.txt`, `2026-11-15-pqz-three-keys-round/summary.txt`, `2026-11-13-fix3-chainuid/summary.txt`, `2026-11-14-msig-members/mutants.txt`, `2026-11-15-3zh-mldsa.txt`
- `T/smartcontracts/evm/size-baseline.json` with `T/scripts/size_gate.py` (the size ratchet, ceiling 64 KiB)

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CTR-UA-03, -07, -14, -16, -24, -31, -32, -36 to -40, -42, -44 and CTR-ACC-08, -11 one by one against `UARegistry.sol`, `UARegistryCoreLib.sol`, `UARegistryAuxLib.sol`, `UAKinds.sol`; the gen-1 kind rule (Change 2026-11-15); every BUILT row of `docs/contracts/accounts.md` and `mandates.md` has code and a test; code with no rule (a view or entry no CTR-UA row names). |
| 2 | Cryptography | The registration typed digest (`UAKinds` / `uaMessage(kind, purpose, typedDigest)`): what it binds (kind, key data, `pqzKeyHash`, KEM record hash, `pqzPopHash`, generation, `chainUid`) and what it does not; the purpose tags and the closed `requirePortable` purpose set (domain separation); the `msig` id hash over its first structure; the ML-DSA cache parts binding the key (`mldsa_cache` hash); canonical key data per kind (one accepted encoding, `0x0142` a scheme, never an id kind); the KEM record (scheme 1, ML-KEM-1024 + X25519) hashed as clients hash it; PoP (`pop`, `pqzPop`) bound to the id and version. |
| 3 | Security | Who may call each entry (`register`, `setKemKey`, PQZ key writes, `msig` update, member accept, `rescue`, `UAAdmin`); replay across chain id, `chainUid`, generation, kind and purpose; nonce lanes and `UAMembership` replay after disable + re-add; front-running a registration with other `pop` bytes; downgrade from an `msig` update to an older version; the 7702 classification at verify time (invariant 8); `SmartKeyAccount` guardian and recovery rights, `MandateWallet` payee and revoke. |
| 4 | Rules that do not bend | Every state-changing `mtx*` / `ua*` entry relayable with fee 0; explicit parameters on every entry (no packed key bundles beyond one crypto object); no EIP-7702 path; maximal support (ARCH-POS-18): an uncached ML-DSA key on a no-precompile registry reverts by name rather than disabling the kind, `mldsa87` as CTR-UA-39 rules; one rule on every chain (no L1 / L2 split in `UAKinds`); nothing upgradable in the registry, the libs or the accounts. |
| 5 | Secrets and privacy | Business identifiers in clear in the registry's events and state (ARCH-POS-17); what a public observer links between a UA, its KEM key, its PQZ keys and its `msig` members; `SmartKeyAccount` guardian lists and `MandateWallet` payees as public metadata. |
| 6 | Robustness and denial of service | Unbounded `msig` slot loops, member lists, generation walks (`predecessor` chains, `MAX_GENERATION`), `uaPage` reads; storage griefing by many registrations or key versions; an input that locks a UA (a member that never accepts, CTR-UA-37 accepted); every verify path <= 2^24 regular gas; registration with the largest key data (SLH-DSA, ML-DSA-87, `msig` of 16) within EIP-8037. |
| 7 | Failure handling | Named errors on every refusal (`UAKeyNotCached` and the rest); no partial registration after a revert in a library call (revert bubbling through `UARegistryCoreLib` / `AuxLib`); reentrancy through a verifier or an account callback; `rescue` cannot move anything else. |
| 8 | Consistency across languages and layers | The registration bytes and digests equal `T/smartcontracts/vectors/ua/` and what clientkeys `ua.js`, `ua-rs` `ua_portable.rs` / `keydata.rs` and the SDK `account/register.rs` build; the registry views the SDK's `line.rs` reads (`holderOf`, `kindHome`, `generation`, `uaPage`, `pqzKeyOf`) answer as the SDK expects; the node's allow-lists for the registry entries (`typed.rs`, `guard.rs`, `selector_audit.json`); the Soroban registry's same rule (`smartcontracts/soroban/contracts/ua-registry/`) where this unit's rule claims one rule on every chain. |
| 9 | Contract specifics | The library split (DELEGATECALL storage, `this`, `msg.sender`, return data, `LinkClosure` release pins); the layout pins under `test/v2/layout/`; every typehash `*TypehashIsPinned`; `UARegistryAuxLib` only what the owner allowed to move; immutability (no admin upgrade path in `UAAdmin`); the size gate rows of the registry and libs. |
| 10 | Performance and cost | Gas per registration and per verify against `docs/contracts/accounts.md`; the ML-DSA cache write cost and who pays it; storage growth per UA, per key version and per `msig` member over a long life. |
| 11 | Interfaces and misuse | The registry view API is hard to misuse: a view that returns a default for an unknown UA instead of refusing; `requirePortable` callers that can pass a purpose outside the closed set; error codes stable across generations. |
| 12 | Tests | Each refusal of invariants 1-11 has a positive twin and a test that can fail; the `msig` mutants (`runs/2026-11-14-msig-members/mutants.txt`) cover every check, survivors explained; the vectors under `vectors/ua/` read by the forge tests. |
| 13 | Operations and the supply chain | N/A for config and dependencies (no off-chain code in this unit); SPDX headers on every file in scope. |

## 9. Report format (Markdown, English)

```
# evm-ua-registry: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### UAR-1 [P1] <short title>
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
