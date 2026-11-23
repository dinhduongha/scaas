# AI audit prompt, unit `crypto-pqchat-tree` (DRAFT, 2026-11-24)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-crypto-pqchat-tree.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.1-sol-high-crypto-pqchat-tree.md`, `20261120-09-agy-gemini-4-argon-high-crypto-pqchat-tree.md`). Use the tool's
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

## 8. Your unit: `crypto-pqchat-tree`

**FRAME: finalize when the TreeKEM build merges** (branch `pqchat-treekem`; the paths below are the branch's).

PqChat's TreeKEM mode (`groupMode = 1`) read vertically: the key schedule, path secrets from the seed, the tree and its hash,
the admission of node keys, post-compromise security on removal, through clientkeys `treekem.js`, `ua-rs` `wallet/tree.rs` and
Solidity `PqGroupTree`.

**How to read (dimension 2, read vertically, `T/docs/review.md` §1-§2).** One primitive at a time, through every
implementation and layer listed below: C, Rust, wasm32, JS, Solidity, C#, the generic and the specialised verifier, the
signer and every verifier. First read the standard or the spec's mathematics; then each implementation against it; then the
implementations against each other on the shared vectors. **A bug class found once is checked everywhere it can recur**, and
the finding lists every place. Where a primitive comes from a library (`ml-dsa`, `@noble/post-quantum`, .NET `MLDsa`, a
Soroban host function), audit our use of it (parameters, encodings, context, lengths, error handling), not the library
itself, and name its pinned version.

This unit leads dimension 2 for the tree; unit `evm-pqchat` audits the contract alone (its invariant 9), the `ua-rs-*` units and
`app-cores` the clients alone.

**Primitives and every implementation (paths under `T/`; find any implementation this list misses and name it):**
Paths are on branch `pqchat-treekem` (worktree `.claude/worktrees/pqchat-treekem` until it merges); at the tag they are under
`T/`.
- **The key schedule** (spec §5: `H(ikm, info) = HKDF-SHA-256(ikm, salt = empty, info, 32)`; `treeId`, `pathContext`,
  `firstPathSecret` from the seed, `pathSecrets`, `nodeKeyOf`, the path ciphertext's `ctKek` and AAD, `epochContext`,
  `joinerSecret`, `schedule`, `K`, the tree info and wrap seals): clientkeys `clients/clientkeys/src/treekem.js` (`treeScope`,
  `PQCHAT_TREE`, `pathSecrets`, `nodeKeyOf`, `pathContext`, `firstPathSecret`, `sealPathSecret`, `openPathSecret`,
  `epochContext`, `joinerSecret`, `schedule`, `sealTreeInfo`, `openTreeInfo`, `sealTreeWrap`, `openTreeWrap`, `createGenesis`,
  `buildCommit`, `reader`), `src/pqchat-tree.js`, `src/kem.js` (`kemKeyFromSeed`); `ua-rs` `clients/ua-rs/src/wallet/tree.rs`
  (`TreeScope`, `PQCHAT_TREE`, `path_context`, `EpochFields`, `PathCt`, `wrap_hash`, `Genesis`, `CommitInput`, `BuiltCommit`,
  `tree_prepare`, `tree_prepare_leave`, `tree_prepare_remove`, `key_of`, the replay), `src/wallet/kem.rs`, `src/wallet/pqchat.rs`
- **The tree and its hash** (RFC 9420 array layout, blanks, resolution without unmerged leaves; the typed tree hash `TreeLeaf`
  / `TreeParent`; no RFC parent hash): `ua-rs` `src/wallet/tree_public.rs` (`level`, `root`, `parent`, `sibling`,
  `direct_path`, `copath`, `leaf_hash`, `parent_hash` (the tree hash's parent node), `ct_targets_hash`, `struct_hash`);
  clientkeys `src/treekem.js`, `src/pqchat-tree.js`; Solidity `smartcontracts/evm/src/pqgroup/PqGroupTree.sol` (tree math, tree
  hash, `treeHash` at acceptance), `src/pqchat/PqChatTree.sol`
- **Admission of node keys** (scheme 1, 1,601 B, canonical X25519 `pk_X`, ML-KEM `ek` coefficient bound 3,329, no two live
  leaves with the same key bytes): `PqGroupTree.sol`; `ua-rs` `tree_public.rs`; clientkeys `treekem.js`, `kem.js`
- **PCS on removal and the no-return sets** (`gone`, `goneOwnKey`, `goneKey`; a removed or departed UA's leaves blanked by the
  next commit): `PqGroupTree.sol`, `PqChatTree.sol`; the clients' replay
- **Vectors and fixtures**: `smartcontracts/vectors/pqchat/tree.json`, `tree-secrets.json`, clientkeys
  `scripts/pqchat-vectors.mjs`, `scripts/treekem-fixture.mjs`; tests `clients/clientkeys/test/treekem.test.js`,
  `pqchat-tree.test.js`, `clients/ua-rs/tests/tree.rs`, `smartcontracts/evm/test/pqchat/PqChatTree*.t.sol`,
  `PqChatTreeModel.sol`
- **Not built at the time of writing:** the SDK's and pqchat-core's tree layer (`clients/scaas-sdk/tests/feature_tree.rs` only);
  read what the merge adds

**Specifications and standards to read first:**
- spec `T/docs/superpowers/specs/2026-11-23-pqchat-treekem.md` (§2 controller calls, §3 deviations from RFC 9420, §4 the
  tree, §5 secrets, §8 what the contract checks and what only clients check, §14 threats, §15 client layers), plan
  `T/docs/superpowers/plans/2026-11-23-pqchat-treekem.md`, research `T/docs/research/2026-11-23-treekem-pqchat.md`
- RFC 9420 (tree math, resolution, TreeKEM, the key schedule it departs from), FIPS 203, RFC 7748, RFC 5869
- decisions CTR-CHAT-26, -27, -28; `T/docs/clients/pqchat-core.md` CLI-PQC-17

**Invariants to check (beyond section 5; each a finding when it fails):**
1. The key schedule equal in clientkeys and `ua-rs` byte for byte on `tree-secrets.json`, and equal to the spec's §5;
   every label `<prefix>/<name>` from the scope (CTR-CHAT-28), no two derivations sharing a label and input.
2. Path secrets from the seed (committer's `firstPathSecret` from `kemSeed(ua, keyId)` and the path context): what binds the
   path context (`treeId`, epoch, `ctTargets`, removes, adds), and that a committer cannot reuse a path secret across commits
   or sessions; the accepted cost of no `init` chain (CTR-CHAT-26).
3. The tree hash: the same root in Solidity (`PqGroupTree.sol`), `ua-rs` and clientkeys for every tree shape the vectors
   hold, blanks and resolution as RFC 9420 without unmerged leaves; what the tree hash binds and does not (no parent hash: a
   node key known only by its signed hash).
4. Admission: the contract, `ua-rs` and clientkeys admit exactly the same node keys; the hygiene limit of `goneKey`
   (equivalent keys with another `kemHash`, accepted lending residual) stated, nothing more claimed.
5. Post-compromise security on removal: after the next commit a removed or departed UA learns no later path secret, `K` or
   message key; what it can still learn as the spec states (forward secrecy and PCS claims of §14); a member that cannot
   follow an epoch shows it and sends nothing by itself.
6. Path ciphertexts: KEM scheme 1, `ctKek` and AAD binding `treeId`, epoch, node, target and `kemPk`; a ciphertext opened by
   the wrong target refused without an oracle.
7. Constant time and zeroize of path secrets, node private keys, `joinerSecret` and `K`; every step inside `ua-rs` (spec §15).

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

**Also accepted for this unit (do not report):** the accepted cost of the joiner without RFC 9420's `init` chain; the key
 no-return set as hygiene only (equivalent keys, the lending residual); the owner rulings on the spec's open points
 (CTR-CHAT-26); the spec reviews' resolved findings (`scratchpad/treekem-review-20261123-1426/resolution.md`).

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CTR-CHAT-26 to -28 and the spec's §5 and §8 for each implementation. |
| 2 | Cryptography | **Leads this dimension for its family, read vertically.** Section 8's invariants 1-7 through clientkeys, `ua-rs` and Solidity. |
| 3 | Security | A non-admin changing another UA's keys; a commit with a forged path for another leaf; `treeId` or `parentTreeHash` not bound; a removed UA re-added. |
| 4 | Rules that do not bend | Never lose ciphertext (path ciphertexts and node keys in state); no decryption oracle in the client's replay. |
| 5 | Secrets and privacy | Path secrets, node private keys, `joinerSecret` and `K` only in `ua-rs` key memory; what the tree shape reveals. |
| 6 | Robustness and denial of service | Tree sizes at the bounds (256 leaves, 32 changes) in every implementation; the resolution walk's cost. |
| 7 | Failure handling | A member that cannot follow an epoch shows it and sends nothing; a closed session's state. |
| 8 | Consistency across languages and layers | The same tree hash, schedule and admission in Solidity, `ua-rs` and clientkeys on `tree.json` and `tree-secrets.json`; `PqChatTreeModel.sol` against both. |
| 9 | Contract specifics | `PqGroupTree.sol`'s namespace, the body module split, the size gate, gas pins. |
| 10 | Performance and cost | Commit size and client CPU at 256 leaves; the completion's gas (spec §13 estimates). |
| 11 | Interfaces and misuse | The tree API in `ua-rs` (`tree_prepare*`) hard to misuse: the scope explicit, every field shown before signing. |
| 12 | Tests | The T1a, T1b, T2, T3a, T3b mutant records; vectors read by both clients and the forge tests. |
| 13 | Operations and the supply chain | N/A for new dependencies (none added for the tree: say if one is). |

## 9. Report format (Markdown, English)

```
# crypto-pqchat-tree: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### CTK-1 [P1] <short title>
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
