# AI audit prompt, unit `adversarial` (DRAFT, 2026-11-24)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-adversarial.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.1-sol-high-adversarial.md`, `20261120-09-agy-gemini-4-argon-high-adversarial.md`). Use the tool's
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

## 8. Your unit: `adversarial`

The adversarial area of `T/docs/review.md` §2: it **plays every role against the whole system** and tries to break each rule
that does not bend, and to break recovery from state alone. Work from roles to code: for each role, write the attack as a
concrete sequence of calls, transactions, RPC answers or messages, then trace it through the named files until it lands or is
refused. A refusal you traced is a result too ("Checked and sound").

**Scope (paths under `T/`):** the whole pre-freeze target, as the layer units divide it (`T/smartcontracts/evm/src/`,
`T/pqz-core/` and `pqz-core/nethermind/`, `T/clients/{ua-rs,clientkeys,scaas-sdk,scaas-rpc,pqchat-core,pqvault-core}/`,
`T/scaas-node/src/`, `T/scaas-pqz-verifier/src/`), with the Soroban registry and token where a rule claims one rule on every
chain. Not in scope: `*/legacy/`, `test/` except to read what a test claims.

**Specifications and rules to read first:**
- `T/docs/review.md` §1 dimension 4 (the rules that do not bend) and §2 (the adversarial area); `T/AGENTS.md` "Rules that do
  not bend"; `T/docs/node/threat-model.md` (NODE-SEC-01); the threat sections of the specs: PqChat TreeKEM §14, PqVault §10,
  pqchat-core §9, the three-key spec, the proof-path spec
- decisions ARCH-POS-13, -15, -17, -18, CTR-UA-24 (no EIP-7702), CTR-CHAT-09, -14, -20, -26, -27, CTR-PQV-03 to -17, CTR-PQZ-07,
  -08, -37, CTR-ZTH-16, -36, -42, CTR-GOV-20, -25, -28 to -30, CTR-DEX-19, NODE-LANE-03, -09, -12, NODE-JOB-07, -11, -24

**Roles (each one a section of your report; for each, try every rule of section 5 and recovery from state alone):**

a. **A malicious subject, holder or member.** Replays a signed record to another chain, `chainUid`, generation, token,
   session, epoch, vault, kind, purpose or nonce lane; races two entries for one intent; registers another UA's public KEM or
   PQZ key as its own (PqChat tree: the no-return sets, the lending residual accepted in CTR-CHAT-26); stages a record that no
   piece can complete (PqChat tree commit, PqVault batch) so that others cannot move on; floods pending credits, wraps,
   topics or messages to grief a recipient (state gas accepted for open topics); takes the home child slot first (accepted,
   CTR-CHAT-09 O2); sends a crafted ciphertext to make another holder's client or a verifier decrypt it (ARCH-POS-13).
b. **A malicious admin or role holder.** Exceeds a grant's terms (min / max / total / per window / uses / valid until /
   delegable narrower); bypasses `grantDelay`; re-enables a disabled feature; keeps a removed member in `admins`
   (`PqChatRemovedKept`, `PqVaultRemovedKept`); a regulator control (FREEZE, FORCE, DENYLIST) that decrypts, reveals or
   moves confidential value; a `WHOLE` holder (unbounded by design, CTR-GOV-20: skip); a rescue that moves anything but the
   stated asset to the constant.
c. **A relayer that refuses, delays or reorders.** It may refuse or delay, never forge or alter: try to alter a fee, a
   recipient, a floor or an unbound field; reorder two signed records of one signer into a different outcome (nonce scopes,
   PqChat pieces, PqVault batches, PQZ rollover halves); delay past a deadline to force a refund or a `dead` report; make the
   node report `dead` while the transaction may still land (NODE-LANE-09, the cancel one nonce ahead); hold back the last
   piece of a multi-transaction flow.
d. **A lying RPC node, below and above the strict-majority option.** Below it (failover, one endpoint answers): what a lying
   endpoint can make a client sign, show or decrypt (a balance, a KEM key, a recipient, an epoch, a decoy set, a gas quote, a
   finality answer); the rule that a read feeding a decryption uses the majority option with at least three nodes and a
   discovered node only then (ARCH-POS-15, CLI-RPC-06). Above it (a strict majority of the configured nodes lies): what
   remains guarded by the contracts alone, and what a client then signs; name every read that feeds a decryption or a key
   choice and say which purpose it runs under. A mix of two endpoints inside one read; a stale head; a forked chain with the
   same chain id but another `chainUid` (NET-ALL-25).
e. **A front-runner.** Front-runs `initialize` on a clone or a deploy at a CREATE2 / CREATE3 address; a registration with other
   `pop` bytes; a DEX fill against a signed floor; a PqChat or PqVault child slot; a PQZ rollover against a debit; a grant
   change against its use.
f. **A removed party.** A member that left or was removed (PqChat flat and tree, PqVault, `msig` slot disabled): what it can
   still read (forward secrecy and post-compromise claims as the specs state them), sign, replay (`UAMembership` after
   disable + re-add), or block; a removed device key; an auditor replaced or a verifier rotated (`pqzVerifierEpoch`); a key
   version rotated with a debit in flight.

**Recovery from state alone** (CTR-CHAT-14, CTR-PQV-10, the PQZ proof path, Zether rollover): for each role, say whether an
honest party can still recover its balance, keys, sessions or vaults from contract state alone after the attack, with no
event log and no local list.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/docs/research/security-review-record.md` (index of every review, and what no review covered)
- `T/pqz-core/research/code-review-2026-10-26/README.md`, `code-review-2026-10-19/README.md`
- `scratchpad/review-ua-mtx-merge/` (A to E, recheck-*, recheck2-*), `scratchpad/review-3w/` (`triage.md`),
  `scratchpad/review-3zh/`, `scratchpad/review-t21/` (`ledger.md`, O1-O8), `scratchpad/sdk-complete-review/`,
  `scratchpad/sdk-review-20261123-0621/` (T26, `STATUS.md`), `scratchpad/pqvault-review/`,
  `scratchpad/treekem-review-20261123-1426/`
- the reports of the layer units of this round under `scratchpad/ai-audit/results/` when they exist: read them for leads,
  do not repeat their findings; a finding of yours that a layer unit already reported names that unit's id

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/smartcontracts/evm/runs/2026-11-18-prefreeze-matrix-summary.txt`, `2026-11-19-pr-a-matrix-summary.txt`, and the tag's own
  closing matrix (every forge directory at the default set, the set-sensitive tests at the other three sets, node and e2e,
  clients, vectors)
- `T/pqz-core/runs/gate/3zh-g2-<set>-summary.txt` for the four sets

**Also accepted for this unit:** section 7 in full; an attack that needs the owner's own keys or the SCaaS testnet's
operator is out of scope; the SCaaS testnet's RPC exposure is not a finding.

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | Each role tried against the rule ids section 8 names; a doc's threat section that claims a defence the code does not make. |
| 2 | Cryptography | N/A for the soundness of primitives (the `crypto-*` units lead dimension 2); here only how an attacker uses a binding gap: a field a digest omits, a key used outside its purpose, a forward-secrecy or post-compromise claim a removed party breaks. |
| 3 | Security | **Leads this dimension.** Roles a to f: authorization per role, forgery, replay and nonces, front-running and ordering, downgrade between modes or versions (`groupMode`, `sigStore`, PRECOMPILE / OFFCHAIN, key versions), input validation at each trust boundary. |
| 4 | Rules that do not bend | Every rule that does not bend, tried by every role: ciphertext lost, a decryption oracle through any layer, packed parameters, an unrelayable write, a 7702 path, a chain assumption, maximal support, a split rule, an RPC consumer on one node, a node guarantee placed in one consumer, an upgrade path. |
| 5 | Secrets and privacy | What each role learns from state, events, calldata, sizes and timing (a removed member's view; a lying RPC's view of reads it serves). |
| 6 | Robustness and denial of service | Griefing by each role: a staged state that blocks others, storage and gas griefing, queue exhaustion at the node, a call that cannot fit a block (EIP-8037, EIP-7825) on a path a user must take. |
| 7 | Failure handling | Recovery from state alone after each attack; reorgs and finality used by a role (an RPC answering a non-final block); the node never reporting `dead` while a transaction may land. |
| 8 | Consistency across languages and layers | A fork an attacker can steer: a record valid for the contract and refused by clients (or the reverse) used to split a group's view. |
| 9 | Contract specifics | Initialisation and deploy front-running; module splits that change `msg.sender` for a role check. |
| 10 | Performance and cost | Who pays when a role griefs (the lane, the user, the victim). |
| 11 | Interfaces and misuse | A misuse an attacker can lure a user into: a prepare that hides a field, a default that is not the safe choice, a hand-off import of a crafted blob. |
| 12 | Tests | For each attack that is refused, the test that shows the refusal and whether it can fail. |
| 13 | Operations and the supply chain | A secret an attacker reads from config, logs or a published artifact; a supply-chain path to a signer (the `bindings-cli-ci` unit leads; here only an attack that uses it). |

## 9. Report format (Markdown, English)

```
# adversarial: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### ADV-1 [P1] <short title>
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
